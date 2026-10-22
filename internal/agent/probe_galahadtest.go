//go:build galahadtest

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// probeEnabled says whether this build runs P8 probe jobs. A galahadtest build does.
const probeEnabled = true

// The P8 probes. Each one is harmless by construction: it stops at a fixed size or time, and the
// ones that push at the limits of the machine run only in a VM, never on a host that is not one.
const (
	probeForkBomb           = "fork-bomb"
	probeMemory             = "memory"
	probeDiskFill           = "disk-fill"
	probeRootfsWrite        = "rootfs-write"
	probeMounts             = "mounts"
	probeDirectConnect      = "direct-connect"
	probeProxy              = "proxy"
	probeVsock              = "vsock"
	probeSleep              = "sleep"
	probeResultOversize     = "result-oversize"
	probeResultUnknownField = "result-unknown-field"
	probeResultEarly        = "result-early"
)

// Limits of the probes.
const (
	diskFillMax   = 5 << 30 // bytes; more than the 4 GiB scratch drive, so the drive ends the fill
	diskFillBlock = 1 << 20
	connectWait   = 5 * time.Second
	vsockWait     = 8 * time.Second
	maxProcFile   = 64 << 10 // bytes read of /proc/mounts
	maxMountLines = 64
)

// probeEnv is what a probe may use.
type probeEnv struct {
	host     *hostConn
	relay    *guestRelay // nil without a proxy channel
	dir      string      // a writable directory on the scratch drive; empty for a probe that runs before the input
	deadline time.Time   // when the probe has to be done, a minute before the end of the job
}

// probe is one P8 probe. run returns what it observed, which goes to the host as artifacts/probe.json.
type probe struct {
	vmOnly    bool // pushes at the limits of the machine: it refuses to run outside a VM
	ownResult bool // sends its own, bad, Result frame
	run       func(probeEnv) (map[string]any, error)
}

var probes = map[string]probe{
	probeForkBomb:           {vmOnly: true, run: forkBomb},
	probeMemory:             {vmOnly: true, run: memoryHog},
	probeDiskFill:           {vmOnly: true, run: diskFill},
	probeRootfsWrite:        {vmOnly: true, run: rootfsWrite},
	probeMounts:             {vmOnly: true, run: mounts},
	probeDirectConnect:      {vmOnly: true, run: directConnect},
	probeProxy:              {run: proxyRequests},
	probeVsock:              {vmOnly: true, run: vsockDials},
	probeSleep:              {vmOnly: true, run: sleepForever},
	probeResultOversize:     {ownResult: true, run: resultOversize},
	probeResultUnknownField: {ownResult: true, run: resultUnknownField},
	probeResultEarly:        {ownResult: true, run: resultEarly},
}

// probeBeforeInput says whether the probe acts before the guest has read the input.
func probeBeforeInput(name string) bool { return name == probeResultEarly }

// probeReport is artifacts/probe.json. Only the tests parse it.
type probeReport struct {
	Probe        string         `json:"probe"`
	Observations map[string]any `json:"observations"`
}

// runProbe runs the probe called name, sends what it saw as the probe artifact, and ends the job with
// an empty Result. A probe with its own Result sends that instead.
func runProbe(host *hostConn, name string, relay *guestRelay, dir string, unsafeHost bool) error {
	p, ok := probes[name]
	switch {
	case !ok:
		return fail(protocol.CodeProtocol, "unknown probe %q", protocol.CleanPath(name))
	case p.vmOnly && unsafeHost:
		return fail(protocol.CodeInternal, "probe %q pushes at the limits of the machine and runs only in a VM, not on this host", name)
	}
	obs, err := p.run(probeEnv{host: host, relay: relay, dir: dir, deadline: host.deadline.Add(-analysisMargin)})
	if err != nil {
		return err
	}
	if p.ownResult {
		return nil
	}
	data, err := json.Marshal(probeReport{Probe: name, Observations: obs})
	if err != nil {
		return err
	}
	if err := host.send(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactProbeJSON, Data: data}.Marshal()); err != nil {
		return fmt.Errorf("send probe artifact: %w", err)
	}
	return sendEmptyResult(host)
}

// sendEmptyResult ends the job with a Result that has nothing in it.
func sendEmptyResult(host *hostConn) error {
	res := emptyResult("probe")
	data, err := protocol.EncodeResult(&res)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return sendResult(host, data)
}

// errnoNames are the errors the probes expect to see, by name.
var errnoNames = map[syscall.Errno]string{
	syscall.EACCES: "EACCES", syscall.ECONNREFUSED: "ECONNREFUSED", syscall.ECONNRESET: "ECONNRESET",
	syscall.EINVAL: "EINVAL", syscall.ENETUNREACH: "ENETUNREACH", syscall.ENODEV: "ENODEV", syscall.ENOSPC: "ENOSPC",
	syscall.EPERM: "EPERM", syscall.EROFS: "EROFS", syscall.EHOSTUNREACH: "EHOSTUNREACH",
}

// errName names the errno inside err, or says what else it was.
func errName(err error) string {
	var e syscall.Errno
	switch {
	case errors.As(err, &e):
		if n, ok := errnoNames[e]; ok {
			return n
		}
		return fmt.Sprintf("errno %d", int(e))
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	}
	return protocol.Snippet(err.Error())
}

// diskFill writes zeros into a file on the scratch drive until the write fails, then deletes the file.
// It stops at diskFillMax and at the deadline too, so it ends even if the drive were bigger.
func diskFill(env probeEnv) (map[string]any, error) {
	path := filepath.Join(env.dir, "p8-fill")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a fixed name in the work directory
	if err != nil {
		return nil, fmt.Errorf("create the fill file: %w", err)
	}
	block := make([]byte, diskFillBlock)
	var written int64
	stoppedBy := "cap"
	for written < diskFillMax {
		if time.Now().After(env.deadline) {
			stoppedBy = "deadline"
			break
		}
		n, err := f.Write(block)
		written += int64(n)
		if err != nil {
			stoppedBy = errName(err)
			break
		}
	}
	_ = f.Close()       // the fill is over; a close error changes nothing
	_ = os.Remove(path) // best effort: the VM is gone at the end of the job
	return map[string]any{"bytes_written": written, "stopped_by": stoppedBy}, nil
}

// mounts lists what the guest has mounted and the block devices it sees.
func mounts(probeEnv) (map[string]any, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxProcFile))
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var types []string
	for _, l := range lines {
		if fields := strings.Fields(l); len(fields) >= 3 && !slices.Contains(types, fields[2]) {
			types = append(types, fields[2])
		}
	}
	slices.Sort(types)
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	devices := make([]string, len(entries))
	for i, e := range entries {
		devices[i] = e.Name()
	}
	slices.Sort(devices)
	return map[string]any{
		"mounts": lines[:min(len(lines), maxMountLines)], "fs_types": types, "block_devices": devices,
		"agent": procIdentity("/proc/self/status"),
	}, nil
}

// procIdentity reads who a process is from its status file: the real and effective user and group ids,
// the effective capabilities as hex, and no_new_privs. A field it cannot read is missing.
func procIdentity(statusPath string) map[string]any {
	data, err := os.ReadFile(statusPath) // #nosec G304 -- /proc
	if err != nil {
		return map[string]any{"error": errName(err)}
	}
	id := map[string]any{}
	for line := range strings.Lines(string(data)) {
		key, rest, ok := strings.Cut(line, ":")
		f := strings.Fields(rest)
		switch {
		case !ok || len(f) == 0:
		case key == "Uid" && len(f) >= 2:
			id["uid_real"], id["uid_effective"] = f[0], f[1]
		case key == "Gid" && len(f) >= 2:
			id["gid_real"], id["gid_effective"] = f[0], f[1]
		case key == "CapEff":
			id["cap_eff"] = f[0]
		case key == "NoNewPrivs":
			id["no_new_privs"] = f[0]
		}
	}
	return id
}

// directConnect dials public and metadata addresses without the proxy. The guest has no network card,
// so every dial has to fail.
func directConnect(probeEnv) (map[string]any, error) {
	obs := map[string]any{}
	for _, addr := range []string{"1.1.1.1:443", "169.254.169.254:80"} {
		c, err := net.DialTimeout("tcp", addr, connectWait)
		if err != nil {
			obs[addr] = errName(err)
			continue
		}
		_ = c.Close() // it only showed that the dial worked
		obs[addr] = "connected"
	}
	return obs, nil
}

// proxyRequests asks the relay for tunnels to the metadata address, a private address, localhost and a name
// that resolves to a private address. The host proxy has to deny each of them.
func proxyRequests(env probeEnv) (map[string]any, error) {
	if env.relay == nil {
		return nil, fail(protocol.CodeInternal, "the proxy probe needs the proxy")
	}
	obs := map[string]any{}
	for _, host := range []string{"169.254.169.254", "10.1.2.3", "localhost", "rebind.test"} {
		obs[host+":443"] = probeConnect(env.relay.addr, &url.URL{Scheme: "http", Host: host + ":443"})
	}
	return obs, nil
}

// vsockTargets are vsock addresses other than the two ports the host serves (1024 and 1025 of CID 2).
var vsockTargets = []struct{ cid, port uint32 }{
	{2, 1}, {2, 22}, {2, 1023}, {2, 1026}, {2, 4096}, {2, 65535},
	{0, 1024}, {1, 1024}, {3, 1024}, {4, 1024}, {0xFFFFFFFF, 1024},
}

// vsockDials dials host ports and other CIDs. None of them may connect.
func vsockDials(probeEnv) (map[string]any, error) {
	obs := map[string]any{}
	for _, t := range vsockTargets {
		obs[fmt.Sprintf("%d:%d", t.cid, t.port)] = vsockDial(t.cid, t.port)
	}
	return obs, nil
}

func vsockDial(cid, port uint32) string {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := dialVsock(cid, port)
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return errName(r.err)
		}
		_ = r.conn.Close() // it only showed that the dial worked
		return "connected"
	case <-time.After(vsockWait):
		go func() { // a late connection is closed all the same
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return "timeout"
	}
}

// sleepForever never answers. The host ends the job at its time limit.
func sleepForever(probeEnv) (map[string]any, error) {
	for {
		time.Sleep(time.Hour)
	}
}

// resultOversize announces a Result frame of 64 MiB + 1 bytes, over the limit of its type.
func resultOversize(env probeEnv) (map[string]any, error) {
	_, err := env.host.conn.Write([]byte{byte(protocol.FrameResult), 0x04, 0x00, 0x00, 0x01})
	return nil, err
}

// resultUnknownField sends a Result with a field the schema does not have.
func resultUnknownField(env probeEnv) (map[string]any, error) {
	res := emptyResult("probe")
	data, err := protocol.EncodeResult(&res)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return nil, env.host.send(protocol.FrameResult, bytes.Replace(data, []byte("{"), []byte(`{"bogus":1,`), 1))
}

// resultEarly sends a good Result before the guest has read the input, so before the host has sent
// the end of it.
func resultEarly(env probeEnv) (map[string]any, error) {
	return nil, sendEmptyResult(env.host)
}
