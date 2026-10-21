//go:build linux

// Package firecracker runs the guest in a Firecracker microVM. It talks to the Firecracker
// process over the unix socket of its API, and to the guest over the unix sockets Firecracker
// maps vsock ports to. It reads nothing from the guest and nothing from Firecracker but the
// capped API answers and the capped console, which go raw into console.log.
package firecracker

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/images"
)

const (
	controlPort = 1024 // the guest dials this port first; the connect timeout watches it
	guestCID    = 3
	bootArgs    = "console=ttyS0 reboot=k panic=1 pci=off ro root=/dev/vda init=/sbin/galahad-init"

	defaultCPUs       = 2
	defaultMemoryMiB  = 3072
	defaultScratchMiB = 4096
	maxCPUs           = 32
	maxMemoryMiB      = 64 << 10
	maxScratchMiB     = 64 << 10

	defaultAPITimeout     = 10 * time.Second
	defaultConnectTimeout = 30 * time.Second

	// galahad-init copies the agent into a 64 MiB tmpfs (/run), which also holds other files.
	maxAgentBytes = 48 << 20
	sectorSize    = 512
	maxConsole    = 1 << 20 // bytes of the Firecracker console kept in console.log

	// maxSocketPath is below the 108 bytes of sun_path, which leaves room for the terminating zero.
	maxSocketPath = 100
)

// Params describes the machine to start. It has the fields of sandbox.Spec, which this package
// cannot import: the sandbox package imports it.
type Params struct {
	JobDir             string
	Image              string // core | re
	CPUs               int    // 0 = 2
	MemoryMiB          int    // 0 = 3072
	ScratchMiB         int64  // 0 = 4096
	AgentPath          string // "" = Backend.AgentPath
	Signatures         string // "" = none
	SignaturesWritable bool
	Ports              []uint32
}

// Backend starts Firecracker microVMs.
type Backend struct {
	FirecrackerPath string        // the pinned Firecracker binary
	ImagesDir       string        // holds vmlinux, core.ext4 and re.ext4 of the pinned version
	AgentPath       string        // the galahad-agent that is attached to the machine
	APITimeout      time.Duration // for the API socket to appear and for each API call; 0 = 10 s
	ConnectTimeout  time.Duration // for the first control connection after boot; 0 = 30 s
}

// New returns the backend for the state directory of this user: the pinned Firecracker in the
// bin directory, the pinned images, and the galahad-agent next to this executable.
func New() (*Backend, error) {
	home, err := config.Home()
	if err != nil {
		return nil, err
	}
	pins, err := images.Load()
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find this executable: %w", err)
	}
	return &Backend{
		FirecrackerPath: filepath.Join(config.BinDir(home), "firecracker"),
		ImagesDir:       filepath.Join(config.ImagesDir(home), pins.Version),
		AgentPath:       filepath.Join(filepath.Dir(exe), "galahad-agent"),
	}, nil
}

// call is one API request.
type call struct {
	path string
	body any
}

// Machine is a running microVM.
type Machine struct {
	cmd       *exec.Cmd
	console   *os.File
	listeners map[uint32]net.Listener
	transient []string // files that Kill removes
	sockDir   string   // a directory made for the sockets; "" if they are in the job directory
	done      chan struct{}
	waitErr   error
	timedOut  atomic.Bool
	connect   time.Duration
	killOnce  sync.Once
	killErr   error
}

// Start boots a machine. The listeners for p.Ports exist before it boots. On an error nothing is
// left running and the transient files are gone; console.log stays.
func (b *Backend) Start(ctx context.Context, p Params) (*Machine, error) {
	p, err := b.check(p)
	if err != nil {
		return nil, err
	}
	kernel := filepath.Join(b.ImagesDir, "vmlinux")
	rootfs := filepath.Join(b.ImagesDir, p.Image+".ext4")
	for _, f := range []string{kernel, rootfs} {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("the image file %s is missing; run galahad setup", f)
		}
	}

	m := &Machine{listeners: map[uint32]net.Listener{}, done: make(chan struct{}), connect: orDefault(b.ConnectTimeout, defaultConnectTimeout)}
	started := false
	defer func() {
		if !started { // an error, or a panic inside start
			_ = m.Kill() // best effort; the start error is the one to report
		}
	}()
	if err := m.start(ctx, b, p, kernel, rootfs); err != nil {
		return nil, err
	}
	started = true
	return m, nil
}

// check fills in the defaults of p and rejects values out of range.
func (b *Backend) check(p Params) (Params, error) {
	if p.JobDir == "" {
		return p, errors.New("firecracker: no job directory")
	}
	abs, err := filepath.Abs(p.JobDir)
	if err != nil {
		return p, fmt.Errorf("firecracker: %w", err)
	}
	p.JobDir = abs
	if p.Image != "core" && p.Image != "re" {
		return p, fmt.Errorf("firecracker: unknown image %q", p.Image)
	}
	for _, c := range []struct {
		name string
		v    int64
		max  int64
	}{
		{"CPUs", int64(p.CPUs), maxCPUs},
		{"MemoryMiB", int64(p.MemoryMiB), maxMemoryMiB},
		{"ScratchMiB", p.ScratchMiB, maxScratchMiB},
	} {
		if c.v < 0 || c.v > c.max {
			return p, fmt.Errorf("firecracker: %s %d is out of range 0 to %d", c.name, c.v, c.max)
		}
	}
	p.CPUs = cmp.Or(p.CPUs, defaultCPUs)
	p.MemoryMiB = cmp.Or(p.MemoryMiB, defaultMemoryMiB)
	p.ScratchMiB = cmp.Or(p.ScratchMiB, defaultScratchMiB)
	if p.AgentPath == "" {
		p.AgentPath = b.AgentPath
	}
	return p, nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// start does the work of Start. The caller kills m when it returns an error.
func (m *Machine) start(ctx context.Context, b *Backend, p Params, kernel, rootfs string) error {
	sockDir, err := m.socketDir(p)
	if err != nil {
		return err
	}
	fcSock := filepath.Join(sockDir, "fc.sock")
	vsock := filepath.Join(sockDir, "v.sock")
	m.transient = append(m.transient, fcSock, vsock)
	for _, port := range p.Ports {
		path := vsock + "_" + strconv.FormatUint(uint64(port), 10)
		m.transient = append(m.transient, path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return fmt.Errorf("firecracker: listen for port %d: %w", port, err)
		}
		if port == controlPort {
			l = &watchListener{Listener: l, first: make(chan struct{})}
		}
		m.listeners[port] = l
	}

	scratch := filepath.Join(p.JobDir, "scratch.img")
	agent := filepath.Join(p.JobDir, "agent.img")
	m.transient = append(m.transient, scratch, agent)
	if err := makeScratch(scratch, p.ScratchMiB); err != nil {
		return err
	}
	if err := makeAgentImage(p.AgentPath, agent); err != nil {
		return err
	}

	console, err := os.OpenFile(filepath.Join(p.JobDir, "console.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the job directory is made by this program
	if err != nil {
		return fmt.Errorf("firecracker: open console log: %w", err)
	}
	m.console = console
	w := &capWriter{w: console, left: maxConsole}
	m.cmd = exec.CommandContext(ctx, b.FirecrackerPath, "--api-sock", fcSock) // #nosec G204 -- the path is the pinned binary of this user
	m.cmd.Stdout, m.cmd.Stderr = w, w                                         // the same writer: exec serializes its writes
	m.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}      // the machine dies with the host
	m.cmd.WaitDelay = 5 * time.Second                                         // do not wait forever for an output held open by a child
	if err := m.cmd.Start(); err != nil {
		m.cmd = nil
		return fmt.Errorf("firecracker: start %s (run galahad setup): %w", b.FirecrackerPath, err)
	}
	go func() {
		m.waitErr = m.cmd.Wait()
		_ = m.console.Close() // all output is copied once Wait returns
		close(m.done)
	}()

	timeout := orDefault(b.APITimeout, defaultAPITimeout)
	if err := m.waitForAPI(ctx, fcSock, timeout); err != nil {
		return err
	}
	api := newAPIClient(fcSock, timeout)
	calls := []call{
		{"/machine-config", machineConfig{VCPUCount: p.CPUs, MemSizeMiB: p.MemoryMiB, SMT: false}},
		{"/boot-source", bootSource{KernelImagePath: kernel, BootArgs: bootArgs}},
		// The guest sees the drives as vda, vdb, vdc, vdd in this order.
		{"/drives/rootfs", drive{DriveID: "rootfs", PathOnHost: rootfs, IsRootDevice: true, IsReadOnly: true}},
		{"/drives/scratch", drive{DriveID: "scratch", PathOnHost: scratch}},
		{"/drives/agent", drive{DriveID: "agent", PathOnHost: agent, IsReadOnly: true}},
	}
	if p.Signatures != "" {
		sig, err := filepath.Abs(p.Signatures)
		if err != nil {
			return fmt.Errorf("firecracker: %w", err)
		}
		calls = append(calls, call{"/drives/signatures", drive{DriveID: "signatures", PathOnHost: sig, IsReadOnly: !p.SignaturesWritable}})
	}
	calls = append(calls, call{"/vsock", vsockDevice{GuestCID: guestCID, UDSPath: vsock}}, call{"/actions", action{ActionType: "InstanceStart"}})
	for _, c := range calls {
		if err := api.put(ctx, c.path, c.body); err != nil {
			return fmt.Errorf("firecracker: %w", err)
		}
	}

	if wl, ok := m.listeners[controlPort].(*watchListener); ok {
		go m.watchConnect(wl)
	}
	return nil
}

// socketDir returns the directory of the sockets: the job directory, or a directory of its own
// if a socket path there would be too long for a unix socket.
func (m *Machine) socketDir(p Params) (string, error) {
	longest := "fc.sock"
	for _, port := range p.Ports {
		if name := "v.sock_" + strconv.FormatUint(uint64(port), 10); len(name) > len(longest) {
			longest = name
		}
	}
	if len(filepath.Join(p.JobDir, longest)) <= maxSocketPath {
		return p.JobDir, nil
	}
	dir, err := os.MkdirTemp("", "gh")
	if err != nil {
		return "", fmt.Errorf("firecracker: make the socket directory: %w", err)
	}
	m.sockDir = dir
	return dir, nil
}

// waitForAPI waits until the API socket accepts a connection. It gives up when Firecracker exits.
func (m *Machine) waitForAPI(ctx context.Context, sock string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if c, err := net.DialTimeout("unix", sock, 100*time.Millisecond); err == nil {
			_ = c.Close() // it was only a probe
			return nil
		}
		select {
		case <-m.done:
			return fmt.Errorf("firecracker: exited before its API was ready: %v", m.waitErr)
		case <-ctx.Done():
			return fmt.Errorf("firecracker: wait for the API: %w", ctx.Err())
		case <-deadline.C:
			return fmt.Errorf("firecracker: the API socket did not appear within %s", timeout)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// watchConnect kills Firecracker if the guest has not connected to the control port in time.
func (m *Machine) watchConnect(l *watchListener) {
	t := time.NewTimer(m.connect)
	defer t.Stop()
	select {
	case <-l.first:
	case <-m.done:
	case <-t.C:
		m.timedOut.Store(true)
		_ = m.cmd.Process.Kill() // best effort; if it is gone already, so is the machine
	}
}

// Listener returns the guest-to-host connections on a port, or nil if the port was not requested.
func (m *Machine) Listener(port uint32) net.Listener {
	l, ok := m.listeners[port]
	if !ok {
		return nil
	}
	return l
}

// Wait returns when Firecracker exits. If the guest never connected in time, the error says so.
func (m *Machine) Wait() error {
	<-m.done
	if m.timedOut.Load() {
		return fmt.Errorf("the guest did not connect within %s", m.connect)
	}
	return m.waitErr
}

// Kill sends SIGKILL, waits for the process, closes the listeners and removes the scratch disk,
// the agent image and the sockets. Calling it again returns the first result.
func (m *Machine) Kill() error {
	m.killOnce.Do(func() {
		var errs []error
		if m.cmd != nil {
			if err := m.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				errs = append(errs, fmt.Errorf("firecracker: kill: %w", err))
			}
			<-m.done
		}
		for _, l := range m.listeners {
			_ = l.Close() // best effort; the socket file is removed below
		}
		if m.cmd == nil && m.console != nil {
			_ = m.console.Close() // Start failed before the process; nobody else closes it
		}
		for _, f := range m.transient {
			if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("firecracker: %w", err))
			}
		}
		if m.sockDir != "" {
			if err := os.RemoveAll(m.sockDir); err != nil {
				errs = append(errs, fmt.Errorf("firecracker: %w", err))
			}
		}
		m.killErr = errors.Join(errs...)
	})
	return m.killErr
}

// watchListener notes the first connection.
type watchListener struct {
	net.Listener
	once  sync.Once
	first chan struct{}
}

func (l *watchListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.once.Do(func() { close(l.first) })
	}
	return c, err
}

// makeScratch creates a sparse file of mib MiB.
func makeScratch(path string, mib int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the job directory is made by this program
	if err != nil {
		return fmt.Errorf("firecracker: create the scratch disk: %w", err)
	}
	if err := f.Truncate(mib << 20); err != nil {
		_ = f.Close() // the truncate error is the one to report
		return fmt.Errorf("firecracker: size the scratch disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("firecracker: create the scratch disk: %w", err)
	}
	return nil
}

// makeAgentImage copies the agent to dst and pads it with zeros to a multiple of 512 bytes, which
// a block device needs. The guest init copies the whole drive, and the trailing zeros are harmless.
func makeAgentImage(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- the agent path is next to this executable, or set by the caller
	if err != nil {
		return fmt.Errorf("firecracker: open the agent: %w", err)
	}
	defer func() { _ = in.Close() }() // read only
	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("firecracker: open the agent: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("firecracker: the agent %s is not a regular file", src)
	}
	if st.Size() > maxAgentBytes {
		return fmt.Errorf("firecracker: the agent is larger than %d bytes", maxAgentBytes)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the job directory is made by this program
	if err != nil {
		return fmt.Errorf("firecracker: create the agent image: %w", err)
	}
	n, err := io.Copy(out, io.LimitReader(in, maxAgentBytes+1))
	if err == nil && n == 0 {
		err = errors.New("the agent is empty")
	}
	if err == nil && n > maxAgentBytes {
		err = fmt.Errorf("the agent is larger than %d bytes", maxAgentBytes)
	}
	if err == nil && n%sectorSize != 0 {
		err = out.Truncate(n + sectorSize - n%sectorSize)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("firecracker: create the agent image: %w", err)
	}
	return nil
}

// capWriter writes at most left bytes to w and drops the rest, so Firecracker never blocks on a
// full pipe.
type capWriter struct {
	w    *os.File
	left int
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.left > 0 {
		n := min(len(p), c.left)
		c.left -= n
		if _, err := c.w.Write(p[:n]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
