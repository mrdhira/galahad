//go:build linux

package firecracker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/images"
	"github.com/mrdhira/galahad/internal/sandbox/firecracker"
)

// The test binary is also the fake Firecracker: the backend starts it with --api-sock, and
// helperEnv says how it behaves. It serves the API on that socket and logs every request.
const (
	helperEnv  = "GALAHAD_FC_TEST_HELPER"  // mode: "" (not a helper), ok, exit, hang, bigerror, bigok, stall, console, reboot
	logEnv     = "GALAHAD_FC_TEST_LOG"     // file that gets one JSON line per request
	failEnv    = "GALAHAD_FC_TEST_FAIL"    // request path that answers 400
	consoleEnv = "GALAHAD_FC_TEST_CONSOLE" // bytes the console mode writes to stdout
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		runFakeFirecracker(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type loggedRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
}

func runFakeFirecracker(mode string) {
	if mode == "exit" {
		fmt.Fprintln(os.Stderr, "fake firecracker: exiting at once")
		os.Exit(3)
	}
	if mode == "hang" {
		select {}
	}
	logFile, err := os.OpenFile(os.Getenv(logEnv), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
	var mu sync.Mutex
	record := func(r loggedRequest) {
		mu.Lock()
		defer mu.Unlock()
		line, _ := json.Marshal(r)
		_, _ = logFile.Write(append(line, '\n'))
	}
	record(loggedRequest{Method: "ARGS", Body: strings.Join(os.Args[1:], " ")})
	if len(os.Args) != 3 || os.Args[1] != "--api-sock" {
		os.Exit(5)
	}
	l, err := net.Listen("unix", os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(6)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		record(loggedRequest{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		big := bytes.Repeat([]byte("e"), 1<<20)
		switch {
		case r.URL.Path == os.Getenv(failEnv) && mode == "bigerror":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(big)
		case r.URL.Path == os.Getenv(failEnv):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"fault_message":"nope"}`))
		case mode == "bigok":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(big)
		case mode == "stall":
			time.Sleep(3 * time.Second)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
		if r.URL.Path != "/actions" {
			return
		}
		switch mode {
		case "console":
			n, _ := strconv.Atoi(os.Getenv(consoleEnv))
			_, _ = os.Stdout.Write(consoleBytes(n))
		case "reboot":
			go func() {
				time.Sleep(50 * time.Millisecond)
				os.Exit(0)
			}()
		}
	})
	_ = http.Serve(l, handler)
}

// consoleBytes returns n bytes that cycle through every byte value, so the test sees raw bytes.
func consoleBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// fixture is a backend with images, an agent, a job directory and the fake Firecracker.
type fixture struct {
	backend *firecracker.Backend
	jobDir  string
	log     string
	agent   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	imagesDir := filepath.Join(dir, "images")
	mustMkdir(t, imagesDir)
	for _, f := range []string{"vmlinux", "core.ext4", "re.ext4"} {
		mustWrite(t, filepath.Join(imagesDir, f), []byte(f))
	}
	f := &fixture{jobDir: filepath.Join(dir, "job"), log: filepath.Join(dir, "requests.log"), agent: []byte("agent-bytes")}
	mustMkdir(t, f.jobDir)
	mustWrite(t, filepath.Join(dir, "galahad-agent"), f.agent)
	f.backend = &firecracker.Backend{
		FirecrackerPath: exe,
		ImagesDir:       imagesDir,
		AgentPath:       filepath.Join(dir, "galahad-agent"),
		APITimeout:      2 * time.Second,
		ConnectTimeout:  time.Minute,
	}
	t.Setenv(logEnv, f.log)
	return f
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// requests returns what the fake Firecracker logged: its arguments and the API requests.
func (f *fixture) requests(t *testing.T) (args string, reqs []loggedRequest) {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r loggedRequest
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		if r.Method == "ARGS" {
			args = r.Body
			continue
		}
		reqs = append(reqs, r)
	}
	return args, reqs
}

// entries lists the names in a directory.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

const bootArgs = "console=ttyS0 reboot=k panic=1 pci=off ro root=/dev/vda init=/sbin/galahad-init"

func TestStart(t *testing.T) {
	longJobDir := strings.Repeat("d", 90)
	allPaths := []string{"/machine-config", "/boot-source", "/drives/rootfs", "/drives/scratch", "/drives/agent", "/vsock", "/actions"}
	withSig := []string{"/machine-config", "/boot-source", "/drives/rootfs", "/drives/scratch", "/drives/agent", "/drives/signatures", "/vsock", "/actions"}
	tests := []struct {
		name string
		// inputs
		mode           string // helper mode; "" is ok
		fail           string // request path that answers 400
		image          string // "" is core
		cpus           int
		memoryMiB      int
		scratchMiB     int64
		signatures     bool
		writableSig    bool
		ports          []uint32 // nil is 1024 and 1025
		jobSubdir      string   // the job directory below the temp directory; "" is the usual one
		agent          string   // "" is the usual agent; missing, empty, large, dir
		noKernel       bool
		noRootfs       bool
		firecracker    string // "missing" is a path that does not exist
		apiTimeout     time.Duration
		wantErr        string
		wantPaths      []string // the API requests the fake Firecracker saw, in order
		wantBodies     []string // their bodies, where {job}, {images} and {socks} are replaced; nil skips the check
		wantScratch    int64    // size of scratch.img
		wantTempSocks  bool     // the sockets are not in the job directory
		wantJobEntries []string // what is left in the job directory after Kill
		wantNoRequests bool     // Firecracker never ran
	}{
		{
			name:        "the full request sequence",
			wantPaths:   allPaths,
			wantScratch: 4096 << 20,
			wantBodies: []string{
				`{"vcpu_count":2,"mem_size_mib":3072,"smt":false}`,
				`{"kernel_image_path":"{images}/vmlinux","boot_args":"` + bootArgs + `"}`,
				`{"drive_id":"rootfs","path_on_host":"{images}/core.ext4","is_root_device":true,"is_read_only":true}`,
				`{"drive_id":"scratch","path_on_host":"{job}/scratch.img","is_root_device":false,"is_read_only":false}`,
				`{"drive_id":"agent","path_on_host":"{job}/agent.img","is_root_device":false,"is_read_only":true}`,
				`{"guest_cid":3,"uds_path":"{socks}/v.sock"}`,
				`{"action_type":"InstanceStart"}`,
			},
			wantJobEntries: []string{"console.log"},
		},
		{
			name:        "limits, the re image and a read-only signatures drive",
			image:       "re",
			cpus:        4,
			memoryMiB:   1024,
			scratchMiB:  8,
			signatures:  true,
			wantPaths:   withSig,
			wantScratch: 8 << 20,
			wantBodies: []string{
				`{"vcpu_count":4,"mem_size_mib":1024,"smt":false}`,
				`{"kernel_image_path":"{images}/vmlinux","boot_args":"` + bootArgs + `"}`,
				`{"drive_id":"rootfs","path_on_host":"{images}/re.ext4","is_root_device":true,"is_read_only":true}`,
				`{"drive_id":"scratch","path_on_host":"{job}/scratch.img","is_root_device":false,"is_read_only":false}`,
				`{"drive_id":"agent","path_on_host":"{job}/agent.img","is_root_device":false,"is_read_only":true}`,
				`{"drive_id":"signatures","path_on_host":"{job}/signatures.img","is_root_device":false,"is_read_only":true}`,
				`{"guest_cid":3,"uds_path":"{socks}/v.sock"}`,
				`{"action_type":"InstanceStart"}`,
			},
			wantJobEntries: []string{"console.log", "signatures.img"},
		},
		{
			name:        "a writable signatures drive",
			signatures:  true,
			writableSig: true,
			wantPaths:   withSig,
			wantScratch: 4096 << 20,
			wantBodies: []string{
				`{"vcpu_count":2,"mem_size_mib":3072,"smt":false}`,
				`{"kernel_image_path":"{images}/vmlinux","boot_args":"` + bootArgs + `"}`,
				`{"drive_id":"rootfs","path_on_host":"{images}/core.ext4","is_root_device":true,"is_read_only":true}`,
				`{"drive_id":"scratch","path_on_host":"{job}/scratch.img","is_root_device":false,"is_read_only":false}`,
				`{"drive_id":"agent","path_on_host":"{job}/agent.img","is_root_device":false,"is_read_only":true}`,
				`{"drive_id":"signatures","path_on_host":"{job}/signatures.img","is_root_device":false,"is_read_only":false}`,
				`{"guest_cid":3,"uds_path":"{socks}/v.sock"}`,
				`{"action_type":"InstanceStart"}`,
			},
			wantJobEntries: []string{"console.log", "signatures.img"},
		},
		{
			name:           "a long job directory puts the sockets in a directory of their own",
			jobSubdir:      longJobDir,
			wantPaths:      allPaths,
			wantScratch:    4096 << 20,
			wantTempSocks:  true,
			wantJobEntries: []string{"console.log"},
		},
		{name: "no job directory", jobSubdir: "none", wantErr: "no job directory", wantNoRequests: true},
		{name: "unknown image", image: "huge", wantErr: `unknown image "huge"`, wantNoRequests: true},
		{name: "negative CPUs", cpus: -1, wantErr: "CPUs -1 is out of range", wantNoRequests: true},
		{name: "too much memory", memoryMiB: 1 << 20, wantErr: "MemoryMiB 1048576 is out of range", wantNoRequests: true},
		{name: "too much scratch", scratchMiB: 1 << 30, wantErr: "ScratchMiB 1073741824 is out of range", wantNoRequests: true},
		{name: "kernel missing", noKernel: true, wantErr: "vmlinux is missing; run galahad setup", wantNoRequests: true},
		{name: "root filesystem missing", noRootfs: true, wantErr: "core.ext4 is missing; run galahad setup", wantNoRequests: true},
		{name: "two listeners on one port", ports: []uint32{1024, 1024}, wantErr: "listen for port 1024", wantNoRequests: true},
		{name: "agent missing", agent: "missing", wantErr: "open the agent", wantNoRequests: true},
		{name: "agent is a directory", agent: "dir", wantErr: "is not a regular file", wantNoRequests: true},
		{name: "agent is empty", agent: "empty", wantErr: "the agent is empty", wantNoRequests: true},
		{name: "agent is too large", agent: "large", wantErr: "larger than 50331648 bytes", wantNoRequests: true},
		{name: "firecracker binary missing", firecracker: "missing", wantErr: "run galahad setup", wantNoRequests: true},
		{name: "firecracker exits before its API is up", mode: "exit", wantErr: "exited before its API was ready: exit status 3", wantNoRequests: true},
		{name: "the API socket never appears", mode: "hang", apiTimeout: 300 * time.Millisecond, wantErr: "did not appear within 300ms", wantNoRequests: true},
		{name: "machine-config fails", fail: "/machine-config", wantErr: `PUT /machine-config: status 400: "{\"fault_message\":\"nope\"}"`, wantPaths: allPaths[:1], wantJobEntries: []string{"console.log"}},
		{name: "boot-source fails", fail: "/boot-source", wantErr: "PUT /boot-source: status 400", wantPaths: allPaths[:2], wantJobEntries: []string{"console.log"}},
		{name: "rootfs fails", fail: "/drives/rootfs", wantErr: "PUT /drives/rootfs: status 400", wantPaths: allPaths[:3], wantJobEntries: []string{"console.log"}},
		{name: "scratch fails", fail: "/drives/scratch", wantErr: "PUT /drives/scratch: status 400", wantPaths: allPaths[:4], wantJobEntries: []string{"console.log"}},
		{name: "agent drive fails", fail: "/drives/agent", wantErr: "PUT /drives/agent: status 400", wantPaths: allPaths[:5], wantJobEntries: []string{"console.log"}},
		{name: "signatures drive fails", fail: "/drives/signatures", signatures: true, wantErr: "PUT /drives/signatures: status 400", wantPaths: withSig[:6], wantJobEntries: []string{"console.log", "signatures.img"}},
		{name: "vsock fails", fail: "/vsock", wantErr: "PUT /vsock: status 400", wantPaths: allPaths[:6], wantJobEntries: []string{"console.log"}},
		{name: "InstanceStart fails", fail: "/actions", wantErr: "PUT /actions: status 400", wantPaths: allPaths, wantJobEntries: []string{"console.log"}},
		{name: "a long error body is cut", mode: "bigerror", fail: "/machine-config", wantErr: "PUT /machine-config: status 400", wantPaths: allPaths[:1], wantJobEntries: []string{"console.log"}},
		{name: "a long answer is an error", mode: "bigok", wantErr: "PUT /machine-config: the response is larger than 65536 bytes", wantPaths: allPaths[:1], wantJobEntries: []string{"console.log"}},
		{name: "a slow answer times out", mode: "stall", apiTimeout: 300 * time.Millisecond, wantErr: "PUT /machine-config", wantPaths: allPaths[:1], wantJobEntries: []string{"console.log"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.mode == "" {
				t.Setenv(helperEnv, "ok")
			} else {
				t.Setenv(helperEnv, tt.mode)
			}
			t.Setenv(failEnv, tt.fail)
			imagesDir := f.backend.ImagesDir
			if tt.noKernel {
				mustRemove(t, filepath.Join(imagesDir, "vmlinux"))
			}
			if tt.noRootfs {
				mustRemove(t, filepath.Join(imagesDir, "core.ext4"))
			}
			if tt.jobSubdir != "" && tt.jobSubdir != "none" {
				f.jobDir = filepath.Join(filepath.Dir(f.jobDir), tt.jobSubdir)
				mustMkdir(t, f.jobDir)
			}
			switch tt.agent {
			case "missing":
				f.backend.AgentPath = filepath.Join(t.TempDir(), "nope")
			case "dir":
				f.backend.AgentPath = t.TempDir()
			case "empty":
				mustWrite(t, f.backend.AgentPath, nil)
			case "large":
				if err := os.Truncate(f.backend.AgentPath, 48<<20+1); err != nil {
					t.Fatal(err)
				}
			}
			if tt.firecracker == "missing" {
				f.backend.FirecrackerPath = filepath.Join(t.TempDir(), "firecracker")
			}
			if tt.apiTimeout != 0 {
				f.backend.APITimeout = tt.apiTimeout
			}
			spec := firecracker.Params{
				JobDir: f.jobDir, Image: tt.image, CPUs: tt.cpus, MemoryMiB: tt.memoryMiB, ScratchMiB: tt.scratchMiB,
				SignaturesWritable: tt.writableSig, Ports: tt.ports,
			}
			if tt.jobSubdir == "none" {
				spec.JobDir = ""
			}
			if spec.Image == "" {
				spec.Image = "core"
			}
			if spec.Ports == nil {
				spec.Ports = []uint32{1024, 1025}
			}
			if tt.signatures {
				spec.Signatures = filepath.Join(f.jobDir, "signatures.img")
				mustWrite(t, spec.Signatures, []byte("sig"))
			}

			m, err := f.backend.Start(context.Background(), spec)
			args, reqs := f.requests(t)
			var gotPaths []string
			for _, r := range reqs {
				if r.Method != http.MethodPut {
					t.Errorf("request %s %s, want PUT", r.Method, r.Path)
				}
				gotPaths = append(gotPaths, r.Path)
			}
			if tt.wantNoRequests && (args != "" || len(reqs) != 0) {
				t.Errorf("firecracker ran with %q and %d requests, want it not to run", args, len(reqs))
			}
			if !tt.wantNoRequests && !equal(gotPaths, tt.wantPaths) {
				t.Errorf("requests = %v, want %v", gotPaths, tt.wantPaths)
			}

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				for _, name := range entries(t, f.jobDir) {
					if name == "scratch.img" || name == "agent.img" || strings.HasPrefix(name, "fc.sock") || strings.HasPrefix(name, "v.sock") {
						t.Errorf("%s is left in the job directory after a failed start", name)
					}
				}
				if len(err.Error()) > 1024 {
					t.Errorf("the error is %d bytes long, want it bounded", len(err.Error()))
				}
				if m != nil {
					t.Errorf("machine = %v, want nil", m)
				}
				if tt.wantJobEntries != nil {
					if got := entries(t, f.jobDir); !equal(got, tt.wantJobEntries) {
						t.Errorf("job directory = %v, want %v", got, tt.wantJobEntries)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			socks := f.jobDir
			if tt.wantTempSocks {
				var v struct {
					UDSPath string `json:"uds_path"`
				}
				if err := json.Unmarshal([]byte(reqs[5].Body), &v); err != nil {
					t.Fatal(err)
				}
				socks = filepath.Dir(v.UDSPath)
				if socks == f.jobDir {
					t.Errorf("the sockets are in the job directory %s, want a directory of their own", socks)
				}
			}
			wantArgs := "--api-sock " + filepath.Join(socks, "fc.sock")
			if args != wantArgs {
				t.Errorf("firecracker args = %q, want %q", args, wantArgs)
			}
			if tt.wantBodies != nil {
				repl := strings.NewReplacer("{images}", imagesDir, "{job}", f.jobDir, "{socks}", socks)
				for i, want := range tt.wantBodies {
					if got := reqs[i].Body; got != repl.Replace(want) {
						t.Errorf("body of %s = %s, want %s", reqs[i].Path, got, repl.Replace(want))
					}
				}
			}

			if st, err := os.Stat(filepath.Join(f.jobDir, "scratch.img")); err != nil || st.Size() != tt.wantScratch {
				t.Errorf("scratch.img = %v, %v, want %d bytes", st, err, tt.wantScratch)
			}
			image, err := os.ReadFile(filepath.Join(f.jobDir, "agent.img"))
			if err != nil {
				t.Fatal(err)
			}
			wantImage := append(append([]byte{}, f.agent...), make([]byte, 512-len(f.agent))...)
			if !bytes.Equal(image, wantImage) {
				t.Errorf("agent.img is %d bytes, want the agent padded to 512 bytes", len(image))
			}
			if m.Listener(9) != nil {
				t.Error("a listener for a port that was not asked for")
			}
			for _, port := range spec.Ports {
				l := m.Listener(port)
				if l == nil {
					t.Fatalf("no listener for port %d", port)
				}
				c, err := net.Dial("unix", filepath.Join(socks, "v.sock_"+strconv.Itoa(int(port))))
				if err != nil {
					t.Fatalf("dial port %d: %v", port, err)
				}
				_ = c.Close() // the dial was the check
			}

			if err := m.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := m.Kill(); err != nil {
				t.Errorf("second Kill: %v", err)
			}
			if err := m.Wait(); err == nil || !strings.Contains(err.Error(), "killed") {
				t.Errorf("Wait after Kill = %v, want the process to be killed", err)
			}
			if got := entries(t, f.jobDir); !equal(got, tt.wantJobEntries) {
				t.Errorf("job directory after Kill = %v, want %v", got, tt.wantJobEntries)
			}
			if tt.wantTempSocks {
				if _, err := os.Stat(socks); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the socket directory %s is left after Kill: %v", socks, err)
				}
			}
		})
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestStartCanceled(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
	}{
		{name: "a canceled context stops the start", wantErr: "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			t.Setenv(helperEnv, "stall")
			f.backend.APITimeout = 10 * time.Second
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			time.AfterFunc(300*time.Millisecond, cancel)
			start := time.Now()
			m, err := f.backend.Start(ctx, firecracker.Params{JobDir: f.jobDir, Image: "core", Ports: []uint32{1024}})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
			}
			if m != nil {
				t.Errorf("machine = %v, want nil", m)
			}
			if time.Since(start) > 3*time.Second {
				t.Errorf("Start took %s after the cancel", time.Since(start))
			}
			if got := entries(t, f.jobDir); !equal(got, []string{"console.log"}) {
				t.Errorf("job directory = %v, want only console.log", got)
			}
		})
	}
}

func TestMachine(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		mode           string
		connectTimeout time.Duration
		dial           uint32 // the port the test connects to right after Start; 0 = none
		wait           time.Duration
		// expectations
		wantExited  bool   // Wait has returned after the wait time
		wantWaitErr string // "" means nil
	}{
		{name: "a connection to the control port in time keeps the machine", connectTimeout: 300 * time.Millisecond, dial: 1024, wait: 800 * time.Millisecond, wantExited: false},
		{name: "no connection in time kills the machine", connectTimeout: 300 * time.Millisecond, wait: 2 * time.Second, wantExited: true, wantWaitErr: "the guest did not connect within 300ms"},
		{name: "a connection to another port does not count", connectTimeout: 300 * time.Millisecond, dial: 1025, wait: 2 * time.Second, wantExited: true, wantWaitErr: "the guest did not connect within 300ms"},
		{name: "the machine exits by itself", mode: "reboot", connectTimeout: time.Minute, wait: 2 * time.Second, wantExited: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			mode := tt.mode
			if mode == "" {
				mode = "ok"
			}
			t.Setenv(helperEnv, mode)
			f.backend.ConnectTimeout = tt.connectTimeout
			m, err := f.backend.Start(context.Background(), firecracker.Params{JobDir: f.jobDir, Image: "core", Ports: []uint32{1024, 1025}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Kill() }() // cleanup
			if tt.dial != 0 {
				l := m.Listener(tt.dial)
				accepted := make(chan error, 1)
				go func() {
					c, err := l.Accept()
					if err == nil {
						_ = c.Close() // only the arrival matters
					}
					accepted <- err
				}()
				c, err := net.Dial("unix", filepath.Join(f.jobDir, "v.sock_"+strconv.Itoa(int(tt.dial))))
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = c.Close() }() // cleanup
				if err := <-accepted; err != nil {
					t.Fatal(err)
				}
			}
			waited := make(chan error, 1)
			go func() { waited <- m.Wait() }()
			select {
			case err := <-waited:
				if !tt.wantExited {
					t.Fatalf("the machine exited: %v", err)
				}
				if tt.wantWaitErr == "" && err != nil {
					t.Errorf("Wait = %v, want nil", err)
				}
				if tt.wantWaitErr != "" && (err == nil || err.Error() != tt.wantWaitErr) {
					t.Errorf("Wait = %v, want %q", err, tt.wantWaitErr)
				}
			case <-time.After(tt.wait):
				if tt.wantExited {
					t.Fatalf("the machine is still running after %s", tt.wait)
				}
			}
			if err := m.Kill(); err != nil {
				t.Errorf("Kill: %v", err)
			}
			if got := entries(t, f.jobDir); !equal(got, []string{"console.log"}) {
				t.Errorf("job directory after Kill = %v, want only console.log", got)
			}
		})
	}
}

func TestConsole(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		consoleBytes int
		// expectations
		wantBytes int
	}{
		{name: "a short console is kept raw", consoleBytes: 1000, wantBytes: 1000},
		{name: "a console over the cap is cut", consoleBytes: 2 << 20, wantBytes: 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			t.Setenv(helperEnv, "console")
			t.Setenv(consoleEnv, strconv.Itoa(tt.consoleBytes))
			m, err := f.backend.Start(context.Background(), firecracker.Params{JobDir: f.jobDir, Image: "core", Ports: []uint32{1024}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.jobDir, "console.log")
			for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
				if st, err := os.Stat(path); err == nil && st.Size() >= int64(tt.wantBytes) {
					break
				}
			}
			if err := m.Kill(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, consoleBytes(tt.wantBytes)) {
				t.Errorf("console.log is %d bytes, want the first %d bytes of the console", len(got), tt.wantBytes)
			}
		})
	}
}

func TestNew(t *testing.T) {
	pins, err := images.Load()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		// inputs
		galahadHome string
		home        string // $HOME
		// expectations
		wantFirecracker string
		wantImages      string
		wantAgent       string
		wantErr         string
	}{
		{
			name:            "paths below the galahad home",
			galahadHome:     "/state/galahad",
			wantFirecracker: "/state/galahad/bin/firecracker",
			wantImages:      "/state/galahad/images/" + pins.Version,
			wantAgent:       filepath.Join(filepath.Dir(exe), "galahad-agent"),
		},
		{name: "no home directory", wantErr: "home directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_HOME", tt.galahadHome)
			t.Setenv("HOME", tt.home)
			b, err := firecracker.New()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b.FirecrackerPath != tt.wantFirecracker || b.ImagesDir != tt.wantImages || b.AgentPath != tt.wantAgent {
				t.Errorf("backend = %+v, want %s, %s, %s", b, tt.wantFirecracker, tt.wantImages, tt.wantAgent)
			}
		})
	}
}
