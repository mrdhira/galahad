package job_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/sandbox"
)

const hostVersion = "v1.2.3"

// pipeListener hands out the host ends of net.Pipe connections, which are unbuffered: a
// write blocks until the other side reads, so the order of the frames is exact.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "pipe"} }

// fakeBackend runs a scripted guest in a goroutine instead of a machine.
type fakeBackend struct {
	script   func(g *guest)
	startErr error
	onStart  func() // runs when the machine starts, after the host has walked the target

	noProxyListener bool // the machine has no listener for the proxy port

	mu      sync.Mutex
	ports   []uint32      // the ports of the last Start
	proxyL  *pipeListener // the proxy listener of the last Start
	starts  int
	kills   int
	done    chan struct{} // closed when the guest script has ended
	input   map[string]tarEntry
	inputOK bool
}

// tarEntry is what the guest read of one entry of the tar stream.
type tarEntry struct {
	typ  byte
	body string
	link string
}

func (b *fakeBackend) Name() string { return "fake" }

func (b *fakeBackend) Start(_ context.Context, s sandbox.Spec) (sandbox.Machine, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starts++
	if b.onStart != nil {
		b.onStart()
	}
	if b.startErr != nil {
		return nil, b.startErr
	}
	l := &pipeListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	pl := &pipeListener{conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	b.proxyL = pl
	m := &fakeMachine{b: b, l: l, pl: pl, killed: make(chan struct{})}
	b.ports = s.Ports
	b.done = make(chan struct{})
	go func() {
		defer close(b.done)
		g := &guest{b: b, l: l, killed: m.killed}
		b.script(g)
		if g.conn != nil {
			_ = g.conn.Close() // the guest is gone
		}
	}()
	return m, nil
}

type fakeMachine struct {
	b      *fakeBackend
	l      *pipeListener // control
	pl     *pipeListener // proxy
	killed chan struct{}
}

func (m *fakeMachine) Listener(port uint32) net.Listener {
	switch port {
	case 1024:
		return m.l
	case 1025:
		if m.b.noProxyListener {
			return nil
		}
		return m.pl
	}
	return nil
}

func (m *fakeMachine) Wait() error {
	<-m.b.done
	return nil
}

func (m *fakeMachine) Kill() error {
	m.b.mu.Lock()
	defer m.b.mu.Unlock()
	if m.b.kills++; m.b.kills == 1 {
		close(m.killed)
		_ = m.l.Close() // the machine is gone
	}
	return nil
}

// guest is the guest side of a script. Every helper ends the script when the connection fails,
// which is what happens when the host gives up on the job.
type guest struct {
	b      *fakeBackend
	l      *pipeListener
	conn   net.Conn
	killed chan struct{}
	job    protocol.Job
}

func (g *guest) dial() {
	host, guestEnd := net.Pipe()
	g.l.conns <- host
	g.conn = guestEnd
}

func (g *guest) send(t protocol.FrameType, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	g.sendRaw(t, data)
}

func (g *guest) sendRaw(t protocol.FrameType, payload []byte) {
	if err := protocol.WriteFrame(g.conn, t, payload); err != nil {
		runtime.Goexit()
	}
}

func (g *guest) hello(version string) {
	g.send(protocol.FrameHello, protocol.Hello{Protocol: protocol.ProtocolVersion, AgentVersion: version})
}

func (g *guest) readJob() {
	t, payload, err := protocol.ReadFrame(g.conn)
	if err != nil || t != protocol.FrameJob {
		runtime.Goexit()
	}
	if err := protocol.DecodeStrict(payload, &g.job); err != nil || g.job.Validate() != nil {
		runtime.Goexit()
	}
}

// readInput reads Data frames up to the End frame, checks the End frame against the bytes, and keeps
// the entries of the tar stream for the test.
func (g *guest) readInput() {
	var stream bytes.Buffer
	for {
		t, payload, err := protocol.ReadFrame(g.conn)
		if err != nil {
			runtime.Goexit()
		}
		if t == protocol.FrameData {
			if len(payload) > 1<<20 {
				runtime.Goexit()
			}
			stream.Write(payload)
			continue
		}
		var end protocol.End
		sum := sha256.Sum256(stream.Bytes())
		if t != protocol.FrameEnd || protocol.DecodeStrict(payload, &end) != nil || end.Validate() != nil ||
			end.Bytes != int64(stream.Len()) || end.SHA256 != hex.EncodeToString(sum[:]) {
			runtime.Goexit()
		}
		break
	}
	entries := map[string]tarEntry{}
	tr := tar.NewReader(&stream)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			runtime.Goexit()
		}
		body, _ := io.ReadAll(tr)
		entries[hdr.Name] = tarEntry{typ: hdr.Typeflag, body: string(body), link: hdr.Linkname}
	}
	g.b.mu.Lock()
	g.b.input, g.b.inputOK = entries, true
	g.b.mu.Unlock()
}

// result is a valid Result for the input: the kind and, for a file, the sha256 come from the tar stream.
func (g *guest) result(version string) protocol.Result {
	res := protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad-agent", Version: version},
		Target:        protocol.Target{Name: g.job.Name, Kind: protocol.TargetDir},
		StartedAt:     g.job.Now, FinishedAt: g.job.Now.Add(time.Second),
		Files: []protocol.FileInfo{}, Findings: []protocol.Finding{}, IOCs: []protocol.IOC{},
		Coverage: protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1, Skipped: []protocol.Skip{}, Analyzers: []string{"static"}},
		Reasons:  []string{},
	}
	g.b.mu.Lock()
	e, ok := g.b.input[g.job.Name]
	g.b.mu.Unlock()
	if ok && e.typ == tar.TypeReg {
		sum := sha256.Sum256([]byte(e.body))
		res.Target.Kind, res.Target.SHA256 = protocol.TargetFile, hex.EncodeToString(sum[:])
	}
	return res
}

// serve is the whole job of a well-behaved guest: hello, the input, two stages, and the result that edit changes.
func serve(version string, edit func(res *protocol.Result)) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(version)
		g.readJob()
		g.readInput()
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageIngest})
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageAnalyze})
		res := g.result(version)
		if edit != nil {
			edit(&res)
		}
		g.send(protocol.FrameResult, res)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func dirTarget(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "proj")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	writeFile(t, filepath.Join(dir, "sub", "a.txt"), "alpha\n")
	return dir
}

func fileTarget(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "one.txt")
	writeFile(t, p, "hello\n")
	return p
}

// linkTarget is a folder with a file, a symlink to an absolute path and a unix socket.
func linkTarget(t *testing.T) string {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	base, err := os.MkdirTemp("", "g") // a short path: a socket path is limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	dir := filepath.Join(base, "proj")
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n")
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", filepath.Join(dir, "sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return dir
}

func criticalFinding() protocol.Finding {
	return protocol.Rule{ID: "GAL-AUTOEXEC-001", Severity: protocol.SeverityCritical, Title: "Runs on open", Attack: "T1204"}.
		Finding(protocol.Evidence{Path: "main.go", Line: 1, Snippet: "x"})
}

func TestRun(t *testing.T) {
	bigArtifact := bytes.Repeat([]byte("a"), 600<<10)
	probe := func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactProbeJSON, Data: []byte("{}")}.Marshal())
		g.send(protocol.FrameResult, g.result(hostVersion))
	}
	probeCase := struct {
		state job.State
		err   string
		exit  int
		files map[string]int
	}{state: job.StateFailed, err: "artifact id 3 is not accepted here", exit: 1}
	if probeAccepted {
		probeCase.state, probeCase.err, probeCase.exit, probeCase.files = job.StateDone, "", 0, map[string]int{"probe.json": 2}
	}
	tests := []struct {
		name string
		// inputs
		target      func(t *testing.T) string // the dir target when nil
		script      func(g *guest)
		version     string        // of the host; hostVersion when empty
		timeout     time.Duration // of the job; job.MinTimeout when zero
		ctxTimeout  time.Duration // deadline of the caller's context
		cancelAfter time.Duration // the caller cancels
		startErr    error
		atStart     func(t *testing.T, target string) // changes the target while the machine starts
		// expectations
		wantState    job.State
		wantErr      string // substring; empty means success
		wantExit     int
		wantVerdict  string
		wantStages   []string
		wantStarts   int // calls of Start
		wantNoJob    bool
		wantReport   bool
		wantEntries  map[string]tarEntry
		wantArtifact map[string]int // file name to size
	}{
		{
			name:      "directory target ends done",
			script:    serve(hostVersion, nil),
			wantState: job.StateDone, wantVerdict: "clean", wantStages: []string{"ingest", "analyze"}, wantStarts: 1, wantReport: true,
			wantEntries: map[string]tarEntry{
				"proj/":          {typ: tar.TypeDir},
				"proj/main.go":   {typ: tar.TypeReg, body: "package main\n"},
				"proj/sub/":      {typ: tar.TypeDir},
				"proj/sub/a.txt": {typ: tar.TypeReg, body: "alpha\n"},
			},
		},
		{
			name:      "a symlink is sent as a link and not followed, and a socket is left out",
			target:    linkTarget,
			script:    serve(hostVersion, nil),
			wantState: job.StateDone, wantVerdict: "clean", wantStarts: 1, wantReport: true,
			wantEntries: map[string]tarEntry{
				"proj/main.go": {typ: tar.TypeReg, body: "package main\n"},
				"proj/link":    {typ: tar.TypeSymlink, link: "/etc/passwd"},
				"proj/sock":    {},
			},
		},
		{
			name:      "file target ends done and its sha256 is checked",
			target:    fileTarget,
			script:    serve(hostVersion, nil),
			wantState: job.StateDone, wantVerdict: "clean", wantStarts: 1, wantReport: true,
			wantEntries: map[string]tarEntry{"one.txt": {typ: tar.TypeReg, body: "hello\n"}},
		},
		{
			name: "the result is scored again by the host",
			script: serve(hostVersion, func(res *protocol.Result) {
				res.Findings, res.Verdict, res.Score = []protocol.Finding{criticalFinding()}, protocol.VerdictClean, 0
			}),
			wantState: job.StateDone, wantExit: 20, wantVerdict: "malicious", wantStarts: 1, wantReport: true,
		},
		{
			name:      "a dev host takes any agent version",
			script:    serve("v9.9.9", func(res *protocol.Result) { res.Tool.Version = "v9.9.9" }),
			version:   "dev",
			wantState: job.StateDone, wantVerdict: "clean", wantStarts: 1, wantReport: true,
		},
		{
			name:      "timeout below the minimum",
			script:    serve(hostVersion, nil),
			timeout:   time.Minute,
			wantNoJob: true,
			wantErr:   "shorter than the minimum",
		},
		{
			name:      "input over the byte cap fails before the machine starts",
			target:    sparseTarget,
			script:    serve(hostVersion, nil),
			wantNoJob: true,
			wantErr:   "the input is too large: more than 1073741824 bytes",
		},
		{
			name:      "the machine does not start",
			script:    serve(hostVersion, nil),
			startErr:  errors.New("no kvm"),
			wantState: job.StateFailed, wantErr: "start the sandbox: no kvm", wantExit: 1, wantStarts: 1,
		},
		{
			name:      "the guest exits before it connects",
			script:    func(*guest) {},
			wantState: job.StateFailed, wantErr: "exited before the guest connected", wantExit: 1, wantStarts: 1,
		},
		{
			name:      "hello from another version",
			script:    func(g *guest) { g.dial(); g.hello("v0.0.1"); g.readJob() },
			wantState: job.StateFailed, wantErr: `the agent is version "v0.0.1"`, wantExit: 1, wantStarts: 1,
		},
		{
			name: "hello is not valid",
			script: func(g *guest) {
				g.dial()
				g.sendRaw(protocol.FrameHello, []byte(`{"protocol":1,"agent_version":"v","x":1}`))
				g.readJob()
			},
			wantState: job.StateFailed, wantErr: "hello frame: json: unknown field", wantExit: 1, wantStarts: 1,
		},
		{
			name: "progress is not allowed before hello",
			script: func(g *guest) {
				g.dial()
				g.send(protocol.FrameProgress, protocol.Progress{Stage: "ingest"})
				g.readJob()
			},
			wantState: job.StateFailed, wantErr: "unexpected progress frame", wantExit: 1, wantStarts: 1,
		},
		{
			name: "progress has an unknown stage",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.send(protocol.FrameProgress, protocol.Progress{Stage: "mining"})
			},
			wantState: job.StateFailed, wantErr: `progress frame: stage "mining" not allowed`, wantExit: 1, wantStarts: 1,
		},
		{
			name: "a frame the host sends is not allowed from the guest",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.sendRaw(protocol.FrameData, []byte("x"))
			},
			wantState: job.StateFailed, wantErr: "unexpected data frame", wantExit: 1, wantStarts: 1,
		},
		{
			name: "artifacts are stored raw and capped at 1 MiB each",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
				for range 2 {
					g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactIngestLog, Data: bigArtifact}.Marshal())
				}
				g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactIngestLog, Data: []byte("past the cap")}.Marshal())
				g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactToolsLog, Data: []byte("tools\n")}.Marshal())
				g.send(protocol.FrameResult, g.result(hostVersion))
			},
			wantState: job.StateDone, wantVerdict: "clean", wantStarts: 1, wantReport: true,
			wantArtifact: map[string]int{"ingest.log": 1 << 20, "tools.log": 6},
		},
		{
			name:      "the probe artifact is stored in test builds only",
			script:    probe,
			wantState: probeCase.state, wantErr: probeCase.err, wantExit: probeCase.exit, wantVerdict: map[bool]string{true: "clean"}[probeCase.err == ""],
			wantStarts: 1, wantReport: probeCase.err == "", wantArtifact: probeCase.files,
		},
		{
			name: "artifact with an unknown id",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.sendRaw(protocol.FrameArtifact, []byte{9, 'x'})
			},
			wantState: job.StateFailed, wantErr: "artifact frame: artifact id 9 not allowed", wantExit: 1, wantStarts: 1,
		},
		{
			name: "the guest stops reading and says why",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.send(protocol.FrameError, protocol.Error{Code: protocol.CodeIngest, Message: "bad tar"})
			},
			wantState: job.StateFailed, wantErr: "the guest failed (ingest): bad tar", wantExit: 1, wantStarts: 1,
		},
		{
			name: "error frame with an unknown code",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.send(protocol.FrameError, protocol.Error{Code: "oops"})
			},
			wantState: job.StateFailed, wantErr: `error frame: code "oops" not allowed`, wantExit: 1, wantStarts: 1,
		},
		{
			name: "result before the end of the input",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.send(protocol.FrameResult, g.result(hostVersion))
			},
			wantState: job.StateFailed, wantErr: "result before the end of the input", wantExit: 1, wantStarts: 1,
		},
		{
			name: "the guest hangs up without a result",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
			},
			wantState: job.StateFailed, wantErr: "read from the guest: EOF", wantExit: 1, wantStarts: 1,
		},
		{
			name:      "result with a field the schema does not have",
			script:    serveRaw(hostVersion, func(data []byte) []byte { return bytes.Replace(data, []byte("{"), []byte(`{"bogus":{},`), 1) }),
			wantState: job.StateFailed, wantErr: `result frame: json: unknown field "bogus"`, wantExit: 1, wantStarts: 1,
		},
		{
			name:      "result that is not valid",
			script:    serve(hostVersion, func(res *protocol.Result) { res.Score = 101 }),
			wantState: job.StateFailed, wantErr: "result frame: score 101 out of range", wantExit: 1, wantStarts: 1,
		},
		{
			name:      "result from another version",
			script:    serve(hostVersion, func(res *protocol.Result) { res.Tool.Version = "v0.0.1" }),
			wantState: job.StateFailed, wantErr: `the result is from version "v0.0.1"`, wantExit: 1, wantStarts: 1,
		},
		{
			name:      "result of another kind",
			script:    serve(hostVersion, func(res *protocol.Result) { res.Target.Kind = protocol.TargetFile }),
			wantState: job.StateFailed, wantErr: "the result is for a file, the input is a dir", wantExit: 1, wantStarts: 1,
		},
		{
			name:      "result with another sha256 for a file",
			target:    fileTarget,
			script:    serve(hostVersion, func(res *protocol.Result) { res.Target.SHA256 = strings.Repeat("0", 64) }),
			wantState: job.StateFailed, wantErr: "the result has sha256 " + strings.Repeat("0", 64), wantExit: 1, wantStarts: 1,
		},
		{
			name:       "the guest never answers",
			script:     func(g *guest) { g.dial(); g.hello(hostVersion); g.readJob(); g.readInput(); <-g.killed },
			ctxTimeout: 300 * time.Millisecond,
			wantState:  job.StateTimeout, wantErr: "timed out", wantExit: 1, wantStarts: 1,
		},
		{
			name:        "the caller cancels",
			script:      func(g *guest) { g.dial(); g.hello(hostVersion); g.readJob(); g.readInput(); <-g.killed },
			cancelAfter: 300 * time.Millisecond,
			wantState:   job.StateCanceled, wantErr: "canceled", wantExit: 1, wantStarts: 1,
		},
		{
			name: "a file swapped for a FIFO after the walk does not hang the job",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
				<-g.killed
			},
			atStart: func(t *testing.T, target string) {
				p := filepath.Join(target, "main.go")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := mkfifo(p); err != nil {
					t.Skipf("no FIFOs here: %v", err)
				}
			},
			cancelAfter: 300 * time.Millisecond,
			wantState:   job.StateCanceled, wantErr: "canceled", wantExit: 1, wantStarts: 1,
		},
		{
			name:       "the guest stops taking input",
			script:     func(g *guest) { g.dial(); g.hello(hostVersion); g.readJob(); <-g.killed },
			ctxTimeout: 300 * time.Millisecond,
			wantState:  job.StateTimeout, wantErr: "timed out", wantExit: 1, wantStarts: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a job directory, a scripted guest and a target
			jobs := t.TempDir()
			target := dirTarget
			if tt.target != nil {
				target = tt.target
			}
			b := &fakeBackend{script: tt.script, startErr: tt.startErr}
			targetPath := target(t)
			if tt.atStart != nil {
				b.onStart = func() { tt.atStart(t, targetPath) }
			}
			var stages []string
			spec := job.Spec{
				JobsDir: jobs,
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: cmpOr(tt.version, hostVersion),
				Timeout: cmpOr(tt.timeout, job.MinTimeout),
				Image:   "core",
				Progress: func(stage string) {
					stages = append(stages, stage)
				},
			}
			ctx := context.Background()
			if tt.ctxTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
				defer cancel()
			}
			if tt.cancelAfter > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				time.AfterFunc(tt.cancelAfter, cancel)
			}

			// When it runs
			began := time.Now()
			out, err := job.Run(ctx, b, spec, targetPath)
			if took := time.Since(began); took > 3*time.Second {
				t.Errorf("Run took %s, want it to end promptly", took)
			}
			if b.done != nil {
				<-b.done // the script has seen the connection close
			}

			// Then the error, the job and the machine are as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Run error = %v, want one containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if b.starts != tt.wantStarts {
				t.Errorf("Start called %d times, want %d", b.starts, tt.wantStarts)
			}
			if b.starts > 0 && b.startErr == nil && b.kills == 0 {
				t.Error("the machine was not killed")
			}
			entries, _ := os.ReadDir(jobs)
			if tt.wantNoJob {
				if len(entries) != 0 {
					t.Errorf("job directories = %v, want none", entries)
				}
				return
			}
			saved, err := job.Load(jobs, out.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.State != tt.wantState || saved.ExitCode != tt.wantExit || saved.Verdict != tt.wantVerdict || saved.FinishedAt == nil {
				t.Errorf("job.json = %+v, want state %s, exit code %d, verdict %q, a finish time", saved, tt.wantState, tt.wantExit, tt.wantVerdict)
			}
			if (saved.Error != "") != (tt.wantErr != "") {
				t.Errorf("job.json error = %q, want one: %v", saved.Error, tt.wantErr != "")
			}
			if saved.Backend != "fake" || saved.Image != "core" || saved.Target.Kind != "path" {
				t.Errorf("job.json = %+v, want backend fake, image core, target kind path", saved)
			}
			if out.Job.State != saved.State {
				t.Errorf("Outcome.Job.State = %s, job.json has %s", out.Job.State, saved.State)
			}
			_, statErr := os.Stat(filepath.Join(jobs, out.Job.ID, "report.json"))
			if (statErr == nil) != tt.wantReport || (out.Result != nil) != tt.wantReport {
				t.Errorf("report.json exists = %v, Outcome.Result set = %v, want %v", statErr == nil, out.Result != nil, tt.wantReport)
			}
			if tt.wantStages != nil && strings.Join(stages, ",") != strings.Join(tt.wantStages, ",") {
				t.Errorf("stages = %v, want %v", stages, tt.wantStages)
			}
			for name, want := range tt.wantEntries {
				got, ok := b.input[name]
				if (want == tarEntry{}) {
					if ok {
						t.Errorf("tar entry %q exists, want it absent", name)
					}
					continue
				}
				if !ok || got != want {
					t.Errorf("tar entry %q = %+v (present %v), want %+v", name, got, ok, want)
				}
			}
			for name, size := range tt.wantArtifact {
				if fi, err := os.Stat(filepath.Join(jobs, out.Job.ID, "artifacts", name)); err != nil || fi.Size() != int64(size) {
					t.Errorf("artifact %s = %v, %v, want %d bytes", name, fi, err, size)
				}
			}
		})
	}
}

// serveRaw is serve with a change to the encoded Result.
func serveRaw(version string, edit func(data []byte) []byte) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(version)
		g.readJob()
		g.readInput()
		data, err := json.Marshal(g.result(version))
		if err != nil {
			panic(err)
		}
		g.sendRaw(protocol.FrameResult, edit(data))
	}
}

func cmpOr[T comparable](v, fallback T) T {
	var zero T
	if v == zero {
		return fallback
	}
	return v
}

// sparseTarget is a file one byte over the cap that takes no disk.
func sparseTarget(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(p) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // the file is only truncated
	if err := f.Truncate(protocol.MaxInputBytes + 1); err != nil {
		t.Skipf("filesystem cannot hold a sparse 1 GiB file: %v", err)
	}
	return p
}
