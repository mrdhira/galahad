package agent_test

import (
	"archive/tar"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

// tarEntry is one entry of a test tar stream.
type tarEntry struct {
	name string
	typ  byte   // tar.TypeReg when zero
	link string // link target
	body string
	size int64 // declared size when it differs from the body
}

func buildTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Size: int64(len(e.body))}
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Typeflag != tar.TypeReg {
			hdr.Size = 0
		}
		if e.size != 0 {
			hdr.Size = e.size
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if e.size != 0 {
			return buf.Bytes() // the declared size is never delivered
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testJob(name string, timeout int) protocol.Job {
	return protocol.Job{
		ID: "20261021-153012-a1b2c3", Kind: protocol.KindScan, Source: protocol.SourceLocal, Name: name,
		Timeouts: protocol.Timeouts{Job: timeout}, Now: time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC),
	}
}

func endOf(data []byte) protocol.End {
	sum := sha256.Sum256(data)
	return protocol.End{Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

func writeJSON(c net.Conn, t protocol.FrameType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(c, t, data)
}

// sendInput writes Data frames of the tar stream, then the End frame.
func sendInput(c net.Conn, data []byte, end protocol.End) error {
	for chunk := range slices.Chunk(data, 4096) {
		if err := protocol.WriteFrame(c, protocol.FrameData, chunk); err != nil {
			return err
		}
	}
	return writeJSON(c, protocol.FrameEnd, end)
}

// guestFrames is what a test host read from the guest.
type guestFrames struct {
	stages []string
	result *protocol.Result
	errMsg *protocol.Error
}

// readGuest reads the frames of the guest as the host would: in order, then EOF.
func readGuest(t *testing.T, c net.Conn) guestFrames {
	t.Helper()
	var got guestFrames
	order := protocol.NewGuestOrder()
	for !order.Complete() {
		if err := c.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		ft, payload, err := protocol.ReadFrame(c)
		if err != nil {
			t.Fatalf("read frame from guest: %v (stages %v)", err, got.stages)
		}
		if err := order.Accept(ft); err != nil {
			t.Fatalf("guest frame order: %v", err)
		}
		switch ft {
		case protocol.FrameHello:
			var h protocol.Hello
			if err := protocol.DecodeStrict(payload, &h); err != nil || h.Validate() != nil {
				t.Fatalf("hello %s: %v, %v", payload, err, h.Validate())
			}
		case protocol.FrameProgress:
			var p protocol.Progress
			if err := protocol.DecodeStrict(payload, &p); err != nil || p.Validate() != nil {
				t.Fatalf("progress %s: %v, %v", payload, err, p.Validate())
			}
			got.stages = append(got.stages, p.Stage)
		case protocol.FrameResult:
			var r protocol.Result
			if err := protocol.DecodeStrict(payload, &r); err != nil {
				t.Fatalf("result: %v", err)
			}
			if err := r.Validate(); err != nil {
				t.Fatalf("result does not validate: %v", err)
			}
			got.result = &r
		case protocol.FrameError:
			var e protocol.Error
			if err := protocol.DecodeStrict(payload, &e); err != nil || e.Validate() != nil {
				t.Fatalf("error frame %s: %v, %v", payload, err, e.Validate())
			}
			got.errMsg = &e
		}
	}
	if _, _, err := protocol.ReadFrame(c); !errors.Is(err, io.EOF) {
		t.Errorf("after the last frame: %v, want EOF", err)
	}
	_ = c.Close() // the host is done; the guest waits for this before it closes
	return got
}

type guestExit struct {
	code   int
	stderr string
}

// startGuest runs the guest in this process against a listener and returns the
// connection it made, and a channel with its exit.
func startGuest(t *testing.T, extraArgs ...string) (net.Conn, <-chan guestExit) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	exit := make(chan guestExit, 1)
	go func() {
		var stderr bytes.Buffer
		env := agent.Env{DetectVM: func() (bool, string) { return false, "test" }}
		args := append([]string{"guest", "--unsafe-host", "--control", "tcp:" + l.Addr().String()}, extraArgs...)
		code := agent.RunWithEnv(args, io.Discard, &stderr, env)
		exit <- guestExit{code, stderr.String()}
	}()
	if tl, ok := l.(*net.TCPListener); ok {
		_ = tl.SetDeadline(time.Now().Add(10 * time.Second))
	}
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("the guest did not dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, exit
}

func TestGuest(t *testing.T) {
	goMain := tarEntry{name: "proj/main.go", body: "package main\n\nfunc main() {}\n"}
	tree := []tarEntry{{name: "proj/", typ: tar.TypeDir}, goMain, {name: "proj/README.md", body: "# proj\n"}}
	deepDir := strings.Repeat("d/", 63) // with "proj/" in front, the name is 65 elements deep
	tests := []struct {
		name string
		// inputs
		entries []tarEntry // the tar stream; the tree above when empty
		target  string     // Job.Name; "proj" when empty
		kind    string     // Job.Kind; scan when empty
		timeout int        // Job.Timeouts.Job in seconds; 300 when zero
		ingest  int        // Job.Timeouts.Ingest in seconds; 0 means the job timeout
		mode    string     // how the host misbehaves: "", "stall", "hang up", "data first", "unknown job field", "slow", "bad sha", "bad count"
		// want*
		wantCode       int
		wantErrCode    string // the Error frame code; empty means a Result
		wantMessage    string // substring of the Error message
		wantTargetKind string
		wantTimeout    bool   // the Result has a timeout skip
		wantDepthSkip  string // the path of the depth skip the Result must have, and then a verdict that is not clean
	}{
		{name: "directory target", wantTargetKind: protocol.TargetDir},
		{name: "file target", entries: []tarEntry{{name: "one.txt", body: "hello\n"}}, target: "one.txt", wantTargetKind: protocol.TargetFile},
		{name: "host stalls until the job timeout", mode: "stall", timeout: 1, wantCode: agent.ExitError, wantErrCode: protocol.CodeTimeout, wantMessage: "timed out"},
		{name: "host hangs up", mode: "hang up", wantCode: agent.ExitError, wantErrCode: protocol.CodeProtocol, wantMessage: "closed the connection"},
		{name: "bad frame order", mode: "data first", wantCode: agent.ExitError, wantErrCode: protocol.CodeProtocol, wantMessage: "data frame"},
		{name: "unknown job field", mode: "unknown job field", wantCode: agent.ExitError, wantErrCode: protocol.CodeProtocol, wantMessage: "unknown field"},
		{name: "unsupported kind", kind: protocol.KindProbe, wantCode: agent.ExitError, wantErrCode: protocol.CodeProtocol, wantMessage: "not supported"},
		{name: "target name with a slash", target: "proj/sub", wantCode: agent.ExitError, wantErrCode: protocol.CodeProtocol, wantMessage: "single path element"},
		{
			name:     "path traversal",
			entries:  []tarEntry{{name: "proj/", typ: tar.TypeDir}, {name: "../escape.txt", body: "x"}},
			wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "unsafe path",
		},
		{
			name:     "write through a symlink",
			entries:  []tarEntry{{name: "proj/", typ: tar.TypeDir}, {name: "proj/out", typ: tar.TypeSymlink, link: "../.."}, {name: "proj/out/pwned", body: "x"}},
			wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "pwned",
		},
		{
			name:     "oversize tar",
			entries:  []tarEntry{{name: "proj", size: protocol.MaxInputBytes + 1}},
			wantCode: agent.ExitError, wantErrCode: protocol.CodeTooLarge, wantMessage: "bytes of files",
		},
		{name: "ingest share runs out", mode: "slow", ingest: 1, wantCode: agent.ExitError, wantErrCode: protocol.CodeTimeout, wantMessage: "deadline exceeded"},
		{name: "sha256 mismatch", mode: "bad sha", wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "sha256 is"},
		{name: "byte count mismatch", mode: "bad count", wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "read "},
		{
			name:     "target missing from the tar",
			entries:  []tarEntry{{name: "other.txt", body: "x"}},
			wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "no entry named",
		},
		{
			name:     "target is a symlink",
			entries:  []tarEntry{{name: "proj", typ: tar.TypeSymlink, link: "/etc"}},
			wantCode: agent.ExitError, wantErrCode: protocol.CodeIngest, wantMessage: "not a regular file",
		},
		{name: "timeout skip reaches the host", timeout: 1, wantTargetKind: protocol.TargetDir, wantTimeout: true},
		{
			name:           "entries too deep for the extractor become a depth skip",
			entries:        append(slices.Clone(tree), tarEntry{name: "proj/" + deepDir + "f.txt", body: "x"}, tarEntry{name: "proj/a/" + deepDir + "f.txt", body: "x"}),
			wantTargetKind: protocol.TargetDir, wantDepthSkip: deepDir + "f.txt",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(tt.name, "symlink") {
				t.Skip("creating symlinks needs a privilege on Windows, and the guest is Linux")
			}
			entries := tt.entries
			if entries == nil {
				entries = tree
			}
			data := buildTar(t, entries...)
			job := testJob(cmp.Or(tt.target, "proj"), cmp.Or(tt.timeout, 300))
			job.Timeouts.Ingest = tt.ingest
			job.Kind = cmp.Or(tt.kind, protocol.KindScan)
			if tt.kind != "" {
				job.Source = ""
			}
			end := endOf(data)
			switch tt.mode {
			case "bad sha":
				end.SHA256 = strings.Repeat("0", 64)
			case "bad count":
				end.Bytes++
			}

			c, exit := startGuest(t)
			go func() { // the host writes while it reads, as the real one does; write errors are expected after a refusal
				var jobJSON any = job
				if tt.mode == "unknown job field" {
					jobJSON = map[string]any{"id": job.ID, "kind": job.Kind, "bogus": 1}
				}
				if tt.mode == "data first" {
					_ = protocol.WriteFrame(c, protocol.FrameData, []byte("x"))
					return
				}
				if err := writeJSON(c, protocol.FrameJob, jobJSON); err != nil {
					return
				}
				switch tt.mode {
				case "stall":
				case "hang up":
					_ = c.(*net.TCPConn).CloseWrite()
				case "slow": // the second entry arrives after the ingest share is gone
					_ = protocol.WriteFrame(c, protocol.FrameData, data[:512])
					time.Sleep(1500 * time.Millisecond)
					_ = sendInput(c, data[512:], end)
				default:
					_ = sendInput(c, data, end)
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			if ex.code != tt.wantCode {
				t.Errorf("exit = %d, want %d; stderr %q", ex.code, tt.wantCode, ex.stderr)
			}
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode {
					t.Fatalf("error frame = %+v, want code %q; stderr %q", got.errMsg, tt.wantErrCode, ex.stderr)
				}
				if !strings.Contains(got.errMsg.Message, tt.wantMessage) {
					t.Errorf("error message %q does not contain %q", got.errMsg.Message, tt.wantMessage)
				}
				if got.result != nil {
					t.Error("an Error was followed by a Result")
				}
				return
			}
			if got.errMsg != nil || got.result == nil {
				t.Fatalf("want a Result, got %+v; stderr %q", got.errMsg, ex.stderr)
			}
			if want := []string{protocol.StageIngest, protocol.StageAnalyze}; !slices.Equal(got.stages, want) {
				t.Errorf("stages = %v, want %v", got.stages, want)
			}
			res := got.result
			if res.Target.Name != job.Name || res.Target.Kind != tt.wantTargetKind {
				t.Errorf("target = %q %q, want %q %q", res.Target.Name, res.Target.Kind, job.Name, tt.wantTargetKind)
			}
			if res.Tool.Name != "galahad-agent" || res.Verdict == "" {
				t.Errorf("tool %+v, verdict %q: want the agent, scored", res.Tool, res.Verdict)
			}
			if tt.wantDepthSkip != "" {
				if want := []protocol.Skip{{Path: tt.wantDepthSkip, Reason: protocol.SkipDepth}}; !slices.Equal(res.Coverage.Skipped, want) || res.Verdict == protocol.VerdictClean {
					t.Errorf("skips = %+v, verdict %q; want %+v and a verdict that is not clean", res.Coverage.Skipped, res.Verdict, want)
				}
			}
			gotTimeout := slices.ContainsFunc(res.Coverage.Skipped, func(s protocol.Skip) bool { return s.Reason == protocol.SkipTimeout })
			if gotTimeout != tt.wantTimeout || (tt.wantTimeout && !res.Coverage.Truncated) {
				t.Errorf("timeout skip = %v, truncated = %v; want skip %v", gotTimeout, res.Coverage.Truncated, tt.wantTimeout)
			}
		})
	}
}

func TestGuestArgs(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close() // nothing listens here now

	tests := []struct {
		name string
		args []string
		// want*
		wantCode   int
		wantStderr string
	}{
		{name: "unknown flag", args: []string{"guest", "--nope"}, wantCode: agent.ExitUsage, wantStderr: "flag provided but not defined"},
		{name: "bad memory limit", args: []string{"guest", "--memory-limit", "lots"}, wantCode: agent.ExitUsage, wantStderr: "invalid value"},
		{name: "extra argument", args: []string{"guest", "--control", "vsock:2:1024", "x"}, wantCode: agent.ExitUsage, wantStderr: `unexpected argument "x"`},
		{name: "control is required", args: []string{"guest", "--unsafe-host"}, wantCode: agent.ExitUsage, wantStderr: "--control is required"},
		{name: "tcp control without --unsafe-host", args: []string{"guest", "--control", "tcp:127.0.0.1:1"}, wantCode: agent.ExitUsage, wantStderr: "only allowed together with --unsafe-host"},
		{name: "bad control", args: []string{"guest", "--unsafe-host", "--control", "udp:1"}, wantCode: agent.ExitUsage, wantStderr: "--control: transport"},
		{name: "bad proxy", args: []string{"guest", "--unsafe-host", "--control", "tcp:" + closedAddr, "--proxy", "vsock:2"}, wantCode: agent.ExitUsage, wantStderr: "--proxy: transport"},
		{name: "outside a VM without --unsafe-host", args: []string{"guest", "--control", "vsock:2:1024"}, wantCode: agent.ExitUsage, wantStderr: "refusing to take untrusted input outside a VM"},
		{name: "control cannot be reached", args: []string{"guest", "--unsafe-host", "--control", "tcp:" + closedAddr, "--proxy", "tcp:" + closedAddr}, wantCode: agent.ExitError, wantStderr: "dial control"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			env := agent.Env{DetectVM: func() (bool, string) { return false, "test" }}
			if got := agent.RunWithEnv(tt.args, io.Discard, &stderr, env); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d; stderr %q", got, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

func TestGuestEncodesResultWithEncodeResult(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("guest.go"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		// inputs
		text string
		// want*
		wantPresent bool
	}{
		{name: "uses EncodeResult", text: "protocol.EncodeResult(", wantPresent: true},
		{name: "no json import", text: `"encoding/json"`},
		{name: "no json.Marshal", text: "json.Marshal"},
		{name: "no json encoder", text: "NewEncoder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Contains(string(src), tt.text); got != tt.wantPresent {
				t.Errorf("guest.go contains %q = %v, want %v", tt.text, got, tt.wantPresent)
			}
		})
	}
}

func TestGuestMemoryLimit(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// want*
		wantLimit int64
	}{
		{name: "limit from the flag", args: []string{"--memory-limit", "64MiB"}, wantLimit: 64 << 20},
		{name: "default limit", wantLimit: -1}, // some positive value, or GOMEMLIMIT leaves it alone
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOMEMLIMIT", "")
			var got int64
			var stderr bytes.Buffer
			env := agent.Env{
				DetectVM:       func() (bool, string) { return false, "test" },
				SetMemoryLimit: func(n int64) { got = n },
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			_ = l.Close() // the guest cannot dial: the limit is set before it does
			args := append([]string{"guest", "--unsafe-host", "--control", "tcp:" + addr}, tt.args...)
			if code := agent.RunWithEnv(args, io.Discard, &stderr, env); code != agent.ExitError {
				t.Fatalf("exit = %d, want %d; stderr %q", code, agent.ExitError, stderr.String())
			}
			if tt.wantLimit >= 0 && got != tt.wantLimit || tt.wantLimit < 0 && got <= 0 {
				t.Errorf("memory limit = %d, want %d", got, tt.wantLimit)
			}
		})
	}
}
