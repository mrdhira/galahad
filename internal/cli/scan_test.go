package cli_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/sandbox"
)

// brokenBackend is a backend whose machine never starts.
type brokenBackend struct{}

func (brokenBackend) Name() string { return "broken" }

func (brokenBackend) Start(context.Context, sandbox.Spec) (sandbox.Machine, error) {
	return nil, errors.New("no kvm")
}

// spy records what the host asked of the machine and the guest.
type spy struct {
	mu         sync.Mutex
	spec       sandbox.Spec
	jobTimeout int // seconds, from the Job frame
}

// cleanBackend runs a guest that takes the input and answers that a file is clean. A non-nil spy
// records the machine spec and the job timeout.
type cleanBackend struct {
	fileSHA string
	spy     *spy
}

func (cleanBackend) Name() string { return "clean" }

func (b cleanBackend) Start(_ context.Context, s sandbox.Spec) (sandbox.Machine, error) {
	if b.spy != nil {
		b.spy.mu.Lock()
		b.spy.spec = s
		b.spy.mu.Unlock()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	pl, err := net.Listen("tcp", "127.0.0.1:0") // the proxy port: nobody connects
	if err != nil {
		_ = l.Close() // the listen error is the one to report
		return nil, err
	}
	m := &cleanMachine{l: l, pl: pl, done: make(chan struct{})}
	go func() {
		defer close(m.done)
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }() // the guest is gone
		send := func(t protocol.FrameType, v any) {
			data, _ := json.Marshal(v)
			_ = protocol.WriteFrame(conn, t, data)
		}
		send(protocol.FrameHello, protocol.Hello{Protocol: protocol.ProtocolVersion, AgentVersion: "dev"})
		var job protocol.Job
		for {
			t, payload, err := protocol.ReadFrame(conn)
			if err != nil {
				return
			}
			if t == protocol.FrameJob {
				_ = protocol.DecodeStrict(payload, &job)
				if b.spy != nil {
					b.spy.mu.Lock()
					b.spy.jobTimeout = job.Timeouts.Job
					b.spy.mu.Unlock()
				}
			}
			if t == protocol.FrameEnd {
				break
			}
		}
		send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageAnalyze})
		now := time.Now().UTC()
		send(protocol.FrameResult, protocol.Result{
			SchemaVersion: protocol.SchemaVersion,
			Tool:          protocol.Tool{Name: "galahad-agent", Version: "dev"},
			Target:        protocol.Target{Name: job.Name, Kind: protocol.TargetFile, SHA256: b.fileSHA},
			StartedAt:     now, FinishedAt: now,
			Files: []protocol.FileInfo{}, Findings: []protocol.Finding{}, IOCs: []protocol.IOC{},
			Coverage: protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1, Skipped: []protocol.Skip{}, Analyzers: []string{"static"}},
			Reasons:  []string{},
		})
	}()
	return m, nil
}

type cleanMachine struct {
	l, pl net.Listener // control and proxy
	done  chan struct{}
}

func (m *cleanMachine) Listener(port uint32) net.Listener {
	if port == 1025 {
		return m.pl
	}
	return m.l
}
func (m *cleanMachine) Wait() error { <-m.done; return nil }
func (m *cleanMachine) Kill() error { return errors.Join(m.l.Close(), m.pl.Close()) }

func TestRunScan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello\n"))
	var seen spy
	clean := func() (sandbox.Backend, error) {
		return cleanBackend{fileSHA: hex.EncodeToString(sum[:]), spy: &seen}, nil
	}
	broken := func() (sandbox.Backend, error) { return brokenBackend{}, nil }
	hostile := filepath.Join(t.TempDir(), "\x1b]0;PWNED\a\x1b[2J")
	tests := []struct {
		name string
		// inputs
		args       []string
		backend    func() (sandbox.Backend, error)
		signatures bool // home holds signatures.img from setup
		// expectations
		wantCode    int
		wantStdout  string // substring
		wantStderr  string // substring
		wantJob     bool   // a job directory exists
		wantKind    string // the target kind in job.json, when not empty
		wantSpec    sandbox.Spec
		wantTimeout int // seconds of the job timeout the guest got; 0 means it was not checked
	}{
		{
			name: "a clean file", args: []string{file}, backend: clean, wantCode: cli.ExitClean, wantStdout: "CLEAN", wantStderr: "galahad: analyze", wantJob: true,
			wantSpec: sandbox.Spec{Image: "core", CPUs: 2, MemoryMiB: 3072, Ports: []uint32{1024, 1025}}, wantTimeout: 600,
		},
		{
			name: "the signatures of setup are attached read-only", args: []string{file}, backend: clean, signatures: true, wantCode: cli.ExitClean, wantStdout: "CLEAN", wantJob: true,
			wantSpec: sandbox.Spec{Image: "core", CPUs: 2, MemoryMiB: 3072, Ports: []uint32{1024, 1025}}, wantTimeout: 600,
		},
		{
			name: "the re image gets a longer default timeout", args: []string{"--image", "re", file}, backend: clean,
			wantCode: cli.ExitClean, wantStdout: "CLEAN", wantJob: true,
			wantSpec: sandbox.Spec{Image: "re", CPUs: 2, MemoryMiB: 3072, Ports: []uint32{1024, 1025}}, wantTimeout: 1200,
		},
		{
			name: "flags reach the machine and the job", args: []string{"--image", "re", "--timeout", "3m", "--cpus", "4", "--memory", "2048", file}, backend: clean,
			wantCode: cli.ExitClean, wantStdout: "CLEAN", wantJob: true,
			wantSpec: sandbox.Spec{Image: "re", CPUs: 4, MemoryMiB: 2048, Ports: []uint32{1024, 1025}}, wantTimeout: 180,
		},
		{
			name: "no network serves no proxy port", args: []string{"--no-network", file}, backend: clean, wantCode: cli.ExitClean, wantStdout: "CLEAN", wantJob: true,
			wantSpec: sandbox.Spec{Image: "core", CPUs: 2, MemoryMiB: 3072, Ports: []uint32{1024}}, wantTimeout: 600,
		},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: "Usage: galahad"},
		{name: "no path", wantCode: cli.ExitUsage, wantStderr: "want exactly one path or link, got 0"},
		{name: "two paths", args: []string{"a", "b"}, wantCode: cli.ExitUsage, wantStderr: "want exactly one path or link, got 2"},
		{name: "allow-host is not a host name", args: []string{"--allow-host", "a b", file}, wantCode: cli.ExitUsage, wantStderr: `--allow-host "a b" is not a host name`},
		{name: "allow-host is an IP address", args: []string{"--allow-host", "10.0.0.1", file}, wantCode: cli.ExitUsage, wantStderr: "is not a host name"},
		{name: "a link with a space", args: []string{"https://example.com/a b"}, wantCode: cli.ExitUsage, wantStderr: "percent-encode"},
		{name: "a link that is not http", args: []string{"ftp://example.com/a"}, wantCode: cli.ExitUsage, wantStderr: "only http and https links are supported"},
		{name: "a link that is too long", args: []string{"https://example.com/" + strings.Repeat("a", 2100)}, wantCode: cli.ExitUsage, wantStderr: "the most is 2048"},
		{name: "a link without a host", args: []string{"https:///a"}, wantCode: cli.ExitUsage, wantStderr: "has no host"},
		{name: "a link with a password", args: []string{"https://user:secret@example.com/a"}, wantCode: cli.ExitUsage, wantStderr: "user name or password"},
		{name: "a Drive link that is not a file", args: []string{"https://drive.google.com/drive/folders/1AbCdEfGhIjKl"}, wantCode: cli.ExitUsage, wantStderr: "is not a Google Drive file link"},
		{name: "a Docs page is not supported yet", args: []string{"https://docs.google.com/document/d/1AbCdEfGhIjKl/edit"}, wantCode: cli.ExitUsage, wantStderr: "Google Docs, Sheets, Slides and Forms pages are not supported yet"},
		{name: "a Forms page is not supported yet", args: []string{"https://docs.google.com/forms/d/e/1AbCdEfGhIjKl/viewform"}, wantCode: cli.ExitUsage, wantStderr: "Google Docs, Sheets, Slides and Forms pages are not supported yet"},
		{name: "a Docs link of another kind is not a file", args: []string{"https://docs.google.com/other/d/1AbCdEfGhIjKl/edit"}, wantCode: cli.ExitUsage, wantStderr: "use /file/d/<id>"},
		{name: "a link without the network", args: []string{"--no-network", "https://example.com/a.pdf"}, wantCode: cli.ExitUsage, wantStderr: "a link needs the network"},
		{name: "unknown flag", args: []string{"--nope", file}, wantCode: cli.ExitUsage, wantStderr: "flag provided but not defined"},
		{name: "cpus is not a number", args: []string{"--cpus", "many", file}, wantCode: cli.ExitUsage, wantStderr: "invalid value"},
		{name: "unknown image", args: []string{"--image", "full", file}, wantCode: cli.ExitUsage, wantStderr: `--image "full": want core or re`},
		{name: "unknown image with escape codes", args: []string{"--image", "\x1b[2J", file}, wantCode: cli.ExitUsage, wantStderr: `--image "\\u001b[2J"`},
		{name: "timeout below the minimum", args: []string{"--timeout", "119s", file}, wantCode: cli.ExitUsage, wantStderr: "--timeout 1m59s: want 2m0s to 24h0m0s"},
		{name: "timeout above the maximum", args: []string{"--timeout", "25h", file}, wantCode: cli.ExitUsage, wantStderr: "--timeout 25h0m0s"},
		{name: "no cpus", args: []string{"--cpus", "0", file}, wantCode: cli.ExitUsage, wantStderr: "--cpus 0: want 1 to 8"},
		{name: "too many cpus", args: []string{"--cpus", "9", file}, wantCode: cli.ExitUsage, wantStderr: "--cpus 9: want 1 to 8"},
		{name: "memory below the minimum", args: []string{"--memory", "1023", file}, wantCode: cli.ExitUsage, wantStderr: "--memory 1023: want 1024 to 16384 MiB"},
		{name: "memory above the maximum", args: []string{"--memory", "16385", file}, wantCode: cli.ExitUsage, wantStderr: "--memory 16385: want 1024 to 16384 MiB"},
		{
			name: "no sandbox backend", args: []string{file}, wantCode: cli.ExitError, wantStderr: "sandbox not supported",
			backend: func() (sandbox.Backend, error) { return nil, sandbox.ErrUnsupported },
		},
		{name: "missing target", args: []string{filepath.Join(t.TempDir(), "missing")}, backend: broken, wantCode: cli.ExitError, wantStderr: "galahad scan:"},
		{name: "missing target with escape codes in its name", args: []string{hostile}, backend: broken, wantCode: cli.ExitError, wantStderr: `\u001b]0;PWNED\u0007\u001b[2J`},
		{name: "the machine does not start", args: []string{file}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "path"},
		{name: "a link starts a job", args: []string{"--allow-host", "Files.Example.com", "--allow-host", "cdn.example.com", "https://example.com/a.pdf"}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "url"},
		{name: "a Drive link starts a job", args: []string{"https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view"}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "drive"},
		{name: "a Drive open link starts a job", args: []string{"HTTPS://Drive.Google.com/open?id=1AbCdEfGhIjKlMnOp"}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "drive"},
		{name: "a Drive uc link starts a job", args: []string{"http://drive.google.com/uc?export=download&id=1AbCdEfGhIjKlMnOp"}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "drive"},
		{name: "a docs uc link starts a job", args: []string{"https://docs.google.com/uc?id=1AbCdEfGhIjKlMnOp"}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true, wantKind: "drive"},
		{name: "a link to a host the policy refuses", args: []string{"http://a_b.example.com/x"}, backend: broken, wantCode: cli.ExitError, wantStderr: "is not a valid host name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if tt.signatures {
				if err := os.WriteFile(filepath.Join(home, "signatures.img"), []byte("sig"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			seen = spy{}
			env := cli.Env{Home: home, Backend: tt.backend, Now: time.Now}
			var out, errb bytes.Buffer
			if got := cli.RunWithEnv(append([]string{"scan"}, tt.args...), &out, &errb, env); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", got, tt.wantCode, errb.String())
			}
			if !strings.Contains(out.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantStdout)
			}
			if !strings.Contains(errb.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", errb.String(), tt.wantStderr)
			}
			if strings.ContainsAny(errb.String(), "\x1b\a") {
				t.Errorf("stderr has control characters: %q", errb.String())
			}
			entries, _ := os.ReadDir(filepath.Join(home, "jobs"))
			if (len(entries) > 0) != tt.wantJob {
				t.Errorf("job directories = %v, want one: %v", entries, tt.wantJob)
			}
			if tt.wantKind != "" {
				saved, err := job.Load(filepath.Join(home, "jobs"), entries[0].Name())
				if err != nil {
					t.Fatal(err)
				}
				if saved.Target.Kind != tt.wantKind {
					t.Errorf("job.json target kind = %q, want %q", saved.Target.Kind, tt.wantKind)
				}
			}
			if tt.wantTimeout > 0 {
				seen.mu.Lock()
				defer seen.mu.Unlock()
				if got := seen.spec; got.Image != tt.wantSpec.Image || got.CPUs != tt.wantSpec.CPUs || got.MemoryMiB != tt.wantSpec.MemoryMiB || !slices.Equal(got.Ports, tt.wantSpec.Ports) {
					t.Errorf("machine spec = %+v, want image %q, %d CPUs, %d MiB, ports %v", got, tt.wantSpec.Image, tt.wantSpec.CPUs, tt.wantSpec.MemoryMiB, tt.wantSpec.Ports)
				}
				wantSig := ""
				if tt.signatures {
					wantSig = filepath.Join(home, "signatures.img")
				}
				if got := seen.spec; got.Signatures != wantSig || got.SignaturesWritable {
					t.Errorf("signatures drive = %q (writable %v), want %q, read-only", got.Signatures, got.SignaturesWritable, wantSig)
				}
				// The guest sees what is left of the timeout, a moment after the start.
				if seen.jobTimeout > tt.wantTimeout || seen.jobTimeout < tt.wantTimeout-5 {
					t.Errorf("job timeout = %ds, want about %ds", seen.jobTimeout, tt.wantTimeout)
				}
			}
		})
	}
}
