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
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/sandbox"
)

// brokenBackend is a backend whose machine never starts.
type brokenBackend struct{}

func (brokenBackend) Name() string { return "broken" }

func (brokenBackend) Start(context.Context, sandbox.Spec) (sandbox.Machine, error) {
	return nil, errors.New("no kvm")
}

// cleanBackend runs a guest that takes the input and answers that a file is clean.
type cleanBackend struct{ fileSHA string }

func (cleanBackend) Name() string { return "clean" }

func (b cleanBackend) Start(context.Context, sandbox.Spec) (sandbox.Machine, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	m := &cleanMachine{l: l, done: make(chan struct{})}
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
	l    net.Listener
	done chan struct{}
}

func (m *cleanMachine) Listener(uint32) net.Listener { return m.l }
func (m *cleanMachine) Wait() error                  { <-m.done; return nil }
func (m *cleanMachine) Kill() error                  { return m.l.Close() }

func TestRunScan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello\n"))
	clean := func() (sandbox.Backend, error) { return cleanBackend{fileSHA: hex.EncodeToString(sum[:])}, nil }
	broken := func() (sandbox.Backend, error) { return brokenBackend{}, nil }
	hostile := filepath.Join(t.TempDir(), "\x1b]0;PWNED\a\x1b[2J")
	tests := []struct {
		name string
		// inputs
		args    []string
		backend func() (sandbox.Backend, error)
		// expectations
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring
		wantJob    bool   // a job directory exists
	}{
		{name: "a clean file", args: []string{file}, backend: clean, wantCode: cli.ExitClean, wantStdout: "CLEAN", wantStderr: "galahad: analyze", wantJob: true},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: "Usage: galahad"},
		{name: "no path", wantCode: cli.ExitUsage, wantStderr: "want exactly one path, got 0"},
		{name: "two paths", args: []string{"a", "b"}, wantCode: cli.ExitUsage, wantStderr: "want exactly one path, got 2"},
		{name: "unknown flag", args: []string{"--nope", file}, wantCode: cli.ExitUsage, wantStderr: "flag provided but not defined"},
		{
			name: "no sandbox backend", args: []string{file}, wantCode: cli.ExitError, wantStderr: "sandbox not supported",
			backend: func() (sandbox.Backend, error) { return nil, sandbox.ErrUnsupported },
		},
		{name: "missing target", args: []string{filepath.Join(t.TempDir(), "missing")}, backend: broken, wantCode: cli.ExitError, wantStderr: "galahad scan:"},
		{name: "missing target with escape codes in its name", args: []string{hostile}, backend: broken, wantCode: cli.ExitError, wantStderr: `\u001b]0;PWNED\u0007\u001b[2J`},
		{name: "the machine does not start", args: []string{file}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
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
		})
	}
}
