//go:build galahadtest

// Package fake is a test-only sandbox backend. It runs galahad-agent as a local
// subprocess and gives it TCP listeners on 127.0.0.1 instead of vsock. It does not
// isolate anything and does not enforce CPU or memory limits. It exists only in
// galahadtest builds.
package fake

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	controlPort = 1024
	proxyPort   = 1025

	maxConsole = 1 << 20
)

// Machine is a running agent subprocess.
type Machine struct {
	cmd       *exec.Cmd
	listeners map[uint32]net.Listener
	done      chan struct{}
	waitErr   error
	killOnce  sync.Once
	killErr   error
}

// Start runs the agent with a listener for each port. The ports are the control port 1024
// and the proxy port 1025. The listeners exist before the process starts. The agent's
// stderr goes to <jobDir>/console.log, capped at 1 MiB.
func Start(ctx context.Context, jobDir string, ports []uint32) (*Machine, error) {
	m := &Machine{listeners: map[uint32]net.Listener{}, done: make(chan struct{})}
	args := []string{"guest", "--unsafe-host"}
	for _, p := range ports {
		var flag string
		switch p {
		case controlPort:
			flag = "--control"
		case proxyPort:
			flag = "--proxy"
		default:
			m.closeListeners()
			return nil, fmt.Errorf("fake sandbox: unknown port %d", p)
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			m.closeListeners()
			return nil, fmt.Errorf("fake sandbox: listen for port %d: %w", p, err)
		}
		m.listeners[p] = l
		args = append(args, flag, "tcp:"+l.Addr().String())
	}

	console, err := os.OpenFile(filepath.Join(jobDir, "console.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the job directory is made by this program
	if err != nil {
		m.closeListeners()
		return nil, fmt.Errorf("fake sandbox: open console log: %w", err)
	}
	m.cmd = exec.CommandContext(ctx, agentPath(), args...) // #nosec G204 -- test-only backend; the agent path is set by the test setup
	m.cmd.Stderr = &capWriter{w: console, left: maxConsole}
	m.cmd.WaitDelay = 5 * time.Second // do not wait forever for a stderr held open by a child
	if err := m.cmd.Start(); err != nil {
		_ = console.Close() // best effort; the start error is the one to report
		m.closeListeners()
		return nil, fmt.Errorf("fake sandbox: start agent: %w", err)
	}
	go func() {
		m.waitErr = m.cmd.Wait()
		_ = console.Close() // all stderr is copied once Wait returns
		close(m.done)
	}()
	return m, nil
}

// agentPath returns $GALAHAD_FAKE_AGENT, or galahad-agent next to this executable.
func agentPath() string {
	if p := os.Getenv("GALAHAD_FAKE_AGENT"); p != "" {
		return p
	}
	exe, err := os.Executable()
	if err != nil {
		return "galahad-agent"
	}
	name := "galahad-agent"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}

// Listener returns the listener for a port, or nil if the port was not requested.
func (m *Machine) Listener(port uint32) net.Listener {
	l, ok := m.listeners[port]
	if !ok {
		return nil
	}
	return l
}

// Wait returns when the agent process exits.
func (m *Machine) Wait() error {
	<-m.done
	return m.waitErr
}

// Kill kills the agent and closes the listeners. Calling it again returns the first result.
func (m *Machine) Kill() error {
	m.killOnce.Do(func() {
		if err := m.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			m.killErr = fmt.Errorf("fake sandbox: kill agent: %w", err)
		}
		<-m.done
		m.closeListeners()
	})
	return m.killErr
}

func (m *Machine) closeListeners() {
	for _, l := range m.listeners {
		_ = l.Close() // best effort; the listener is local
	}
}

// capWriter writes at most left bytes to w and silently drops the rest, so the process
// never blocks on a full pipe.
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
