package agent_test

import (
	"archive/tar"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestRelay(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		proxy bool // pass --proxy
		// expectations
		wantRelay bool // the relay runs, and the proxy variables are set
	}{
		{name: "with a proxy channel the relay runs and the proxy variables are set", proxy: true, wantRelay: true},
		{name: "without a proxy channel there is no relay and no variable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a guest that records the variables it sets, and a host proxy that refuses every tunnel
			var mu sync.Mutex
			vars := map[string]string{}
			env := agent.Env{Setenv: func(k, v string) {
				mu.Lock()
				defer mu.Unlock()
				vars[k] = v
			}}
			var args []string
			if tt.proxy {
				proxyAddr := fakeProxyAt(t, func(c net.Conn) {
					readConnectFrame(c)
					writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"test"}`)
				})
				args = []string{"--proxy", "tcp:" + proxyAddr}
			}
			data := buildTar(t, tarEntry{name: "proj/", typ: tar.TypeDir}, tarEntry{name: "proj/a.txt", body: "a\n"})

			// When the host sends the job
			c, exit := startGuestWith(t, env, args...)
			if err := writeJSON(c, protocol.FrameJob, testJob("proj", 300)); err != nil {
				t.Fatal(err)
			}

			// Then the relay answers on the address in the variables, and is gone when the guest ends
			var relayAddr string
			if tt.wantRelay {
				relayAddr = waitForVars(t, &mu, vars)
				answer := exchange(t, relayAddr, "CONNECT api.osv.dev:443 HTTP/1.1\r\n\r\n", "")
				if !strings.HasPrefix(answer, "HTTP/1.1 403 Forbidden") || !strings.Contains(answer, "denied: test") {
					t.Errorf("answer through the relay = %q, want a 403 with the reason", answer)
				}
			}
			if err := sendInput(c, data, endOf(data)); err != nil {
				t.Fatal(err)
			}
			got := readGuest(t, c)
			if ex := <-exit; ex.code != agent.ExitClean || got.result == nil {
				t.Fatalf("exit = %d, result = %v; stderr %q", ex.code, got.result, ex.stderr)
			}
			mu.Lock()
			defer mu.Unlock()
			if !tt.wantRelay {
				if len(vars) != 0 {
					t.Errorf("variables set = %v, want none", vars)
				}
				return
			}
			if conn, err := net.DialTimeout("tcp", relayAddr, time.Second); err == nil {
				_ = conn.Close()
				t.Errorf("the relay still listens on %s after the job", relayAddr)
			}
		})
	}
}

// waitForVars waits for the guest to set the four proxy variables, checks them and returns the relay address.
func waitForVars(t *testing.T, mu *sync.Mutex, vars map[string]string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(vars)
		mu.Unlock()
		if n == 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the guest set %d proxy variables, want 4", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	want := vars["http_proxy"]
	host, _, err := net.SplitHostPort(strings.TrimPrefix(want, "http://"))
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("http_proxy = %q, want http://127.0.0.1:<port>", want)
	}
	for _, k := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		if vars[k] != want {
			t.Errorf("%s = %q, want %q", k, vars[k], want)
		}
	}
	return strings.TrimPrefix(want, "http://")
}
