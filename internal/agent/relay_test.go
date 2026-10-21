package agent_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

// seen is what the backend saw of the requests that reached it.
type seen struct {
	mu   sync.Mutex
	list []string
}

func (s *seen) add(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append(s.list, line)
}

func (s *seen) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.list...)
}

// newBackend serves one line of text for every request and records what it saw of it.
func newBackend(t *testing.T) (addr string, got *seen) {
	t.Helper()
	got = &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.add(fmt.Sprintf("%s %s host=%s close=%v proxy-connection=%q x-test=%q body=%q",
			r.Method, r.RequestURI, r.Host, r.Close, r.Header.Get("Proxy-Connection"), r.Header.Get("X-Test"), body))
		_, _ = io.WriteString(w, "hello from backend")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), got
}

// hostProxy serves the real host proxy for allowed.example.com on a loopback listener, with every tunnel
// going to backend, and returns a dialer for its tunnels.
func hostProxy(t *testing.T, backend string) agent.Dialer {
	t.Helper()
	return tcpDialer(hostProxyAt(t, backend))
}

// hostProxyAt is hostProxy, and returns the address of the proxy.
func hostProxyAt(t *testing.T, backend string) string {
	t.Helper()
	pol, err := proxy.NewPolicy(proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://allowed.example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.New(pol, io.Discard)
	p.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	p.Dial = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return l.Addr().String()
}

func tcpDialer(addr string) agent.Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// fakeProxy serves handler for each tunnel the relay opens, and returns a dialer for them.
func fakeProxy(t *testing.T, handler func(c net.Conn)) agent.Dialer {
	t.Helper()
	return tcpDialer(fakeProxyAt(t, handler))
}

// fakeProxyAt is fakeProxy, and returns the address of the listener.
func fakeProxyAt(t *testing.T, handler func(c net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				handler(c)
			}()
		}
	}()
	return l.Addr().String()
}

// reading the Connect frame, the fake proxies answer with this
func readConnectFrame(c net.Conn) {
	_, _, _ = protocol.ReadFrameOf(c, protocol.FrameConnect)
}

func writeReply(c net.Conn, ft protocol.FrameType, payload string) {
	_ = protocol.WriteFrame(c, ft, []byte(payload))
}

// startRelay serves a relay on a loopback listener and returns its address. It stops when the test ends.
func startRelay(t *testing.T, dial agent.Dialer, tweak func(*agent.Relay)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := agent.NewRelay(dial)
	if tweak != nil {
		tweak(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return l.Addr().String()
}

// exchange sends payload to the relay and reads until the relay closes the connection. For a CONNECT
// request it reads the head of the answer, sends after through the tunnel and then reads to the end.
func exchange(t *testing.T, addr, payload, after string) string {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	var out strings.Builder
	if after != "" {
		// The answer to CONNECT ends at the blank line.
		for {
			line, err := br.ReadString('\n')
			out.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		if strings.HasPrefix(out.String(), "HTTP/1.1 200") {
			if _, err := io.WriteString(c, after); err != nil {
				t.Fatalf("write through the tunnel: %v", err)
			}
		}
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read answer: %v (got %q)", err, out.String()+string(rest))
	}
	return out.String() + string(rest)
}

func TestRelay(t *testing.T) {
	longHeader := "X-Long: " + strings.Repeat("a", 9000) + "\r\n"
	many := strings.Repeat("X-A: b\r\n", 101)
	big := strings.Repeat("X-Big: "+strings.Repeat("a", 600)+"\r\n", 60)
	const get = "GET http://allowed.example.com/p?q=1 HTTP/1.1\r\nHost: ignored.example.com\r\n"
	tests := []struct {
		name string
		// inputs
		request string
		after   string                                          // sent through the tunnel after the 200 of a CONNECT
		proxy   func(t *testing.T, backend string) agent.Dialer // the real host proxy when nil
		tweak   func(r *agent.Relay)
		// expectations
		wantAnswer    string   // substring of everything the client got
		wantNoAnswer  string   // substring that must not be there
		wantResponses int      // occurrences of "HTTP/1.1 200 OK" in the answer
		wantSeen      []string // what the backend saw
	}{
		{
			name:       "absolute form reaches the backend in origin form and the client is closed after the response",
			request:    get + "Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nX-Test: kept\r\n\r\n",
			wantAnswer: "hello from backend", wantResponses: 1,
			wantSeen: []string{`GET /p?q=1 host=allowed.example.com close=true proxy-connection="" x-test="kept" body=""`},
		},
		{
			name:       "absolute form with a body and an explicit port 80",
			request:    "POST http://allowed.example.com:80/up HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
			wantAnswer: "hello from backend", wantResponses: 1,
			wantSeen: []string{`POST /up host=allowed.example.com close=true proxy-connection="" x-test="" body="hello"`},
		},
		{
			name:       "a second request on the same connection is not served, whatever its host",
			request:    get + "\r\n" + "GET http://other.example.com/ HTTP/1.1\r\n\r\n",
			wantAnswer: "hello from backend", wantResponses: 1,
			wantSeen: []string{`GET /p?q=1 host=allowed.example.com close=true proxy-connection="" x-test="" body=""`},
		},
		{
			name:       "CONNECT opens a tunnel and the bytes pass both ways",
			request:    "CONNECT Allowed.Example.com:80 HTTP/1.1\r\nHost: allowed.example.com:80\r\n\r\n",
			after:      "GET /t HTTP/1.1\r\nHost: allowed.example.com\r\nConnection: close\r\n\r\n",
			wantAnswer: "HTTP/1.1 200 Connection Established\r\n\r\nHTTP/1.1 200 OK", wantResponses: 1,
			wantSeen: []string{`GET /t host=allowed.example.com close=true proxy-connection="" x-test="" body=""`},
		},
		{
			name:       "origin form is a bad request",
			request:    "GET /p HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "https in absolute form is a bad request",
			request:    "GET https://allowed.example.com/ HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "CONNECT without a port is a bad request",
			request:    "CONNECT allowed.example.com HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a request line with two parts is a bad request",
			request:    "GET http://allowed.example.com/\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a lower case method is a bad request",
			request:    "get http://allowed.example.com/ HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "another HTTP version is a bad request",
			request:    "GET http://allowed.example.com/ HTTP/2.0\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a host with an underscore is a bad request",
			request:    "GET http://a_b.example.com/ HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "an IPv6 host is a bad request",
			request:    "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a port out of range is a bad request",
			request:    "CONNECT allowed.example.com:70000 HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a header line over the limit is a bad request",
			request:    get + longHeader + "\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "more than 100 headers is a bad request",
			request:    get + many + "\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a head over the byte limit is a bad request",
			request:    get + big + "\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a header line without a colon is a bad request",
			request:    get + "nonsense\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a folded header line is a bad request",
			request:    get + "X-A: b\r\n continued\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a bare CR in a header is a bad request",
			request:    get + "X-A: b\rc\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a NUL in a header is a bad request",
			request:    get + "X-A: b\x00\r\n\r\n",
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:       "a head that never ends is cut at the head timeout",
			request:    get,
			tweak:      func(r *agent.Relay) { r.HeadTimeout = 100 * time.Millisecond },
			wantAnswer: "HTTP/1.1 400 Bad Request",
		},
		{
			name:    "the host proxy cannot be reached",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return func(context.Context) (net.Conn, error) { return nil, io.ErrClosedPipe }
			},
			wantAnswer: "HTTP/1.1 502 Bad Gateway",
		},
		{
			name:    "the host proxy closes without a reply, as it does over its tunnel cap",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) { readConnectFrame(c) })
			},
			wantAnswer: "HTTP/1.1 502 Bad Gateway", wantNoAnswer: "denied",
		},
		{
			name:    "the host proxy never replies",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) { readConnectFrame(c); _, _ = io.Copy(io.Discard, c) })
			},
			tweak:      func(r *agent.Relay) { r.Handshake = 100 * time.Millisecond },
			wantAnswer: "HTTP/1.1 502 Bad Gateway",
		},
		{
			name:    "the reply is read before the host closes its side after a refusal",
			request: "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) {
					readConnectFrame(c)
					writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"metadata"}`)
					_ = c.(*net.TCPConn).CloseWrite()
					_, _ = io.Copy(io.Discard, c)
				})
			},
			wantAnswer: "HTTP/1.1 403 Forbidden", wantResponses: 0,
		},
		{
			name:    "the reply is not a ConnectReply frame",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) { readConnectFrame(c); writeReply(c, protocol.FrameHello, `{}`) })
			},
			wantAnswer: "HTTP/1.1 502 Bad Gateway",
		},
		{
			name:    "the reply has an unknown field",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) {
					readConnectFrame(c)
					writeReply(c, protocol.FrameConnectReply, `{"ok":true,"reason":"","x":1}`)
				})
			},
			wantAnswer: "HTTP/1.1 502 Bad Gateway",
		},
		{
			name:    "the reply has a control character in its reason",
			request: get + "\r\n",
			proxy: func(t *testing.T, _ string) agent.Dialer {
				return fakeProxy(t, func(c net.Conn) {
					readConnectFrame(c)
					writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"a\u001b[2Jb"}`)
				})
			},
			wantAnswer: "HTTP/1.1 502 Bad Gateway", wantNoAnswer: "\x1b",
		},
		{
			name:       "a host that is not allowed is a 403 with the reason",
			request:    "GET http://other.example.com/ HTTP/1.1\r\n\r\n",
			wantAnswer: "HTTP/1.1 403 Forbidden", wantNoAnswer: "hello from backend",
		},
		{
			name:       "the metadata address is a 403 with its reason",
			request:    "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n",
			wantAnswer: "denied: metadata",
		},
		{
			name:       "a port the policy does not allow is a 403",
			request:    "GET http://allowed.example.com:8080/ HTTP/1.1\r\n\r\n",
			wantAnswer: "denied: port not allowed",
		},
		{
			name:       "a silent tunnel is closed at the idle timeout",
			request:    "CONNECT allowed.example.com:80 HTTP/1.1\r\n\r\n",
			after:      " ",
			tweak:      func(r *agent.Relay) { r.Idle = 100 * time.Millisecond },
			wantAnswer: "HTTP/1.1 200 Connection Established",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a backend, a host proxy and a relay
			backend, got := newBackend(t)
			var dial agent.Dialer
			if tt.proxy != nil {
				dial = tt.proxy(t, backend)
			} else {
				dial = hostProxy(t, backend)
			}
			addr := startRelay(t, dial, tt.tweak)

			// When a client sends the request
			answer := exchange(t, addr, tt.request, tt.after)

			// Then the client got the answer and the backend saw what it should
			if !strings.Contains(answer, tt.wantAnswer) {
				t.Errorf("answer = %q, want it to contain %q", answer, tt.wantAnswer)
			}
			if tt.wantNoAnswer != "" && strings.Contains(answer, tt.wantNoAnswer) {
				t.Errorf("answer = %q, want no %q", answer, tt.wantNoAnswer)
			}
			if n := strings.Count(answer, "HTTP/1.1 200 OK"); n != tt.wantResponses {
				t.Errorf("answer has %d responses, want %d: %q", n, tt.wantResponses, answer)
			}
			seenLines := got.all()
			if len(seenLines) != len(tt.wantSeen) {
				t.Fatalf("backend saw %q, want %q", seenLines, tt.wantSeen)
			}
			for i := range seenLines {
				if seenLines[i] != tt.wantSeen[i] {
					t.Errorf("backend saw %q, want %q", seenLines[i], tt.wantSeen[i])
				}
			}
		})
	}
}

func TestRelayConnectionCap(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		idle int // connections that send nothing
		// expectations
		wantAnswer string // what the next client gets
	}{
		{name: "up to 64 connections are served", idle: 63, wantAnswer: "HTTP/1.1 400 Bad Request"},
		{name: "the 65th connection gets a 503", idle: 64, wantAnswer: "HTTP/1.1 503 Service Unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startRelay(t, hostProxy(t, "127.0.0.1:1"), func(r *agent.Relay) { r.HeadTimeout = 20 * time.Second })
			var held []net.Conn
			for range tt.idle {
				c, err := net.Dial("tcp", addr)
				if err != nil {
					t.Fatal(err)
				}
				held = append(held, c)
			}
			t.Cleanup(func() {
				for _, c := range held {
					_ = c.Close()
				}
			})
			// Wait until the relay holds them all, so that the next one is counted after them.
			time.Sleep(300 * time.Millisecond)

			payload := ""
			if tt.idle < 64 { // over the cap the relay answers without reading, so the client sends nothing
				payload = "nonsense\r\n\r\n"
			}
			answer := exchange(t, addr, payload, "")

			if !strings.Contains(answer, tt.wantAnswer) {
				t.Errorf("answer = %q, want it to contain %q", answer, tt.wantAnswer)
			}
		})
	}
}

func TestRelayShutdown(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "Serve closes an open connection and returns nil"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- agent.NewRelay(tcpDialer("127.0.0.1:1")).Serve(ctx, l) }()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			time.Sleep(100 * time.Millisecond) // the relay has taken the connection and waits for its head

			cancel()

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned %v, want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return")
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Errorf("the connection was not closed cleanly: %v", err)
			}
		})
	}
}
