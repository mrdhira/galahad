package proxy_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

// lockedBuf is a log sink the test can read while the proxy writes.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// lines waits until the log holds n lines, then returns them decoded.
func (l *lockedBuf) lines(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l.mu.Lock()
		s := strings.TrimSpace(l.b.String())
		l.mu.Unlock()
		var raw []string
		if s != "" {
			raw = strings.Split(s, "\n")
		}
		if len(raw) >= n || time.Now().After(deadline) {
			if len(raw) != n {
				t.Fatalf("log has %d lines, want %d:\n%s", len(raw), n, s)
			}
			out := make([]map[string]any, n)
			for i, r := range raw {
				if err := json.Unmarshal([]byte(r), &out[i]); err != nil {
					t.Fatalf("log line %q is not JSON: %v", r, err)
				}
			}
			return out
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// start serves p on a loopback listener and returns its address. The proxy stops when the test ends.
func start(t *testing.T, pol proxy.Policy, tweak func(*proxy.Proxy)) (string, *proxy.Proxy, *lockedBuf) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &lockedBuf{}
	p := proxy.New(pol, log)
	if tweak != nil {
		tweak(p)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v", err)
		}
	})
	return l.Addr().String(), p, log
}

func policy(t *testing.T, in proxy.Input) proxy.Policy {
	t.Helper()
	p, err := proxy.NewPolicy(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// readReply reads the ConnectReply, or returns an error when the proxy closed the connection.
func readReply(c net.Conn) (protocol.ConnectReply, error) {
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var r protocol.ConnectReply
	ft, payload, err := protocol.ReadFrame(c)
	if err != nil {
		return r, err
	}
	if ft != protocol.FrameConnectReply {
		return r, fmt.Errorf("got a %s frame", ft)
	}
	return r, protocol.DecodeStrict(payload, &r)
}

// open asks the proxy at addr for a tunnel to host:port.
func open(t *testing.T, addr, host string, port int) (net.Conn, protocol.ConnectReply, error) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// The proxy may close first (at the tunnel cap), so a write error is not a failure; the read reports it.
	_ = protocol.WriteFrame(c, protocol.FrameConnect, []byte(fmt.Sprintf(`{"host":%q,"port":%d}`, host, port)))
	r, err := readReply(c)
	return c, r, err
}

// dialTo returns a Dial that records the vetted address and connects to backend instead.
func dialTo(backend string, got *netip.AddrPort, err error) func(context.Context, netip.AddrPort) (net.Conn, error) {
	var mu sync.Mutex
	return func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
		mu.Lock()
		*got = a
		mu.Unlock()
		if err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend)
	}
}

func resolveTo(ips ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, ip := range ips {
			out = append(out, netip.MustParseAddr(ip))
		}
		return out, nil
	}
}

func newBackend(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from backend")
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestServe(t *testing.T) {
	scan := func(allow ...string) proxy.Input {
		return proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: allow}
	}
	tests := []struct {
		name string
		// inputs
		in      proxy.Input
		host    string
		port    int
		resolve func(context.Context, string) ([]netip.Addr, error)
		dialErr error
		// expectations
		wantOK      bool
		wantReason  string
		wantDial    string
		wantIP      string
		wantBlocked bool
	}{
		{
			name: "allowed host is resolved, dialed by address and relayed",
			in:   scan("files.example.com"), host: "files.example.com", port: 443,
			resolve: resolveTo("93.184.216.34"),
			wantOK:  true, wantDial: "93.184.216.34:443", wantIP: "93.184.216.34",
		},
		{
			name: "http target on port 80",
			in:   proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://dl.example.com/x"}, host: "dl.example.com", port: 80,
			resolve: resolveTo("2606:2800:220:1:248:1893:25c8:1946"),
			wantOK:  true, wantDial: "[2606:2800:220:1:248:1893:25c8:1946]:80", wantIP: "2606:2800:220:1:248:1893:25c8:1946",
		},
		{
			name: "IP literal that is the target",
			in:   proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "https://93.184.216.34/x"}, host: "93.184.216.34", port: 443,
			resolve: func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("must not resolve a literal")
			},
			wantOK: true, wantDial: "93.184.216.34:443", wantIP: "93.184.216.34",
		},
		{
			name: "host with an invalid shape",
			in:   scan("a.example.com"), host: "a..example.com", port: 443,
			wantReason: "bad host name",
		},
		{
			name: "short IP form is not a name",
			in:   scan(), host: "127.1", port: 443,
			wantReason: "bad host name",
		},
		{
			name: "IP literal in a blocked range is refused before the policy",
			in:   proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://10.0.0.5/x"}, host: "10.0.0.5", port: 80,
			wantReason: "private", wantIP: "10.0.0.5", wantBlocked: true,
		},
		{
			name: "metadata address has its own reason",
			in:   scan(), host: "169.254.169.254", port: 443,
			wantReason: "metadata", wantIP: "169.254.169.254", wantBlocked: true,
		},
		{
			name: "IP literal that is not the target",
			in:   proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "https://93.184.216.34/x"}, host: "93.184.216.35", port: 443,
			wantReason: "host not allowed",
		},
		{
			name: "host not listed",
			in:   scan(), host: "example.com", port: 443,
			wantReason: "host not allowed",
		},
		{
			name: "wrong port",
			in:   scan("files.example.com"), host: "files.example.com", port: 8443,
			wantReason: "port not allowed",
		},
		{
			name: "DNS failure",
			in:   scan("files.example.com"), host: "files.example.com", port: 443,
			resolve:    func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") },
			wantReason: "dns lookup failed",
		},
		{
			name: "DNS answer without addresses",
			in:   scan("files.example.com"), host: "files.example.com", port: 443,
			resolve:    resolveTo(),
			wantReason: "dns lookup failed",
		},
		{
			name: "name resolves to a private address",
			in:   scan("rebind.example.com"), host: "rebind.example.com", port: 443,
			resolve:    resolveTo("192.168.1.10"),
			wantReason: "private", wantIP: "192.168.1.10", wantBlocked: true,
		},
		{
			name: "name resolves to a public and a private address",
			in:   scan("mixed.example.com"), host: "mixed.example.com", port: 443,
			resolve:    resolveTo("93.184.216.34", "10.0.0.1"),
			wantReason: "private", wantIP: "10.0.0.1", wantBlocked: true,
		},
		{
			name: "name resolves to loopback",
			in:   scan("local.example.com"), host: "local.example.com", port: 443,
			resolve:    resolveTo("127.0.0.1"),
			wantReason: "loopback", wantIP: "127.0.0.1", wantBlocked: true,
		},
		{
			name: "name resolves to IPv4-mapped IPv6 loopback",
			in:   scan("mapped.example.com"), host: "mapped.example.com", port: 443,
			resolve:    resolveTo("::ffff:127.0.0.1"),
			wantReason: "loopback", wantIP: "::ffff:127.0.0.1", wantBlocked: true,
		},
		{
			name: "dial failure",
			in:   scan("files.example.com"), host: "files.example.com", port: 443,
			resolve: resolveTo("93.184.216.34"), dialErr: errors.New("connection refused"),
			wantReason: "dial failed", wantDial: "93.184.216.34:443", wantIP: "93.184.216.34",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := newBackend(t)
			var dialed netip.AddrPort
			addr, p, log := start(t, policy(t, tt.in), func(p *proxy.Proxy) {
				if tt.resolve != nil {
					p.Resolve = tt.resolve
				}
				p.Dial = dialTo(backend, &dialed, tt.dialErr)
			})
			c, reply, err := open(t, addr, tt.host, tt.port)
			if err != nil {
				t.Fatalf("reading the reply: %v", err)
			}
			if reply.OK != tt.wantOK || reply.Reason != tt.wantReason {
				t.Errorf("reply = %+v, want ok=%v reason=%q", reply, tt.wantOK, tt.wantReason)
			}
			if got := dialed.String(); tt.wantDial != "" && got != tt.wantDial {
				t.Errorf("dialed %s, want %s", got, tt.wantDial)
			} else if tt.wantDial == "" && dialed.IsValid() {
				t.Errorf("dialed %s, want no dial", got)
			}
			wantDecision := proxy.Denied
			if tt.wantOK {
				wantDecision = proxy.Allowed
				if _, err := io.WriteString(c, "GET / HTTP/1.0\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(c)
				if !strings.Contains(string(body), "hello from backend") {
					t.Errorf("relayed response = %q", body)
				}
			}
			_ = c.Close()
			line := log.lines(t, 1)[0]
			if line["host"] != tt.host || line["port"] != float64(tt.port) || line["decision"] != wantDecision {
				t.Errorf("log line = %v", line)
			}
			if tt.wantIP != "" && line["ip"] != tt.wantIP {
				t.Errorf("log ip = %v, want %s", line["ip"], tt.wantIP)
			}
			if !tt.wantOK && line["reason"] != tt.wantReason {
				t.Errorf("log reason = %v, want %q", line["reason"], tt.wantReason)
			}
			events := p.Events()
			if len(events) != 1 {
				t.Fatalf("events = %+v, want 1", events)
			}
			want := proxy.Event{Host: tt.host, Port: tt.port, Decision: wantDecision, Reason: tt.wantReason, Blocked: tt.wantBlocked, Count: 1}
			if events[0] != want {
				t.Errorf("event = %+v, want %+v", events[0], want)
			}
		})
	}
}

func frame(ft protocol.FrameType, payload string) []byte {
	var b bytes.Buffer
	_ = protocol.WriteFrame(&b, ft, []byte(payload))
	return b.Bytes()
}

func TestServeBadConnect(t *testing.T) {
	oversize := make([]byte, 5)
	oversize[0] = byte(protocol.FrameConnect)
	binary.BigEndian.PutUint32(oversize[1:], 1<<20)
	// A Result header that claims 64 MiB, a valid length for that type. A guest could
	// send it on many connections to make the host allocate, so it is refused on the header.
	hugeResult := []byte{byte(protocol.FrameResult), 0x04, 0, 0, 0}
	tests := []struct {
		name string
		// inputs
		raw []byte
		// expectations: the proxy refuses and logs a line without a host
		wantReason string
		// The proxy refuses on the header and never reads the rest, so on some systems the
		// guest sees a reset instead of the reply.
		wantMaySeeReset bool
	}{
		{name: "unknown field", raw: frame(protocol.FrameConnect, `{"host":"api.osv.dev","port":443,"extra":1}`), wantReason: "bad connect frame"},
		{name: "frame over the Connect limit", raw: oversize, wantReason: "bad connect frame"},
		{name: "wrong frame type", raw: frame(protocol.FrameHello, `{}`), wantReason: "bad connect frame"},
		{name: "wrong frame type with a 64 MiB length", raw: hugeResult, wantReason: "bad connect frame", wantMaySeeReset: true},
		{name: "not JSON", raw: frame(protocol.FrameConnect, `host=api.osv.dev`), wantReason: "bad connect frame"},
		{name: "trailing data", raw: frame(protocol.FrameConnect, `{"host":"api.osv.dev","port":443} {}`), wantReason: "bad connect frame"},
		{name: "upper case host", raw: frame(protocol.FrameConnect, `{"host":"API.osv.dev","port":443}`), wantReason: "bad connect frame"},
		{name: "port out of range", raw: frame(protocol.FrameConnect, `{"host":"api.osv.dev","port":0}`), wantReason: "bad connect frame"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, p, log := start(t, policy(t, proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}), func(p *proxy.Proxy) {
				p.Resolve = resolveTo("93.184.216.34")
				p.Dial = func(context.Context, netip.AddrPort) (net.Conn, error) {
					return nil, errors.New("must not dial")
				}
			})
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write(tt.raw); err != nil {
				t.Fatal(err)
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			began := time.Now()
			reply, err := readReply(c)
			if err != nil && !tt.wantMaySeeReset {
				t.Fatalf("reading the reply: %v", err)
			}
			// The proxy must not wait for a payload that never comes (its deadline is 10 s).
			if d := time.Since(began); d > 2*time.Second {
				t.Errorf("refusal took %v, want a prompt one", d)
			}
			// Nothing near the 64 MiB the header claims may be allocated.
			runtime.ReadMemStats(&after)
			if grown := after.TotalAlloc - before.TotalAlloc; grown > 8<<20 {
				t.Errorf("host allocated %d bytes for a refused frame", grown)
			}
			if err == nil && (reply.OK || reply.Reason != tt.wantReason) {
				t.Errorf("reply = %+v, want refusal %q", reply, tt.wantReason)
			}
			line := log.lines(t, 1)[0]
			if line["host"] != "" || line["decision"] != proxy.Denied || line["reason"] != tt.wantReason {
				t.Errorf("log line = %v", line)
			}
			if events := p.Events(); len(events) != 0 {
				t.Errorf("events = %+v, want none for an unreadable request", events)
			}
		})
	}
}

func TestServeDrainIsBounded(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		chunk int // bytes per guest write after the bad frame
		// expectations
		wantMaxTime time.Duration
	}{
		{name: "guest that keeps sending is cut off", chunk: 64 << 10, wantMaxTime: 4 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, _, _ := start(t, relayPolicy(t), nil)
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write(frame(protocol.FrameHello, `{}`)); err != nil {
				t.Fatal(err)
			}
			if _, err := readReply(c); err != nil {
				t.Fatalf("reading the reply: %v", err)
			}
			// The proxy reads at most 64 KiB, then closes. One large write may still
			// complete into socket buffers (Windows does that), so write small chunks
			// until one fails. After the close, a reset fails the writes on every system.
			junk := make([]byte, tt.chunk)
			deadline := time.Now().Add(tt.wantMaxTime)
			_ = c.SetWriteDeadline(deadline)
			var werr error
			for werr == nil {
				_, werr = c.Write(junk)
			}
			if errors.Is(werr, os.ErrDeadlineExceeded) || time.Now().After(deadline) {
				t.Errorf("guest could still write after %v: the proxy did not close (last error %v)", tt.wantMaxTime, werr)
			}
		})
	}
}

// echoBackend accepts connections, writes greeting to each, and reports what each one sent.
func echoBackend(t *testing.T, greeting string) (string, <-chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	got := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.WriteString(c, greeting)
				b, _ := io.ReadAll(c)
				got <- string(b)
			}()
		}
	}()
	return l.Addr().String(), got
}

// tunnel opens a tunnel to an allowed host, sends payload, signals the end of it and reads until the proxy closes.
func tunnel(t *testing.T, addr, payload string) string {
	t.Helper()
	c, reply, err := open(t, addr, "files.example.com", 443)
	if err != nil || !reply.OK {
		t.Fatalf("open: reply %+v, err %v", reply, err)
	}
	if _, err := io.WriteString(c, payload); err != nil {
		t.Fatal(err)
	}
	_ = c.(*net.TCPConn).CloseWrite()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

func relayPolicy(t *testing.T) proxy.Policy {
	return policy(t, proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"files.example.com"}})
}

func TestServeByteLimits(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		up, down int64
		greeting string
		payloads []string // one tunnel each, in order
		// expectations
		wantBackend []string // what the backend received on each tunnel
		wantClient  []string // what the guest received on each tunnel
		wantReason  string   // in the log line of the last tunnel
		wantUp      float64
		wantDown    float64
	}{
		{
			name: "under the limits, everything goes through",
			up:   100, down: 100, greeting: "0123456789", payloads: []string{"ping"},
			wantBackend: []string{"ping"}, wantClient: []string{"0123456789"}, wantReason: "", wantUp: 4, wantDown: 10,
		},
		{
			name: "upload is cut at the limit",
			up:   10, down: 100, payloads: []string{"abcdefghijklmnop"},
			wantBackend: []string{"abcdefghij"}, wantClient: []string{""}, wantReason: "byte limit", wantUp: 10, wantDown: 0,
		},
		{
			name: "download is cut at the limit",
			up:   100, down: 10, greeting: "0123456789abcdef", payloads: []string{""},
			wantBackend: []string{""}, wantClient: []string{"0123456789"}, wantReason: "byte limit", wantUp: 0, wantDown: 10,
		},
		{
			name: "the limit is shared by tunnels",
			up:   10, down: 100, payloads: []string{"123456", "abcdef"},
			wantBackend: []string{"123456", "abcd"}, wantClient: []string{"", ""}, wantReason: "byte limit", wantUp: 4, wantDown: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, got := echoBackend(t, tt.greeting)
			var dialed netip.AddrPort
			addr, _, log := start(t, relayPolicy(t), func(p *proxy.Proxy) {
				p.Resolve = resolveTo("93.184.216.34")
				p.Dial = dialTo(backend, &dialed, nil)
				p.Limits.Up, p.Limits.Down = tt.up, tt.down
			})
			for i, payload := range tt.payloads {
				if gotClient := tunnel(t, addr, payload); gotClient != tt.wantClient[i] {
					t.Errorf("tunnel %d: guest received %q, want %q", i, gotClient, tt.wantClient[i])
				}
				select {
				case b := <-got:
					if b != tt.wantBackend[i] {
						t.Errorf("tunnel %d: backend received %q, want %q", i, b, tt.wantBackend[i])
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("tunnel %d: backend saw no connection end", i)
				}
				// A tunnel logs after the guest has seen it close; wait, so the lines keep their order.
				log.lines(t, i+1)
			}
			line := log.lines(t, len(tt.payloads))[len(tt.payloads)-1]
			if line["reason"] != tt.wantReason || line["up"] != tt.wantUp || line["down"] != tt.wantDown {
				t.Errorf("log line = %v, want reason %q up %v down %v", line, tt.wantReason, tt.wantUp, tt.wantDown)
			}
		})
	}
}

func TestServeIdle(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		ticks int // bytes the backend sends, 40 ms apart, before it goes quiet
		// expectations
		wantGot     int
		wantMinTime time.Duration
	}{
		{name: "silent tunnel is closed", ticks: 0, wantGot: 0, wantMinTime: 100 * time.Millisecond},
		{name: "bytes in one direction keep the tunnel open", ticks: 5, wantGot: 5, wantMinTime: 300 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })
			go func() {
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				for range tt.ticks {
					time.Sleep(40 * time.Millisecond)
					_, _ = c.Write([]byte("x"))
				}
				_, _ = io.Copy(io.Discard, c)
			}()
			var dialed netip.AddrPort
			addr, _, log := start(t, relayPolicy(t), func(p *proxy.Proxy) {
				p.Resolve = resolveTo("93.184.216.34")
				p.Dial = dialTo(l.Addr().String(), &dialed, nil)
				p.Limits.Idle = 100 * time.Millisecond
			})
			began := time.Now()
			c, reply, err := open(t, addr, "files.example.com", 443)
			if err != nil || !reply.OK {
				t.Fatalf("open: reply %+v, err %v", reply, err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, _ := io.ReadAll(c)
			if len(b) != tt.wantGot {
				t.Errorf("guest received %d bytes, want %d", len(b), tt.wantGot)
			}
			if d := time.Since(began); d < tt.wantMinTime {
				t.Errorf("tunnel closed after %v, want at least %v", d, tt.wantMinTime)
			}
			if line := log.lines(t, 1)[0]; line["reason"] != "idle timeout" {
				t.Errorf("log line = %v, want reason idle timeout", line)
			}
		})
	}
}

func TestServeTunnelCap(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		tunnels int
		// expectations
		wantSecondOK bool
	}{
		{name: "second tunnel refused at the cap", tunnels: 1, wantSecondOK: false},
		{name: "second tunnel accepted under the cap", tunnels: 2, wantSecondOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, _ := echoBackend(t, "")
			var dialed netip.AddrPort
			addr, _, log := start(t, relayPolicy(t), func(p *proxy.Proxy) {
				p.Resolve = resolveTo("93.184.216.34")
				p.Dial = dialTo(backend, &dialed, nil)
				p.Limits.Tunnels = tt.tunnels
			})
			_, reply, err := open(t, addr, "files.example.com", 443)
			if err != nil || !reply.OK {
				t.Fatalf("first tunnel: reply %+v, err %v", reply, err)
			}
			_, reply, err = open(t, addr, "files.example.com", 443)
			if gotOK := err == nil && reply.OK; gotOK != tt.wantSecondOK {
				t.Errorf("second tunnel ok = %v (reply %+v, err %v), want %v", gotOK, reply, err, tt.wantSecondOK)
			}
			if !tt.wantSecondOK {
				if line := log.lines(t, 1)[0]; line["decision"] != proxy.Denied || line["reason"] != "too many tunnels" {
					t.Errorf("log line = %v", line)
				}
			}
		})
	}
}

// deadWriteConn reads like the guest connection but fails every write, as a guest that went away would.
type deadWriteConn struct{ net.Conn }

func (deadWriteConn) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type deadWriteListener struct{ net.Listener }

func (l deadWriteListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return deadWriteConn{c}, err
}

func TestServeReplyFailed(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantReason string
	}{
		{name: "a failed reply write is logged as a denial", wantReason: "reply failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, _ := echoBackend(t, "")
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			log := &lockedBuf{}
			p := proxy.New(relayPolicy(t), log)
			p.Resolve = resolveTo("93.184.216.34")
			var dialed netip.AddrPort
			p.Dial = dialTo(backend, &dialed, nil)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- p.Serve(ctx, deadWriteListener{l}) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Errorf("Serve returned %v", err)
				}
			}()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if err := protocol.WriteFrame(c, protocol.FrameConnect, []byte(`{"host":"files.example.com","port":443}`)); err != nil {
				t.Fatal(err)
			}
			line := log.lines(t, 1)[0]
			if line["decision"] != proxy.Denied || line["reason"] != tt.wantReason {
				t.Errorf("log line = %v, want a denial with reason %q", line, tt.wantReason)
			}
		})
	}
}

func TestServeShutdown(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantClosed bool
	}{
		{name: "cancel closes open tunnels and Serve returns", wantClosed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, _ := echoBackend(t, "")
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p := proxy.New(relayPolicy(t), nil)
			p.Resolve = resolveTo("93.184.216.34")
			var dialed netip.AddrPort
			p.Dial = dialTo(backend, &dialed, nil)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- p.Serve(ctx, l) }()
			c, reply, err := open(t, l.Addr().String(), "files.example.com", 443)
			if err != nil || !reply.OK {
				t.Fatalf("open: reply %+v, err %v", reply, err)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return")
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = c.Read(make([]byte, 1))
			if closed := err != nil && !errors.Is(err, os.ErrDeadlineExceeded); closed != tt.wantClosed {
				t.Errorf("tunnel closed = %v (err %v), want %v", closed, err, tt.wantClosed)
			}
		})
	}
}

func TestServeShutdownDuringDrain(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantMaxTime time.Duration
	}{
		{name: "a handler that drains stops at once on cancel", wantMaxTime: 500 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p := proxy.New(relayPolicy(t), nil)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- p.Serve(ctx, l) }()
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err := c.Write(frame(protocol.FrameHello, `{}`)); err != nil {
				t.Fatal(err)
			}
			// The guest stays silent after the refusal, so the proxy is draining now.
			if _, err := readReply(c); err != nil {
				t.Fatalf("reading the reply: %v", err)
			}
			began := time.Now()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Serve returned %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return")
			}
			if d := time.Since(began); d > tt.wantMaxTime {
				t.Errorf("Serve took %v to return, want at most %v", d, tt.wantMaxTime)
			}
		})
	}
}

func TestLog(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		maxLines int
		requests int
		metadata int // requests for the metadata address, after the others
		// expectations
		wantLines    int
		wantDropped  int
		wantMetadata int // log lines with the reason "metadata"
	}{
		{name: "one line per decision", maxLines: 10, requests: 3, wantLines: 3, wantDropped: 0},
		{name: "lines over the limit are dropped and counted", maxLines: 3, requests: 5, wantLines: 3, wantDropped: 2},
		{
			name: "a tenth of the lines is kept for blocked decisions", maxLines: 10, requests: 15, metadata: 3,
			wantLines: 10, wantDropped: 8, wantMetadata: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, p, log := start(t, policy(t, proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}), func(p *proxy.Proxy) {
				p.Limits.LogLines = tt.maxLines
			})
			for range tt.requests {
				// Close after the reply, as a guest does, so the proxy does not drain the connection.
				c, _, err := open(t, addr, "example.com", 443)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
			}
			for range tt.metadata {
				c, _, err := open(t, addr, "169.254.169.254", 443)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
			}
			lines := log.lines(t, tt.wantLines)
			metadata := 0
			for _, l := range lines {
				for _, k := range []string{"time", "host", "port", "ip", "decision", "reason", "up", "down"} {
					if _, ok := l[k]; !ok {
						t.Errorf("log line %v lacks %q", l, k)
					}
				}
				if l["reason"] == "metadata" {
					metadata++
				}
			}
			if metadata != tt.wantMetadata {
				t.Errorf("log has %d metadata lines, want %d", metadata, tt.wantMetadata)
			}
			if got := p.Dropped(); got != tt.wantDropped {
				t.Errorf("Dropped() = %d, want %d", got, tt.wantDropped)
			}
		})
	}
}

func TestEvents(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		hosts   []string
		allow   []string // --allow-host values
		answers []string // DNS answer per request: an IP, or "" for a failure
		// expectations
		wantEvents  int
		wantBlocked int // events with Blocked set
		wantFirst   proxy.Event
	}{
		{
			name:  "same host, port and decision are counted together",
			hosts: []string{"a.example.com", "a.example.com", "b.example.com"}, wantEvents: 2,
			wantFirst: proxy.Event{Host: "a.example.com", Port: 443, Decision: proxy.Denied, Reason: "host not allowed", Count: 2},
		},
		{
			name:  "at most 150 events that are not blocked",
			hosts: manyHosts(205), wantEvents: 150,
			wantFirst: proxy.Event{Host: "h0.example.com", Port: 443, Decision: proxy.Denied, Reason: "host not allowed", Count: 1},
		},
		{
			name:  "a blocked address is listed after the other events are full",
			hosts: append(manyHosts(205), "169.254.169.254"), wantEvents: 151, wantBlocked: 1,
			wantFirst: proxy.Event{Host: "h0.example.com", Port: 443, Decision: proxy.Denied, Reason: "host not allowed", Count: 1},
		},
		{
			name:  "blocked events use every place, at most 200",
			hosts: blockedHosts(205), wantEvents: 200, wantBlocked: 200,
			wantFirst: proxy.Event{Host: "10.0.0.0", Port: 443, Decision: proxy.Denied, Reason: "private", Blocked: true, Count: 1},
		},
		{
			name:  "a later blocked address is not hidden by an earlier DNS failure",
			hosts: []string{"rebind.example.com", "rebind.example.com"}, allow: []string{"rebind.example.com"},
			answers: []string{"", "10.0.0.1"}, wantEvents: 1, wantBlocked: 1,
			wantFirst: proxy.Event{Host: "rebind.example.com", Port: 443, Decision: proxy.Denied, Reason: "private", Blocked: true, Count: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			addr, p, log := start(t, policy(t, proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: tt.allow}), func(p *proxy.Proxy) {
				p.Limits.LogLines = 1 << 20
				p.Resolve = func(context.Context, string) ([]netip.Addr, error) {
					mu.Lock()
					defer mu.Unlock()
					ans := tt.answers[calls]
					calls++
					if ans == "" {
						return nil, errors.New("no such host")
					}
					return []netip.Addr{netip.MustParseAddr(ans)}, nil
				}
			})
			for _, h := range tt.hosts {
				c, _, err := open(t, addr, h, 443)
				if err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
			}
			log.lines(t, len(tt.hosts))
			events := p.Events()
			if len(events) != tt.wantEvents {
				t.Fatalf("got %d events, want %d", len(events), tt.wantEvents)
			}
			if events[0] != tt.wantFirst {
				t.Errorf("first event = %+v, want %+v", events[0], tt.wantFirst)
			}
			blocked := 0
			for _, e := range events {
				if e.Blocked {
					blocked++
				}
			}
			if blocked != tt.wantBlocked {
				t.Errorf("%d blocked events, want %d", blocked, tt.wantBlocked)
			}
		})
	}
}

func manyHosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("h%d.example.com", i)
	}
	return out
}

func blockedHosts(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.0.%d", i)
	}
	return out
}
