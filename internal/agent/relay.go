package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of the relay. The request line and each header line must fit the read buffer.
const (
	maxRelayLine    = 8 << 10  // bytes of one line
	maxRelayHeaders = 100      // header lines
	maxRelayHead    = 32 << 10 // bytes of the head: the request line and the headers
	maxRelayConns   = 64       // at the same time, as many as the host proxy serves
)

// relayDrain is how long the relay waits for the client to stop sending after a response.
const relayDrain = time.Second

// Relay is the proxy the guest tools use. It listens on the loopback address of the guest and
// turns each request into a tunnel through the host proxy: it sends one Connect frame, reads the
// ConnectReply, and then only copies bytes. It accepts two request forms, because tools use both:
// CONNECT host:port, and an absolute-form request such as GET http://host/path, which it sends
// on in origin form and closes after the response. Everything else gets a 400. The guest has no
// DNS, so the relay passes host names on and never resolves them.
type Relay struct {
	// HeadTimeout is how long a client has to send its request head.
	HeadTimeout time.Duration
	// Handshake is how long the host proxy has to answer the Connect frame.
	Handshake time.Duration
	// Idle is how long a tunnel may be silent in both directions.
	Idle time.Duration

	dial Dialer
}

// NewRelay returns a relay that opens its tunnels with dial. The defaults are 10 s for the
// request head, 30 s for the host proxy and 60 s idle.
func NewRelay(dial Dialer) *Relay {
	return &Relay{HeadTimeout: 10 * time.Second, Handshake: 30 * time.Second, Idle: 60 * time.Second, dial: dial}
}

// Serve accepts clients on l until ctx ends. It closes l then, closes the open connections,
// waits for them and returns nil.
func (r *Relay) Serve(ctx context.Context, l net.Listener) error {
	sem := make(chan struct{}, maxRelayConns)
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			writeStatus(c, 503, "too many connections")
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.handle(ctx, c)
		}()
	}
}

// request is what the relay takes from a client: where to connect, and for an absolute-form
// request the head to send on.
type request struct {
	host    string
	port    int
	connect bool
	head    []byte // absolute form: the request in origin form, with its headers
}

func (r *Relay) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	_ = c.SetReadDeadline(time.Now().Add(r.HeadTimeout))
	br := bufio.NewReaderSize(c, maxRelayLine)
	req, err := readRequest(br)
	if err != nil {
		refuse(c, br, 400, "bad request")
		return
	}
	up, status, why := r.tunnel(ctx, req)
	if up == nil {
		refuse(c, br, status, why)
		return
	}
	defer func() { _ = up.Close() }()

	if req.connect {
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		r.tunnelBoth(c, br, up)
		return
	}
	r.forward(c, br, up, req.head)
}

// tunnel asks the host proxy for a tunnel. It returns the connection once the host has said yes. Else it
// returns the status for the client: 403 when the host refused, and 502 when it could not be asked or
// closed the connection without a reply, as it does over its tunnel cap.
func (r *Relay) tunnel(ctx context.Context, req request) (net.Conn, int, string) {
	up, err := r.dial(ctx)
	if err != nil {
		return nil, 502, "the host proxy is not reachable"
	}
	data, err := json.Marshal(protocol.Connect{Host: req.host, Port: req.port})
	if err != nil {
		_ = up.Close()
		return nil, 502, "bad gateway"
	}
	stop := context.AfterFunc(ctx, func() { _ = up.Close() }) // a shutdown ends the wait for the reply
	defer stop()
	_ = up.SetDeadline(time.Now().Add(r.Handshake))
	if err := protocol.WriteFrame(up, protocol.FrameConnect, data); err != nil {
		_ = up.Close()
		return nil, 502, "the host proxy closed the connection"
	}
	// The host may close its side right after a refusal, so the reply is read before anything else.
	_, payload, err := protocol.ReadFrameOf(up, protocol.FrameConnectReply)
	var reply protocol.ConnectReply
	if err == nil {
		if err = protocol.DecodeStrict(payload, &reply); err == nil {
			err = reply.Validate()
		}
	}
	if err != nil {
		_ = up.Close()
		return nil, 502, "the host proxy closed the connection"
	}
	if !reply.OK {
		_ = up.Close()
		return nil, 403, "denied: " + protocol.Snippet(reply.Reason)
	}
	_ = up.SetDeadline(time.Time{})
	return up, 0, ""
}

// forward sends an absolute-form request on and copies the response back. The request carries
// Connection: close, so the server ends after one response, and the client is closed then. One
// connection of the client therefore never reaches a second host.
func (r *Relay) forward(c net.Conn, body io.Reader, up net.Conn, head []byte) {
	_ = up.SetWriteDeadline(time.Now().Add(r.Idle))
	if _, err := up.Write(head); err != nil {
		return
	}
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		_ = pump(up, body, c, r.Idle)
	}()
	_ = pump(c, up, up, r.Idle)
	// The response is over. Let the client finish sending before the close, because a connection
	// closed with unread bytes may be reset, and the reset can destroy the response.
	closeWrite(c)
	_ = up.Close()
	timer := time.AfterFunc(relayDrain, func() { _ = c.Close() }) // ends the read of the body
	defer timer.Stop()
	<-sent
}

// tunnelBoth copies bytes both ways until both directions end or the tunnel is idle.
func (r *Relay) tunnelBoth(c net.Conn, fromClient io.Reader, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		if err := pump(up, fromClient, c, r.Idle); err != nil {
			_ = up.Close()
			_ = c.Close()
		}
		done <- struct{}{}
	}()
	go func() {
		if err := pump(c, up, up, r.Idle); err != nil {
			_ = up.Close()
			_ = c.Close()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// pump copies src to dst until src ends, and then closes the write side of dst. Each read has the
// idle deadline. A clean end returns nil.
func pump(dst net.Conn, src io.Reader, srcConn net.Conn, idle time.Duration) error {
	buf := make([]byte, 32<<10)
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(idle))
		n, rerr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idle))
			if _, err := dst.Write(buf[:n]); err != nil {
				return err
			}
		}
		if errors.Is(rerr, io.EOF) {
			closeWrite(dst)
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// Limit of the drain after a refusal: the bytes are thrown away and never looked at.
const relayDrainBytes = 64 << 10

// refuse answers a client that gets no tunnel and ends the conversation. The client may have sent bytes
// the relay did not read, and closing a connection with unread bytes may reset it, which can destroy the
// answer before the client reads it. So the relay closes its write side, then reads and throws away at
// most relayDrainBytes for at most relayDrain.
func refuse(c net.Conn, unread io.Reader, code int, text string) {
	writeStatus(c, code, text)
	closeWrite(c)
	_ = c.SetReadDeadline(time.Now().Add(relayDrain))
	_, _ = io.CopyN(io.Discard, unread, relayDrainBytes)
}

// writeStatus writes an answer for a client that gets no tunnel. The text is fixed or cleaned.
func writeStatus(c net.Conn, code int, text string) {
	body := text + "\n"
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, statusText(code), len(body), body)
}

func statusText(code int) string {
	switch code {
	case 400:
		return "Bad Request"
	case 403:
		return "Forbidden"
	case 502:
		return "Bad Gateway"
	}
	return "Service Unavailable"
}

var errBadRequest = errors.New("bad request")

// readRequest reads and checks the request head: the request line and the headers, within the limits.
// Whatever the client sent after the head stays in br.
func readRequest(br *bufio.Reader) (request, error) {
	line, err := readHeadLine(br)
	if err != nil {
		return request{}, err
	}
	method, target, ok := splitRequestLine(line)
	if !ok {
		return request{}, errBadRequest
	}
	var req request
	var path string
	if method == "CONNECT" {
		req, err = connectTarget(target)
	} else {
		req, path, err = absoluteTarget(target)
	}
	if err != nil {
		return request{}, err
	}

	used := len(line)
	count := 0
	var kept [][]byte
	for {
		h, err := readHeadLine(br)
		if err != nil {
			return request{}, err
		}
		if len(h) == 0 {
			break
		}
		used += len(h)
		if count++; count > maxRelayHeaders || used > maxRelayHead {
			return request{}, errBadRequest
		}
		name, ok := headerName(h)
		if !ok {
			return request{}, errBadRequest
		}
		if !hopByHop(name) {
			kept = append(kept, h)
		}
	}
	if req.connect {
		return req, nil
	}
	authority := req.host
	if req.port != 80 {
		authority += ":" + strconv.Itoa(req.port)
	}
	head := fmt.Appendf(nil, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, path, authority)
	for _, h := range kept {
		head = append(append(head, h...), '\r', '\n')
	}
	req.head = append(head, '\r', '\n')
	return req, nil
}

// readHeadLine reads one line without its line end. A line over maxRelayLine bytes, a NUL and a
// bare CR are errors.
func readHeadLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		return nil, errBadRequest // too long, or the client went away
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if bytes.ContainsAny(line, "\x00\r") {
		return nil, errBadRequest
	}
	return bytes.Clone(line), nil
}

// splitRequestLine splits "METHOD target HTTP/1.x".
func splitRequestLine(line []byte) (method, target string, ok bool) {
	parts := strings.Split(string(line), " ")
	if len(parts) != 3 || (parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0") {
		return "", "", false
	}
	method = parts[0]
	if method == "" || len(method) > 16 || strings.ContainsFunc(method, func(r rune) bool { return r < 'A' || r > 'Z' }) {
		return "", "", false
	}
	return method, parts[1], true
}

// connectTarget reads the host:port of a CONNECT request. The port is required.
func connectTarget(target string) (request, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return request{}, errBadRequest
	}
	req, err := checked(host, port)
	req.connect = true
	return req, err
}

// absoluteTarget reads an absolute-form target. Only http is accepted, and the default port is 80.
// It returns the target in origin form.
func absoluteTarget(target string) (req request, path string, err error) {
	u, err := url.Parse(target)
	if err != nil || !strings.EqualFold(u.Scheme, "http") || u.Opaque != "" || u.Host == "" {
		return request{}, "", errBadRequest
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	req, err = checked(u.Hostname(), port)
	return req, u.RequestURI(), err
}

// checked lowercases the host and applies the checks of a Connect frame.
func checked(host, port string) (request, error) {
	n, err := strconv.Atoi(port)
	if err != nil {
		return request{}, errBadRequest
	}
	c := protocol.Connect{Host: strings.ToLower(host), Port: n}
	if c.Validate() != nil {
		return request{}, errBadRequest
	}
	return request{host: c.Host, port: c.Port}, nil
}

// headerName returns the name of a header line, and false when the line is not "name: value" with
// a token as name, which includes a line that continues the one before.
func headerName(h []byte) (string, bool) {
	name, _, ok := bytes.Cut(h, []byte(":"))
	if !ok || len(name) == 0 {
		return "", false
	}
	for _, b := range name {
		if !isTokenChar(b) {
			return "", false
		}
	}
	return strings.ToLower(string(name)), true
}

func isTokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
}

// hopByHop reports the headers the relay drops from a forwarded request. It sets Host and
// Connection itself, and Upgrade could keep the connection open after the response.
func hopByHop(name string) bool {
	switch name {
	case "host", "connection", "proxy-connection", "proxy-authorization", "keep-alive", "upgrade":
		return true
	}
	return false
}

// vmRelayAddr is where the relay listens in the VM. With --unsafe-host the port is any free one, so that
// agents of concurrent jobs on one machine do not collide.
const vmRelayAddr = "127.0.0.1:3128"

// guestRelay is the relay running for one job.
type guestRelay struct {
	addr   string // host:port of the listener
	cancel context.CancelFunc
	done   chan struct{}
}

// startRelay listens on the loopback address and serves the relay in the background, then sets
// the proxy variables for the tools of the guest. It returns nil without a dialer: the host serves
// no proxy port then, and the tools get no proxy variable.
func startRelay(dial Dialer, unsafeHost bool, setenv func(key, value string)) (*guestRelay, error) {
	if dial == nil {
		return nil, nil
	}
	listen := vmRelayAddr
	if unsafeHost {
		listen = "127.0.0.1:0"
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &guestRelay{addr: l.Addr().String(), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(g.done)
		_ = NewRelay(dial).Serve(ctx, l) // ends when ctx does
	}()
	// curl reads only the lowercase http_proxy, and other tools read only the uppercase names.
	for _, k := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
		setenv(k, "http://"+g.addr)
	}
	return g, nil
}

// close stops the relay and waits for its connections. It is safe on a nil relay.
func (g *guestRelay) close() {
	if g == nil {
		return
	}
	g.cancel()
	<-g.done
}
