// Package proxy is the host side of the guest's network access. The guest has no
// network device. It opens a tunnel per connection by sending one Connect frame
// with a host name and port. The proxy checks the policy, resolves the name on the
// host, refuses any address that is not public, dials the vetted address and then
// relays bytes without reading them.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Decisions in the log and in Event.
const (
	Allowed = protocol.DecisionAllowed
	Denied  = protocol.DecisionDenied
)

// Fixed timeouts: reading the Connect frame and writing the reply, resolving a name and dialing.
const (
	handshakeTimeout = 10 * time.Second
	resolveTimeout   = 5 * time.Second
	addrTimeout      = 5 * time.Second  // one dial
	dialTimeout      = 15 * time.Second // all dials of one request
)

// A guest can fill the log and the event list with requests that do not matter before it asks for
// a blocked address, so part of both is kept for the blocked decisions. Other decisions stop
// short of the whole size; a blocked decision may use the whole of it, which leaves at least the
// reserve for blocked decisions.
const (
	maxEvents     = 200 // the most events, as in protocol.MaxNetEvents
	blockedEvents = 50  // of them, the last ones, which only a blocked decision may fill
	// A tenth of the log lines is kept for blocked decisions.
	logReserveDiv = 10
)

// Test hooks. They stay nil in a build without the galahadtest tag.
// testhooks_fake.go sets them.
var (
	hookResolve  func(host string) ([]netip.Addr, bool)
	hookSinkhole func() (netip.AddrPort, bool)
	hookHTTPHost func(host string) bool
)

// Limits caps a job. Up and Down are shared by all tunnels of the job.
type Limits struct {
	Tunnels  int           // concurrent tunnels
	Idle     time.Duration // no byte in either direction
	Down     int64         // bytes from the network to the guest
	Up       int64         // bytes from the guest to the network
	LogLines int           // lines in the log
}

// Event is the aggregate of the decisions for one host, port and decision.
// Reason is the reason of the first one. Blocked is set when the host resolved
// to, or was, an address that is not public.
type Event struct {
	Host     string
	Port     int
	Decision string
	Reason   string
	Blocked  bool
	Count    int
}

// Proxy serves the tunnels of one job. Change Resolve, Dial and Limits before Serve.
type Proxy struct {
	// Resolve returns the addresses of a host name. The default asks the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// Dial connects to a vetted address. The default dials TCP.
	Dial   func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	Limits Limits

	policy Policy
	log    io.Writer
	up     budget
	down   budget

	mu      sync.Mutex
	lines   int
	dropped int
	events  []Event
}

// New returns a proxy that enforces p and writes one JSON line per decision to log.
// The defaults are 64 tunnels, 60 s idle, 2 GiB down, 64 MiB up and 10 000 log lines.
func New(p Policy, log io.Writer) *Proxy {
	if log == nil {
		log = io.Discard
	}
	return &Proxy{
		Resolve: defaultResolve,
		Dial:    defaultDial,
		Limits:  Limits{Tunnels: 64, Idle: 60 * time.Second, Down: 2 << 30, Up: 64 << 20, LogLines: 10000},
		policy:  p,
		log:     log,
	}
}

func defaultResolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if hookResolve != nil {
		if addrs, ok := hookResolve(host); ok {
			return addrs, nil
		}
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func defaultDial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr.String())
}

// Events returns the aggregated decisions so far, at most 200 entries. A decision for a new
// host, port and decision beyond that is not listed, except that the last 50 entries are kept
// for blocked decisions: once 150 are full, a blocked one is still listed.
func (p *Proxy) Events() []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Event(nil), p.events...)
}

// Dropped returns the number of log lines left out because of Limits.LogLines. A tenth of the
// lines is kept for blocked decisions, so those are written after the others are dropped.
func (p *Proxy) Dropped() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

// Serve accepts tunnel requests on l until ctx ends. It closes l then, closes the
// open tunnels, waits for them and returns nil. The caller owns the listener otherwise.
func (p *Proxy) Serve(ctx context.Context, l net.Listener) error {
	p.up.max, p.down.max = p.Limits.Up, p.Limits.Down
	sem := make(chan struct{}, p.Limits.Tunnels)
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
			_ = c.Close()
			p.logLine(decision{reason: "too many tunnels"}, Denied, 0, 0)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			p.handle(ctx, c)
		}()
	}
}

// decision is what the proxy knows about one request. host is empty until the
// Connect frame passed Validate, so a bad name never reaches the log.
type decision struct {
	host    string
	port    int
	ip      netip.Addr
	reason  string
	blocked bool
}

func (p *Proxy) handle(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))

	req, ok := readConnect(c)
	if !ok {
		p.refuse(c, decision{reason: "bad connect frame"})
		return
	}
	addrs, d := p.vet(ctx, req)
	if d.reason != "" {
		p.refuse(c, d)
		return
	}
	r, d := p.dial(ctx, d, addrs)
	if d.reason != "" {
		p.refuse(c, d)
		return
	}
	defer func() { _ = r.Close() }()
	p.addEvent(d, Allowed)
	if !p.reply(c, protocol.ConnectReply{OK: true}) {
		d.reason = "reply failed"
		p.logLine(d, Denied, 0, 0)
		return
	}
	_ = c.SetDeadline(time.Time{})
	up, down, why := p.relay(c, r)
	d.reason = why
	p.logLine(d, Allowed, up, down)
}

// readConnect reads the one frame a guest may send before the tunnel opens.
func readConnect(c net.Conn) (protocol.Connect, bool) {
	var req protocol.Connect
	// Only a Connect frame is allowed, so the header of anything else is refused before an allocation.
	_, payload, err := protocol.ReadFrameOf(c, protocol.FrameConnect)
	if err != nil {
		return req, false
	}
	if err := protocol.DecodeStrict(payload, &req); err != nil || req.Validate() != nil {
		return protocol.Connect{}, false
	}
	return req, true
}

// vet checks the request and returns the addresses that may be dialed. A decision
// with a reason is a refusal.
func (p *Proxy) vet(ctx context.Context, req protocol.Connect) ([]netip.AddrPort, decision) {
	d := decision{host: req.Host, port: req.Port}
	if !validHost(req.Host) {
		d.reason = "bad host name"
		return nil, d
	}
	ip, err := netip.ParseAddr(req.Host)
	literal := err == nil
	if literal {
		// The block list comes first, so 169.254.169.254 gets its own reason.
		if r := blockReason(ip); r != "" {
			d.ip, d.reason, d.blocked = ip, r, true
			return nil, d
		}
	}
	if ok, r := p.policy.Allows(req.Host, req.Port); !ok {
		d.reason = r
		return nil, d
	}
	addrs := []netip.Addr{ip}
	if !literal {
		rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		defer cancel()
		addrs, err = p.Resolve(rctx, req.Host)
		if err != nil || len(addrs) == 0 {
			d.reason = "dns lookup failed"
			return nil, d
		}
	}
	out := make([]netip.AddrPort, len(addrs))
	for i, a := range addrs {
		if r := blockReason(a); r != "" {
			d.ip, d.reason, d.blocked = a, r, true
			return nil, d
		}
		out[i] = addrPort(a, req.Port)
	}
	return out, d
}

// blockReason is BlockReason, except that the sinkhole of a test build passes.
func blockReason(ip netip.Addr) string {
	if hookSinkhole != nil {
		if s, ok := hookSinkhole(); ok && ip.Unmap() == s.Addr() {
			return ""
		}
	}
	return BlockReason(ip)
}

// addrPort pairs a vetted address with the port. In a test build the sinkhole
// address keeps its own port.
func addrPort(ip netip.Addr, port int) netip.AddrPort {
	ip = ip.Unmap()
	if hookSinkhole != nil {
		if s, ok := hookSinkhole(); ok && ip == s.Addr() {
			return s
		}
	}
	return netip.AddrPortFrom(ip, uint16(port)) // #nosec G115 -- Validate bounds it to 1-65535
}

// dial connects to the first vetted address that answers. Each address gets its
// own timeout, so one that never answers does not use up the budget of the rest.
func (p *Proxy) dial(ctx context.Context, d decision, addrs []netip.AddrPort) (net.Conn, decision) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	for _, a := range addrs {
		d.ip = a.Addr()
		actx, acancel := context.WithTimeout(ctx, addrTimeout)
		r, err := p.Dial(actx, a)
		acancel()
		if err == nil {
			return r, d
		}
	}
	d.reason = "dial failed"
	return nil, d
}

// reply sends the answer to the guest. It reports whether the write worked. The
// deadline starts again here, because resolving and dialing may have used up most of it.
func (p *Proxy) reply(c net.Conn, r protocol.ConnectReply) bool {
	b, err := json.Marshal(r)
	if err != nil {
		return false
	}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	return protocol.WriteFrame(c, protocol.FrameConnectReply, b) == nil
}

func (p *Proxy) refuse(c net.Conn, d decision) {
	// Log and count before the reply, so whoever sees the reply also sees both.
	p.logLine(d, Denied, 0, 0)
	p.addEvent(d, Denied)
	if p.reply(c, protocol.ConnectReply{Reason: d.reason}) {
		drain(c)
	}
}

// Limits of drain.
const (
	drainBytes = 64 << 10
	drainTime  = time.Second
)

// drain ends a conversation after a denial. The guest may have sent bytes the
// proxy did not read, and closing a socket with unread bytes makes some systems
// (Windows) reset the connection, which can destroy the reply before the guest
// reads it. So it closes the write side, then reads and throws away at most
// drainBytes or for at most drainTime. The caller closes the conn after that, and
// a shutdown closes it sooner, which ends the read. The bytes are never looked at.
func drain(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	_ = c.SetReadDeadline(time.Now().Add(drainTime))
	_, _ = io.CopyN(io.Discard, c, drainBytes)
}

// budget is a byte count shared by the tunnels of a job.
type budget struct {
	used atomic.Int64
	max  int64
}

// take counts n bytes and returns how many of them fit under the limit.
func (b *budget) take(n int64) int64 {
	over := b.used.Add(n) - b.max
	switch {
	case over <= 0:
		return n
	case over >= n:
		return 0
	}
	return n - over
}

var errLimit = errors.New("byte limit")

// tunnel is the state two copy loops share.
type tunnel struct {
	idle time.Duration
	last atomic.Int64 // unix nanoseconds of the last byte in either direction
}

func (p *Proxy) relay(guest, remote net.Conn) (up, down int64, reason string) {
	t := &tunnel{idle: p.Limits.Idle}
	t.last.Store(time.Now().UnixNano())
	var nUp, nDown atomic.Int64
	errc := make(chan error, 2)
	go func() { errc <- t.copy(remote, guest, &p.up, &nUp) }()
	go func() { errc <- t.copy(guest, remote, &p.down, &nDown) }()
	failed := false
	for range 2 {
		err := <-errc
		if err == nil || failed {
			continue
		}
		failed = true
		switch {
		case errors.Is(err, errLimit):
			reason = "byte limit"
		case errors.Is(err, os.ErrDeadlineExceeded):
			reason = "idle timeout"
		}
		// Closing both ends stops the other copy loop.
		_ = guest.Close()
		_ = remote.Close()
	}
	return nUp.Load(), nDown.Load(), reason
}

type closeWriter interface{ CloseWrite() error }

// copy moves bytes from src to dst until src ends, the byte budget runs out or
// the tunnel is idle. The bytes are never looked at. At a clean end it closes
// the write side of dst, so the other direction can finish.
func (t *tunnel) copy(dst, src net.Conn, b *budget, n *atomic.Int64) error {
	buf := make([]byte, 32<<10)
	for {
		_ = src.SetReadDeadline(time.Now().Add(t.idle))
		m, rerr := src.Read(buf)
		if m > 0 {
			t.last.Store(time.Now().UnixNano())
			ok := b.take(int64(m))
			if ok > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(t.idle))
				if _, err := dst.Write(buf[:ok]); err != nil {
					return err
				}
				n.Add(ok)
			}
			if ok < int64(m) {
				return errLimit
			}
		}
		switch {
		case rerr == nil:
		case errors.Is(rerr, io.EOF):
			if cw, ok := dst.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			return nil
		case errors.Is(rerr, os.ErrDeadlineExceeded) && time.Since(time.Unix(0, t.last.Load())) < t.idle:
			// The other direction moved bytes, so the tunnel is not idle.
		default:
			return rerr
		}
	}
}

func (p *Proxy) addEvent(d decision, verdict string) {
	if d.host == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.events {
		if e := &p.events[i]; e.Host == d.host && e.Port == d.port && e.Decision == verdict {
			e.Count++
			// A refusal for a non-public address must not be hidden by an earlier one.
			if d.blocked && !e.Blocked {
				e.Blocked, e.Reason = true, d.reason
			}
			return
		}
	}
	// Only a blocked decision may take one of the last blockedEvents places.
	limit := maxEvents - blockedEvents
	if d.blocked {
		limit = maxEvents
	}
	if len(p.events) >= limit {
		return
	}
	p.events = append(p.events, Event{Host: d.host, Port: d.port, Decision: verdict, Reason: d.reason, Blocked: d.blocked, Count: 1})
}

type logEntry struct {
	Time     string `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	IP       string `json:"ip"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Up       int64  `json:"up"`
	Down     int64  `json:"down"`
}

func (p *Proxy) logLine(d decision, verdict string, up, down int64) {
	e := logEntry{
		Time: time.Now().UTC().Format(time.RFC3339), Host: d.host, Port: d.port,
		Decision: verdict, Reason: d.reason, Up: up, Down: down,
	}
	if d.ip.IsValid() {
		e.IP = d.ip.String()
	}
	b, _ := json.Marshal(e)
	p.mu.Lock()
	defer p.mu.Unlock()
	limit := p.Limits.LogLines
	if !d.blocked {
		limit -= limit / logReserveDiv
	}
	if p.lines >= limit {
		p.dropped++
		return
	}
	p.lines++
	_, _ = p.log.Write(append(b, '\n'))
}
