package job

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

// proxyPort is the port the guest dials for its tunnels.
const proxyPort = 1025

// ruleNetBlocked is the host finding for a request to a non-public address.
var ruleNetBlocked = protocol.Rule{
	ID:       "GAL-NET-001",
	Severity: protocol.SeverityHigh,
	Title:    "The input led to a request to a private, loopback, link-local or metadata address",
}

// netProxy is the proxy of one job and its log file.
type netProxy struct {
	p      *proxy.Proxy
	cancel context.CancelFunc
	done   chan error
	log    *os.File

	once   sync.Once
	events []proxy.Event
	err    error
}

// startProxy serves the policy of the job on l and writes proxy.log into jobDir.
func startProxy(ctx context.Context, l net.Listener, jobDir string, pol proxy.Policy) (*netProxy, error) {
	log, err := os.OpenFile(filepath.Join(jobDir, "proxy.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the job directory is made by this program
	if err != nil {
		return nil, fmt.Errorf("open proxy.log: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	n := &netProxy{p: proxy.New(pol, log), cancel: cancel, done: make(chan error, 1), log: log}
	go func() { n.done <- n.p.Serve(ctx, l) }()
	return n, nil
}

// stop ends the proxy, closes its tunnels, waits for them and returns the decisions it made.
// It may be called again and returns the same. On a nil proxy it returns nothing.
func (n *netProxy) stop() ([]proxy.Event, error) {
	if n == nil {
		return nil, nil
	}
	n.once.Do(func() {
		n.cancel()
		n.err = <-n.done
		if err := n.log.Close(); err != nil && n.err == nil {
			n.err = err
		}
		n.events = n.p.Events()
	})
	return n.events, n.err
}

// networkOf turns the decisions of the proxy into the Network section of the Result.
func networkOf(events []proxy.Event) *protocol.Network {
	n := &protocol.Network{Events: make([]protocol.NetEvent, len(events))}
	for i, e := range events {
		n.Events[i] = protocol.NetEvent{Host: e.Host, Port: e.Port, Decision: e.Decision, Reason: e.Reason, Blocked: e.Blocked, Count: e.Count}
	}
	return n
}

// countsAsBlocked reports whether a blocked request to host counts against the input. A block for the
// infrastructure host that the guest contacts by itself on every scan (api.osv.dev) does not: the
// input did not make the request, and the host blocks it only when the DNS of the computer that
// runs Galahad answers with a non-public address, as fake-IP proxies, Pi-hole and split-horizon DNS
// do. It is decided here from the record of the host proxy, by the exact host name. The guest only
// loses the OSV lookup.
func countsAsBlocked(host string, blocked bool) bool {
	return blocked && !proxy.IsInfraHost(host)
}

// addInfraReason adds a line to the reasons of res when the host proxy blocked a request to an
// infrastructure host, so that a report that lacks OSV says why. The verdict does not change.
func addInfraReason(res *protocol.Result) {
	if len(res.Reasons) >= protocol.MaxReasonCount {
		return
	}
	for _, e := range res.Network.Events {
		if e.Blocked && !countsAsBlocked(e.Host, e.Blocked) {
			res.Reasons = append(res.Reasons, protocol.CleanPath(fmt.Sprintf(
				"the OSV lookup was blocked: %s resolved to an address that is not public (%s), which is usually a setting of the DNS of this computer; OSV was left out and no network finding was added", e.Host, e.Reason)))
			return
		}
	}
}

// addNetworkFinding adds GAL-NET-001 to res when a request was blocked. It has one finding with an
// evidence entry for each blocked destination, up to the evidence limit.
func addNetworkFinding(res *protocol.Result) {
	var ev []protocol.Evidence
	for _, e := range res.Network.Events {
		if !countsAsBlocked(e.Host, e.Blocked) || len(ev) == protocol.MaxEvidence {
			continue
		}
		snippet := protocol.Snippet(fmt.Sprintf("CONNECT %s:%d denied: %s", e.Host, e.Port, e.Reason))
		ev = append(ev, protocol.Evidence{Path: "(network)", Snippet: snippet})
	}
	if len(ev) == 0 {
		return
	}
	f := ruleNetBlocked.Finding(ev...)
	f.Analyzer = "network"
	if len(res.Findings) >= protocol.MaxFindings {
		// The finding decides the verdict, so it takes the place of the last one, and the
		// coverage says that the list was cut.
		res.Findings = res.Findings[:protocol.MaxFindings-1]
		res.Coverage.Truncated = true
	}
	res.Findings = append(res.Findings, f)
}
