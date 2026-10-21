//go:build galahadtest

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// netProbeEnabled says whether this build runs net-probe jobs. A galahadtest build does.
const netProbeEnabled = true

const (
	probeTimeout = 20 * time.Second
	probeBody    = 4096 // bytes of a response that are kept
)

// probeResult is the outcome of one request of a net-probe job.
type probeResult struct {
	Form   string `json:"form"` // absolute or connect
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error"`
}

// runNetProbe asks the relay for rawURL in both request forms the relay accepts, and sends what came
// back to the host as the probe artifact. A failed request is a result, not a failed job: the tests
// look for refusals.
func runNetProbe(host *hostConn, relay *guestRelay, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || relay == nil {
		return fail(protocol.CodeInternal, "net-probe needs an http URL and the proxy")
	}
	results := []probeResult{probeAbsolute(relay.addr, rawURL), probeConnect(relay.addr, u)}
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}
	return host.send(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactProbeJSON, Data: data}.Marshal())
}

// probeAbsolute requests the URL the way Go's http.Transport does for plain http through a proxy.
func probeAbsolute(relayAddr, rawURL string) probeResult {
	res := probeResult{Form: "absolute"}
	client := &http.Client{
		Timeout:   probeTimeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: relayAddr})},
	}
	resp, err := client.Get(rawURL) // #nosec G107 -- test-only job; the URL comes from the test setup
	if err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBody))
	res.Status, res.Body = resp.StatusCode, protocol.Snippet(strings.TrimSpace(string(body)))
	return res
}

// probeConnect opens a tunnel with CONNECT and sends a plain http request through it.
func probeConnect(relayAddr string, u *url.URL) probeResult {
	res := probeResult{Form: "connect"}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	target := net.JoinHostPort(u.Hostname(), port)
	conn, err := net.DialTimeout("tcp", relayAddr, probeTimeout)
	if err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	br := bufio.NewReader(conn)

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBody))
		_ = resp.Body.Close()
		res.Status, res.Body = resp.StatusCode, protocol.Snippet(strings.TrimSpace(string(body)))
		return res
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", u.RequestURI(), u.Host); err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	resp, err = http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		res.Error = protocol.Snippet(err.Error())
		return res
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBody))
	res.Status, res.Body = resp.StatusCode, protocol.Snippet(strings.TrimSpace(string(body)))
	return res
}
