// Package decision is the host side of the decision provider: it sends one request to the
// Decisions API and checks the answer. The guest never links it, so the agent never holds a key.
package decision

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/protocol"
)

const (
	maxRetryAfter  = 5 * time.Second
	maxHeaderBytes = 16 << 10
	pathDecisions  = "/v1/decisions"
)

// waits are the pauses before the second and the third attempt.
var waits = [...]time.Duration{500 * time.Millisecond, time.Second}

// statusMessages are the texts of a status failure. They are Galahad's own: nothing of the
// response is ever used.
var statusMessages = map[int]string{
	http.StatusBadRequest:            "request refused",
	http.StatusUnauthorized:          "invalid credentials",
	http.StatusPaymentRequired:       "insufficient credit",
	http.StatusForbidden:             "permission denied",
	http.StatusNotFound:              "model unavailable",
	http.StatusRequestEntityTooLarge: "request too large",
	http.StatusTooManyRequests:       "rate limited",
	http.StatusBadGateway:            "bad upstream response",
	http.StatusServiceUnavailable:    "scoring unavailable",
	http.StatusGatewayTimeout:        "provider timeout",
}

// Reply is the outcome of Send. Exactly one of Answers and Error is set. Attempts is 1 to 3 and
// LatencyMS is clamped to what Decision.Validate allows, so a Reply fits a protocol.Decision.
type Reply struct {
	Answers   *protocol.DecisionAnswers
	Usage     *protocol.DecisionUsage
	Error     *protocol.DecisionError
	RequestID string
	LatencyMS int
	Attempts  int
}

// Send posts req to the provider and checks the answer. key is the value of the provider's key
// variable, empty for a provider without one. The whole call, retries included, ends at the
// provider's time limit, or sooner when ctx ends. It never returns text from the response.
func Send(ctx context.Context, p config.Provider, key, version string, req protocol.DecisionRequest) Reply {
	start := time.Now()
	var reply Reply
	finish := func() Reply {
		reply.LatencyMS = int(min(time.Since(start).Milliseconds(), protocol.MaxDecisionLatencyMS))
		reply.Attempts = max(reply.Attempts, 1) // a call refused before the first attempt still counts as one
		if reply.Error != nil && key != "" {
			reply.Error.Message = strings.ReplaceAll(reply.Error.Message, key, "[REDACTED:"+protocol.RedactKey+"]")
		}
		return reply
	}

	var body []byte
	err := protocol.CheckDecisionURL(p.URL)
	if err == nil {
		err = req.Validate()
	}
	if err == nil {
		body, err = req.Encode()
	}
	if err != nil {
		reply.Error = &protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "request or provider URL is not valid"}
		return finish()
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
	defer cancel()
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
	defer tr.CloseIdleConnections()
	c := &caller{
		client: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		endpoint:  strings.TrimRight(p.URL, "/") + pathDecisions,
		key:       key,
		userAgent: "galahad/" + version,
		body:      body,
	}

	for attempt := 1; ; attempt++ {
		reply.Attempts = attempt
		res := c.once(ctx)
		if res.gotResponse {
			reply.RequestID = res.requestID
		}
		if res.err == nil {
			reply.Answers, reply.Usage, reply.Error = res.answers, res.usage, nil
			return finish()
		}
		reply.Error = res.err
		if !res.retry || attempt == protocol.MaxDecisionAttempts {
			return finish()
		}
		wait := waits[attempt-1]
		if res.retryAfter != "" {
			var ok bool
			if wait, ok = parseRetryAfter(res.retryAfter); !ok {
				return finish()
			}
		}
		if dl, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(dl) {
			return finish()
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			reply.Error = ctxError(ctx)
			return finish()
		}
	}
}

type caller struct {
	client    *http.Client
	endpoint  string
	key       string
	userAgent string
	body      []byte
}

// attempt is the result of one request.
type attempt struct {
	answers     *protocol.DecisionAnswers
	usage       *protocol.DecisionUsage
	err         *protocol.DecisionError
	retry       bool   // the failure may be tried again
	retryAfter  string // the Retry-After header of a response that may be tried again
	gotResponse bool
	requestID   string
}

func (c *caller) once(ctx context.Context) attempt {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(c.body))
	if err != nil {
		return attempt{err: &protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "request or provider URL is not valid"}}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return attempt{err: ctxError(ctx)}
		}
		return attempt{err: &protocol.DecisionError{Code: protocol.DecisionErrNetwork, Message: "could not reach the provider"}, retry: true}
	}
	defer func() { _ = resp.Body.Close() }() // the body is not needed after the checks below
	res := attempt{gotResponse: true, requestID: requestID(resp.Header)}

	if resp.StatusCode != http.StatusOK {
		msg, ok := statusMessages[resp.StatusCode]
		if !ok {
			msg = "unexpected status"
		}
		res.err = &protocol.DecisionError{Code: protocol.DecisionErrStatus, HTTPStatus: resp.StatusCode, Message: msg}
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			res.retry = true
			res.retryAfter = resp.Header.Get("Retry-After")
		}
		return res
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		res.err = &protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "response is not JSON"}
		return res
	}
	tooLarge := &protocol.DecisionError{Code: protocol.DecisionErrTooLarge, Message: "response is too large"}
	if resp.ContentLength > protocol.MaxDecisionResponse {
		res.err = tooLarge
		return res
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, protocol.MaxDecisionResponse+1))
	switch {
	case err != nil && ctx.Err() != nil:
		res.err = ctxError(ctx)
	case err != nil:
		res.err = &protocol.DecisionError{Code: protocol.DecisionErrNetwork, Message: "could not read the response"}
	case len(data) > protocol.MaxDecisionResponse:
		res.err = tooLarge
	default:
		answers, usage, err := protocol.ParseDecisionResponse(data, protocol.DecisionQuestions())
		if err != nil {
			res.err = &protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "response failed the checks"}
			break
		}
		res.answers, res.usage = &answers, &usage
	}
	return res
}

// ctxError says why ctx ended: the time limit is a timeout, anything else (Ctrl-C) is not.
func ctxError(ctx context.Context) *protocol.DecisionError {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &protocol.DecisionError{Code: protocol.DecisionErrTimeout, Message: "provider did not answer in time"}
	}
	return &protocol.DecisionError{Code: protocol.DecisionErrNetwork, Message: "call canceled"}
}

// parseRetryAfter reads a Retry-After of a whole number of seconds up to 5. A date, a longer wait
// and anything else is not ok.
func parseRetryAfter(v string) (time.Duration, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || time.Duration(n)*time.Second > maxRetryAfter {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// requestID returns the X-Request-Id header when it is 1 to 128 bytes of printable ASCII.
func requestID(h http.Header) string {
	id := h.Get("X-Request-Id")
	if id == "" || len(id) > protocol.MaxDecisionRequestID {
		return ""
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7e {
			return ""
		}
	}
	return id
}
