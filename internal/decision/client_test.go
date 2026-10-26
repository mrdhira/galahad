//go:build galahadtest

package decision_test

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

const (
	fakeKey = "fake-key-for-tests-123"
	version = "v1.2.3"
)

const goodBody = `{
  "object": "decisions",
  "model": "test/model-1",
  "prompt_format_version": 1,
  "answers": {
    "verdict": {"type": "choice", "probabilities": {"clean": 0.05, "suspicious": 0.15, "malicious": 0.80}, "label_mass": 0.6, "choice": "malicious"},
    "risk": {"type": "score", "probabilities": {"0": 0.05, "1": 0.1, "2": 0.35, "3": 0.5}, "label_mass": 0.4, "score": 2.3},
    "steals_secrets": {"type": "yes_no", "probabilities": {"yes": 0.9, "no": 0.1}, "label_mass": 0.5}
  },
  "usage": {"prompt_tokens": 3600, "completion_tokens": 0, "total_tokens": 3600}
}`

// extraBody has a new field at the top and inside an answer, which the client must ignore.
var extraBody = strings.Replace(strings.Replace(goodBody, `"object": "decisions",`, `"object": "decisions", "id": "dec_1",`, 1),
	`"label_mass": 0.5}`, `"label_mass": 0.5, "rationale": "new field"}`, 1)

// step is one scripted answer of the mock.
type step struct {
	status   int
	header   map[string]string
	body     string
	location bool // redirect to the second server
	echo     bool // put the Authorization header in the status text and the body
	hang     bool // never answer
}

var okStep = step{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: goodBody}

func busy(code int) step { return step{status: code, body: "busy"} }

func TestSend(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		steps          []step
		keyless        bool
		timeoutSeconds int // 0 means 10
		closedPort     bool
		// expectations
		wantCode        string // empty means ok
		wantHTTP        int
		wantMessage     string
		wantAttempts    int
		wantRequestID   string
		wantRequests    int
		wantOtherServer int
		wantMinTime     time.Duration
		wantMaxTime     time.Duration // 0 means 5s
		wantModel       string
	}{
		{
			name:  "a good answer is ok after one attempt",
			steps: []step{okStep}, wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1",
		},
		{
			name:  "a provider with no key variable sends no Authorization header",
			steps: []step{okStep}, keyless: true, wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1",
		},
		{
			name:         "a charset parameter on the content type is allowed",
			steps:        []step{{status: 200, header: map[string]string{"Content-Type": "application/json; charset=utf-8"}, body: goodBody}},
			wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1",
		},
		{
			name:         "new fields in the answer are ignored",
			steps:        []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: extraBody}},
			wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1",
		},
		{
			name:  "two 503 answers and then a 200 is ok after three attempts",
			steps: []step{busy(503), busy(503), okStep}, wantAttempts: 3, wantRequests: 3, wantModel: "test/model-1", wantMinTime: 1400 * time.Millisecond,
		},
		{
			name:  "a 504 and then a 200 is ok",
			steps: []step{busy(504), okStep}, wantAttempts: 2, wantRequests: 2, wantModel: "test/model-1", wantMinTime: 450 * time.Millisecond,
		},
		{
			name:  "a 429 with Retry-After 1 waits about a second",
			steps: []step{{status: 429, header: map[string]string{"Retry-After": "1"}}, okStep}, wantAttempts: 2, wantRequests: 2, wantModel: "test/model-1",
			wantMinTime: 900 * time.Millisecond, wantMaxTime: 1900 * time.Millisecond,
		},
		{
			name:  "four 503 answers fail after three attempts",
			steps: []step{busy(503), busy(503), busy(503), busy(503)}, wantCode: "status", wantHTTP: 503, wantMessage: "scoring unavailable",
			wantAttempts: 3, wantRequests: 3, wantMinTime: 1400 * time.Millisecond,
		},
		{
			name:  "a 500 is tried again and the end is unexpected status",
			steps: []step{busy(500), busy(500), busy(500)}, wantCode: "status", wantHTTP: 500, wantMessage: "unexpected status",
			wantAttempts: 3, wantRequests: 3, wantMinTime: 1400 * time.Millisecond,
		},
		{
			name:  "a Retry-After of 60 ends the call at once",
			steps: []step{{status: 429, header: map[string]string{"Retry-After": "60"}}, okStep}, wantCode: "status", wantHTTP: 429, wantMessage: "rate limited",
			wantAttempts: 1, wantRequests: 1, wantMaxTime: 400 * time.Millisecond,
		},
		{
			name:  "a Retry-After date counts as too long",
			steps: []step{{status: 503, header: map[string]string{"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}}, okStep}, wantCode: "status", wantHTTP: 503,
			wantMessage: "scoring unavailable", wantAttempts: 1, wantRequests: 1, wantMaxTime: 400 * time.Millisecond,
		},
		{
			name:  "a wait that does not fit the deadline ends the call",
			steps: []step{{status: 503, header: map[string]string{"Retry-After": "5"}}, okStep}, timeoutSeconds: 1, wantCode: "status", wantHTTP: 503,
			wantMessage: "scoring unavailable", wantAttempts: 1, wantRequests: 1, wantMaxTime: 400 * time.Millisecond,
		},
		{
			name:  "a 400 is tried once",
			steps: []step{busy(400), okStep}, wantCode: "status", wantHTTP: 400, wantMessage: "request refused", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 401 is tried once",
			steps: []step{busy(401), okStep}, wantCode: "status", wantHTTP: 401, wantMessage: "invalid credentials", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 402 is insufficient credit whatever the body says",
			steps: []step{{status: 402, body: `{"error": "you are out of money, please pay"}`}, okStep}, wantCode: "status", wantHTTP: 402,
			wantMessage: "insufficient credit", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 403 has its own message",
			steps: []step{busy(403)}, wantCode: "status", wantHTTP: 403, wantMessage: "permission denied", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 404 has its own message",
			steps: []step{busy(404)}, wantCode: "status", wantHTTP: 404, wantMessage: "model unavailable", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 413 has its own message",
			steps: []step{busy(413)}, wantCode: "status", wantHTTP: 413, wantMessage: "request too large", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "another status is unexpected",
			steps: []step{busy(418)}, wantCode: "status", wantHTTP: 418, wantMessage: "unexpected status", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a 302 is a status failure and the second server gets nothing",
			steps: []step{{status: 302, location: true}}, wantCode: "status", wantHTTP: 302, wantMessage: "unexpected status", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:         "a request ID is kept on ok",
			steps:        []step{{status: 200, header: map[string]string{"Content-Type": "application/json", "X-Request-Id": "req_123"}, body: goodBody}},
			wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1", wantRequestID: "req_123",
		},
		{
			name:  "a request ID is kept on a failed call",
			steps: []step{{status: 402, header: map[string]string{"X-Request-Id": "req_123"}}}, wantCode: "status", wantHTTP: 402, wantMessage: "insufficient credit",
			wantAttempts: 1, wantRequests: 1, wantRequestID: "req_123",
		},
		{
			name:  "a request ID of 129 bytes is dropped",
			steps: []step{{status: 402, header: map[string]string{"X-Request-Id": strings.Repeat("a", 129)}}}, wantCode: "status", wantHTTP: 402, wantMessage: "insufficient credit",
			wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a request ID with a control character is dropped",
			steps: []step{{status: 402, header: map[string]string{"X-Request-Id": "req\tid"}}}, wantCode: "status", wantHTTP: 402, wantMessage: "insufficient credit",
			wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a request ID that holds the key is dropped",
			steps: []step{{status: 402, header: map[string]string{"X-Request-Id": "echo-" + fakeKey}}}, wantCode: "status", wantHTTP: 402, wantMessage: "insufficient credit",
			wantAttempts: 1, wantRequests: 1,
		},
		{
			name:         "a request ID that holds the Authorization value is dropped",
			steps:        []step{{status: 200, header: map[string]string{"Content-Type": "application/json", "X-Request-Id": "Bearer " + fakeKey}, body: goodBody}},
			wantAttempts: 1, wantRequests: 1, wantModel: "test/model-1",
		},
		{
			name:  "a mock that never answers is a timeout within the limit",
			steps: []step{{hang: true}}, timeoutSeconds: 1, wantCode: "timeout", wantMessage: "provider did not answer in time",
			wantAttempts: 1, wantRequests: 1, wantMinTime: 900 * time.Millisecond, wantMaxTime: 2 * time.Second,
		},
		{
			name:     "a 2 MiB body is too large",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: strings.Repeat(" ", 2<<20)}},
			wantCode: "too_large", wantMessage: "response is too large", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:     "a body of 64 KiB and one byte is too large",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: goodBody + strings.Repeat(" ", protocol.MaxDecisionResponse)}},
			wantCode: "too_large", wantMessage: "response is too large", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:     "a 200 that is not JSON by content type is invalid",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "text/html"}, body: goodBody}},
			wantCode: "invalid", wantMessage: "response is not JSON", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:     "a 200 that fails the checks is tried once",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: `{"object": "decisions"}`}, okStep},
			wantCode: "invalid", wantMessage: "response failed the checks", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:     "an ok answer whose model holds the key is invalid",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: strings.Replace(goodBody, `"model": "test/model-1"`, `"model": "Bearer `+fakeKey+`"`, 1)}},
			wantCode: "invalid", wantMessage: "response failed the checks", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:  "a mock that echoes the Authorization header leaves the key out of the error",
			steps: []step{{status: 402, echo: true}}, wantCode: "status", wantHTTP: 402, wantMessage: "insufficient credit", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:     "a 200 that echoes the Authorization header in a text body leaves the key out of the error",
			steps:    []step{{status: 200, header: map[string]string{"Content-Type": "application/json"}, echo: true}},
			wantCode: "invalid", wantMessage: "response failed the checks", wantAttempts: 1, wantRequests: 1,
		},
		{
			name:       "a closed port is a network failure after three attempts",
			closedPort: true, wantCode: "network", wantMessage: "could not reach the provider", wantAttempts: 3, wantMinTime: 1400 * time.Millisecond,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var requests, other atomic.Int32
			second := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other.Add(1) }))
			defer second.Close()
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := int(requests.Add(1))
				checkRequest(t, r, tt.keyless)
				if n > len(tt.steps) {
					t.Errorf("request %d, but only %d steps", n, len(tt.steps))
					w.WriteHeader(500)
					return
				}
				s := tt.steps[n-1]
				if s.hang {
					<-r.Context().Done()
					return
				}
				for k, v := range s.header {
					w.Header().Set(k, v)
				}
				if s.location {
					w.Header().Set("Location", second.URL+"/v1/decisions")
				}
				if s.echo {
					echo(w, r.Header.Get("Authorization"), s)
					return
				}
				w.WriteHeader(s.status)
				_, _ = w.Write([]byte(s.body))
			}))
			defer mock.Close()
			url := mock.URL
			if tt.closedPort {
				mock.Close()
			}

			p := config.Provider{Name: "mock", URL: url, KeyEnv: "NETRA_API_KEY", Model: "test/model-1", TimeoutSeconds: cmp.Or(tt.timeoutSeconds, 10)}
			key := fakeKey
			if tt.keyless {
				p.KeyEnv, key = "", ""
			}
			start := time.Now()
			reply := decision.Send(context.Background(), p, key, version, validRequest())
			elapsed := time.Since(start)

			if elapsed < tt.wantMinTime {
				t.Errorf("took %v, want at least %v", elapsed, tt.wantMinTime)
			}
			if maxTime := cmp.Or(tt.wantMaxTime, 5*time.Second); elapsed > maxTime {
				t.Errorf("took %v, want at most %v", elapsed, maxTime)
			}
			if reply.Attempts != tt.wantAttempts {
				t.Errorf("attempts = %d, want %d", reply.Attempts, tt.wantAttempts)
			}
			if reply.RequestID != tt.wantRequestID {
				t.Errorf("request ID = %q, want %q", reply.RequestID, tt.wantRequestID)
			}
			if got := int(requests.Load()); !tt.closedPort && got != tt.wantRequests {
				t.Errorf("mock got %d requests, want %d", got, tt.wantRequests)
			}
			if got := int(other.Load()); got != tt.wantOtherServer {
				t.Errorf("second server got %d requests, want %d", got, tt.wantOtherServer)
			}
			if reply.LatencyMS < 0 || reply.LatencyMS > protocol.MaxDecisionLatencyMS {
				t.Errorf("latency = %d ms, out of range", reply.LatencyMS)
			}
			if tt.wantCode == "" {
				if reply.Error != nil || reply.Answers == nil || reply.Usage == nil {
					t.Fatalf("reply = %+v, want ok", reply)
				}
				if reply.Answers.Model != tt.wantModel || reply.Usage.PromptTokens != 3600 {
					t.Errorf("answers model %q, prompt tokens %d", reply.Answers.Model, reply.Usage.PromptTokens)
				}
				return
			}
			if reply.Answers != nil || reply.Usage != nil || reply.Error == nil {
				t.Fatalf("reply = %+v, want a failure", reply)
			}
			if got := *reply.Error; got.Code != tt.wantCode || got.HTTPStatus != tt.wantHTTP || got.Message != tt.wantMessage {
				t.Errorf("error = %+v, want code %s, status %d, message %q", got, tt.wantCode, tt.wantHTTP, tt.wantMessage)
			}
			if out := fmt.Sprintf("%+v", reply); strings.Contains(out, fakeKey) {
				t.Errorf("the key is in the reply: %s", out)
			}
			d := protocol.Decision{
				Provider: "mock", URL: url, Model: "test/model-1", Status: protocol.DecisionFailed, Error: reply.Error,
				Sent: ptr(validRequest()), RequestID: reply.RequestID, LatencyMS: reply.LatencyMS, Attempts: reply.Attempts,
			}
			if err := d.Validate(); err != nil {
				t.Errorf("the failure does not make a valid Decision: %v", err)
			}
		})
	}
}

// checkRequest checks what every request of the mock must be: the method, the path, the headers
// and a body that decodes with unknown fields refused, as the real API does.
func checkRequest(t *testing.T, r *http.Request, keyless bool) {
	t.Helper()
	if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" {
		t.Errorf("request is %s %s, want POST /v1/decisions", r.Method, r.URL.Path)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got, want := r.Header.Get("User-Agent"), "galahad/"+version; got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
	auth, hasAuth := r.Header["Authorization"]
	switch {
	case keyless && hasAuth:
		t.Errorf("Authorization = %q, want none", auth)
	case !keyless && (len(auth) != 1 || auth[0] != "Bearer "+fakeKey):
		t.Errorf("Authorization = %q, want the bearer key", auth)
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req protocol.DecisionRequest
	if err := dec.Decode(&req); err != nil {
		t.Errorf("body does not decode: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Errorf("body is not a valid request: %v", err)
	}
}

// echo answers with the Authorization header in the status text and in the body.
func echo(w http.ResponseWriter, auth string, s step) {
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	body := "echo: " + auth
	ct := "text/plain"
	if s.header["Content-Type"] != "" {
		ct = s.header["Content-Type"]
	}
	writeRaw(rw.Writer, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", s.status, auth, ct, len(body), body))
}

func writeRaw(w *bufio.Writer, s string) {
	_, _ = w.WriteString(s)
	_ = w.Flush()
}

func ptr[T any](v T) *T { return &v }
