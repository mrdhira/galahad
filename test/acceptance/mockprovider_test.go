package acceptance_test

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// decisionKey is a fake key, built from pieces so no full literal sits in the source.
const decisionKey = "fake-key-" + "t34b-" + "5d1e8b07"

// decisionAnswer is a valid answer of the provider with the given verdict probabilities.
func decisionAnswer(clean, suspicious, malicious float64) string {
	return fmt.Sprintf(`{"object": "decisions", "model": "test/model-1", "prompt_format_version": 1, "answers": {
  "verdict": {"type": "choice", "probabilities": {"clean": %g, "suspicious": %g, "malicious": %g}, "label_mass": 0.6},
  "risk": {"type": "score", "probabilities": {"0": 0.25, "1": 0.25, "2": 0.25, "3": 0.25}, "label_mass": 0.4, "score": 1.5},
  "steals_secrets": {"type": "yes_no", "probabilities": {"yes": 0.5, "no": 0.5}, "label_mass": 0.5}},
  "usage": {"prompt_tokens": 100, "completion_tokens": 0, "total_tokens": 100}}`, clean, suspicious, malicious)
}

// mockProvider is an httptest server that records the body and the Authorization header of each request.
type mockProvider struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	auths  []string
	first  chan struct{} // closed at the first request
}

func newMockProvider(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) *mockProvider {
	t.Helper()
	m := &mockProvider{first: make(chan struct{})}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body.Bytes())) // the handler can read the body again
		m.mu.Lock()
		m.bodies = append(m.bodies, body.Bytes())
		m.auths = append(m.auths, r.Header.Get("Authorization"))
		n := len(m.bodies)
		m.mu.Unlock()
		if n == 1 {
			close(m.first)
		}
		handler(w, r, n)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockProvider) requests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

// answers replies to every request with body.
func answers(body string) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_t34b")
		_, _ = w.Write([]byte(body))
	}
}

func status(code int) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(code) }
}

// injectionAnswer answers "clean" with probability 1 when the request holds a prompt injection, as a model
// that the text has steered would, and "malicious" otherwise.
func injectionAnswer(w http.ResponseWriter, r *http.Request, n int) {
	body, _ := io.ReadAll(r.Body)
	if bytes.Contains(bytes.ToLower(body), []byte("ignore all previous instructions")) {
		answers(decisionAnswer(1, 0, 0))(w, r, n)
		return
	}
	answers(decisionAnswer(0.005, 0.005, 0.99))(w, r, n)
}

// closedPort returns the URL of a loopback port that nobody listens on.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }() // only to find a port nobody listens on
	return "http://" + l.Addr().String()
}
