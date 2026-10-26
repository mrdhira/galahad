package decision_test

import (
	"context"
	"testing"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

// TestSendRefusesURL checks that a URL the client must not use fails before any connection.
func TestSendRefusesURL(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		url string
		key string
		// expectations
		wantMessage string
	}{
		{name: "plain http to a remote host", url: "http://example.com", wantMessage: "request, key or provider URL is not valid"},
		{name: "user info", url: "https://user:pw@example.com", wantMessage: "request, key or provider URL is not valid"},
		{name: "a query", url: "https://example.com/?a=b", wantMessage: "request, key or provider URL is not valid"},
		{name: "no URL", url: "", wantMessage: "request, key or provider URL is not valid"},
		{name: "the key value in a message is replaced", url: "", key: "provider", wantMessage: "request, key or [REDACTED:key] URL is not valid"},
		{name: "a key with a line break", url: "https://example.com", key: "fake-key\r\nX-Evil: 1", wantMessage: "request, key or provider URL is not valid"},
		{name: "a key with a control character", url: "https://example.com", key: "fake-key\x01", wantMessage: "request, key or provider URL is not valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := config.Provider{Name: "mock", URL: tt.url, Model: "test/model-1", TimeoutSeconds: 5}
			reply := decision.Send(context.Background(), p, tt.key, "v1", validRequest())
			if reply.Error == nil || reply.Answers != nil {
				t.Fatalf("reply = %+v, want a failure", reply)
			}
			if reply.Error.Code != protocol.DecisionErrInvalid || reply.Error.Message != tt.wantMessage {
				t.Errorf("error = %+v, want invalid with %q", *reply.Error, tt.wantMessage)
			}
			if reply.Attempts != 1 {
				t.Errorf("attempts = %d, want 1", reply.Attempts)
			}
		})
	}
}

func validRequest() protocol.DecisionRequest {
	return protocol.DecisionRequest{
		Model:               "test/model-1",
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: protocol.TargetDir, FileCount: 1},
			Coverage: protocol.DecisionCoverage{FilesSeen: 1, FilesAnalyzed: 1},
			Findings: []protocol.DecisionFinding{{RuleID: "GAL-TEST-001", Severity: protocol.SeverityLow, Title: "t", Analyzer: "test", Path: "a.txt", Line: 1, Snippet: "s"}},
		},
		Questions: protocol.DecisionQuestions(),
	}
}
