package decision

import (
	"context"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Ask asks the provider for an opinion on res and returns the record for Result.Decision. It selects
// the findings to send, redacts the request, sends it and checks the answer. A Result with nothing
// to judge is skipped and nothing is sent. A call that fails is a Decision of status failed, not an
// error: the error is set only when the request cannot be built at all. key is the value of the
// provider's key variable. The Decision holds the request exactly as it was sent.
func Ask(ctx context.Context, p config.Provider, key, version string, res protocol.Result) (protocol.Decision, error) {
	d := protocol.Decision{Provider: p.Name, URL: p.URL, Model: p.Model}
	req, ok, err := Select(res, p.Model)
	if err != nil {
		return protocol.Decision{}, err
	}
	if !ok {
		d.Status, d.Reason = protocol.DecisionSkipped, protocol.DecisionSkipNoFindings
		return d, nil
	}
	if counts := Redact(&req); len(counts) > 0 {
		d.Redactions = counts
	}
	reply := Send(ctx, p, key, version, req)
	d.Sent, d.RequestID, d.LatencyMS, d.Attempts = &req, reply.RequestID, reply.LatencyMS, reply.Attempts
	if reply.Error != nil {
		d.Status, d.Error = protocol.DecisionFailed, reply.Error
		return d, nil
	}
	d.Status, d.Answers, d.Usage = protocol.DecisionOK, reply.Answers, reply.Usage
	return d, nil
}
