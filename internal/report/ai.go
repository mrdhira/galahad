package report

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// aiReasonPrefix starts the reason that scoring adds when an AI opinion counts. The provider name
// and ")" follow. It must match internal/scoring.
const aiReasonPrefix = "AI opinion ("

const (
	aiNote       = "These are model scores over fixed labels, not calibrated probabilities."
	aiWarning    = "This input holds text that tries to steer an AI reviewer (GAL-INJECT-001). An AI opinion on it may have been influenced by that text."
	aiNoChange   = "no change: an AI opinion never lowers a verdict"
	aiSkipped    = "skipped: no findings to send"
	aiAuthNoName = "Authorization from the provider's key variable (not shown)"
	aiAlone      = "; the verdict comes from the analysis alone"
)

// aiAnswer is one answer as text. Probs lists every label with its percentage; Pick is the label the
// provider chose or the expected level; Mass is the label_mass, a diagnostic.
type aiAnswer struct{ Title, Probs, Pick, Mass string }

// aiView is the "AI opinions" section as cleaned text. The renderers escape it for their format.
// The Decision is written by the host, but the model name and the request ID come from the provider.
type aiView struct {
	Provider, URL, Model, AnsweredBy, Status string
	Attempts, Latency                        string
	InputTokens, RequestID                   string
	Effect                                   string
	Answers                                  []aiAnswer
	Note, Warning                            string
	HasSent                                  bool
	Sent, Redactions, Auth                   string
}

// aiSection returns the section for a Result with a Decision, or nil.
func aiSection(res *protocol.Result) *aiView {
	d := res.Decision
	if d == nil {
		return nil
	}
	v := &aiView{
		Provider: clean(d.Provider), URL: cleanValue(d.URL), Model: clean(d.Model), Status: clean(d.Status),
		Effect: aiEffect(res, d),
	}
	if slices.ContainsFunc(res.Findings, func(f protocol.Finding) bool { return f.RuleID == "GAL-INJECT-001" }) {
		v.Warning = aiWarning
	}
	if d.Status == protocol.DecisionSkipped {
		return v
	}
	v.Attempts = strconv.Itoa(d.Attempts)
	v.Latency = strconv.Itoa(d.LatencyMS) + " ms"
	v.RequestID = clean(d.RequestID)
	if d.Usage != nil {
		v.InputTokens = strconv.Itoa(d.Usage.PromptTokens)
	}
	if d.Answers != nil {
		if m := clean(d.Answers.Model); m != v.Model {
			v.AnsweredBy = m
		}
		v.Answers = aiAnswers(d.Answers)
		v.Note = aiNote
	}
	if d.Sent != nil {
		// The same indented JSON as in report.json, so the reader sees what the provider got.
		if b, err := json.MarshalIndent(d.Sent, "", "  "); err == nil {
			v.HasSent, v.Sent = true, string(b)
		}
		v.Redactions = aiRedactions(d.Redactions)
		v.Auth = aiAuthNoName
	}
	return v
}

// aiMalicious returns the probability that the verdict answer gives to "malicious", or 0 without one.
func aiMalicious(d *protocol.Decision) float64 {
	if d.Answers == nil {
		return 0
	}
	return d.Answers.Questions[protocol.QuestionVerdict].Probabilities[protocol.LabelMalicious]
}

// aiRaised is true when the opinion counted: scoring then adds a reason for this provider. The
// report cannot know the static verdict, so it only says "raised to suspicious".
func aiRaised(res *protocol.Result, d *protocol.Decision) bool {
	prefix := aiReasonPrefix + d.Provider + ")"
	return d.Status == protocol.DecisionOK && slices.ContainsFunc(res.Reasons, func(r string) bool { return strings.HasPrefix(r, prefix) })
}

func aiPercent(p float64) string { return strconv.Itoa(int(math.Round(p*100))) + "%" }

// aiUnavailable is "timeout" or "status 402: insufficient credit".
func aiUnavailable(e *protocol.DecisionError) string {
	s := clean(e.Code)
	if e.HTTPStatus != 0 {
		s += " " + strconv.Itoa(e.HTTPStatus)
	}
	if e.Message != "" {
		s += ": " + clean(e.Message)
	}
	return s
}

func aiEffect(res *protocol.Result, d *protocol.Decision) string {
	switch {
	case d.Status == protocol.DecisionSkipped:
		return aiSkipped
	case d.Status == protocol.DecisionFailed && d.Error != nil:
		return "unavailable (" + aiUnavailable(d.Error) + ")" + aiAlone
	case d.Status == protocol.DecisionFailed:
		return "unavailable" + aiAlone
	case aiRaised(res, d):
		return "raised to suspicious"
	}
	return aiNoChange
}

// aiTerminal is the one terminal line, or "" without a Decision. It holds no model name and no text
// of the provider.
func aiTerminal(res *protocol.Result) string {
	d := res.Decision
	if d == nil {
		return ""
	}
	head := "AI opinion (" + clean(d.Provider) + "): "
	switch {
	case d.Status == protocol.DecisionSkipped:
		return head + aiSkipped
	case d.Status == protocol.DecisionFailed && d.Error != nil:
		return head + "unavailable (" + aiUnavailable(d.Error) + ")"
	case d.Status == protocol.DecisionFailed:
		return head + "unavailable"
	}
	line := head + "malicious " + aiPercent(aiMalicious(d)) + ", "
	if aiRaised(res, d) {
		return line + "raised to suspicious"
	}
	return line + "no change"
}

func aiAnswers(a *protocol.DecisionAnswers) []aiAnswer {
	titles := map[string]string{protocol.QuestionVerdict: "Verdict", protocol.QuestionRisk: "Risk", protocol.QuestionStealsSecrets: "Steals secrets"}
	var out []aiAnswer
	for _, q := range protocol.DecisionQuestions() {
		ans, ok := a.Questions[q.ID]
		if !ok {
			continue
		}
		var parts []string
		for i, l := range q.Labels() {
			p, ok := ans.Probabilities[l]
			if !ok {
				continue
			}
			name := l
			if q.Type == protocol.QuestionScore {
				name = q.Levels[i] // a score answer is keyed by the level index
			}
			parts = append(parts, name+" "+aiPercent(p))
		}
		x := aiAnswer{Title: titles[q.ID], Probs: strings.Join(parts, ", "), Mass: fmt.Sprintf("label_mass %.2f (a diagnostic, not a measure of quality)", ans.LabelMass)}
		switch {
		case ans.Score != nil:
			x.Pick = fmt.Sprintf("expected level %.1f of %d", *ans.Score, len(q.Levels)-1)
		case ans.Choice != "":
			x.Pick = "chosen: " + clean(ans.Choice)
		}
		out = append(out, x)
	}
	return out
}

func aiRedactions(r map[string]int) string {
	if len(r) == 0 {
		return "Redactions: none"
	}
	kinds := make([]string, 0, len(r))
	for k := range r {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = clean(k) + " " + strconv.Itoa(r[k])
	}
	return "Redactions: " + strings.Join(parts, ", ")
}
