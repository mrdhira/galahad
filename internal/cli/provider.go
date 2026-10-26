package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

// runProvider manages the decision providers in config.json: "provider add|list|remove|test".
func runProvider(args []string, stdout, stderr io.Writer, env Env) int {
	if len(args) > 0 {
		switch args[0] {
		case "add":
			return runProviderAdd(args[1:], stdout, stderr, env)
		case "list":
			return runProviderList(args[1:], stdout, stderr, env)
		case "remove":
			return runProviderRemove(args[1:], stdout, stderr, env)
		case "test":
			return runProviderTest(args[1:], stdout, stderr, env)
		}
	}
	fmt.Fprintf(stderr, "galahad provider: want add, list, remove or test\n\n%s", usage)
	return ExitUsage
}

// runProviderAdd adds a provider. The name "netra" is a preset, and the flags override its fields.
func runProviderAdd(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("provider add", flag.ContinueOnError)
	url := fs.String("url", "", "base URL of the provider (https)")
	model := fs.String("model", "", "model name")
	keyEnv := fs.String("key-env", "", "environment variable that holds the key")
	timeout := fs.Duration("timeout", 0, "time limit for one call, from 1s to 150s")
	pos, code, done := parseArgs("provider add", fs, args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "galahad provider add: want one provider name\n\n%s", usage)
		return ExitUsage
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	p, preset := config.Preset(pos[0])
	if !preset {
		if !set["url"] || !set["model"] {
			fmt.Fprintf(stderr, "galahad provider add: --url and --model are required unless the name is netra\n\n%s", usage)
			return ExitUsage
		}
		p = config.Provider{Name: pos[0], TimeoutSeconds: config.DefaultTimeoutSeconds}
	}
	if set["url"] {
		p.URL = *url
	}
	if set["model"] {
		p.Model = *model
	}
	if set["key-env"] {
		p.KeyEnv = *keyEnv
	}
	if set["timeout"] {
		if *timeout%time.Second != 0 {
			fmt.Fprintf(stderr, "galahad provider add: --timeout must be a whole number of seconds\n\n%s", usage)
			return ExitUsage
		}
		p.TimeoutSeconds = int(*timeout / time.Second)
	}
	if err := p.Validate(); err != nil {
		fmt.Fprintf(stderr, "galahad provider add: %v\n\n%s", err, usage)
		return ExitUsage
	}

	home, err := env.home()
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider add: %v\n", err)
		return ExitError
	}
	cfg, err := config.Load(home)
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider add: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	if _, ok := cfg.Find(p.Name); ok {
		fmt.Fprintf(stderr, "galahad provider add: provider %s already exists; remove it first with galahad provider remove %s\n", p.Name, p.Name)
		return ExitError
	}
	cfg.Providers = append(cfg.Providers, p)
	if err := config.Save(home, cfg); err != nil {
		fmt.Fprintf(stderr, "galahad provider add: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	fmt.Fprintf(stdout, "added provider %s\n", p.Name)
	return ExitClean
}

// runProviderList lists the providers. KEY_SET says whether the variable is set; the value is never read into the output.
func runProviderList(args []string, stdout, stderr io.Writer, env Env) int {
	pos, code, done := parseArgs("provider list", flag.NewFlagSet("provider list", flag.ContinueOnError), args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) > 0 {
		fmt.Fprintf(stderr, "galahad provider list: unexpected argument %q\n\n%s", protocol.CleanPath(pos[0]), usage)
		return ExitUsage
	}
	home, err := env.home()
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider list: %v\n", err)
		return ExitError
	}
	cfg, err := config.Load(home)
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider list: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	if len(cfg.Providers) == 0 {
		fmt.Fprintln(stdout, "No providers. Add one with galahad provider add")
		return ExitClean
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tURL\tMODEL\tKEY_ENV\tKEY_SET\tTIMEOUT")
	for _, p := range cfg.Providers {
		keySet := "no"
		if p.KeyEnv != "" && os.Getenv(p.KeyEnv) != "" {
			keySet = "yes"
		}
		keyEnv := p.KeyEnv
		if keyEnv == "" {
			keyEnv = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%ds\n", p.Name, p.URL, p.Model, keyEnv, keySet, p.TimeoutSeconds)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "galahad provider list: %v\n", err)
		return ExitError
	}
	return ExitClean
}

// runProviderRemove removes the provider with the given name.
func runProviderRemove(args []string, stdout, stderr io.Writer, env Env) int {
	pos, code, done := parseArgs("provider remove", flag.NewFlagSet("provider remove", flag.ContinueOnError), args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "galahad provider remove: want one provider name\n\n%s", usage)
		return ExitUsage
	}
	home, err := env.home()
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider remove: %v\n", err)
		return ExitError
	}
	cfg, err := config.Load(home)
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider remove: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	kept := cfg.Providers[:0]
	for _, p := range cfg.Providers {
		if p.Name != pos[0] {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(cfg.Providers) {
		fmt.Fprintf(stderr, "galahad provider remove: no provider %s\n", protocol.CleanPath(pos[0]))
		return ExitError
	}
	cfg.Providers = kept
	if err := config.Save(home, cfg); err != nil {
		fmt.Fprintf(stderr, "galahad provider remove: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	fmt.Fprintf(stdout, "removed provider %s\n", pos[0])
	return ExitClean
}

// runProviderTest sends the fixed sample input to a provider and prints what came back. The sample
// holds no user data (docs/decision-api.md).
func runProviderTest(args []string, stdout, stderr io.Writer, env Env) int {
	pos, code, done := parseArgs("provider test", flag.NewFlagSet("provider test", flag.ContinueOnError), args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "galahad provider test: want one provider name\n\n%s", usage)
		return ExitUsage
	}
	home, err := env.home()
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider test: %v\n", err)
		return ExitError
	}
	cfg, err := config.Load(home)
	if err != nil {
		fmt.Fprintf(stderr, "galahad provider test: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	p, ok := cfg.Find(pos[0])
	if !ok {
		fmt.Fprintf(stderr, "galahad provider test: no provider %s\n", protocol.CleanPath(pos[0]))
		return ExitUsage
	}
	var key string
	if p.KeyEnv != "" {
		if key = os.Getenv(p.KeyEnv); key == "" {
			fmt.Fprintf(stderr, "galahad provider test: provider %s needs the key in $%s, which is not set\n", p.Name, p.KeyEnv)
			return ExitUsage
		}
		if err := decision.CheckKey(key); err != nil {
			fmt.Fprintf(stderr, "galahad provider test: $%s: %v\n", p.KeyEnv, err)
			return ExitUsage
		}
	}

	reply := decision.Send(context.Background(), p, key, env.version(), sampleRequest(p.Model))
	if reply.Error != nil {
		fmt.Fprintf(stderr, "galahad provider test: %s failed: %s", p.Name, reply.Error.Code)
		if reply.Error.HTTPStatus != 0 {
			fmt.Fprintf(stderr, " %d", reply.Error.HTTPStatus)
		}
		fmt.Fprintf(stderr, ": %s (attempts %d, latency %d ms", reply.Error.Message, reply.Attempts, reply.LatencyMS)
		if reply.RequestID != "" {
			fmt.Fprintf(stderr, ", request id %s", reply.RequestID)
		}
		fmt.Fprintln(stderr, ")")
		return ExitError
	}

	fmt.Fprintf(stdout, "provider %s: ok\n", p.Name)
	for _, q := range protocol.DecisionQuestions() {
		a := reply.Answers.Questions[q.ID]
		var labels []string
		for i, l := range q.Labels() {
			name := l
			if q.Type == protocol.QuestionScore {
				name = q.Levels[i]
			}
			labels = append(labels, fmt.Sprintf("%s %.2f", name, a.Probabilities[l]))
		}
		fmt.Fprintf(stdout, "  %-15s %s", q.ID, strings.Join(labels, ", "))
		if a.Choice != "" {
			fmt.Fprintf(stdout, "; choice %s", a.Choice)
		}
		if a.Score != nil {
			fmt.Fprintf(stdout, "; expected level %.2f", *a.Score)
		}
		fmt.Fprintf(stdout, "; label_mass %.2f (diagnostic)\n", a.LabelMass)
	}
	fmt.Fprintf(stdout, "input tokens: %d\n", reply.Usage.PromptTokens)
	if reply.RequestID != "" {
		fmt.Fprintf(stdout, "request id: %s\n", reply.RequestID)
	}
	fmt.Fprintf(stdout, "latency: %d ms (attempts %d)\n", reply.LatencyMS, reply.Attempts)
	return ExitClean
}

// sampleRequest is the fixed input of "provider test": one made-up finding, no user data.
func sampleRequest(model string) protocol.DecisionRequest {
	return protocol.DecisionRequest{
		Model:               model,
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: protocol.TargetDir, FileCount: 1},
			Coverage: protocol.DecisionCoverage{FilesSeen: 1, FilesAnalyzed: 1},
			Findings: []protocol.DecisionFinding{{
				RuleID: "GAL-TEST-001", Severity: protocol.SeverityLow, Title: "Sample finding for provider test", Analyzer: "test",
				Path: "sample.txt", Line: 1, Snippet: "echo hello",
			}},
		},
		Questions: protocol.DecisionQuestions(),
	}
}
