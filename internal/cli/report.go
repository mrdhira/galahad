package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
)

// maxReportSize is the largest report.json that is read: the largest Result the host accepts.
const maxReportSize = 64 << 20

// runReport prints the report of a past job and exits with the code of its verdict.
func runReport(args []string, stdout, stderr io.Writer, env Env) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	asJSON := flags.Bool("json", false, "print report.json")
	pos, code, done := parseArgs("report", flags, args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "galahad report: want exactly one job id, got %d arguments\n\n%s", len(pos), usage)
		return ExitUsage
	}
	id := pos[0]
	if !job.ValidID(id) {
		fmt.Fprintf(stderr, "galahad report: invalid job id %q\n\n%s", protocol.CleanPath(id), usage)
		return ExitUsage
	}
	dir, err := env.jobsDir()
	if err != nil {
		fmt.Fprintf(stderr, "galahad report: %v\n", err)
		return ExitError
	}

	// report.json is a file on disk: it is read like input, with a size cap, a strict decode and Validate.
	data, err := job.ReadFile(dir, id, report.JSONName, maxReportSize)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(stderr, "galahad report: no %s for job %s: there is no such job, or its scan did not finish\n", report.JSONName, id)
		return ExitError
	}
	if err != nil {
		fmt.Fprintf(stderr, "galahad report: job %s: %s\n", id, protocol.CleanPath(err.Error()))
		return ExitError
	}
	var res protocol.Result
	if err := protocol.DecodeStrict(data, &res); err != nil {
		fmt.Fprintf(stderr, "galahad report: job %s: %s: %s\n", id, report.JSONName, protocol.CleanPath(err.Error()))
		return ExitError
	}
	if err := res.Validate(); err != nil {
		fmt.Fprintf(stderr, "galahad report: job %s: %s: %s\n", id, report.JSONName, protocol.CleanPath(err.Error()))
		return ExitError
	}

	if *asJSON {
		if _, err := stdout.Write(data); err != nil {
			fmt.Fprintf(stderr, "galahad report: %v\n", err)
			return ExitError
		}
		return res.Verdict.ExitCode()
	}
	jobDir := job.Dir(dir, id)
	report.Terminal(stdout, &res, report.Paths{
		JSON:     filepath.Join(jobDir, report.JSONName),
		Markdown: filepath.Join(jobDir, report.MarkdownName),
		HTML:     filepath.Join(jobDir, report.HTMLName),
	}, useColor(stdout))
	return res.Verdict.ExitCode()
}
