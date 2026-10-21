package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"text/tabwriter"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// runJobs lists the jobs, or removes some of them with "jobs rm <id>...".
func runJobs(args []string, stdout, stderr io.Writer, env Env) int {
	if len(args) > 0 && args[0] == "rm" {
		return runJobsRm(args[1:], stdout, stderr, env)
	}
	pos, code, done := parseArgs("jobs", flag.NewFlagSet("jobs", flag.ContinueOnError), args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) > 0 {
		fmt.Fprintf(stderr, "galahad jobs: unexpected argument %q\n\n%s", protocol.CleanPath(pos[0]), usage)
		return ExitUsage
	}
	dir, err := env.jobsDir()
	if err != nil {
		fmt.Fprintf(stderr, "galahad jobs: %v\n", err)
		return ExitError
	}

	jobs, err := job.List(dir)
	if err != nil && !errors.Is(err, job.ErrListTruncated) {
		fmt.Fprintf(stderr, "galahad jobs: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	if err != nil {
		fmt.Fprintf(stderr, "galahad jobs: %s; not all jobs are listed\n", err)
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	listed := 0
	for _, j := range jobs {
		if j.State == job.StateUnreadable {
			fmt.Fprintf(stderr, "galahad jobs: skipped %s: job.json is missing, unreadable or invalid\n", protocol.CleanPath(j.ID))
			continue
		}
		if listed == 0 {
			fmt.Fprintln(tw, "ID\tSTATE\tVERDICT\tSCORE\tDATE\tTARGET")
		}
		listed++
		verdict, score := "-", "-"
		if j.Verdict != "" {
			verdict = protocol.CleanPath(j.Verdict)
		}
		if j.State == job.StateDone {
			score = fmt.Sprint(j.Score)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", j.ID, j.State, verdict, score,
			j.CreatedAt.UTC().Format("2006-01-02 15:04:05"), protocol.CleanPath(j.Target.Input))
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "galahad jobs: %v\n", err)
		return ExitError
	}
	if listed == 0 {
		fmt.Fprintln(stdout, "No jobs.")
	}
	return ExitClean
}

// runJobsRm removes the jobs with the given IDs. It checks every ID before it removes any.
func runJobsRm(args []string, stdout, stderr io.Writer, env Env) int {
	ids, code, done := parseArgs("jobs rm", flag.NewFlagSet("jobs rm", flag.ContinueOnError), args, stdout, stderr)
	if done {
		return code
	}
	if len(ids) == 0 {
		fmt.Fprintf(stderr, "galahad jobs rm: want at least one job id\n\n%s", usage)
		return ExitUsage
	}
	for _, id := range ids {
		if !job.ValidID(id) {
			fmt.Fprintf(stderr, "galahad jobs rm: invalid job id %q\n\n%s", protocol.CleanPath(id), usage)
			return ExitUsage
		}
	}
	dir, err := env.jobsDir()
	if err != nil {
		fmt.Fprintf(stderr, "galahad jobs rm: %v\n", err)
		return ExitError
	}

	code = ExitClean
	for _, id := range ids {
		switch err := job.Remove(dir, id); {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(stderr, "galahad jobs rm: no job %s\n", id)
			code = ExitError
		case err != nil:
			fmt.Fprintf(stderr, "galahad jobs rm: %s\n", protocol.CleanPath(err.Error()))
			code = ExitError
		default:
			fmt.Fprintf(stdout, "removed %s\n", id)
		}
	}
	return code
}

// jobsDir returns the directory that holds the jobs.
func (e Env) jobsDir() (string, error) {
	if e.Home != "" {
		return config.JobsDir(e.Home), nil
	}
	home, err := config.Home()
	if err != nil {
		return "", err
	}
	return config.JobsDir(home), nil
}

// parseArgs parses the flags of flags, which may come before and after the positional arguments, and
// returns the positional arguments. When done is true the command must return code now: the
// flags were bad or asked for help.
func parseArgs(name string, flags *flag.FlagSet, args []string, stdout, stderr io.Writer) (pos []string, code int, done bool) {
	flags.SetOutput(io.Discard)
	for {
		if err := flags.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				fmt.Fprint(stdout, usage)
				return nil, ExitClean, true
			}
			fmt.Fprintf(stderr, "galahad %s: %v\n\n%s", name, err, usage)
			return nil, ExitUsage, true
		}
		if flags.NArg() == 0 {
			return pos, ExitClean, false
		}
		pos = append(pos, flags.Arg(0))
		args = flags.Args()[1:]
	}
}
