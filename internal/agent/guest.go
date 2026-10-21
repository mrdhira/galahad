package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static"
	"github.com/mrdhira/galahad/internal/analyze/tools"
	"github.com/mrdhira/galahad/internal/ingest"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/scoring"
)

const (
	// guestInputDir is where the VM image gives the agent room for the input.
	guestInputDir = "/work/input"
	// analysisMargin is how long before the end of the job the analysis stops, so that a
	// result with a timeout skip reaches the host before it kills the VM.
	analysisMargin = 60 * time.Second
)

// runGuest is the guest side of one job: dial the host, take the job and its tar stream,
// analyze the input and send back a Result, or an Error. With --proxy it also runs the relay
// that guest tools reach the network through. T2.6b adds the update kinds.
func runGuest(args []string, _, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("guest", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	control := fs.String("control", "", "control channel of the host: vsock:<cid>:<port> or tcp:<host:port>")
	proxy := fs.String("proxy", "", "proxy channel of the host, same syntax as --control")
	var memoryLimit int64
	fs.Func("memory-limit", "soft memory limit in bytes, with an optional KiB, MiB or GiB suffix", func(s string) (err error) {
		memoryLimit, err = ParseSize(s)
		return err
	})
	unsafeHost := fs.Bool("unsafe-host", false, "run on this host even though it is not a VM, and allow tcp transports; you accept the risk")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "galahad-agent guest: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "galahad-agent guest: unexpected argument %q\n\n%s", fs.Arg(0), usage)
		return ExitUsage
	}
	if *control == "" {
		fmt.Fprintf(stderr, "galahad-agent guest: --control is required\n\n%s", usage)
		return ExitUsage
	}
	dialControl, err := ParseTransport(*control, *unsafeHost)
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent guest: --control: %v\n", err)
		return ExitUsage
	}
	var dialProxy Dialer // nil without --proxy: the guest has no network then
	if *proxy != "" {
		if dialProxy, err = ParseTransport(*proxy, *unsafeHost); err != nil {
			fmt.Fprintf(stderr, "galahad-agent guest: --proxy: %v\n", err)
			return ExitUsage
		}
	}

	if inVM, reason := env.DetectVM(); !inVM {
		if !*unsafeHost {
			fmt.Fprintf(stderr, "galahad-agent: refusing to take untrusted input outside a VM (%s). "+
				"Galahad runs the guest inside its VM; use `galahad scan`. "+
				"To run on this host anyway, pass --unsafe-host; you accept the risk.\n", reason)
			return ExitUsage
		}
		fmt.Fprintf(stderr, "galahad-agent: WARNING: --unsafe-host: taking untrusted input outside a VM (%s)\n", reason)
	}

	applyMemoryLimit(env, memoryLimit, true)

	conn, err := dialControl(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent guest: dial control: %v\n", err)
		return ExitError
	}

	host := newHostConn(conn)
	defer host.close()
	if err := guestJob(host, *unsafeHost, dialProxy, env); err != nil {
		code, msg := errorCode(err)
		fmt.Fprintf(stderr, "galahad-agent guest: %s: %v\n", code, err)
		// Best effort: the connection may be the thing that failed.
		_ = host.sendJSON(protocol.FrameError, protocol.Error{Code: code, Message: protocol.Snippet(msg)})
		return ExitError
	}
	return ExitClean
}

// errorCode maps a failure to the Error code and message for the host.
func errorCode(err error) (code, msg string) {
	var ce *codeError
	switch {
	case errors.As(err, &ce):
		return ce.code, ce.err.Error()
	case errors.Is(err, ingest.ErrTooLarge):
		return protocol.CodeTooLarge, err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.CodeTimeout, err.Error()
	}
	return protocol.CodeInternal, err.Error()
}

// guestJob runs one job on an open control connection. The input is the tar stream of one
// target, whose top-level entry is named Job.Name: a file, or a directory with the files in it.
func guestJob(host *hostConn, unsafeHost bool, dialProxy Dialer, env Env) error {
	hello := protocol.Hello{Protocol: protocol.ProtocolVersion, AgentVersion: version}
	if err := host.sendJSON(protocol.FrameHello, hello); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	_, payload, err := host.next()
	if err != nil {
		return err
	}
	var job protocol.Job // the order check guarantees that this is the Job frame
	if err := protocol.DecodeStrict(payload, &job); err != nil {
		return fail(protocol.CodeProtocol, "job frame: %v", err)
	}
	if err := job.Validate(); err != nil {
		return fail(protocol.CodeProtocol, "job frame: %v", err)
	}
	// A net-probe job takes its input like a local scan, and also asks the proxy for job.URL.
	local := job.Kind == protocol.KindScan && job.Source == protocol.SourceLocal
	probe := job.Kind == protocol.KindNetProbe && netProbeEnabled
	// A url, drive or git job has no input of its own: the host sends an empty stream, and the guest
	// fetches job.URL itself and, for a link to a file, names the file.
	remote := job.Kind == protocol.KindScan && (job.Source == protocol.SourceURL || job.Source == protocol.SourceDrive || job.Source == protocol.SourceGit)
	clone := remote && job.Source == protocol.SourceGit
	if !local && !probe && !remote {
		return fail(protocol.CodeProtocol, "job kind %q with source %q is not supported", job.Kind, job.Source)
	}
	if !remote && (job.Name == "." || !filepath.IsLocal(job.Name) || filepath.Base(job.Name) != job.Name) {
		return fail(protocol.CodeProtocol, "job name %q is not a single path element", protocol.CleanPath(job.Name))
	}
	relay, err := startRelay(dialProxy, unsafeHost, env.Setenv)
	if err != nil {
		return fmt.Errorf("start the relay: %w", err)
	}
	defer relay.close()
	if remote && relay == nil {
		return fail(protocol.CodeIngest, "a %s job needs the network, and this job has none", job.Source)
	}
	start := time.Now()
	jobTime := time.Duration(job.Timeouts.Job) * time.Second
	host.deadline = start.Add(jobTime)

	if err := host.sendJSON(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageIngest}); err != nil {
		return fmt.Errorf("send progress: %w", err)
	}
	dir, err := inputDir(unsafeHost)
	if err != nil {
		return err
	}
	if unsafeHost {
		defer func() { _ = os.RemoveAll(dir) }() // a temp dir of this process
	}
	// The ingest share of the job, or the whole job when the host gave no share.
	ingestTime := jobTime
	if s := time.Duration(job.Timeouts.Ingest) * time.Second; s > 0 {
		ingestTime = min(s, jobTime)
	}
	ingestCtx, cancelIngest := context.WithDeadline(context.Background(), start.Add(ingestTime))
	defer cancelIngest()
	in := &inputReader{host: host}
	stream, err := ingest.Extract(ingestCtx, in, dir)
	if err != nil {
		return fail(ingestCode(err), "ingest: %w", err)
	}
	if err := stream.Verify(*in.end); err != nil {
		return fail(protocol.CodeIngest, "ingest: %w", err)
	}

	var downloaded ingest.File
	switch {
	case clone:
		if err := cloneRepo(ingestCtx, host, job, relay.addr, dir); err != nil {
			return fail(ingestCode(err), "ingest: %w", err)
		}
	case remote:
		if downloaded, err = download(ingestCtx, job, relay.addr, dir); err != nil {
			return fail(ingestCode(err), "ingest: %w", err)
		}
		job.Name = downloaded.Name
	}
	if probe {
		if err := runNetProbe(host, relay, job.URL); err != nil {
			return err
		}
	}
	if err := host.sendJSON(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageAnalyze}); err != nil {
		return fmt.Errorf("send progress: %w", err)
	}
	// The name comes from the host or from a download: it must be one local path element.
	if job.Name == "." || !filepath.IsLocal(job.Name) || filepath.Base(job.Name) != job.Name {
		return fail(protocol.CodeIngest, "the input name %q is not a single local name", protocol.CleanPath(job.Name))
	}
	target := filepath.Join(dir, job.Name)
	if clone {
		target = dir // the repository is the whole directory
	}
	info, err := os.Lstat(target)
	if err != nil {
		return fail(protocol.CodeIngest, "the input has no entry named %q", protocol.CleanPath(job.Name))
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return fail(protocol.CodeIngest, "the entry %q is not a regular file or a directory", protocol.CleanPath(job.Name))
	}
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(max(jobTime-analysisMargin, 0)))
	defer cancel()
	res, err := analyze.Run(ctx, target, static.All())
	if err != nil {
		return fmt.Errorf("analyze: %w", err)
	}
	// The tools share what is left of the job time after the engine.
	toolsLog, err := tools.Apply(ctx, tools.All(), target, &res, func(stage string) error {
		return host.sendJSON(protocol.FrameProgress, protocol.Progress{Stage: stage})
	})
	if err != nil {
		return fmt.Errorf("send progress: %w", err)
	}
	if err := host.send(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactToolsLog, Data: toolsLog}.Marshal()); err != nil {
		return fmt.Errorf("send tools log: %w", err)
	}
	res.Tool = protocol.Tool{Name: "galahad-agent", Version: version}
	if remote && !clone && res.Target.SHA256 != downloaded.SHA256 {
		return fmt.Errorf("the analyzed file has sha256 %s, the download had %s", res.Target.SHA256, downloaded.SHA256)
	}
	if stream.TooDeep > 0 && len(res.Coverage.Skipped) < protocol.MaxSkipped {
		// The extractor dropped entries the analyzer never saw. A full list already ends with a budget skip.
		shallowest := protocol.CleanPath(strings.TrimPrefix(stream.Shallowest, job.Name+"/"))
		res.Coverage.Skipped = append(res.Coverage.Skipped, protocol.Skip{Path: shallowest, Reason: protocol.SkipDepth})
	}
	scoring.Apply(&res)
	if err := res.Validate(); err != nil {
		return fmt.Errorf("invalid result: %w", err)
	}
	data, err := protocol.EncodeResult(&res)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if err := sendResult(host, data); err != nil {
		return fmt.Errorf("send result: %w", err)
	}
	return nil
}

// download fetches the url or drive target of job into dir through the relay at relayAddr.
func download(ctx context.Context, job protocol.Job, relayAddr, dir string) (ingest.File, error) {
	f := ingest.Fetcher{Dial: ingest.TunnelDialer(relayAddr), DriveBase: driveBase()}
	if job.Source == protocol.SourceDrive {
		return f.Drive(ctx, job.URL, dir)
	}
	return f.URL(ctx, job.URL, dir)
}

// ingestCode is the Error code for a failed extraction or download. A failure the control
// channel caused already has its own code.
func ingestCode(err error) string {
	var ce *codeError
	switch {
	case errors.As(err, &ce):
		return ce.code
	case errors.Is(err, ingest.ErrNotAllowed):
		return protocol.CodeNotAllowed
	case errors.Is(err, ingest.ErrDrivePrivate):
		return protocol.CodeDrivePrivate
	case errors.Is(err, ingest.ErrDriveQuota):
		return protocol.CodeDriveQuota
	case errors.Is(err, ingest.ErrTooLarge):
		return protocol.CodeTooLarge
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.CodeTimeout
	}
	return protocol.CodeIngest
}

// inputDir returns the directory for the input: the VM's work disk, or a temp dir on a host
// that is not a VM.
func inputDir(unsafeHost bool) (string, error) {
	if unsafeHost {
		return os.MkdirTemp("", "galahad-input-")
	}
	if err := os.MkdirAll(guestInputDir, 0o750); err != nil {
		return "", err
	}
	return guestInputDir, nil
}
