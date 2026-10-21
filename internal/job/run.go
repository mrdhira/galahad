package job

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
	"github.com/mrdhira/galahad/internal/report"
	"github.com/mrdhira/galahad/internal/sandbox"
	"github.com/mrdhira/galahad/internal/scoring"
)

const (
	// DefaultTimeout is the time limit of a whole job, ClamAV and YARA included, for the core image.
	// The re image gets twice as much, for capa.
	DefaultTimeout = 10 * time.Minute
	// MinTimeout is the shortest job time limit. The guest stops its analysis a minute before
	// the end of the job, so a shorter limit would leave it no time.
	MinTimeout = 2 * time.Minute

	controlPort   = 1024
	acceptTimeout = 30 * time.Second // for the guest to connect, and to say hello
	writeGrace    = 5 * time.Second  // how long the guest's own answer is awaited after a failed write
	maxArtifact   = 1 << 20          // bytes kept of one artifact
	readSlack     = time.Second      // how long after the job deadline a read gives up
)

// artifactNames are the file names of the artifacts below the job directory. galahadtest builds
// add the probe artifact.
var artifactNames = map[protocol.ArtifactID]string{
	protocol.ArtifactIngestLog: "ingest.log",
	protocol.ArtifactToolsLog:  "tools.log",
}

// Spec says how to run a job.
type Spec struct {
	JobsDir string
	// Now returns the current time.
	Now func() time.Time
	// Version is the version of this program. The agent must report the same one, unless it is "dev".
	Version string
	// Timeout is the time limit of the whole job, at least MinTimeout.
	Timeout time.Duration
	Image   string
	// CPUs and MemoryMiB size the machine. Zero leaves the choice to the backend.
	CPUs      int
	MemoryMiB int
	// NoNetwork gives the guest no proxy port, so it has no network at all.
	NoNetwork bool
	// Source says what the target is: protocol.SourceLocal (the default) for a path, or
	// protocol.SourceURL, SourceDrive or SourceGit for a link that the guest fetches.
	Source string
	// AllowHosts are the extra hosts the guest may reach (--allow-host).
	AllowHosts []string
	// Submodules asks the guest to update the submodules of a Git target.
	Submodules bool
	// Signatures is the signatures image: a scan attaches it read-only, and the update job fills it. Empty
	// means the machine gets no signatures drive.
	Signatures string
	// Progress is called with each stage the guest reports. It may be nil.
	Progress func(stage string)
}

// Outcome is what a job leaves. Job is set as soon as the job directory exists. Result and
// Paths are set when the job is done.
type Outcome struct {
	Job    Job
	Result *protocol.Result
	Paths  report.Paths
}

// Run scans a local file or folder, or a link the guest downloads (spec.Source), in a machine of
// backend and writes the reports into the job directory. It checks the input first, so an input
// over the caps fails before anything boots.
// The error says why the job did not end in the state done; job.json has that state. The
// machine is always killed before Run returns.
func Run(ctx context.Context, backend sandbox.Backend, spec Spec, target string) (Outcome, error) {
	if err := checkTimeout(spec.Timeout); err != nil {
		return Outcome{}, err
	}
	in, err := newPlan(spec.Source, target)
	if err != nil {
		return Outcome{}, err
	}
	return execute(ctx, backend, spec, in, in.jobTarget(target), spec.AllowHosts)
}

func checkTimeout(d time.Duration) error {
	if d < MinTimeout {
		return fmt.Errorf("the timeout %s is shorter than the minimum %s", d, MinTimeout)
	}
	return nil
}

// execute runs the job of plan in a machine of backend. It makes the job directory and the proxy policy, and
// leaves the state of the job in job.json.
func execute(ctx context.Context, backend sandbox.Backend, spec Spec, in *plan, target Target, allowHosts []string) (Outcome, error) {
	pol, err := in.policy(allowHosts)
	if err != nil {
		return Outcome{}, err
	}
	now := spec.Now()
	j, err := Create(spec.JobsDir, now, target, spec.Image, backend.Name())
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{Job: j}

	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	r := &runner{backend: backend, spec: spec, in: in, pol: pol, jobDir: Dir(spec.JobsDir, j.ID), job: &out.Job, start: now}
	runErr := r.run(ctx, &out)

	switch {
	case runErr == nil:
		out.Job.State = StateDone
		if out.Result != nil { // an update has no Result to report
			out.Job.ExitCode = out.Result.Verdict.ExitCode()
			out.Job.Verdict, out.Job.Score = string(out.Result.Verdict), out.Result.Score
		}
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		out.Job.State = StateTimeout
		runErr = fmt.Errorf("timed out: %w", runErr)
	case ctx.Err() != nil:
		out.Job.State = StateCanceled
		runErr = fmt.Errorf("canceled: %w", runErr)
	default:
		out.Job.State = StateFailed
	}
	if runErr != nil {
		out.Result, out.Paths = nil, report.Paths{}
		out.Job.ExitCode = 1
		out.Job.Error = protocol.CleanPath(runErr.Error())
	}
	finished := spec.Now().UTC()
	out.Job.FinishedAt = &finished
	if err := Save(spec.JobsDir, out.Job); err != nil {
		return out, errors.Join(runErr, err)
	}
	return out, runErr
}

// runner is the state of one job.
type runner struct {
	backend sandbox.Backend
	spec    Spec
	in      *plan
	pol     proxy.Policy
	jobDir  string
	job     *Job
	start   time.Time
	px      *netProxy // nil without network
}

func (r *runner) setState(s State) error {
	r.job.State = s
	return Save(r.spec.JobsDir, *r.job)
}

// event is one frame of the guest, or the error that ended the stream.
type event struct {
	typ     protocol.FrameType
	payload []byte
	err     error
}

func (r *runner) run(ctx context.Context, out *Outcome) error {
	if err := r.setState(StateBooting); err != nil {
		return err
	}
	ports := []uint32{controlPort}
	probe := r.in.probe
	if !r.spec.NoNetwork {
		ports = append(ports, proxyPort)
	}
	m, err := r.backend.Start(ctx, sandbox.Spec{
		JobDir: r.jobDir, Image: r.spec.Image, CPUs: r.spec.CPUs, MemoryMiB: r.spec.MemoryMiB, Ports: ports,
		Signatures: r.spec.Signatures, SignaturesWritable: r.in.update, // only the update job writes the drive
	})
	if err != nil {
		return fmt.Errorf("start the sandbox: %w", err)
	}
	defer func() { _ = m.Kill() }() // best effort; it removes the transient files
	l := m.Listener(controlPort)
	if l == nil {
		return errors.New("the sandbox has no control listener")
	}
	if !r.spec.NoNetwork {
		pl := m.Listener(proxyPort)
		if pl == nil {
			return errors.New("the sandbox has no proxy listener")
		}
		if r.px, err = startProxy(ctx, pl, r.jobDir, r.pol); err != nil {
			return err
		}
		defer func() { _, _ = r.px.stop() }()
	}
	exited := make(chan struct{})
	go func() {
		_ = m.Wait() // how it ended does not matter; the guest's frames say why
		close(exited)
	}()

	conn, err := accept(ctx, l, exited)
	if err != nil {
		return err
	}
	var reader sync.WaitGroup
	done := make(chan struct{})
	defer func() { // free every blocked call, kill the machine, then wait for the reader
		close(done)
		_ = conn.Close() // the session is over
		_ = m.Kill()     // before any wait: a stuck file read must not keep the machine alive
		reader.Wait()
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // unblocks every read and write
	defer stop()

	deadline, _ := ctx.Deadline()        // Run always sets one
	readLimit := deadline.Add(readSlack) // the context ends the job first, so the state says timeout
	order := protocol.NewGuestOrder()
	next := func(limit time.Time) (protocol.FrameType, []byte, error) {
		_ = conn.SetReadDeadline(limit) // if the connection is gone, the read says so
		t, payload, err := protocol.ReadFrameOf(conn, order.Allowed()...)
		if err != nil {
			return 0, nil, err
		}
		return t, payload, order.Accept(t)
	}

	_, payload, err := next(minTime(time.Now().Add(acceptTimeout), readLimit))
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if err := r.checkHello(payload); err != nil {
		return err
	}
	if err := r.setState(StateRunning); err != nil {
		return err
	}

	job := protocol.Job{
		ID: r.job.ID, Kind: protocol.KindScan, Source: r.in.source, Name: r.in.name, URL: cmp.Or(r.in.url, probe), Submodules: r.spec.Submodules,
		Timeouts: protocol.Timeouts{Job: min(max(int(time.Until(deadline).Seconds()), 1), protocol.MaxTimeoutSec)},
		Now:      r.start.UTC(),
	}
	if probe != "" { // a net-probe job takes the input like a local scan and also asks for the URL
		job.Kind, job.Source = protocol.KindNetProbe, ""
	}
	if r.in.update {
		job.Kind, job.Source = protocol.KindUpdate, ""
	}
	var endSent atomic.Bool
	sentCh := make(chan sent, 1)
	go func() { // the guest may stop reading early, so its frames are read while the input is written
		sentCh <- r.in.send(conn, job, &endSent) // buffered: a writer stuck in a file read is left behind
	}()
	reader.Add(1)
	events := make(chan event)
	go func() {
		defer reader.Done()
		for {
			t, p, err := next(readLimit)
			select {
			case events <- event{typ: t, payload: p, err: err}:
			case <-done:
				return
			}
			if err != nil || order.Complete() {
				return
			}
		}
	}()

	var s sent // what the writer reports, once it has
	var writeErr error
	var grace <-chan time.Time
	written := (<-chan sent)(sentCh) // nil once the result of the writer is taken
	artifacts := map[protocol.ArtifactID]int{}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case s = <-written:
			written = nil
			if s.err != nil {
				writeErr = s.err
				grace = time.After(writeGrace) // the guest may have said why it stopped reading
			}
		case <-grace:
			return writeErr
		case ev := <-events:
			if ev.err != nil {
				if writeErr != nil {
					return writeErr
				}
				return fmt.Errorf("read from the guest: %w", ev.err)
			}
			switch ev.typ {
			case protocol.FrameProgress:
				var p protocol.Progress
				if err := decode(ev.payload, &p); err != nil {
					return fmt.Errorf("progress frame: %w", err)
				}
				if r.spec.Progress != nil {
					r.spec.Progress(p.Stage)
				}
			case protocol.FrameArtifact:
				if err := r.storeArtifact(ev.payload, artifacts); err != nil {
					return err
				}
			case protocol.FrameError:
				var e protocol.Error
				if err := decode(ev.payload, &e); err != nil {
					return fmt.Errorf("error frame: %w", err)
				}
				return r.guestError(e, out)
			case protocol.FrameResult:
				if !endSent.Load() {
					return errors.New("the guest sent a result before the end of the input")
				}
				if written != nil {
					s = <-written // End is out, so the writer is finishing
				}
				if s.err != nil {
					return s.err
				}
				return r.finish(ev.payload, s.fileSHA, out)
			}
		}
	}
}

// accept waits for the guest to connect to l. It gives up when the machine exits first.
func accept(ctx context.Context, l net.Listener, exited <-chan struct{}) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.Accept()
		ch <- result{c, err}
	}()
	timer := time.NewTimer(acceptTimeout)
	defer timer.Stop()
	var why error
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("accept the guest: %w", r.err)
		}
		return r.conn, nil
	case <-timer.C:
		why = fmt.Errorf("the guest did not connect within %s", acceptTimeout)
	case <-exited:
		why = errors.New("the sandbox exited before the guest connected")
	case <-ctx.Done():
		why = ctx.Err()
	}
	_ = l.Close() // unblocks Accept
	if r := <-ch; r.conn != nil {
		_ = r.conn.Close() // it came in at the last moment
	}
	return nil, why
}

func (r *runner) checkHello(payload []byte) error {
	var h protocol.Hello
	if err := decode(payload, &h); err != nil {
		return fmt.Errorf("hello frame: %w", err)
	}
	if r.spec.Version != "dev" && h.AgentVersion != r.spec.Version {
		return fmt.Errorf("the agent is version %q, this program is %q", protocol.CleanPath(h.AgentVersion), protocol.CleanPath(r.spec.Version))
	}
	return nil
}

// finish checks the Result, scores it again, and writes the reports.
func (r *runner) finish(payload []byte, fileSHA string, out *Outcome) error {
	var res protocol.Result
	if err := decode(payload, &res); err != nil {
		return fmt.Errorf("result frame: %w", err)
	}
	if r.spec.Version != "dev" && res.Tool.Version != r.spec.Version {
		return fmt.Errorf("the result is from version %q, this program is %q", protocol.CleanPath(res.Tool.Version), protocol.CleanPath(r.spec.Version))
	}
	if r.in.update {
		// There is nothing to report: the Result of an update only says that it went through.
		if _, err := r.px.stop(); err != nil {
			return fmt.Errorf("the proxy: %w", err)
		}
		return nil
	}
	wantKind := protocol.TargetDir
	if !r.in.isDir {
		wantKind = protocol.TargetFile
	}
	if res.Target.Kind != wantKind {
		return fmt.Errorf("the result is for a %s, the input is a %s", res.Target.Kind, wantKind)
	}
	// The host cannot hash what the guest downloaded, so for a link the hash is the guest's own
	// word, like the rest of the Result: Validate above checked its format and no more.
	if !r.in.isDir && !r.in.remote() && res.Target.SHA256 != fileSHA {
		return fmt.Errorf("the result has sha256 %s for the target, the host sent %s", res.Target.SHA256, fileSHA)
	}
	if res.Network != nil {
		return errors.New("the result has network data; only the host writes it")
	}
	for _, f := range res.Findings {
		if f.RuleID == ruleNetBlocked.ID {
			return fmt.Errorf("the result has a %s finding; only the host adds it", ruleNetBlocked.ID)
		}
	}
	// The proxy is stopped first, so the decisions are final. They are the host's own: nothing
	// the guest says about the network is used.
	events, err := r.px.stop()
	if err != nil {
		return fmt.Errorf("the proxy: %w", err)
	}
	res.Network = networkOf(events)
	r.job.Blocked = slices.ContainsFunc(events, func(ev proxy.Event) bool { return ev.Blocked })
	addNetworkFinding(&res)
	scoring.Apply(&res)
	paths, err := report.Write(r.jobDir, &res)
	if err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	out.Result, out.Paths = &res, paths
	return nil
}

// storeArtifact appends the raw bytes of an Artifact frame to its file, which keeps at most maxArtifact bytes.
func (r *runner) storeArtifact(payload []byte, kept map[protocol.ArtifactID]int) error {
	a, err := protocol.ParseArtifact(payload)
	if err != nil {
		return fmt.Errorf("artifact frame: %w", err)
	}
	name, ok := artifactNames[a.ID]
	if !ok {
		return fmt.Errorf("artifact frame: artifact id %d is not accepted here", byte(a.ID))
	}
	data := a.Data[:min(len(a.Data), maxArtifact-kept[a.ID])]
	if len(data) == 0 {
		return nil // nothing is kept past the cap, so the file is left alone
	}
	kept[a.ID] += len(data)
	dir := filepath.Join(r.jobDir, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store artifact: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- the name comes from a fixed list
	if err != nil {
		return fmt.Errorf("store artifact: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close() // the write error is the one to report
		return fmt.Errorf("store artifact: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store artifact: %w", err)
	}
	return nil
}

// decode decodes a message strictly and validates it.
func decode(payload []byte, v interface{ Validate() error }) error {
	if err := protocol.DecodeStrict(payload, v); err != nil {
		return err
	}
	return v.Validate()
}

func writeJSON(conn net.Conn, t protocol.FrameType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeIdle)); err != nil {
		return err
	}
	return protocol.WriteFrame(conn, t, data)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// guestError handles an Error frame of the guest. When a link led the guest to a request to an address
// that is not public, the job still ends done: the host reports what its own proxy saw (blockedResult).
// Otherwise it returns the error. For the codes about the network the text is the host's own, built from
// its proxy record, so nothing the guest wrote is repeated, and the host named in the hint is one the
// proxy saw and refused.
func (r *runner) guestError(e protocol.Error, out *Outcome) error {
	if r.in.remote() {
		events, err := r.px.stop() // the decisions are final once the guest has failed
		if err != nil {
			return fmt.Errorf("the proxy: %w", err)
		}
		if slices.ContainsFunc(events, func(ev proxy.Event) bool { return ev.Blocked }) {
			return r.blockedResult(events, out)
		}
	}
	var why string
	switch e.Code {
	case protocol.CodeDrivePrivate:
		why = "the Drive file is not public; share it with anyone who has the link, or download it and scan the file"
	case protocol.CodeDriveQuota:
		why = "Drive refuses the download because of its quota; try again later"
	case protocol.CodeNotAllowed:
		why = r.deniedText()
	default:
		return fmt.Errorf("the guest failed (%s): %s", e.Code, e.Message)
	}
	return fmt.Errorf("the guest failed (%s): %s", e.Code, why)
}

// deniedText says what the proxy refused last. A host that is only not on the allowlist comes with
// the flag to allow it.
func (r *runner) deniedText() string {
	events, _ := r.px.stop() // the decisions are final once the guest has failed; a stop error does not change the text
	last := -1
	for i, e := range events {
		if e.Decision == proxy.Denied {
			last = i
		}
	}
	if last < 0 {
		return "the proxy refused a connection"
	}
	d := events[last]
	text := fmt.Sprintf("CONNECT %s:%d denied: %s", d.Host, d.Port, d.Reason)
	if _, err := proxy.NewPolicy(proxy.Input{AllowHosts: []string{d.Host}}); err == nil && d.Reason == proxy.ReasonHostNotAllowed && !r.in.update {
		text += fmt.Sprintf("; if you trust %s, rerun with --allow-host %s", d.Host, d.Host)
	}
	return text
}

// blockedResult reports a link whose download led to a blocked request. There is nothing to analyze, so
// the host builds the Result from its own records: the link as the target, the blocked requests, and
// GAL-NET-001, which makes the verdict suspicious. The coverage and the reasons say that the input was
// never read, so the report does not pass for an analysis of content.
func (r *runner) blockedResult(events []proxy.Event, out *Outcome) error {
	res := protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad", Version: r.spec.Version},
		Target:        protocol.Target{Name: protocol.CleanPath(r.in.url), Kind: protocol.TargetFile},
		StartedAt:     r.start.UTC(),
		FinishedAt:    r.spec.Now().UTC(),
		Files:         []protocol.FileInfo{},
		Findings:      []protocol.Finding{},
		IOCs:          []protocol.IOC{},
		Coverage: protocol.Coverage{
			FilesSeen: 1,
			Skipped:   []protocol.Skip{{Path: "(download)", Reason: protocol.SkipUnreadable}},
			Analyzers: []string{"network"},
		},
	}
	res.Network = networkOf(events)
	r.job.Blocked = true
	addNetworkFinding(&res)
	scoring.Apply(&res)
	res.Reasons = append(res.Reasons, "the input could not be downloaded, so only the network requests were examined")
	if err := res.Validate(); err != nil {
		return fmt.Errorf("the result of the host: %w", err)
	}
	paths, err := report.Write(r.jobDir, &res)
	if err != nil {
		return fmt.Errorf("write the report: %w", err)
	}
	out.Result, out.Paths = &res, paths
	return nil
}
