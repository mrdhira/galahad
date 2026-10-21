package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/tools"
	"github.com/mrdhira/galahad/internal/ingest"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of the update job.
const (
	freshclamTimeout = 20 * time.Minute
	yarcTimeout      = 3 * time.Minute
	yaraDownloadTime = 5 * time.Minute
	maxYaraZip       = 64 << 20  // bytes
	maxYaraRules     = 256 << 20 // bytes of the rules file inside the zip
	maxZipMembers    = 100
	maxUpdateLog     = 32 << 10 // bytes of tools.log
	logLines         = 20       // lines kept of the output of a tool
)

// yaraForgeCoreURL is the latest release of the YARA-Forge "core" rule set, the one that keeps the
// false positives lowest. It is a zip with one .yar file. Upstream publishes no checksum or signature
// for it, and it is rebuilt every week, so a pin would freeze the rules. The download goes over https
// to the release host, which the update policy of the host proxy allows, within the size and time
// limits above. The zip must hold exactly one rules file, and yarac must compile it. The sha256 of
// the zip goes to tools.log of the job.
const yaraForgeCoreURL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

// freshclamConf is the configuration of freshclam: the arguments are the database directory and the
// host and port of the relay. DNSDatabaseInfo is off because the guest has no DNS, and the proxy is
// the relay, which turns the CONNECT of the HTTPS download into a tunnel through the host proxy.
const freshclamConf = `DatabaseDirectory %s
DatabaseOwner root
DNSDatabaseInfo no
DatabaseMirror database.clamav.net
HTTPProxyServer %s
HTTPProxyPort %s
ConnectTimeout 30
ReceiveTimeout 120
MaxAttempts 3
`

// runUpdate is the guest side of an update job. It formats and mounts the signatures drive, runs
// freshclam into <drive>/clamav, downloads the YARA-Forge core rules and compiles them to
// <drive>/yara/core.yarc, unmounts the drive and reports success with an empty Result. The job
// has no sample. scratch is where the downloads go, and relayAddr is the address of the relay.
func runUpdate(host *hostConn, relayAddr, scratch string, unsafeHost bool, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	var log bytes.Buffer
	err := updateSignatures(ctx, host, &log, relayAddr, scratch, unsafeHost)
	// The log goes to the host on a failure as well: it is how a failed update is understood.
	sendErr := host.send(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactToolsLog, Data: log.Bytes()[:min(log.Len(), maxUpdateLog)]}.Marshal())
	if err != nil {
		return err
	}
	if sendErr != nil {
		return fmt.Errorf("send tools log: %w", sendErr)
	}
	now := time.Now().UTC()
	res := protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad-agent", Version: version},
		Target:        protocol.Target{Name: "signatures", Kind: protocol.TargetDir},
		StartedAt:     now, FinishedAt: now,
		Files: []protocol.FileInfo{}, Findings: []protocol.Finding{}, IOCs: []protocol.IOC{},
		Coverage: protocol.Coverage{Skipped: []protocol.Skip{}, Analyzers: []string{}},
		Reasons:  []string{},
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

func updateSignatures(ctx context.Context, host *hostConn, log *bytes.Buffer, relayAddr, scratch string, unsafeHost bool) error {
	sig, unmount, err := signaturesDir(ctx, unsafeHost)
	if err != nil {
		return err
	}
	for _, d := range []string{"clamav", "yara"} {
		if err := os.MkdirAll(filepath.Join(sig, d), 0o755); err != nil { // #nosec G301 -- the scan VMs read the drive as another user
			return fmt.Errorf("make %s on the signatures drive: %w", d, err)
		}
	}

	if err := host.sendJSON(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageClamAV}); err != nil {
		return fmt.Errorf("send progress: %w", err)
	}
	if err := freshclam(ctx, log, relayAddr, scratch, filepath.Join(sig, "clamav")); err != nil {
		return err
	}

	if err := host.sendJSON(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageYARA}); err != nil {
		return fmt.Errorf("send progress: %w", err)
	}
	if err := yaraRules(ctx, log, relayAddr, scratch, filepath.Join(sig, "yara", "core.yarc")); err != nil {
		return err
	}

	// Every file is closed, so this makes the drive consistent for the read-only mount of the scan VMs.
	if err := unmount(); err != nil {
		return fmt.Errorf("unmount the signatures drive: %w", err)
	}
	return nil
}

// signaturesDir returns the directory of the signatures drive and the function that finishes it.
// In the VM it formats and mounts the new drive. Outside a VM there is no drive: a galahadtest
// build uses the directory its test names, and a release build refuses.
func signaturesDir(ctx context.Context, unsafeHost bool) (dir string, finish func() error, err error) {
	if unsafeHost {
		if dir = testSigDir(); dir == "" {
			return "", nil, errors.New("an update job needs the signatures drive of the VM")
		}
		return dir, func() error { return nil }, nil
	}
	finish, err = mountSignatures(ctx)
	return sigMount, finish, err
}

// freshclam downloads the ClamAV databases into db, and checks that the main and daily databases are there.
func freshclam(ctx context.Context, log *bytes.Buffer, relayAddr, scratch, db string) error {
	host, port, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return fmt.Errorf("the relay address: %w", err)
	}
	conf := filepath.Join(scratch, "freshclam.conf")
	if err := os.WriteFile(conf, fmt.Appendf(nil, freshclamConf, db, host, port), 0o600); err != nil {
		return fmt.Errorf("write the freshclam configuration: %w", err)
	}
	stdout, stderr, code, err := tools.Exec(ctx, freshclamTimeout, "freshclam", "--config-file="+conf, "--stdout")
	logOutput(log, "freshclam", string(stdout)+stderr)
	if err != nil {
		return fmt.Errorf("freshclam: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("freshclam exited with code %d: %s", code, lastLine(string(stdout)+stderr))
	}
	for _, name := range []string{"main", "daily"} {
		if !isFile(filepath.Join(db, name+".cvd")) && !isFile(filepath.Join(db, name+".cld")) {
			return fmt.Errorf("freshclam left no %s database", name)
		}
	}
	fmt.Fprintf(log, "freshclam: ok\n")
	return nil
}

// yaraRules downloads the YARA-Forge core release through the relay and compiles its rules file to dst.
func yaraRules(ctx context.Context, log *bytes.Buffer, relayAddr, scratch, dst string) error {
	dir := filepath.Join(scratch, "yara-forge")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("make the download directory: %w", err)
	}
	f := ingest.Fetcher{Dial: ingest.TunnelDialer(relayAddr), MaxBytes: maxYaraZip, Timeout: yaraDownloadTime}
	file, err := f.URL(ctx, yaraForgeURL(), dir)
	if err != nil {
		return fail(ingestCode(err), "download the YARA-Forge rules: %w", err)
	}
	fmt.Fprintf(log, "yara-forge: %s, %d bytes, sha256 %s\n", file.Name, file.Size, file.SHA256)

	rules := filepath.Join(dir, "rules.yar")
	if err := extractRules(filepath.Join(dir, file.Name), rules); err != nil {
		return err
	}
	_, stderr, code, err := tools.Exec(ctx, yarcTimeout, "yarac", rules, dst)
	logOutput(log, "yarac", stderr)
	if err != nil {
		return fmt.Errorf("yarac: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("yarac exited with code %d: %s", code, lastLine(stderr))
	}
	if st, err := os.Stat(dst); err != nil || !st.Mode().IsRegular() || st.Size() == 0 {
		return errors.New("yarac wrote no rules file")
	}
	if err := os.Chmod(dst, 0o644); err != nil { // #nosec G302 -- the scan VMs read the drive as another user
		return fmt.Errorf("yarac: %w", err)
	}
	fmt.Fprintf(log, "yarac: ok\n")
	return nil
}

// extractRules copies the one .yar file of the zip at src to dst. The names in the zip are never used as paths.
func extractRules(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("the YARA-Forge zip: %w", err)
	}
	defer func() { _ = zr.Close() }() // read-only
	if len(zr.File) > maxZipMembers {
		return fmt.Errorf("the YARA-Forge zip has more than %d members", maxZipMembers)
	}
	var rules *zip.File
	for _, m := range zr.File {
		if m.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(m.Name), ".yar") {
			continue
		}
		if rules != nil {
			return errors.New("the YARA-Forge zip has more than one .yar file")
		}
		rules = m
	}
	if rules == nil {
		return errors.New("the YARA-Forge zip has no .yar file")
	}
	if rules.UncompressedSize64 > maxYaraRules {
		return fmt.Errorf("the rules file is %d bytes, more than the %d allowed", rules.UncompressedSize64, maxYaraRules)
	}
	rc, err := rules.Open()
	if err != nil {
		return fmt.Errorf("the YARA-Forge zip: %w", err)
	}
	defer func() { _ = rc.Close() }()                                      // read-only
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a fixed name in the download directory
	if err != nil {
		return fmt.Errorf("write the rules file: %w", err)
	}
	n, err := io.Copy(out, io.LimitReader(rc, maxYaraRules+1)) // #nosec G110 -- limited here
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return fmt.Errorf("unpack the rules file: %w", err)
	case n > maxYaraRules:
		return fmt.Errorf("the rules file is larger than %d bytes", maxYaraRules)
	}
	return nil
}

// logOutput writes the last lines of the output of a tool to the log, cleaned and cut like any text from the guest.
func logOutput(log *bytes.Buffer, name, text string) {
	lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' })
	for _, l := range lines[max(len(lines)-logLines, 0):] {
		fmt.Fprintf(log, "%s: %s\n", name, protocol.Snippet(l))
	}
}

// lastLine returns the last non-empty line of text, to say why a tool failed.
func lastLine(text string) string {
	lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) == 0 {
		return "no output"
	}
	return protocol.Snippet(lines[len(lines)-1])
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
