package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// clamTimeout leaves room for a large repo: next.js took more than 3 minutes in a CI VM.
const clamTimeout = 5 * time.Minute

var ruleAV = protocol.Rule{ID: "GAL-AV-001", Severity: protocol.SeverityHigh, Title: "Antivirus signature match"}

// clamSig is what ClamAV names a signature: no spaces, no control characters.
var clamSig = regexp.MustCompile(`^[\x21-\x7e]{1,128}$`)

func init() {
	registered = append(registered, func(Env) Tool { return NewClamAV(filepath.Join(sigRoot, "clamav")) })
}

type clamav struct{ db string }

// NewClamAV returns the ClamAV tool, which scans with the signature directory db.
func NewClamAV(db string) Tool { return clamav{db: db} }

func (clamav) Name() string  { return "clamav" }
func (clamav) Stage() string { return protocol.StageClamAV }

func (c clamav) Run(ctx context.Context, target string) (Result, error) {
	if entries, err := os.ReadDir(c.db); err != nil || len(entries) == 0 {
		return Result{}, fmt.Errorf("no signatures in %s", protocol.CleanPath(c.db))
	}
	bin, err := exec.LookPath("clamscan")
	if err != nil {
		return Result{}, fmt.Errorf("clamscan is not installed: %w", err)
	}
	root, err := scanRoot(target)
	if err != nil {
		return Result{}, err
	}
	out, err := execute(ctx, clamTimeout, bin, "-r", "--database="+c.db, "--infected", "--no-summary",
		"--heuristic-alerts=no", "--max-filesize=32M", "--max-scansize=256M", "--max-recursion=6", root)
	if err != nil {
		return Result{}, err
	}
	switch out.code {
	case 0: // nothing infected, and with --infected nothing is printed
		if len(out.stdout) > 0 {
			return Result{}, errors.New("exit 0 with output")
		}
		return Result{}, nil
	case 1: // infected files found
		// The exit code is the one thing a file name cannot forge. So when the output does not
		// parse in full, for example because a name holds " FOUND\n", the hit is not dropped:
		// it is reported on the target, next to the records that did parse.
		fs, err := parseClamAV(out.stdout, root)
		if err == nil && len(fs) > 0 {
			return Result{Findings: fs}, nil
		}
		if err == nil {
			err = errors.New("exit 1 without a hit")
		}
		fs = append(fs, ruleAV.Finding(protocol.Evidence{Path: protocol.CleanPath(filepath.Base(root)), Snippet: "unparsed clamscan hit"}))
		return Result{Findings: fs, Note: err.Error()}, nil
	case 2: // some files could not be scanned. With --infected stdout holds hits only, so a hit that came with the errors is not dropped.
		fs, err := parseClamAV(out.stdout, root)
		if len(fs) == 0 {
			return Result{}, exitError(out)
		}
		note := "exit 2: some files could not be scanned"
		if err != nil {
			note += "; " + err.Error()
		}
		return Result{Findings: fs, Note: note}, nil
	}
	return Result{}, exitError(out)
}

// parseClamAV reads the lines "<path>: <signature> FOUND" of clamscan --infected. A path can
// hold ": " and newlines, so each record ends at " FOUND\n", the signature is what follows the
// last ": ", and a piece that does not name a signature of a file under root is joined with the
// next one. On an error it still returns the findings parsed before it.
func parseClamAV(out []byte, root string) ([]protocol.Finding, error) {
	var fs []protocol.Finding
	text, pending := string(out), ""
	for text != "" {
		chunk, rest, ok := strings.Cut(text, " FOUND\n")
		if !ok {
			return fs, errors.New("output does not end in FOUND")
		}
		text = rest
		rec := pending + chunk
		i := strings.LastIndex(rec, ": ")
		if i < 0 || !clamSig.MatchString(rec[i+2:]) {
			pending = rec + " FOUND\n"
			continue
		}
		rel, ok := relPath(root, rec[:i])
		if !ok {
			pending = rec + " FOUND\n"
			continue
		}
		pending = ""
		fs = append(fs, ruleAV.Finding(protocol.Evidence{Path: rel, Snippet: protocol.Snippet(rec[i+2:])}))
	}
	if pending != "" {
		return fs, errors.New("output has a line that is not a hit")
	}
	return fs, nil
}

// exitError describes a tool that ended with a code it does not use for success.
func exitError(o output) error {
	why := "was killed"
	if o.code >= 0 {
		why = fmt.Sprintf("exited with code %d", o.code)
	}
	if msg, _, _ := strings.Cut(strings.TrimSpace(o.stderr), "\n"); msg != "" {
		why += ": " + msg
	}
	return errors.New(why)
}
