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

const yaraTimeout = 2 * time.Minute

var ruleYARA = protocol.Rule{ID: "GAL-YARA-001", Severity: protocol.SeverityMedium, Title: "YARA rule match"}

// yaraRule is the identifier of a YARA rule.
var yaraRule = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func init() {
	registered = append(registered, func(Env) Tool { return NewYARA(filepath.Join(sigRoot, "yara", "core.yarc")) })
}

type yara struct{ rules string }

// NewYARA returns the YARA tool, which scans with the compiled rules file rules.
func NewYARA(rules string) Tool { return yara{rules: rules} }

func (yara) Name() string  { return "yara" }
func (yara) Stage() string { return protocol.StageYARA }

func (y yara) Run(ctx context.Context, target string) (Result, error) {
	if info, err := os.Stat(y.rules); err != nil || !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("no rules at %s", protocol.CleanPath(y.rules))
	}
	bin, err := exec.LookPath("yara")
	if err != nil {
		return Result{}, fmt.Errorf("yara is not installed: %w", err)
	}
	root, err := scanRoot(target)
	if err != nil {
		return Result{}, err
	}
	out, err := execute(ctx, yaraTimeout, bin, "-C", "-N", "-r", "-f", y.rules, root)
	if err != nil {
		return Result{}, err
	}
	if out.code != 0 {
		return Result{}, exitError(out)
	}
	fs, err := parseYARA(out.stdout, root)
	return Result{Findings: fs}, err
}

// parseYARA reads the lines "<rule> <path>" of yara. A rule name has no space, so the path
// starts after the first one. A path can hold newlines, so a line that does not start a
// record for a file under root continues the path of the one before it.
func parseYARA(out []byte, root string) ([]protocol.Finding, error) {
	if len(out) == 0 {
		return nil, nil
	}
	if out[len(out)-1] != '\n' {
		return nil, errors.New("output does not end in a newline")
	}
	var fs []protocol.Finding
	var rule, path string
	flush := func() {
		rel, _ := relPath(root, path) // the first line of a record is checked, and a continuation only extends the path
		fs = append(fs, ruleYARA.Finding(protocol.Evidence{Path: rel, Snippet: protocol.Snippet(rule)}))
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(string(out), "\n"), "\n") {
		name, p, ok := strings.Cut(line, " ")
		if _, under := relPath(root, p); ok && yaraRule.MatchString(name) && under {
			if rule != "" {
				flush()
			}
			rule, path = name, p
			continue
		}
		if rule == "" {
			return nil, errors.New("output has a line that is not a match")
		}
		path += "\n" + line
	}
	flush()
	return fs, nil
}
