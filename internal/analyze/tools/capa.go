package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of the capa tool. capa prints a document with every match it found, which is far larger
// than the capabilities it names, so its output cap is its own.
const (
	capaMaxFiles  = 20               // executables per job
	capaMaxSize   = 32 << 20         // bytes of one executable
	capaFileLimit = 60 * time.Second // one executable
	capaTotal     = 5 * time.Minute  // all executables
	capaMaxOutput = 32 << 20         // bytes of the JSON of one executable
	capaMaxNotes  = 8                // problems named in the note
	capaSniff     = 4096             // bytes read to tell an executable from another file
)

var ruleCapa = protocol.Rule{ID: "GAL-CAPA-001", Severity: protocol.SeverityMedium, Title: "Executable has injection, keylogging, credential-theft or anti-debugging capabilities"}

// capaNamespaces are the only capa namespaces that become a finding, with the capability each one
// names. A rule is mapped when its namespace is one of these or below one. Anything else, such as the
// anti-analysis/anti-vm namespace that holds vm-detection, is ignored: many installers and
// legitimate programs check for a virtual machine, so it is never a finding, alone or with others.
var capaNamespaces = []struct{ prefix, capability string }{
	{"host-interaction/process/inject", "injection"},
	{"collection/keylog", "keylogging"},
	{"collection/browser", "credential theft"},
	{"collection/password-manager", "credential theft"},
	{"anti-analysis/anti-debugging", "anti-debugging"},
}

// capaBenign are rules of the mapped namespaces that fire on ordinary software, such as runtimes, games and
// installers. They are not findings, because one medium finding is enough to make a scan suspicious.
var capaBenign = map[string]bool{
	"allocate or change RWX memory":                    true,
	"free user process memory":                         true,
	"attach user process memory":                       true,
	"add value to global atom table":                   true,
	"check for time delay via QueryPerformanceCounter": true,
	"check for time delay via GetTickCount":            true,
}

func init() {
	registered = append(registered, func(env Env) Tool {
		if env.Image != protocol.ImageRE {
			return nil
		}
		return NewCapa(env.Scratch)
	})
}

type capa struct{ scratch string }

// NewCapa returns the capa tool, which runs the capa program of the re image on the PE, ELF and
// Mach-O files of the input. Each run gets a temporary directory below scratch, which is removed
// after the run: capa unpacks itself there, and a run that is killed leaves the files behind. An
// empty scratch means the system temporary directory.
func NewCapa(scratch string) Tool { return capa{scratch: scratch} }

func (capa) Name() string  { return "capa" }
func (capa) Stage() string { return protocol.StageCapa }

func (c capa) Run(ctx context.Context, target string) (Result, error) {
	root, err := scanRoot(target)
	if err != nil {
		return Result{}, err
	}
	files, partial, err := executables(ctx, root)
	if err != nil {
		return Result{}, err
	}
	if len(files) == 0 && !partial {
		return Result{}, nil
	}
	var notes []string
	if partial {
		notes = append(notes, fmt.Sprintf("not every executable was examined: at most %d are, each of at most %d MiB", capaMaxFiles, capaMaxSize>>20))
	}
	if len(files) == 0 {
		return Result{Partial: true, Note: strings.Join(notes, "; ")}, nil
	}
	bin, err := exec.LookPath("capa")
	if err != nil {
		return Result{}, fmt.Errorf("capa is not installed: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, capaTotal)
	defer cancel()
	var res Result
	res.Partial = partial
	scanned := 0
	for _, path := range files {
		rel, _ := relPath(root, path)
		if ctx.Err() != nil {
			res.Partial = true
			notes = append(notes, "out of time before "+rel)
			break
		}
		caps, err := c.file(ctx, bin, path)
		if err != nil {
			res.Partial = true
			if len(notes) < capaMaxNotes {
				notes = append(notes, rel+": "+err.Error())
			}
			if errors.Is(err, errTimedOut) {
				notes = append(notes, "stopped after the first timeout, since the other executables would be slow too")
				break
			}
			continue
		}
		scanned++
		if len(caps) > 0 {
			ev := make([]protocol.Evidence, min(len(caps), protocol.MaxEvidence))
			for i := range ev {
				ev[i] = protocol.Evidence{Path: rel, Snippet: protocol.Snippet(caps[i])}
			}
			res.Findings = append(res.Findings, ruleCapa.Finding(ev...))
		}
	}
	if scanned == 0 {
		return Result{}, errors.New(strings.Join(notes, "; "))
	}
	res.Note = strings.Join(notes, "; ")
	return res, nil
}

// executables lists the PE, ELF and Mach-O files below root, at most capaMaxFiles of them and each
// at most capaMaxSize bytes. partial is set when an executable was left out for its size or because
// there are more of them, or when the walk stopped at its limits.
func executables(ctx context.Context, root string) (files []string, partial bool, err error) {
	seen := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			partial = true
			return nil
		}
		if d.IsDir() {
			if rel, _ := filepath.Rel(root, path); strings.Count(rel, string(filepath.Separator)) >= analyze.MaxDirDepth {
				partial = true
				return filepath.SkipDir
			}
			return nil
		}
		if seen++; seen > analyze.MaxFiles {
			partial = true
			return filepath.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 {
			return nil
		}
		if !isExecutable(path) {
			return nil
		}
		switch {
		case len(files) >= capaMaxFiles:
			partial = true
			return filepath.SkipAll
		case info.Size() > capaMaxSize:
			partial = true
			return nil
		}
		files = append(files, path)
		return nil
	})
	return files, partial, err
}

// isExecutable reports whether the file starts like a PE, ELF or Mach-O file.
func isExecutable(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- a regular file found below the scanned target
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only handle
	head, _ := io.ReadAll(io.LimitReader(f, capaSniff))
	switch ident.Identify(filepath.Base(path), head) {
	case ident.PE, ident.ELF, ident.MachO:
		return true
	}
	return false
}

// file runs capa on one file and returns its mapped capabilities, "<capability>: <rule>". capa is a
// PyInstaller bundle that unpacks about 72 MB into its TMPDIR and removes it only when it ends by
// itself, so every run gets a directory of its own, which is removed whatever happens to the run.
func (c capa) file(ctx context.Context, bin, path string) ([]string, error) {
	tmp, err := os.MkdirTemp(c.scratch, "capa-")
	if err != nil {
		return nil, fmt.Errorf("cannot make a temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }() // best effort; the directory is on the scratch disk of this job
	out, err := executeMax(ctx, capaFileLimit, capaMaxOutput, []string{"TMPDIR=" + tmp}, bin, "-j", "-q", path)
	if err != nil {
		return nil, err
	}
	if out.code != 0 {
		return nil, exitError(out)
	}
	return parseCapa(out.stdout)
}

// capaDoc is the part of the capa JSON document that is used. Its other members are not checked,
// because their set changes with the capa version.
type capaDoc struct {
	Rules *map[string]struct {
		Meta struct {
			Name      string  `json:"name"`
			Namespace *string `json:"namespace"`
		} `json:"meta"`
	} `json:"rules"`
}

// parseCapa reads the document capa prints with -j: one JSON value, with a "rules" object whose
// entries have a meta name. It returns the capabilities of the rules in the namespaces of
// capaNamespaces, sorted by capability and name, once each.
func parseCapa(out []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	var doc capaDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("output is not capa JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("output has data after the JSON document")
	}
	if doc.Rules == nil {
		return nil, errors.New("output has no rules member")
	}
	var caps []string
	for _, r := range *doc.Rules {
		name := r.Meta.Name
		if name == "" || len(name) > protocol.MaxSnippet {
			return nil, errors.New("output has a rule without a usable name")
		}
		if r.Meta.Namespace == nil || capaBenign[name] {
			continue
		}
		for _, m := range capaNamespaces {
			if ns := *r.Meta.Namespace; ns == m.prefix || strings.HasPrefix(ns, m.prefix+"/") {
				caps = append(caps, m.capability+": "+name)
				break
			}
		}
	}
	slices.Sort(caps)
	return slices.Compact(caps), nil
}
