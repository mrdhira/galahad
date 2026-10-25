package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/deps"
	"github.com/mrdhira/galahad/internal/ingest"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of the OSV tool.
const (
	osvRequests    = 3                // requests to the API, which is every request of a job
	osvTotal       = 30 * time.Second // all requests
	osvBatch       = 1000             // queries in one request, the limit of the API
	osvMaxPackages = osvRequests * osvBatch
	osvMaxResponse = 8 << 20 // bytes of one response
	osvMaxRead     = analyze.MaxExtraBytes
	osvHandshake   = 10 * time.Second
)

// osvBase is the address of the API. galahadtest builds can replace it (osvbase_galahadtest.go).
var osvBase = "https://api.osv.dev"

var ruleOSV = protocol.Rule{ID: "GAL-DEPS-005", Severity: protocol.SeverityCritical, Title: "Dependency is a known malicious package (OSV)", Attack: "T1195.001"}

// osvID is an OSV identifier. Only the ones with the prefix MAL- are malicious packages: OSV also
// lists vulnerabilities, which say nothing about the intent of the package.
var osvID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func init() {
	registered = append(registered, func(env Env) Tool { return NewOSV(env.Relay, osvBase) })
}

type osv struct{ relay, base string }

// NewOSV returns the OSV tool. It looks up the pinned dependencies of the input at the API at base,
// through the relay at relay, a host:port. It makes no request when the input pins nothing.
func NewOSV(relay, base string) Tool { return osv{relay: relay, base: base} }

func (osv) Name() string  { return "osv" }
func (osv) Stage() string { return protocol.StageOSV }

func (o osv) Run(ctx context.Context, target string) (Result, error) {
	root, err := scanRoot(target)
	if err != nil {
		return Result{}, err
	}
	pkgs, partial, err := pinnedPackages(ctx, root)
	if err != nil {
		return Result{}, err
	}
	if len(pkgs) == 0 {
		return Result{Partial: partial}, nil
	}
	switch {
	case o.base == "":
		return Result{}, errors.New("no OSV server is configured in this build")
	case o.relay == "":
		return Result{}, fmt.Errorf("the job has no network, so OSV was not asked: %w", errNoNetwork)
	}

	ctx, cancel := context.WithTimeout(ctx, osvTotal)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         ingest.TunnelDialer(o.relay),
			TLSHandshakeTimeout: osvHandshake,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	res := Result{Partial: partial}
	for start := 0; start < len(pkgs); start += osvBatch {
		batch := pkgs[start:min(start+osvBatch, len(pkgs))]
		ids, err := o.query(ctx, client, batch)
		if err != nil {
			if start == 0 {
				return Result{}, osvError(err)
			}
			res.Partial = true
			res.Note = fmt.Sprintf("the lookup stopped after %d packages: %s", start, osvError(err))
			break
		}
		for i, p := range batch {
			if len(ids[i]) == 0 {
				continue
			}
			snippet := fmt.Sprintf("%s %s@%s: %s", p.pkg.Ecosystem, p.pkg.Name, p.pkg.Version, strings.Join(ids[i], ", "))
			res.Findings = append(res.Findings, ruleOSV.Finding(protocol.Evidence{Path: p.file, Snippet: protocol.Snippet(snippet)}))
		}
	}
	return res, nil
}

// osvError says why a lookup did not work. The host proxy tells the guest why it refused a tunnel.
// A failed DNS lookup or dial means the computer that runs Galahad has no network. Any other refusal
// is the case that a local DNS setting can cause, so it is named.
func osvError(err error) error {
	if errors.Is(err, ingest.ErrNotAllowed) {
		if msg := err.Error(); strings.Contains(msg, "dns lookup failed") || strings.Contains(msg, "dial failed") {
			return fmt.Errorf("%w: the computer that runs Galahad could not reach api.osv.dev: %w", errNoNetwork, err)
		}
		return fmt.Errorf("the host proxy refused the OSV lookup; if it names a private address, the DNS of the computer that runs Galahad resolves api.osv.dev to one: %w", err)
	}
	return fmt.Errorf("the OSV lookup failed, possibly because the computer is offline: %w", err)
}

// pinned is a dependency pinned in a file of the input.
type pinned struct {
	pkg  deps.Package
	file string // relative to the target, cleaned
}

// pinnedPackages lists the packages pinned in the lockfiles and requirements files below root, each
// once, at most osvMaxPackages of them. partial is set when the list is cut or a file was skipped.
func pinnedPackages(ctx context.Context, root string) (found []pinned, partial bool, err error) {
	seen := map[deps.Package]bool{}
	entries, read := 0, int64(0)
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
		if entries++; entries > analyze.MaxFiles {
			partial = true
			return filepath.SkipAll
		}
		rel, _ := relPath(root, path)
		name := strings.ToLower(d.Name())
		limit := int64(analyze.MaxConfigSize)
		switch {
		case name == "package-lock.json":
			limit = analyze.MaxFileSize
		case !strings.HasSuffix(name, ".txt"):
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		// A file that is too big or past the read budget cuts the lookup short only if it is one that
		// Pinned reads by its name. Any other .txt file is most likely not a list of requirements.
		mustRead := deps.PinnedByName(rel)
		if info.Size() > limit || read+info.Size() > osvMaxRead {
			partial = partial || mustRead
			return nil
		}
		data, err := os.ReadFile(path) // #nosec G304 -- a regular file found below the scanned target, within the size limit
		if err != nil {
			partial = partial || mustRead
			return nil
		}
		read += int64(len(data))
		for _, p := range deps.Pinned(rel, data) {
			if seen[p] {
				continue
			}
			if len(found) >= osvMaxPackages {
				partial = true
				return filepath.SkipAll
			}
			seen[p] = true
			found = append(found, pinned{pkg: p, file: rel})
		}
		return nil
	})
	return found, partial, err
}

// osvQuery is one entry of a querybatch request.
type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// osvResponse is a querybatch response: one result for each query, in the order of the queries.
type osvResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// query asks the API about batch and returns, for each package, the MAL- IDs it lists.
func (o osv) query(ctx context.Context, client *http.Client, batch []pinned) ([][]string, error) {
	queries := make([]osvQuery, len(batch))
	for i, p := range batch {
		queries[i].Package.Name, queries[i].Package.Ecosystem, queries[i].Version = p.pkg.Name, p.pkg.Ecosystem, p.pkg.Version
	}
	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(o.base, "/")+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "galahad")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // the body was read or is dropped
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the API answered with status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(data) > osvMaxResponse {
		return nil, fmt.Errorf("the response is over %d bytes", osvMaxResponse)
	}
	return parseOSV(data, len(batch))
}

// parseOSV reads a querybatch response for n queries. It is strict about the shape: one JSON value,
// one result for each query, and well formed IDs. It keeps the IDs that start with MAL-.
func parseOSV(data []byte, n int) ([][]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var r osvResponse
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("the response is not OSV JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the response has data after the JSON document")
	}
	if len(r.Results) != n {
		return nil, fmt.Errorf("the response has %d results for %d queries", len(r.Results), n)
	}
	out := make([][]string, n)
	for i, res := range r.Results {
		for _, v := range res.Vulns {
			if !osvID.MatchString(v.ID) {
				return nil, errors.New("the response has a malformed ID")
			}
			if strings.HasPrefix(v.ID, "MAL-") {
				out[i] = append(out[i], v.ID)
			}
		}
	}
	return out, nil
}
