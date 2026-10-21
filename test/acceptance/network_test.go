package acceptance_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// netReport mirrors the network parts of report.json.
type netReport struct {
	Verdict  string `json:"verdict"`
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Evidence []struct {
			Path    string `json:"path"`
			Snippet string `json:"snippet"`
		} `json:"evidence"`
	} `json:"findings"`
	Network *struct {
		Events []struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
			Blocked  bool   `json:"blocked"`
			Count    int    `json:"count"`
		} `json:"events"`
	} `json:"network"`
}

// probeResult mirrors one entry of artifacts/probe.json, which the net-probe job of the guest writes.
type probeResult struct {
	Form   string `json:"form"`
	Status int    `json:"status"`
	Body   string `json:"body"`
	Error  string `json:"error"`
}

// backendPort starts an http backend on loopback and returns its port.
func backendPort(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from backend")
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// P8: a guest that asks for a private address is refused by the host proxy, the denial is in proxy.log and the
// report, and a request to an allowed host goes through in both request forms.
func TestScanNetwork(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args       []string
		probe      string // GALAHAD_TEST_NET_PROBE
		resolve    string // GALAHAD_TEST_RESOLVE
		sinkhole   bool   // GALAHAD_TEST_SINKHOLE is the backend
		fakeResult string // GALAHAD_FAKE_RESULT
		// expectations
		wantCode     int
		wantVerdict  string
		wantStderr   string // substring
		wantStdout   []string
		wantAbsent   []string // not in stdout
		wantEvents   int      // entries of the network section; -1 when the section must not exist
		wantBlocked  bool
		wantEvidence string // snippet of GAL-NET-001; empty means no such finding
		wantProbe    []probeResult
		wantLog      []string // substrings of proxy.log
		wantNoLog    bool     // proxy.log must not exist
		wantNoReport bool
		wantAllowed  int // requests of the one allowed event
	}{
		{
			name:  "a request to a name that resolves to a private address is denied and reported",
			probe: "http://rebind.test/", resolve: "rebind.test=10.0.0.1",
			wantCode: 10, wantVerdict: "suspicious", wantEvents: 1, wantBlocked: true,
			wantEvidence: "CONNECT rebind.test:80 denied: private",
			wantProbe: []probeResult{
				{Form: "absolute", Status: 403, Body: "denied: private"},
				{Form: "connect", Status: 403, Body: "denied: private"},
			},
			wantLog:    []string{`"host":"rebind.test"`, `"ip":"10.0.0.1"`, `"decision":"denied"`, `"reason":"private"`},
			wantStdout: []string{"Network (1 destination):", "BLOCKED rebind[.]test:80 (2 requests): private", "GAL-NET-001"},
			wantAbsent: []string{"rebind.test"},
		},
		{
			name:  "both request forms reach an allowed backend",
			probe: "http://allowed.test/hello", resolve: "allowed.test=127.0.0.1", sinkhole: true,
			wantCode: 0, wantVerdict: "clean", wantEvents: 1, wantAllowed: 2,
			wantProbe: []probeResult{
				{Form: "absolute", Status: 200, Body: "hello from backend"},
				{Form: "connect", Status: 200, Body: "hello from backend"},
			},
			wantLog:    []string{`"host":"allowed.test"`, `"decision":"allowed"`},
			wantStdout: []string{"Network (1 destination):", "allowed allowed[.]test:80 (2 requests)"},
			wantAbsent: []string{"allowed.test"},
		},
		{
			name:     "a scan without requests has an empty network section",
			wantCode: 0, wantVerdict: "clean", wantEvents: 0, wantLog: nil,
			wantStdout: []string{"Network (0 destinations):"},
		},
		{
			name:        "no network serves no proxy port",
			args:        []string{"--no-network"},
			wantCode:    0,
			wantVerdict: "clean", wantEvents: 0, wantNoLog: true,
		},
		{
			name:  "no network leaves a probe without its proxy",
			args:  []string{"--no-network"},
			probe: "http://allowed.test/", resolve: "allowed.test=127.0.0.1", sinkhole: true,
			wantCode: 1, wantStderr: "needs an http URL and the proxy", wantEvents: -1, wantNoLog: true, wantNoReport: true,
		},
		{
			name:       "a result with network data of its own is refused",
			fakeResult: "network",
			wantCode:   1, wantStderr: "the result has network data", wantEvents: -1, wantNoReport: true,
		},
		{
			name:       "a result with a GAL-NET-001 finding of its own is refused",
			fakeResult: "forged-finding",
			wantCode:   1, wantStderr: "only the host adds it", wantEvents: -1, wantNoReport: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a guest that probes the network through the host proxy
			if tt.probe != "" {
				t.Setenv("GALAHAD_TEST_NET_PROBE", tt.probe)
			}
			if tt.resolve != "" {
				t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			}
			if tt.sinkhole {
				t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+backendPort(t))
			}
			if tt.fakeResult != "" {
				t.Setenv("GALAHAD_FAKE_RESULT", tt.fakeResult)
			}
			home := t.TempDir()

			// When the benign fixture is scanned
			stdout, stderr, code := scan(t, home, append(tt.args, corpus(t, "benign-go-cli"))...)

			// Then the exit code, the output, proxy.log and the report are as expected
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tt.wantStderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, a := range tt.wantAbsent {
				if strings.Contains(stdout, a) {
					t.Errorf("stdout has the raw host %q:\n%s", a, stdout)
				}
			}
			dir := onlyJob(t, home)
			logData, logErr := os.ReadFile(filepath.Join(dir, "proxy.log"))
			if tt.wantNoLog != os.IsNotExist(logErr) {
				t.Errorf("proxy.log read error = %v, want it missing: %v", logErr, tt.wantNoLog)
			}
			for _, w := range tt.wantLog {
				if !strings.Contains(string(logData), w) {
					t.Errorf("proxy.log lacks %q:\n%s", w, logData)
				}
			}
			_, statErr := os.Stat(filepath.Join(dir, "report.json"))
			if tt.wantNoReport {
				if statErr == nil {
					t.Error("report.json exists, want none")
				}
				return
			}
			var rep netReport
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "report.json"))), &rep); err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tt.wantVerdict)
			}
			if rep.Network == nil || len(rep.Network.Events) != tt.wantEvents {
				t.Fatalf("network = %+v, want %d events", rep.Network, tt.wantEvents)
			}
			if tt.wantBlocked && !rep.Network.Events[0].Blocked {
				t.Errorf("event = %+v, want it blocked", rep.Network.Events[0])
			}
			if tt.wantAllowed > 0 && (rep.Network.Events[0].Decision != "allowed" || rep.Network.Events[0].Count != tt.wantAllowed) {
				t.Errorf("event = %+v, want %d allowed requests", rep.Network.Events[0], tt.wantAllowed)
			}
			var evidence string
			for _, f := range rep.Findings {
				if f.RuleID == "GAL-NET-001" {
					if f.Severity != "high" || len(f.Evidence) != 1 || f.Evidence[0].Path != "(network)" {
						t.Errorf("GAL-NET-001 = %+v, want one high finding with the evidence path (network)", f)
					}
					evidence = f.Evidence[0].Snippet
				}
			}
			if evidence != tt.wantEvidence {
				t.Errorf("GAL-NET-001 evidence = %q, want %q", evidence, tt.wantEvidence)
			}
			if tt.wantProbe != nil {
				var got []probeResult
				if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "artifacts", "probe.json"))), &got); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(got, tt.wantProbe) {
					t.Errorf("probe.json = %+v, want %+v", got, tt.wantProbe)
				}
			}
			for _, name := range []string{"summary.md", "report.html"} {
				if tt.wantEvents > 0 {
					if text := readFile(t, filepath.Join(dir, name)); !strings.Contains(text, "Network") || strings.Contains(text, "rebind.test") || strings.Contains(text, "allowed.test") {
						t.Errorf("%s has no Network section, or has a raw host", name)
					}
				}
			}
		})
	}
}
