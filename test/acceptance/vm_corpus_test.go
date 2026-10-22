//go:build vm

package acceptance_test

import (
	"path/filepath"
	"testing"
	"time"
)

// These tests run P1-P7 through the real Firecracker backend, so they need the KVM runner of
// .github/workflows/vm.yml: GALAHAD_HOME holds the pinned images, the signatures and Firecracker, and TestMain
// builds galahad and galahad-agent with the galahadtest tag. Every scan gets the default time limit of a core
// scan. A scan that outlasts it ends in the timeout state with exit 1, which fails the case.

// vmScanLimit is the default time limit of a core scan (10 minutes), plus slack for the host.
const vmScanLimit = 10*time.Minute + timeoutSlack

// A real VM is also a sandbox of the demo.
func init() {
	demoBackends = append(demoBackends, demoBackend{name: "firecracker", home: vmHome})
}

// scanInVM scans args in a real VM with its state in home, and checks what the host must show of any scan:
// the exit code, a finished job, no firecracker process and no transient file left. It returns the job directory.
func scanInVM(t *testing.T, home string, wantCode int, args ...string) string {
	t.Helper()
	got := runP8(t, vmScanLimit, args...)
	if got.code != wantCode {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got.code, wantCode, got.stdout, got.stderr)
	}
	if firecrackerRunning() {
		t.Error("a firecracker process is left")
	}
	dir := onlyJob(t, home)
	if left := transientFiles(t, dir); len(left) > 0 {
		t.Errorf("transient files are left in the job directory: %v", left)
	}
	return dir
}

// TestVMCorpus runs the corpus table of corpus_test.go through "galahad scan" in a real VM. The exit codes and
// the evidence are those of the agent alone (TestCorpus) and of the fake sandbox (TestScanCorpus). P6:
// p6-eml-lure is one of the cases.
func TestVMCorpus(t *testing.T) {
	for _, tt := range corpusCases() {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture, committed or built at test time, and an empty set of jobs
			home := vmHome(t)
			target := tt.target(t)
			// When it is scanned in a VM
			dir := scanInVM(t, home, tt.wantCode, target)
			// Then the job is done and the report shows what the agent finds alone
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkCorpus(t, tt, rep, dir)
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode || j.Verdict != rep.Verdict {
				t.Errorf("job.json = %+v, want state done, exit code %d, verdict %q", j, tt.wantCode, rep.Verdict)
			}
		})
	}
}

// TestVMIngest scans a Git repository and a URL in a real VM. The guest clones and downloads through the relay
// and the host proxy, which ends at the sinkhole of startSinkhole, and the report is the one of the same files
// scanned from a path.
func TestVMIngest(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		target string
		// expectations
		wantCode   int
		wantCorpus string // the corpus case whose evidence the report must show
		wantKind   string // target kind in job.json
		wantHost   string // the only host in proxy.log
	}{
		{
			name:   "fake-interview-repo is cloned from a Git host and exits 20 with tasks.json:7 and setup.js:3 as evidence",
			target: "http://git.test/interview.git", wantCode: 20, wantCorpus: "fake-interview-repo", wantKind: "git", wantHost: "git.test",
		},
		{
			name:   "the P4 PDF with a URI action is downloaded from a URL and exits 10",
			target: "http://files.test/statement.pdf", wantCode: 10, wantCorpus: "p4-pdf-openaction-uri", wantKind: "url", wantHost: "files.test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the sinkhole and an empty set of jobs
			startSinkhole(t)
			home := vmHome(t)
			// When the link is scanned in a VM
			dir := scanInVM(t, home, tt.wantCode, tt.target)
			// Then the job is done, the traffic went through the host proxy to the one host, and the report has the evidence
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode || j.Target.Kind != tt.wantKind {
				t.Errorf("job.json = %+v, want state done, exit code %d, target kind %s", j, tt.wantCode, tt.wantKind)
			}
			if hosts := proxyHosts(t, dir); len(hosts) != 1 || hosts[0] != tt.wantHost {
				t.Errorf("hosts in proxy.log = %q, want only %q", hosts, tt.wantHost)
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkCorpus(t, corpusCaseNamed(t, tt.wantCorpus), rep, dir)
		})
	}
}
