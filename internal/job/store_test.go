package job_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
)

var now = time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC)

func TestCreate(t *testing.T) {
	tests := []struct {
		name    string
		jobsDir func(t *testing.T) string
		target  job.Target
		wantErr string
	}{
		{
			name:    "creates a private directory and job.json in state created",
			jobsDir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "jobs") },
			target:  job.Target{Input: "sample.pdf", Kind: "file"},
		},
		{
			name: "jobs directory path is a file",
			jobsDir: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "jobs")
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: "create jobs directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.jobsDir(t)
			j, err := job.Create(dir, now, tt.target, "core", "fake")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if j.State != job.StateCreated || j.Image != "core" || j.Backend != "fake" || j.Target != tt.target || !j.CreatedAt.Equal(now) {
				t.Errorf("job = %+v", j)
			}
			if runtime.GOOS != "windows" {
				for p, want := range map[string]os.FileMode{
					dir:                0o700,
					job.Dir(dir, j.ID): 0o700,
					filepath.Join(job.Dir(dir, j.ID), "job.json"): 0o600,
				} {
					st, err := os.Stat(p)
					if err != nil {
						t.Fatal(err)
					}
					if got := st.Mode().Perm(); got != want {
						t.Errorf("mode of %s = %o, want %o", p, got, want)
					}
				}
			}
			got, err := job.Load(dir, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got != j {
				t.Errorf("Load = %+v, want %+v", got, j)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	const id = "20261021-153012-a1b2c3"
	const valid = `{"id":"` + id + `","created_at":"2026-10-21T15:30:12Z","target":{"input":"a","kind":"file"},"image":"core","backend":"fake","state":"done","exit_code":10,"verdict":"suspicious","score":55,"blocked":true}`
	tests := []struct {
		name    string
		id      string
		content string // job.json; empty means no file
		wantErr string
		want    job.Job
	}{
		{
			name:    "valid job.json",
			id:      id,
			content: valid,
			want: job.Job{
				ID: id, CreatedAt: now, Target: job.Target{Input: "a", Kind: "file"}, Image: "core", Backend: "fake",
				State: job.StateDone, ExitCode: 10, Verdict: "suspicious", Score: 55, Blocked: true,
			},
		},
		{name: "id is not a job id", id: "../x", wantErr: "invalid job id"},
		{name: "missing job.json", id: id, wantErr: "load job"},
		{name: "unknown field", id: id, content: strings.Replace(valid, `"image"`, `"extra":1,"image"`, 1), wantErr: "unknown field"},
		{name: "not JSON", id: id, content: "nope", wantErr: "load job"},
		{name: "trailing data", id: id, content: valid + `{}`, wantErr: "trailing data"},
		{name: "oversize file", id: id, content: valid + strings.Repeat(" ", 1<<20), wantErr: "larger than"},
		{name: "id differs from directory", id: id, content: strings.Replace(valid, id, "20261021-153012-ffffff", 1), wantErr: "has id"},
		{name: "unknown state", id: id, content: strings.Replace(valid, `"done"`, `"unreadable"`, 1), wantErr: "unknown state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.content != "" {
				writeJob(t, dir, tt.id, tt.content)
			}
			got, err := job.Load(dir, tt.id)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("Load = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSave(t *testing.T) {
	finished := now.Add(time.Minute)
	tests := []struct {
		name    string
		update  func(j *job.Job)
		wantErr string
	}{
		{
			name: "saved changes load back",
			update: func(j *job.Job) {
				j.State = job.StateFailed
				j.FinishedAt = &finished
				j.ExitCode = 1
				j.Error = "boom"
			},
		},
		{name: "invalid id", update: func(j *job.Job) { j.ID = "../x" }, wantErr: "invalid job id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			j, err := job.Create(dir, now, job.Target{Input: "a", Kind: "file"}, "core", "fake")
			if err != nil {
				t.Fatal(err)
			}
			tt.update(&j)
			err = job.Save(dir, j)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := job.Load(dir, j.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != j.State || got.FinishedAt == nil || !got.FinishedAt.Equal(finished) || got.ExitCode != 1 || got.Error != "boom" {
				t.Errorf("Load = %+v", got)
			}
			if _, err := os.Stat(filepath.Join(job.Dir(dir, j.ID), "job.json.tmp")); !os.IsNotExist(err) {
				t.Errorf("temporary file left behind: %v", err)
			}
		})
	}
}

func TestList(t *testing.T) {
	const (
		older = "20261021-153012-aaaaaa"
		newer = "20261021-153013-bbbbbb"
		bad   = "20261021-153011-cccccc"
	)
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		noDir      bool
		wantIDs    []string
		wantStates []job.State
	}{
		{
			name: "newest first, unreadable job.json listed as unreadable",
			setup: func(t *testing.T, dir string) {
				writeJob(t, dir, older, `{"id":"`+older+`","created_at":"2026-10-21T15:30:12Z","target":{"input":"a","kind":"file"},"image":"core","backend":"fake","state":"done","exit_code":0,"score":0,"blocked":false}`)
				writeJob(t, dir, newer, `{"id":"`+newer+`","created_at":"2026-10-21T15:30:13Z","target":{"input":"a","kind":"file"},"image":"core","backend":"fake","state":"failed","exit_code":1,"score":0,"blocked":false}`)
				writeJob(t, dir, bad, "not json")
				// Entries that are not job directories are skipped.
				if err := os.WriteFile(filepath.Join(dir, "stray.txt"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(dir, "not-a-job"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantIDs:    []string{newer, older, bad},
			wantStates: []job.State{job.StateFailed, job.StateDone, job.StateUnreadable},
		},
		{name: "missing jobs directory is an empty list", noDir: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "jobs")
			if !tt.noDir {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				tt.setup(t, dir)
			}
			jobs, err := job.List(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(jobs) != len(tt.wantIDs) {
				t.Fatalf("got %d jobs, want %d: %+v", len(jobs), len(tt.wantIDs), jobs)
			}
			for i, j := range jobs {
				if j.ID != tt.wantIDs[i] || j.State != tt.wantStates[i] {
					t.Errorf("jobs[%d] = %s %s, want %s %s", i, j.ID, j.State, tt.wantIDs[i], tt.wantStates[i])
				}
			}
		})
	}
}

func TestRemove(t *testing.T) {
	tests := []struct {
		name    string
		id      func(created string) string
		wantErr string
	}{
		{name: "removes the job directory", id: func(created string) string { return created }},
		{name: "refuses a path that leaves the jobs directory", id: func(string) string { return "../outside" }, wantErr: "invalid job id"},
		{name: "refuses an empty id", id: func(string) string { return "" }, wantErr: "invalid job id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "jobs")
			outside := filepath.Join(root, "outside")
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			j, err := job.Create(dir, now, job.Target{Input: "a", Kind: "file"}, "core", "fake")
			if err != nil {
				t.Fatal(err)
			}
			err = job.Remove(dir, tt.id(j.ID))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				if _, err := os.Stat(outside); err != nil {
					t.Errorf("outside directory was touched: %v", err)
				}
				if _, err := os.Stat(dir); err != nil {
					t.Errorf("jobs directory was touched: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(job.Dir(dir, j.ID)); !os.IsNotExist(err) {
				t.Errorf("job directory still exists: %v", err)
			}
		})
	}
}

func writeJob(t *testing.T, dir, id, content string) {
	t.Helper()
	if err := os.MkdirAll(job.Dir(dir, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(job.Dir(dir, id), "job.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
