package job

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	fileName    = "job.json"
	maxFileSize = 1 << 20
	createTries = 5
)

// Dir returns the directory of the job with the given ID.
func Dir(jobsDir, id string) string { return filepath.Join(jobsDir, id) }

// Create makes the directory of a new job in the state created and writes its job.json.
func Create(jobsDir string, now time.Time, target Target, image, backend string) (Job, error) {
	if err := os.MkdirAll(jobsDir, 0o700); err != nil {
		return Job{}, fmt.Errorf("create jobs directory: %w", err)
	}
	for range createTries {
		id, err := NewID(now)
		if err != nil {
			return Job{}, err
		}
		if err := os.Mkdir(Dir(jobsDir, id), 0o700); err != nil {
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			return Job{}, fmt.Errorf("create job directory: %w", err)
		}
		j := Job{
			ID:        id,
			CreatedAt: now.UTC(),
			Target:    target,
			Image:     image,
			Backend:   backend,
			State:     StateCreated,
		}
		if err := Save(jobsDir, j); err != nil {
			_ = os.RemoveAll(Dir(jobsDir, id)) // best effort; the save error is the one to report
			return Job{}, err
		}
		return j, nil
	}
	return Job{}, errors.New("create job directory: no free job id")
}

// Load reads and strictly decodes job.json of the job with the given ID.
func Load(jobsDir, id string) (Job, error) {
	if !ValidID(id) {
		return Job{}, fmt.Errorf("invalid job id %q", id)
	}
	f, err := os.Open(filepath.Join(Dir(jobsDir, id), fileName)) // #nosec G304 -- the id matches the job id format
	if err != nil {
		return Job{}, fmt.Errorf("load job %s: %w", id, err)
	}
	defer func() { _ = f.Close() }() // read-only file
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Job{}, fmt.Errorf("load job %s: %w", id, err)
	}
	if len(data) > maxFileSize {
		return Job{}, fmt.Errorf("load job %s: %s is larger than %d bytes", id, fileName, maxFileSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var j Job
	if err := dec.Decode(&j); err != nil {
		return Job{}, fmt.Errorf("load job %s: %w", id, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Job{}, fmt.Errorf("load job %s: trailing data after the JSON value", id)
	}
	if j.ID != id {
		return Job{}, fmt.Errorf("load job %s: job.json has id %q", id, j.ID)
	}
	if !j.State.valid() {
		return Job{}, fmt.Errorf("load job %s: unknown state %q", id, j.State)
	}
	return j, nil
}

// Save writes job.json of j, replacing the old file in one step.
func Save(jobsDir string, j Job) error {
	if !ValidID(j.ID) {
		return fmt.Errorf("invalid job id %q", j.ID)
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("save job %s: %w", j.ID, err)
	}
	dir := Dir(jobsDir, j.ID)
	tmp := filepath.Join(dir, fileName+".tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("save job %s: %w", j.ID, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, fileName)); err != nil {
		_ = os.Remove(tmp) // best effort; the rename error is the one to report
		return fmt.Errorf("save job %s: %w", j.ID, err)
	}
	return nil
}

// List returns the jobs in jobsDir, newest first. A job whose job.json cannot be read is
// listed with the state unreadable. A missing jobs directory is an empty list.
func List(jobsDir string) ([]Job, error) {
	entries, err := os.ReadDir(jobsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	var jobs []Job
	for _, e := range entries {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		j, err := Load(jobsDir, e.Name())
		if err != nil {
			j = Job{ID: e.Name(), State: StateUnreadable}
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].ID > jobs[b].ID })
	return jobs, nil
}

// Remove deletes the directory of the job with the given ID. It refuses anything that is
// not a job ID, so a path cannot leave the jobs directory.
func Remove(jobsDir, id string) error {
	if !ValidID(id) {
		return fmt.Errorf("invalid job id %q", id)
	}
	if err := os.RemoveAll(Dir(jobsDir, id)); err != nil {
		return fmt.Errorf("remove job %s: %w", id, err)
	}
	return nil
}
