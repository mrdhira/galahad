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
	// maxListEntries is how many directory entries List reads.
	maxListEntries = 10000
)

// ErrListTruncated is returned by List, next to the jobs it did read, when the jobs directory
// holds more than maxListEntries entries.
var ErrListTruncated = errors.New("too many entries in the jobs directory")

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

// openJob opens the directory of the job with the given ID as a root, so nothing read through it
// can leave the directory. A job directory that is a symlink is refused, even when it points
// inside the jobs directory.
func openJob(jobsDir, id string) (*os.Root, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid job id %q", id)
	}
	jobs, err := os.OpenRoot(jobsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = jobs.Close() }() // read-only handle
	fi, err := jobs.Lstat(id)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a job directory", id)
	}
	return jobs.OpenRoot(id)
}

// ReadFile reads the regular file name of the job with the given ID. It refuses a file larger
// than limit bytes, a symlink that leaves the job directory, and anything that is not a regular
// file.
func ReadFile(jobsDir, id, name string, limit int64) ([]byte, error) {
	root, err := openJob(jobsDir, id)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }() // read-only handle
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	f, err := root.OpenFile(name, readFlags, 0) // without blocking: the file may have become a FIFO since the Lstat
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only file
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return data, nil
}

// Load reads and strictly decodes job.json of the job with the given ID.
func Load(jobsDir, id string) (Job, error) {
	data, err := ReadFile(jobsDir, id, fileName, maxFileSize)
	if err != nil {
		return Job{}, fmt.Errorf("load job %s: %w", id, err)
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
// listed with the state unreadable, and so is an entry with a job ID that is not a directory.
// A missing jobs directory is an empty list. List reads at most maxListEntries entries; when
// there are more, it returns the jobs it read and ErrListTruncated.
func List(jobsDir string) ([]Job, error) {
	d, err := os.Open(jobsDir) // #nosec G304 -- the jobs directory is galahad's own state directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	defer func() { _ = d.Close() }() // read-only directory
	entries, err := d.ReadDir(maxListEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	var truncated error
	if len(entries) > maxListEntries {
		entries, truncated = entries[:maxListEntries], ErrListTruncated
	}
	var jobs []Job
	for _, e := range entries {
		if !ValidID(e.Name()) {
			continue
		}
		j, err := Load(jobsDir, e.Name())
		if err != nil {
			j = Job{ID: e.Name(), State: StateUnreadable}
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].ID > jobs[b].ID })
	return jobs, truncated
}

// Remove deletes the directory of the job with the given ID. The error wraps fs.ErrNotExist
// when there is no such job. It refuses anything that is not a job ID and a job directory that
// is a symlink, and it never follows a symlink inside the job directory.
func Remove(jobsDir, id string) error {
	if !ValidID(id) {
		return fmt.Errorf("invalid job id %q", id)
	}
	jobs, err := os.OpenRoot(jobsDir)
	if err != nil {
		return fmt.Errorf("remove job %s: %w", id, err)
	}
	defer func() { _ = jobs.Close() }() // the handle only scopes the removal
	fi, err := jobs.Lstat(id)
	if err != nil {
		return fmt.Errorf("remove job %s: %w", id, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("remove job %s: not a job directory", id)
	}
	if err := jobs.RemoveAll(id); err != nil {
		return fmt.Errorf("remove job %s: %w", id, err)
	}
	return nil
}
