//go:build unix

package analyze_test

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestRunFIFO(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fifoIsTarget bool
		// expectations
		wantErr      bool
		wantFiles    []string
		wantSeen     int
		wantAnalyzed int
		wantSkips    []protocol.Skip
	}{
		{
			name:         "a FIFO in the tree is skipped without blocking",
			wantFiles:    []string{"a.txt"},
			wantSeen:     2,
			wantAnalyzed: 1,
			wantSkips:    []protocol.Skip{{Path: "pipe", Reason: protocol.SkipUnsupported}},
		},
		{
			name:         "a FIFO as the target is an error",
			fifoIsTarget: true,
			wantErr:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "a.txt", []byte("x"))
			fifo := filepath.Join(dir, "pipe")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			target := dir
			if tt.fifoIsTarget {
				target = fifo
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			res, err := analyze.Run(ctx, target, []analyze.Analyzer{nothing})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			var files []string
			for _, f := range res.Files {
				files = append(files, f.Path)
			}
			if len(files) != len(tt.wantFiles) || files[0] != tt.wantFiles[0] {
				t.Errorf("files = %q, want %q", files, tt.wantFiles)
			}
			if res.Coverage.FilesSeen != tt.wantSeen || res.Coverage.FilesAnalyzed != tt.wantAnalyzed {
				t.Errorf("seen/analyzed = %d/%d, want %d/%d", res.Coverage.FilesSeen, res.Coverage.FilesAnalyzed, tt.wantSeen, tt.wantAnalyzed)
			}
			if len(res.Coverage.Skipped) != 1 || res.Coverage.Skipped[0] != tt.wantSkips[0] {
				t.Errorf("skipped = %v, want %v", res.Coverage.Skipped, tt.wantSkips)
			}
		})
	}
}
