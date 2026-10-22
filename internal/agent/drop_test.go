package agent_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
)

func TestCheckDropped(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		uid, euid, gid, egid int
		setuidErr            error
		// want*
		wantErr string
	}{
		{name: "all ids dropped and root is out of reach", uid: 1000, euid: 1000, gid: 1000, egid: 1000, setuidErr: errors.New("operation not permitted")},
		{name: "uid is still root", uid: 0, euid: 1000, gid: 1000, egid: 1000, setuidErr: errors.New("x"), wantErr: "the uid is 0, want 1000"},
		{name: "euid is still root", uid: 1000, euid: 0, gid: 1000, egid: 1000, setuidErr: errors.New("x"), wantErr: "the euid is 0, want 1000"},
		{name: "gid is still root", uid: 1000, euid: 1000, gid: 0, egid: 1000, setuidErr: errors.New("x"), wantErr: "the gid is 0, want 1000"},
		{name: "egid is still root", uid: 1000, euid: 1000, gid: 1000, egid: 0, setuidErr: errors.New("x"), wantErr: "the egid is 0, want 1000"},
		{name: "the process can become root again", uid: 1000, euid: 1000, gid: 1000, egid: 1000, wantErr: "can still become uid 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var asked []int
			ids := agent.IDs{
				Getuid:  func() int { return tt.uid },
				Geteuid: func() int { return tt.euid },
				Getgid:  func() int { return tt.gid },
				Getegid: func() int { return tt.egid },
				Setuid:  func(uid int) error { asked = append(asked, uid); return tt.setuidErr },
			}
			err := agent.CheckDropped(ids, 1000, 1000)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("error = %v, want none", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.wantErr == "" && (len(asked) != 1 || asked[0] != 0) {
				t.Errorf("Setuid called with %v, want [0]", asked)
			}
		})
	}
}
