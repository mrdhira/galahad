package protocol_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestDriveFileID(t *testing.T) {
	const id = "1AbCdEfGhIjKlMnOp_-x"
	tests := []struct {
		name string
		// inputs
		raw string
		// expectations
		wantID string // empty means not a Drive file link
	}{
		{name: "file link with view", raw: "https://drive.google.com/file/d/" + id + "/view?usp=sharing", wantID: id},
		{name: "file link with edit", raw: "https://drive.google.com/file/d/" + id + "/edit", wantID: id},
		{name: "file link with a slash", raw: "https://drive.google.com/file/d/" + id + "/", wantID: id},
		{name: "file link without a tail", raw: "https://drive.google.com/file/d/" + id, wantID: id},
		{name: "file link with an account number", raw: "https://drive.google.com/file/u/0/d/" + id + "/view", wantID: id},
		{name: "open link", raw: "https://drive.google.com/open?id=" + id, wantID: id},
		{name: "uc link", raw: "https://drive.google.com/uc?id=" + id, wantID: id},
		{name: "uc link with export first", raw: "https://drive.google.com/uc?export=download&id=" + id, wantID: id},
		{name: "http and upper case", raw: "HTTP://Drive.Google.COM/open?id=" + id, wantID: id},
		{name: "docs uc link", raw: "https://docs.google.com/uc?id=" + id, wantID: id},
		{name: "docs open link", raw: "https://docs.google.com/open?id=" + id, wantID: id},
		{name: "usercontent download link", raw: "https://drive.usercontent.google.com/download?id=" + id + "&export=download", wantID: id},
		{name: "usercontent uc link", raw: "https://drive.usercontent.google.com/uc?id=" + id, wantID: id},
		{name: "docs file path form", raw: "https://docs.google.com/file/d/" + id + "/view"},
		{name: "drive host download path", raw: "https://drive.google.com/download?id=" + id, wantID: id},
		{name: "usercontent without an id", raw: "https://drive.usercontent.google.com/download"},
		{name: "another host", raw: "https://example.com/file/d/" + id},
		{name: "a host that only starts with the Drive host", raw: "https://drive.google.com.evil.example/file/d/" + id},
		{name: "a user name", raw: "https://user@drive.google.com/file/d/" + id},
		{name: "a port", raw: "https://drive.google.com:8443/file/d/" + id},
		{name: "another scheme", raw: "ftp://drive.google.com/file/d/" + id},
		{name: "a folder", raw: "https://drive.google.com/drive/folders/" + id},
		{name: "the root", raw: "https://drive.google.com/"},
		{name: "a file link with a deeper tail", raw: "https://drive.google.com/file/d/" + id + "/view/more"},
		{name: "a file link with a short id", raw: "https://drive.google.com/file/d/short"},
		{name: "a file link with a bad character in the id", raw: "https://drive.google.com/file/d/1AbCdEfGhIj%20KlMn/view"},
		{name: "open without an id", raw: "https://drive.google.com/open"},
		{name: "open with two ids", raw: "https://drive.google.com/open?id=" + id + "&id=" + id},
		{name: "uc with a short id", raw: "https://drive.google.com/uc?id=abc"},
		{name: "not a URL", raw: "::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := protocol.DriveFileID(tt.raw)

			if got != tt.wantID || ok != (tt.wantID != "") {
				t.Errorf("DriveFileID(%q) = %q, %v, want %q", tt.raw, got, ok, tt.wantID)
			}
		})
	}
}
