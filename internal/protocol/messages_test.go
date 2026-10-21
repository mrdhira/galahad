package protocol_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	testSHA = strings.Repeat("ab", 32)
	testJob = protocol.Job{
		ID: "20261021-153012-a1b2c3", Kind: protocol.KindScan, Source: protocol.SourceGit,
		Name: "repo", URL: "https://github.com/a/b.git", Submodules: true, Image: protocol.ImageRE,
		Timeouts: protocol.Timeouts{Job: 600, Ingest: 300},
		Now:      time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC),
	}
)

func TestMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		msg  interface{ Validate() error }
		into func() interface{ Validate() error } // a new zero value of the same type
	}{
		{name: "hello", msg: protocol.Hello{Protocol: 1, AgentVersion: "v0.2.0"}, into: func() interface{ Validate() error } { return &protocol.Hello{} }},
		{name: "job", msg: testJob, into: func() interface{ Validate() error } { return &protocol.Job{} }},
		{name: "end", msg: protocol.End{Bytes: 1234, SHA256: testSHA}, into: func() interface{ Validate() error } { return &protocol.End{} }},
		{name: "progress", msg: protocol.Progress{Stage: protocol.StageClamAV}, into: func() interface{ Validate() error } { return &protocol.Progress{} }},
		{name: "error", msg: protocol.Error{Code: protocol.CodeTooLarge, Message: "input too large"}, into: func() interface{ Validate() error } { return &protocol.Error{} }},
		{name: "connect", msg: protocol.Connect{Host: "api.osv.dev", Port: 443}, into: func() interface{ Validate() error } { return &protocol.Connect{} }},
		{name: "connect reply", msg: protocol.ConnectReply{OK: false, Reason: "metadata"}, into: func() interface{ Validate() error } { return &protocol.ConnectReply{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.msg)
			if err != nil {
				t.Fatal(err)
			}
			got := tt.into()
			if err := protocol.DecodeStrict(data, got); err != nil {
				t.Fatalf("DecodeStrict(%s): %v", data, err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(got).Elem().Interface(), tt.msg) {
				t.Errorf("round trip = %+v, want %+v", got, tt.msg)
			}
			if err := tt.msg.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestMessageUnknownField(t *testing.T) {
	tests := []struct {
		name string
		into interface{ Validate() error }
		data string
	}{
		{name: "hello", into: &protocol.Hello{}, data: `{"protocol":1,"agent_version":"v","extra":1}`},
		{name: "job", into: &protocol.Job{}, data: `{"id":"x","extra":1}`},
		{name: "end", into: &protocol.End{}, data: `{"bytes":1,"sha256":"","extra":1}`},
		{name: "progress", into: &protocol.Progress{}, data: `{"stage":"ingest","extra":1}`},
		{name: "error", into: &protocol.Error{}, data: `{"code":"internal","message":"","extra":1}`},
		{name: "connect", into: &protocol.Connect{}, data: `{"host":"a","port":1,"extra":1}`},
		{name: "connect reply", into: &protocol.ConnectReply{}, data: `{"ok":true,"reason":"","extra":1}`},
		{name: "result", into: &protocol.Result{}, data: `{"schema_version":1,"bogus":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := protocol.DecodeStrict([]byte(tt.data), tt.into)
			if err == nil || !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("DecodeStrict = %v, want an unknown field error", err)
			}
		})
	}
}

func TestMessageValidate(t *testing.T) {
	job := func(mutate func(j *protocol.Job)) protocol.Job {
		j := testJob
		mutate(&j)
		return j
	}
	runes := func(s string, n int) string { return strings.Repeat(s, n) }
	tests := []struct {
		name string
		// inputs
		msg interface{ Validate() error }
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "hello", msg: protocol.Hello{Protocol: 1, AgentVersion: "v0.2.0"}},
		{name: "hello wrong protocol", msg: protocol.Hello{Protocol: 2, AgentVersion: "v"}, wantErr: "protocol 2"},
		{name: "hello version empty", msg: protocol.Hello{Protocol: 1}, wantErr: "agent_version is 0 bytes"},
		{name: "hello version too long", msg: protocol.Hello{Protocol: 1, AgentVersion: runes("v", 65)}, wantErr: "agent_version is 65 bytes"},
		{name: "hello version has control character", msg: protocol.Hello{Protocol: 1, AgentVersion: "v\x1b"}, wantErr: "agent_version has control"},

		{name: "job", msg: testJob},
		{name: "job update without a source", msg: job(func(j *protocol.Job) { j.Kind, j.Source, j.Name, j.URL = protocol.KindUpdate, "", "", "" })},
		{name: "job net-probe", msg: job(func(j *protocol.Job) { j.Kind, j.Source = protocol.KindNetProbe, "" })},
		{name: "job probe", msg: job(func(j *protocol.Job) { j.Kind, j.Source = protocol.KindProbe, "" })},
		{name: "job id malformed", msg: job(func(j *protocol.Job) { j.ID = "../etc" }), wantErr: "id"},
		{name: "job kind unknown", msg: job(func(j *protocol.Job) { j.Kind = "format" }), wantErr: `kind "format" not allowed`},
		{name: "job source unknown", msg: job(func(j *protocol.Job) { j.Source = "ftp" }), wantErr: `source "ftp" not allowed`},
		{name: "job scan without a source", msg: job(func(j *protocol.Job) { j.Source = "" }), wantErr: "source"},
		{name: "job source on an update", msg: job(func(j *protocol.Job) { j.Kind = protocol.KindUpdate }), wantErr: "source"},
		{name: "job image core", msg: job(func(j *protocol.Job) { j.Image = protocol.ImageCore })},
		{name: "job image empty means core", msg: job(func(j *protocol.Job) { j.Image = "" })},
		{name: "job image unknown", msg: job(func(j *protocol.Job) { j.Image = "full" }), wantErr: `image "full" not allowed`},
		{name: "job name too long", msg: job(func(j *protocol.Job) { j.Name = runes("a", protocol.MaxPath+1) }), wantErr: "name is"},
		{name: "job name with a bidi character", msg: job(func(j *protocol.Job) { j.Name = "invoice\u202efdp.exe" })},
		{name: "job name has NUL", msg: job(func(j *protocol.Job) { j.Name = "a\x00" }), wantErr: "name is not valid"},
		{name: "job name is not UTF-8", msg: job(func(j *protocol.Job) { j.Name = "a\xff" }), wantErr: "name is not valid"},
		{name: "job url too long", msg: job(func(j *protocol.Job) { j.URL = runes("a", protocol.MaxURL+1) }), wantErr: "url is"},
		{name: "job url has control character", msg: job(func(j *protocol.Job) { j.URL = "http://a\n" }), wantErr: "url has control"},
		{name: "job timeout zero", msg: job(func(j *protocol.Job) { j.Timeouts.Job = 0 }), wantErr: "timeouts.job"},
		{name: "job timeout too long", msg: job(func(j *protocol.Job) { j.Timeouts.Job = protocol.MaxTimeoutSec + 1 }), wantErr: "timeouts.job"},
		{name: "job ingest timeout negative", msg: job(func(j *protocol.Job) { j.Timeouts.Ingest = -1 }), wantErr: "timeouts.ingest"},
		{name: "job ingest timeout default", msg: job(func(j *protocol.Job) { j.Timeouts.Ingest = 0 })},
		{name: "job now missing", msg: job(func(j *protocol.Job) { j.Now = time.Time{} }), wantErr: "now"},

		{name: "end", msg: protocol.End{Bytes: protocol.MaxInputBytes, SHA256: testSHA}},
		{name: "end bytes negative", msg: protocol.End{Bytes: -1, SHA256: testSHA}, wantErr: "bytes -1"},
		{name: "end bytes over the cap", msg: protocol.End{Bytes: protocol.MaxInputBytes + 1, SHA256: testSHA}, wantErr: "bytes 1073741825"},
		{name: "end hash uppercase", msg: protocol.End{SHA256: strings.ToUpper(testSHA)}, wantErr: "sha256"},
		{name: "end hash short", msg: protocol.End{SHA256: "ab"}, wantErr: "sha256"},

		{name: "progress ingest", msg: protocol.Progress{Stage: protocol.StageIngest}},
		{name: "progress analyze", msg: protocol.Progress{Stage: protocol.StageAnalyze}},
		{name: "progress yara", msg: protocol.Progress{Stage: protocol.StageYARA}},
		{name: "progress capa", msg: protocol.Progress{Stage: protocol.StageCapa}},
		{name: "progress osv", msg: protocol.Progress{Stage: protocol.StageOSV}},
		{name: "progress bad stage", msg: protocol.Progress{Stage: "coffee"}, wantErr: `stage "coffee" not allowed`},

		{name: "error", msg: protocol.Error{Code: protocol.CodeInternal, Message: "boom"}},
		{name: "error without message", msg: protocol.Error{Code: protocol.CodeProtocol}},
		{name: "error message at the limit", msg: protocol.Error{Code: protocol.CodeIngest, Message: runes("é", protocol.MaxErrorMessage)}},
		{name: "error bad code", msg: protocol.Error{Code: "oops"}, wantErr: `code "oops" not allowed`},
		{name: "error message too long", msg: protocol.Error{Code: protocol.CodeIngest, Message: runes("é", protocol.MaxErrorMessage+1)}, wantErr: "message has 513 runes"},
		{name: "error message has control character", msg: protocol.Error{Code: protocol.CodeIngest, Message: "a\x1b[2Jb"}, wantErr: "message has control"},
		{name: "error message has bidi character", msg: protocol.Error{Code: protocol.CodeIngest, Message: "a\u202eb"}, wantErr: "message has control"},
		{name: "error message has invalid UTF-8", msg: protocol.Error{Code: protocol.CodeIngest, Message: "a\x9b"}, wantErr: "message has control"},
		{name: "error code drive_private", msg: protocol.Error{Code: protocol.CodeDrivePrivate}},
		{name: "error code drive_quota", msg: protocol.Error{Code: protocol.CodeDriveQuota}},
		{name: "error code not_allowed", msg: protocol.Error{Code: protocol.CodeNotAllowed}},
		{name: "error code timeout", msg: protocol.Error{Code: protocol.CodeTimeout}},

		{name: "connect", msg: protocol.Connect{Host: "169.254.169.254", Port: 80}},
		{name: "connect host empty", msg: protocol.Connect{Port: 80}, wantErr: "host"},
		{name: "connect host uppercase", msg: protocol.Connect{Host: "Example.com", Port: 80}, wantErr: "host"},
		{name: "connect host has control character", msg: protocol.Connect{Host: "a\x1b.com", Port: 80}, wantErr: "host"},
		{name: "connect host too long", msg: protocol.Connect{Host: runes("a", 254), Port: 80}, wantErr: "host"},
		{name: "connect port zero", msg: protocol.Connect{Host: "a.com"}, wantErr: "port 0"},
		{name: "connect port too high", msg: protocol.Connect{Host: "a.com", Port: 65536}, wantErr: "port 65536"},

		{name: "connect reply ok", msg: protocol.ConnectReply{OK: true}},
		{name: "connect reply refused", msg: protocol.ConnectReply{Reason: "private address"}},
		{name: "connect reply reason too long", msg: protocol.ConnectReply{Reason: runes("a", protocol.MaxReply+1)}, wantErr: "reason has 129 runes"},
		{name: "connect reply reason has control character", msg: protocol.ConnectReply{Reason: "a\nb"}, wantErr: "reason has control"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestArtifact(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		payload []byte
		// expectations
		want    protocol.Artifact
		wantErr string
	}{
		{name: "ingest log", payload: []byte("\x01hello"), want: protocol.Artifact{ID: protocol.ArtifactIngestLog, Data: []byte("hello")}},
		{name: "tools log", payload: []byte("\x02"), want: protocol.Artifact{ID: protocol.ArtifactToolsLog, Data: []byte{}}},
		{name: "probe json with raw bytes", payload: []byte{3, 0, 0xff, '\n'}, want: protocol.Artifact{ID: protocol.ArtifactProbeJSON, Data: []byte{0, 0xff, '\n'}}},
		{name: "empty payload", payload: nil, wantErr: "empty"},
		{name: "id zero", payload: []byte{0, 'x'}, wantErr: "artifact id 0 not allowed"},
		{name: "id past the last", payload: []byte{4, 'x'}, wantErr: "artifact id 4 not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protocol.ParseArtifact(tt.payload)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseArtifact = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseArtifact: %v", err)
			}
			if got.ID != tt.want.ID || !bytes.Equal(got.Data, tt.want.Data) {
				t.Errorf("ParseArtifact = %+v, want %+v", got, tt.want)
			}
			if m := got.Marshal(); !bytes.Equal(m, tt.payload) {
				t.Errorf("Marshal() = %v, want %v", m, tt.payload)
			}
		})
	}
}
