package agent_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestRemote(t *testing.T) {
	body := "hello from backend"
	sum := sha256.Sum256([]byte(body))
	refuse := func(reason string) func(net.Conn) {
		return func(c net.Conn) {
			readConnectFrame(c)
			writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"`+reason+`"}`)
		}
	}
	tests := []struct {
		name string
		// inputs
		source string
		url    string
		header string // Content-Disposition of the backend; the plain backend when empty
		proxy  string // "backend": the host proxy in front of the test backend; otherwise the reason of a proxy that refuses; "none": no --proxy
		// expectations
		wantErrCode string // an Error frame instead of a Result
		wantMessage string // substring of the Error message
		wantName    string
	}{
		{
			name: "a url job downloads the file and analyzes it", source: protocol.SourceURL, url: "http://allowed.example.com/dir/report.txt", proxy: "backend",
			wantName: "report.txt",
		},
		{
			name: "a hostile name is written out and the file is still analyzed", source: protocol.SourceURL, url: "http://allowed.example.com/a", proxy: "backend",
			header:   `attachment; filename*=UTF-8''invoice%E2%80%AEfdp%00%ff.exe`,
			wantName: `invoice_u202efdp_u0000_xff.exe`,
		},
		{
			name: "a url job whose host the proxy refuses ends in not_allowed", source: protocol.SourceURL, url: "http://evil.example.com/a.bin", proxy: "host not allowed",
			wantErrCode: protocol.CodeNotAllowed, wantMessage: "evil.example.com:80 denied: host not allowed",
		},
		{
			name: "an address that is not public ends in not_allowed too", source: protocol.SourceURL, url: "http://meta.example.com/a.bin", proxy: "metadata",
			wantErrCode: protocol.CodeNotAllowed, wantMessage: "denied: metadata",
		},
		{
			name: "a drive job asks the proxy for the Drive host", source: protocol.SourceDrive, url: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view", proxy: "host not allowed",
			wantErrCode: protocol.CodeNotAllowed, wantMessage: "drive.usercontent.google.com:443 denied",
		},
		{
			name: "a drive job with a link that is not a Drive link fails", source: protocol.SourceDrive, url: "https://example.com/file/d/1AbCdEfGhIjKlMnOp", proxy: "backend",
			wantErrCode: protocol.CodeIngest, wantMessage: "not a Google Drive file link",
		},
		{
			name: "a url job without a proxy channel fails", source: protocol.SourceURL, url: "http://allowed.example.com/a.txt", proxy: "none",
			wantErrCode: protocol.CodeIngest, wantMessage: "needs the network",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a guest with a proxy channel, and a link
			var args []string
			switch tt.proxy {
			case "none":
			case "backend":
				addr, _ := newBackend(t)
				if tt.header != "" {
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Disposition", tt.header)
						_, _ = io.WriteString(w, body)
					}))
					t.Cleanup(srv.Close)
					addr = srv.Listener.Addr().String()
				}
				args = []string{"--proxy", "tcp:" + hostProxyAt(t, addr)}
			default:
				args = []string{"--proxy", "tcp:" + fakeProxyAt(t, refuse(tt.proxy))}
			}
			job := testJob("", 300)
			job.Source, job.URL = tt.source, tt.url
			empty := endOf(nil)

			// When the host sends the job and an empty stream
			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, args...)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil {
					_ = writeJSON(c, protocol.FrameEnd, empty)
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			// Then the Result is for the downloaded file, or the Error has the code
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || !strings.Contains(got.errMsg.Message, tt.wantMessage) || ex.code != agent.ExitError {
					t.Fatalf("error frame = %+v, exit = %d, want code %q, a message with %q and exit %d", got.errMsg, ex.code, tt.wantErrCode, tt.wantMessage, agent.ExitError)
				}
				return
			}
			if got.result == nil || ex.code != agent.ExitClean {
				t.Fatalf("result = %v, error = %+v, exit = %d; stderr %q", got.result, got.errMsg, ex.code, ex.stderr)
			}
			if tg := got.result.Target; tg.Name != tt.wantName || tg.Kind != protocol.TargetFile || tg.SHA256 != hex.EncodeToString(sum[:]) || tg.Size != int64(len(body)) {
				t.Errorf("target = %+v, want file %s of %d bytes with sha256 %x", tg, tt.wantName, len(body), sum)
			}
		})
	}
}
