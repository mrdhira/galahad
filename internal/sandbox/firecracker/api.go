//go:build linux

package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	maxResponse    = 64 << 10 // bytes read from one API response body
	maxErrorBody   = 256      // bytes of an error body that go into the error message
	maxHeaderBytes = 64 << 10 // bytes of one API response header
)

// The request bodies of the Firecracker API.
type machineConfig struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
}

type bootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type vsockDevice struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type action struct {
	ActionType string `json:"action_type"`
}

// apiClient talks to the Firecracker API over its unix socket.
type apiClient struct {
	http *http.Client
}

func newAPIClient(sock string, timeout time.Duration) *apiClient {
	return &apiClient{http: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: maxHeaderBytes,
		},
		// Firecracker does not redirect; a redirect is an answer to report, not to follow.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// put sends one PUT request. Any status but 2xx is an error, and so is a 2xx body over maxResponse.
func (c *apiClient) put(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://firecracker"+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			// A canceled start also kills the process, so the request may fail with EOF first; say why.
			err = ctx.Err()
		}
		return fmt.Errorf("PUT %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }() // everything wanted is read
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("PUT %s: read the response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("PUT %s: status %d: %s", path, resp.StatusCode, strconv.Quote(string(got[:min(len(got), maxErrorBody)])))
	}
	if len(got) > maxResponse {
		return fmt.Errorf("PUT %s: the response is larger than %d bytes", path, maxResponse)
	}
	return nil
}
