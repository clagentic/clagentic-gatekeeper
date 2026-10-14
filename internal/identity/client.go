package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"time"
)

// Client talks to a running server over its unix socket.
type Client struct {
	Socket  string
	Timeout time.Duration
}

func (c Client) http() *http.Client {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.Socket)
			},
			DisableKeepAlives: true,
		},
	}
}

func (c Client) do(method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://localhost"+path, rd)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("socket %s: %w", c.Socket, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, err
}

func (c Client) issue(path string, req any) (*Issued, error) {
	body, status, err := c.do(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		var ie IssueError
		if json.Unmarshal(body, &ie) == nil && ie.Code != "" {
			ie.Status = status
			return nil, &ie
		}
		return nil, fmt.Errorf("server answered %d: %.200s", status, body)
	}
	var out Issued
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("server reply: %w", err)
	}
	return &out, nil
}

// IssueSession asks for a session assertion.
func (c Client) IssueSession(req SessionRequest) (*Issued, error) {
	return c.issue(PathIssueSession, req)
}

// IssueChild asks for a child assertion.
func (c Client) IssueChild(req ChildRequest) (*Issued, error) {
	return c.issue(PathIssueChild, req)
}

// FetchJWKS reads the key set the server publishes.
func (c Client) FetchJWKS() (JWKS, error) {
	body, status, err := c.do(http.MethodGet, PathJWKS, nil)
	if err != nil {
		return JWKS{}, err
	}
	if status != http.StatusOK {
		return JWKS{}, fmt.Errorf("jwks answered %d", status)
	}
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return JWKS{}, fmt.Errorf("jwks: %w", err)
	}
	return doc, nil
}

// Check is one line of a self-check report.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// SelfCheck reports whether the socket answers and whether the JWKS file at
// jwksPath still matches what the server publishes. maxAge bounds how old the
// file may be; zero skips the age test.
func SelfCheck(c Client, jwksPath string, maxAge time.Duration, now time.Time) []Check {
	var checks []Check
	live, err := c.FetchJWKS()
	if err != nil {
		return append(checks, Check{Name: "socket_reachable", Detail: err.Error()})
	}
	checks = append(checks, Check{Name: "socket_reachable", OK: len(live.Keys) > 0, Detail: fmt.Sprintf("%s serves %d key(s)", c.Socket, len(live.Keys))})
	if jwksPath == "" {
		return append(checks, Check{Name: "jwks_fresh", Detail: "identity.jwks_path is not configured"})
	}
	raw, err := os.ReadFile(jwksPath)
	if err != nil {
		return append(checks, Check{Name: "jwks_fresh", Detail: err.Error()})
	}
	var onDisk JWKS
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s: %v", jwksPath, err)})
	}
	if !sameKids(live, onDisk) {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s lists different key ids than the server publishes", jwksPath)})
	}
	detail := jwksPath + " matches the published key set"
	if fi, err := os.Stat(jwksPath); err == nil && maxAge > 0 && now.Sub(fi.ModTime()) > maxAge {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s is older than %s", jwksPath, maxAge)})
	}
	return append(checks, Check{Name: "jwks_fresh", OK: true, Detail: detail})
}

func sameKids(a, b JWKS) bool {
	ids := func(d JWKS) []string {
		out := make([]string, 0, len(d.Keys))
		for _, k := range d.Keys {
			out = append(out, k.Kid)
		}
		sort.Strings(out)
		return out
	}
	x, y := ids(a), ids(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
