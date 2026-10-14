package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
