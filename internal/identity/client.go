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

// issue posts req and decodes the answer into out; a refusal comes back as an
// *IssueError. It is the one place a refusal is read off the wire, for every
// operation the server offers.
func (c Client) issue(path string, req, out any) error {
	body, status, err := c.do(http.MethodPost, path, req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		var ie IssueError
		if json.Unmarshal(body, &ie) == nil && ie.Code != "" {
			ie.Status = status
			return &ie
		}
		return fmt.Errorf("server answered %d: %.200s", status, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("server reply: %w", err)
	}
	return nil
}

// IssueSession asks for a session assertion.
func (c Client) IssueSession(req SessionRequest) (*Issued, error) {
	var out Issued
	if err := c.issue(PathIssueSession, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IssueChild asks for a child assertion.
func (c Client) IssueChild(req ChildRequest) (*Issued, error) {
	var out Issued
	if err := c.issue(PathIssueChild, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RequestApproval records a pending operator approval bound to the session the
// token belongs to.
func (c Client) RequestApproval(req ApprovalRequest) (*ApprovalPending, error) {
	var out ApprovalPending
	if err := c.issue(PathApprovalRequest, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GrantApproval asks the issuer to sign the approval for a pending request.
func (c Client) GrantApproval(req ApprovalGrantRequest) (*ApprovalGranted, error) {
	var out ApprovalGranted
	if err := c.issue(PathApprovalGrant, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchApproval returns the signed approval of a granted request, once.
func (c Client) FetchApproval(req ApprovalFetchRequest) (*ApprovalFetched, error) {
	var out ApprovalFetched
	if err := c.issue(PathApprovalFetch, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FetchJWKSBytes reads the key set document exactly as the server sends it, so
// a caller can compare it with a file byte for byte.
func (c Client) FetchJWKSBytes() ([]byte, error) {
	body, status, err := c.do(http.MethodGet, PathJWKS, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("jwks answered %d", status)
	}
	return body, nil
}

// FetchJWKS reads the key set the server publishes.
func (c Client) FetchJWKS() (JWKS, error) {
	body, err := c.FetchJWKSBytes()
	if err != nil {
		return JWKS{}, err
	}
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return JWKS{}, fmt.Errorf("jwks: %w", err)
	}
	return doc, nil
}
