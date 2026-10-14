package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"time"
)

// maxJWKSFileBytes bounds the published key set file a self-check reads.
const maxJWKSFileBytes = 1 << 20

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
	body, err := c.fetchJWKSRaw()
	if err != nil {
		return JWKS{}, err
	}
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return JWKS{}, fmt.Errorf("jwks: %w", err)
	}
	return doc, nil
}

// fetchJWKSRaw returns the published document byte for byte, so a comparison
// sees members the typed JWKS does not model.
func (c Client) fetchJWKSRaw() ([]byte, error) {
	body, status, err := c.do(http.MethodGet, PathJWKS, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("jwks answered %d", status)
	}
	return body, nil
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
	liveRaw, err := c.fetchJWKSRaw()
	if err != nil {
		return append(checks, Check{Name: "socket_reachable", Detail: err.Error()})
	}
	var live JWKS
	if err := json.Unmarshal(liveRaw, &live); err != nil {
		return append(checks, Check{Name: "socket_reachable", Detail: fmt.Sprintf("jwks: %v", err)})
	}
	checks = append(checks, Check{Name: "socket_reachable", OK: len(live.Keys) > 0, Detail: fmt.Sprintf("%s serves %d key(s)", c.Socket, len(live.Keys))})
	if jwksPath == "" {
		return append(checks, Check{Name: "jwks_fresh", Detail: "identity.jwks_path is not configured"})
	}
	// One open serves the content and the mtime, so the age reported is the
	// age of the bytes compared.
	f, fi, err := openRegular(jwksPath)
	if err != nil {
		return append(checks, Check{Name: "jwks_fresh", Detail: err.Error()})
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxJWKSFileBytes+1))
	if err != nil || len(raw) > maxJWKSFileBytes {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s is unreadable or larger than %d bytes", jwksPath, maxJWKSFileBytes)})
	}
	same, err := sameJWKSDocument(liveRaw, raw)
	if err != nil {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s: %v", jwksPath, err)})
	}
	if !same {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s differs from the key set the server publishes", jwksPath)})
	}
	detail := jwksPath + " matches the published key set"
	if maxAge > 0 && now.Sub(fi.ModTime()) > maxAge {
		return append(checks, Check{Name: "jwks_fresh", Detail: fmt.Sprintf("%s is older than %s", jwksPath, maxAge)})
	}
	return append(checks, Check{Name: "jwks_fresh", OK: true, Detail: detail})
}

// sameJWKSDocument reports whether two JWKS documents are the same document:
// every JSON member of every key must match, not a chosen field list, so a
// changed alg, use or any unknown member such as key_ops is a difference. Keys
// are matched by kid, so their order does not matter; a repeated or missing kid
// makes the document unusable and is an error.
func sameJWKSDocument(a, b []byte) (bool, error) {
	x, err := normaliseJWKS(a)
	if err != nil {
		return false, err
	}
	y, err := normaliseJWKS(b)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(x, y), nil
}

func normaliseJWKS(raw []byte) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	list, ok := doc["keys"].([]any)
	if !ok {
		return nil, errors.New("no keys array")
	}
	byKid := make(map[string]any, len(list))
	for _, item := range list {
		key, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("a key is not a JSON object")
		}
		kid, _ := key["kid"].(string)
		if kid == "" {
			return nil, errors.New("a key has no kid")
		}
		if _, dup := byKid[kid]; dup {
			return nil, fmt.Errorf("kid %q appears more than once", kid)
		}
		byKid[kid] = key
	}
	doc["keys"] = byKid
	return doc, nil
}
