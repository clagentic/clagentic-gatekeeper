package attestation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// This file owns key set discovery and fetching for the assertion provider:
// the locator rules of docs/identity-contract.md section 5.1 and the bounded
// fetch of section 5.2. It never extends trust; the caller has already matched
// iss against the configured issuers.

const (
	wellKnownJWKS    = "/.well-known/jwks.json"
	maxJWKSBytes     = 65536
	jwksFetchTimeout = 10 * time.Second
)

type locatorKind int

const (
	locFile locatorKind = iota
	locHTTP
	locUnix
)

// locator is where one issuer's key set is read. For locFile and locHTTP the
// target is the document; for locUnix it is the socket serving wellKnownJWKS.
type locator struct {
	kind   locatorKind
	target string
}

// resolveLocator applies the explicit locator when given, else derives one
// from iss.
func resolveLocator(iss, explicit string) (locator, error) {
	if explicit != "" {
		return parseLocator(explicit)
	}
	u, err := url.Parse(iss)
	if err != nil || u.Scheme == "" {
		return locator{}, fmt.Errorf("iss has no derivable key set location; set jwks")
	}
	switch u.Scheme {
	case "https", "http":
		if u.Host == "" {
			return locator{}, fmt.Errorf("iss has no host; set jwks")
		}
		doc := *u
		doc.Path = strings.TrimSuffix(u.Path, "/") + wellKnownJWKS
		doc.RawQuery, doc.Fragment = "", ""
		return parseLocator(doc.String())
	case "file", "unix":
		return parseLocator(iss)
	}
	return locator{}, fmt.Errorf("iss scheme %q has no derivable key set location; set jwks", u.Scheme)
}

// parseLocator reads the contract's notations, and a bare absolute path as a
// file, the form config files use for a path.
func parseLocator(s string) (locator, error) {
	if filepath.IsAbs(s) {
		return locator{kind: locFile, target: filepath.Clean(s)}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return locator{}, fmt.Errorf("jwks locator %q is not a valid URL", s)
	}
	switch u.Scheme {
	case "file", "unix":
		if u.Host != "" || !path.IsAbs(u.Path) {
			return locator{}, fmt.Errorf("jwks locator %q must be %s:///absolute/path", s, u.Scheme)
		}
		kind := locFile
		if u.Scheme == "unix" {
			kind = locUnix
		}
		return locator{kind: kind, target: path.Clean(u.Path)}, nil
	case "https":
		if u.Host == "" {
			return locator{}, fmt.Errorf("jwks locator %q has no host", s)
		}
		return locator{kind: locHTTP, target: u.String()}, nil
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return locator{}, fmt.Errorf("jwks locator %q: plain http is only permitted for a loopback host", s)
		}
		return locator{kind: locHTTP, target: u.String()}, nil
	}
	return locator{}, fmt.Errorf("jwks locator %q: scheme must be file, unix, http, https or an absolute path", s)
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// fetchJWKS reads the key set document. Network reads are bounded by a
// timeout and a size cap and refuse a redirect to another host.
func fetchJWKS(ctx context.Context, l locator) ([]byte, error) {
	switch l.kind {
	case locFile:
		return readJWKSFile(l.target)
	case locUnix:
		client := &http.Client{
			Timeout: jwksFetchTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", l.target)
				},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		return getBounded(ctx, client, "http://localhost"+wellKnownJWKS)
	case locHTTP:
		client := &http.Client{
			Timeout: jwksFetchTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 || req.URL.Host != via[0].URL.Host {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
		return getBounded(ctx, client, l.target)
	}
	return nil, fmt.Errorf("unknown locator kind")
}

func getBounded(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("key set answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("key set larger than %d bytes", maxJWKSBytes)
	}
	return body, nil
}

// readJWKSFile reads a key set file through one no-follow handle and refuses a
// file that group or other can write: such a file would let them add a key.
func readJWKSFile(p string) ([]byte, error) {
	data, fi, err := readFileNoFollow(p, maxJWKSBytes)
	if err != nil {
		switch {
		case errors.Is(err, errFileLink):
			return nil, fmt.Errorf("key set file %s is a symlink or not a regular file", p)
		case errors.Is(err, errFileTooLarge):
			return nil, fmt.Errorf("key set file %s is larger than %d bytes", p, maxJWKSBytes)
		}
		return nil, fmt.Errorf("read key set file: %w", err)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("key set file %s is writable by group or other (mode %#o)", p, fi.Mode().Perm())
	}
	return data, nil
}

func parseJWKS(raw []byte) ([]jwk, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("key set is not a JWKS document: %w", err)
	}
	return doc.Keys, nil
}
