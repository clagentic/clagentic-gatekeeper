// Package githubapp signs the GitHub App JWT and exchanges it for a short-lived,
// permission-narrowed installation access token. It is an I/O leaf: it talks to
// the GitHub API and nothing else. The App private key is used only to sign the
// JWT and is never returned, logged, or persisted.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// Token is a minted installation access token and its expiry.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// MintRequest narrows an installation token to a role's permissions and repos.
type MintRequest struct {
	APIBase        string            // e.g. https://api.github.com
	AppID          string            // GitHub App numeric ID (from broker)
	InstallationID string            // installation ID on the target org (from broker)
	PrivateKeyPEM  string            // App private key PEM (from broker) — never logged
	Permissions    map[string]string // role-narrowed permissions
	Repositories   []string          // repo names to scope the token to (may be empty = all)
	TTL            time.Duration     // requested lifetime; GitHub caps at 1h
}

const maxJWTLifetime = 10 * time.Minute

// Mint signs the App JWT and calls
// POST {APIBase}/app/installations/{InstallationID}/access_tokens
// with the narrowed permissions and repositories, returning the scoped token.
func Mint(ctx context.Context, req MintRequest) (Token, error) {
	appID, err := strconv.ParseInt(req.AppID, 10, 64)
	if err != nil {
		return Token{}, fmt.Errorf("invalid AppID %q: %w", req.AppID, err)
	}

	installationID, err := strconv.ParseInt(req.InstallationID, 10, 64)
	if err != nil {
		return Token{}, fmt.Errorf("invalid InstallationID %q: %w", req.InstallationID, err)
	}

	key, err := parseRSAPrivateKey(req.PrivateKeyPEM)
	if err != nil {
		// Never include the PEM content in errors — return a generic message.
		return Token{}, fmt.Errorf("parse private key: %w", err)
	}

	now := time.Now()
	iat := now.Add(-60 * time.Second)
	ttl := req.TTL
	if ttl <= 0 || ttl > maxJWTLifetime {
		ttl = maxJWTLifetime
	}
	exp := iat.Add(ttl)

	jwt, err := signJWT(key, appID, iat.Unix(), exp.Unix())
	zeroKey(key)
	if err != nil {
		return Token{}, fmt.Errorf("sign JWT: %w", err)
	}

	return exchangeToken(ctx, req.APIBase, installationID, jwt, req.Permissions, req.Repositories)
}

// parseRSAPrivateKey decodes a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// zeroKey overwrites sensitive scalar fields of the RSA private key with zeros.
// The key must not be used after this call.
func zeroKey(key *rsa.PrivateKey) {
	if key == nil {
		return
	}
	zeroInt(key.D)
	for _, p := range key.Primes {
		zeroInt(p)
	}
	zeroInt(key.Precomputed.Dp)
	zeroInt(key.Precomputed.Dq)
	zeroInt(key.Precomputed.Qinv)
}

func zeroInt(n *big.Int) {
	if n == nil {
		return
	}
	b := n.Bits()
	for i := range b {
		b[i] = 0
	}
}

// signJWT produces a compact RS256 JWT with the given claims.
func signJWT(key *rsa.PrivateKey, appID, iat, exp int64) (string, error) {
	header := base64url([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claimsJSON, err := json.Marshal(map[string]any{
		"iss": appID,
		"iat": iat,
		"exp": exp,
	})
	if err != nil {
		return "", err
	}
	claims := base64url(claimsJSON)

	signingInput := header + "." + claims
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64url(sig), nil
}

// base64url encodes b with base64url encoding without padding.
func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// accessTokenRequest is the JSON body sent to GitHub's access_tokens endpoint.
type accessTokenRequest struct {
	Permissions  map[string]string `json:"permissions,omitempty"`
	Repositories []string          `json:"repositories,omitempty"`
}

// accessTokenResponse is the relevant subset of GitHub's access_tokens response.
type accessTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// exchangeToken swaps a signed App JWT for a scoped installation access token.
func exchangeToken(ctx context.Context, apiBase string, installationID int64, jwt string, permissions map[string]string, repositories []string) (Token, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBase, installationID)

	body := accessTokenRequest{
		Permissions: permissions,
	}
	// Omit repositories when empty — GitHub interprets absence as "all installed repos".
	if len(repositories) > 0 {
		body.Repositories = repositories
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return Token{}, fmt.Errorf("marshal request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return Token{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+jwt)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return Token{}, fmt.Errorf("call GitHub API: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// GitHub error bodies are safe to surface — no secrets.
		return Token{}, fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var tokenResp accessTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return Token{}, fmt.Errorf("parse response: %w", err)
	}

	expiresAt, err := time.Parse(time.RFC3339, tokenResp.ExpiresAt)
	if err != nil {
		return Token{}, fmt.Errorf("parse expires_at %q: %w", tokenResp.ExpiresAt, err)
	}

	return Token{
		Value:     tokenResp.Token,
		ExpiresAt: expiresAt,
	}, nil
}
