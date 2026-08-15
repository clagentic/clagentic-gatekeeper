// Package a2atoken implements the B3 mechanism (lr-890fae, settled at
// clagentic-gatekeeper lr-890fae comment #4, live-provisioned per openbao
// lr-fbbf32): gatekeeper signs a short-lived JWT ASSERTION (sub = the
// already-attested A2A caller identity) with its OWN key, and exchanges that
// assertion at OpenBao's dedicated JWT auth mount. OpenBao validates the
// assertion's signature independently, resolves sub via bound_subject to a
// PRE-REGISTERED entity-alias on that mount's own accessor, and returns a
// client token carrying the caller's REAL, pre-existing OpenBao entity. This
// package then reads identity/oidc/token/<role> with that client token to
// obtain the PEER-FACING token, which OpenBao signs — never this package.
//
// This is an I/O leaf, the A2A-domain analog of internal/githubapp: it talks
// to OpenBao's HTTP API and nothing else, and it is deliberately NOT the
// internal/broker.Broker interface — Broker is a plain Get(path)-shaped
// secret read, and this package performs a signed-assertion exchange plus a
// follow-on issuance call, a materially different shape.
//
// Gatekeeper's assertion signing key is a BEARER OF ATTESTATION, not the
// issuing key. It is read from the broker like any other secret, used only
// to sign the short-lived assertion, and is never conflated with, and never
// substitutes for, OpenBao's own identity/oidc signing key — OpenBao alone
// signs the peer-facing token. This package holds no long-lived credential
// of its own beyond what it reads from the broker for the duration of one
// call.
package a2atoken

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
	"strings"
	"time"
)

// Token is a minted peer-facing A2A credential. It is signed exclusively by
// OpenBao; gatekeeper never signs this value.
//
// Subject is the caller entity id OpenBao's issuance resolved sub to — the
// SAME value peers see in the token's own "sub" claim, surfaced here purely
// for gatekeeper's own audit record (mint.go's AC4-successor: gatekeeper's
// own audit trail carries attribution the wire token itself does not, per
// lr-890fae comment #5). It is never used to alter the wire token.
type Token struct {
	Value     string
	ExpiresAt time.Time
	Subject   string
}

// IssueRequest carries everything one A2A issuance call needs. Every value
// is either deployment config or the already-attested caller subject — this
// package never resolves attestation or entitlement itself (that is
// internal/attestation + internal/a2apolicy's job, run BEFORE this package
// is ever called).
type IssueRequest struct {
	// Endpoint is the OpenBao server URL (scheme://host[:port]), no
	// trailing slash required.
	Endpoint string
	// AssertionPrivateKeyPEM is gatekeeper's own RSA signing key for the
	// assertion — the bearer-of-attestation key, read from the broker.
	// Never OpenBao's OIDC signing key.
	AssertionPrivateKeyPEM string
	// Issuer is the value gatekeeper stamps into the assertion's "iss"
	// claim. Must match the JWT auth mount's configured bound_issuer.
	// Deployment-specific; never hardcoded.
	Issuer string
	// Subject is the ALREADY-ATTESTED, already-entitled caller identity
	// (attestation.Identity.Subject) to assert as the assertion's "sub"
	// claim. This package performs no attestation or entitlement check of
	// its own — a caller MUST run those gates first and fail closed before
	// ever constructing an IssueRequest.
	Subject string
	// AssertionTTL bounds the short-lived assertion's own lifetime (iat/exp
	// on the gatekeeper-signed JWT, distinct from the peer-facing token's
	// TTL, which OpenBao's identity/oidc role controls independently).
	AssertionTTL time.Duration
	// AuthMount is the path segment of OpenBao's dedicated JWT auth mount
	// (e.g. "a2a-jwt"), used to build /v1/auth/<AuthMount>/login.
	AuthMount string
	// AuthRole is the JWT auth role name to authenticate against under
	// AuthMount (role_type=jwt, user_claim=sub — this is what makes sub
	// resolve to the pre-registered entity-alias on the mount's own
	// accessor).
	AuthRole string
	// OIDCRole is the identity/oidc role name to read for the peer-facing
	// token: GET /v1/identity/oidc/token/<OIDCRole>.
	OIDCRole string
}

// Issue signs a short-lived assertion for req.Subject, exchanges it at
// OpenBao's JWT auth mount, and reads the peer-facing token from
// identity/oidc/token/<OIDCRole> using the resulting client token.
//
// Gatekeeper performs NO in-process signing of the returned peer-facing
// token (AC3) — only of the internal assertion, which OpenBao independently
// validates before ever resolving an identity from it. Every failure here
// returns no token material: a signature failure, a bound_subject rejection,
// or any transport error all propagate as plain errors with nothing minted.
func Issue(ctx context.Context, req IssueRequest) (Token, error) {
	if req.Endpoint == "" {
		return Token{}, fmt.Errorf("a2atoken: endpoint is required")
	}
	if req.Subject == "" {
		return Token{}, fmt.Errorf("a2atoken: subject is required")
	}
	if req.AuthMount == "" || req.AuthRole == "" {
		return Token{}, fmt.Errorf("a2atoken: auth mount and auth role are both required")
	}
	if req.OIDCRole == "" {
		return Token{}, fmt.Errorf("a2atoken: oidc role is required")
	}

	key, err := parseRSAPrivateKey(req.AssertionPrivateKeyPEM)
	if err != nil {
		// Never include the PEM content in errors — generic message only.
		return Token{}, fmt.Errorf("a2atoken: parse assertion private key: %w", err)
	}

	ttl := req.AssertionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()
	assertion, err := signAssertion(key, req.Issuer, req.Subject, now, now.Add(ttl))
	zeroKey(key)
	if err != nil {
		return Token{}, fmt.Errorf("a2atoken: sign assertion: %w", err)
	}

	endpoint := strings.TrimRight(req.Endpoint, "/")

	clientToken, err := exchangeAssertion(ctx, endpoint, req.AuthMount, req.AuthRole, assertion)
	if err != nil {
		return Token{}, fmt.Errorf("a2atoken: exchange assertion: %w", err)
	}

	return readOIDCToken(ctx, endpoint, req.OIDCRole, clientToken, req.Subject)
}

// signAssertion produces a compact RS256 JWT asserting sub=subject,
// iss=issuer. Deliberately omits "aud": the probe evidence (lr-890fae
// comment #4) established that an aud claim present with no bound_audiences
// configured on the receiving role is a HARD validation failure at OpenBao —
// omitting it entirely, rather than guessing a value, is the safe default.
func signAssertion(key *rsa.PrivateKey, issuer, subject string, iat, exp time.Time) (string, error) {
	header := base64url([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := map[string]any{
		"sub": subject,
		"iat": iat.Unix(),
		"exp": exp.Unix(),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := header + "." + base64url(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64url(sig), nil
}

// exchangeAssertion POSTs the signed assertion to OpenBao's JWT auth mount
// login endpoint and returns the resulting client token. OpenBao performs
// its own independent signature verification against jwt_validation_pubkeys
// and its own bound_subject narrowing — this function trusts OpenBao's
// verdict and returns whatever client token it hands back (or the error
// OpenBao reports, e.g. an untrusted-key or bound_subject rejection).
func exchangeAssertion(ctx context.Context, endpoint, mount, role, assertion string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"role": role,
		"jwt":  assertion,
	})
	if err != nil {
		return "", fmt.Errorf("marshal login request: %w", err)
	}

	url := endpoint + "/v1/auth/" + strings.TrimLeft(mount, "/") + "/login"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// OpenBao's error bodies for a failed JWT-auth login (bad signature,
		// unregistered subject) do not carry secret material — safe to
		// surface for diagnosis. This is exactly where the two negative
		// controls (untrusted key, bogus subject) surface their rejection.
		return "", fmt.Errorf("jwt auth login: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode login response: %w", err)
	}
	if result.Auth.ClientToken == "" {
		return "", fmt.Errorf("jwt auth login returned empty client_token")
	}
	return result.Auth.ClientToken, nil
}

// readOIDCToken reads identity/oidc/token/<role> using clientToken (the
// caller-entity-scoped token obtained from exchangeAssertion) and returns
// the resulting peer-facing Token. The returned token's "sub" claim resolves
// natively to the caller's real, pre-registered OpenBao entity — OpenBao
// signs it; this package never does. wantSubject is carried onto the
// returned Token.Subject for gatekeeper's own audit record — it is NOT
// re-verified against the wire token's claims here (that would require
// parsing/verifying a token this same call just requested, and OpenBao is
// already the trust anchor for what sub the entity resolution produced).
func readOIDCToken(ctx context.Context, endpoint, role, clientToken, wantSubject string) (Token, error) {
	url := endpoint + "/v1/identity/oidc/token/" + strings.TrimLeft(role, "/")
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Token{}, fmt.Errorf("build oidc token request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", clientToken)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return Token{}, fmt.Errorf("oidc token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return Token{}, fmt.Errorf("read oidc token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Token{}, fmt.Errorf("read identity/oidc/token/%s: HTTP %d: %s", role, resp.StatusCode, string(respBody))
	}

	var envelope struct {
		Data struct {
			Token string `json:"token"`
			TTL   int64  `json:"ttl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return Token{}, fmt.Errorf("decode oidc token response: %w", err)
	}
	if envelope.Data.Token == "" {
		return Token{}, fmt.Errorf("identity/oidc/token/%s: empty token in response", role)
	}

	return Token{
		Value:     envelope.Data.Token,
		ExpiresAt: time.Now().Add(time.Duration(envelope.Data.TTL) * time.Second),
		Subject:   wantSubject,
	}, nil
}

// parseRSAPrivateKey decodes a PEM-encoded RSA private key (PKCS#1 or
// PKCS#8). Mirrors internal/githubapp's parser exactly — both packages sign
// a short-lived RS256 JWT with a broker-sourced key, so the parsing logic is
// identical; kept as a private per-package copy rather than a shared helper
// because the two keys serve unrelated trust roles (App JWT signing key vs.
// gatekeeper's own assertion key) and unifying them risks an accidental
// future coupling between two keys that must stay independently rotatable.
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

// zeroKey overwrites sensitive scalar fields of the RSA private key with
// zeros. The key must not be used after this call. Mirrors
// internal/githubapp.zeroKey.
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

// base64url encodes b with base64url encoding without padding.
func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
