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

// maxRawBodyExcerpt bounds how much of an HTTP response body is ever echoed
// into an error message — applied uniformly to BOTH parseOpenBaoErrors
// branches: the joined {"errors":[...]} strings and the raw-body fallback
// alike. OpenBao's own documented error shape is small, but neither branch
// gets a free pass — an OpenBao deployment could still return an oversized
// errors[] array, and the body that ARRIVES looking like something else
// entirely (e.g. an intervening proxy's HTML error page) is unbounded
// third-party content once anything sits between gatekeeper and OpenBao.
// This bound is on the STRING gatekeeper builds from the body, not on the
// bytes read off the wire — see maxResponseBodyBytes for that.
const maxRawBodyExcerpt = 200

// maxResponseBodyBytes caps how many bytes are ever read off an OpenBao HTTP
// response before either parseOpenBaoErrors branch runs. This is a memory
// bound, independent of maxRawBodyExcerpt: without it, io.ReadAll would
// materialize an arbitrarily large body in full BEFORE any truncation logic
// ever sees it, so maxRawBodyExcerpt bounded only the rendered error string,
// never the read itself — a hostile or misconfigured intervening proxy could
// still OOM the process on the read alone.
//
// 64KiB is chosen deliberately: comfortably larger than any legitimate
// OpenBao response this package ever needs to parse (the {"errors":[...]}
// envelope and the identity/oidc/token {"data":{"token":...}} envelope are
// both tiny — well under 4KiB even with a verbose validation message or a
// full-size signed JWT in the token field), so real diagnostics and real
// token payloads are never silently clipped, while still being a real,
// small bound on worst-case memory for a single response.
const maxResponseBodyBytes = 64 * 1024

// TransportError is returned for any failure a2atoken.Issue encounters while
// talking to OpenBao's HTTP API: a non-2xx response, an unreadable body, or
// an undecodable response envelope. It is a distinct error type — rather
// than a plain fmt.Errorf-wrapped string — specifically so a caller (e.g.
// internal/a2amint) can apply targeted redaction to THIS error class without
// having to blanket-redact every error a2amint might see, including its own
// internal ones (a2amint.Service.Mint's other failure paths: missing
// resolver, denied entitlement, missing broker, unreadable key — none of
// which ever carry third-party response content and all of which stay fully
// diagnosable).
//
// Message is already bounded/redacted per Error() below — both the joined
// OpenBao "errors" strings and the raw-body fallback are truncated to
// maxRawBodyExcerpt by parseOpenBaoErrors, and the body itself was never
// read past maxResponseBodyBytes off the wire in the first place. Callers
// should use Error() (or fmt "%v"/"%w") rather than re-deriving a message
// from any other field, so the bound is never bypassed downstream.
type TransportError struct {
	// Op names the OpenBao call that failed (e.g. "jwt auth login",
	// "read identity/oidc/token").
	Op string
	// StatusCode is the HTTP status OpenBao (or an intervening proxy)
	// returned. Zero when the failure occurred before a response was ever
	// received (e.g. a read error).
	StatusCode int
	// detail is the already-bounded/redacted message describing the body —
	// either the joined OpenBao "errors" strings (itself truncated to
	// maxRawBodyExcerpt) or a truncated raw excerpt when the body did not
	// parse as OpenBao's envelope. Unexported so the only way to read it is
	// through Error(), keeping the bound in one place.
	detail string
}

func (e *TransportError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("a2atoken: %s: HTTP %d: %s", e.Op, e.StatusCode, e.detail)
	}
	return fmt.Sprintf("a2atoken: %s: %s", e.Op, e.detail)
}

// parseOpenBaoErrors extracts a bounded, safe-to-log message from an OpenBao
// HTTP error response body. BOTH return paths are bounded to
// maxRawBodyExcerpt — this function never returns an unbounded string.
//
// OpenBao's own documented error shape is {"errors": ["msg", ...]} — its own
// error bodies carry no secret material (they describe validation/policy
// outcomes, e.g. "permission denied", not request or token content), so
// parsing and surfacing those strings is safe from a CONTENT-sensitivity
// standpoint. That safety reasoning is specific to OpenBao's own error
// responses; it does NOT extend to whatever body an intervening proxy might
// substitute in OpenBao's place (a misconfigured gateway, an auth-proxy
// error page, a load balancer 502) — a body that fails to parse as the
// documented envelope is untrusted, third-party content. Regardless of
// which branch runs, the LENGTH bound applies identically: a deployment
// could still configure OpenBao to return an oversized errors[] array, so
// the joined-strings branch is truncated exactly like the fallback rather
// than assumed small because it parsed.
func parseOpenBaoErrors(body []byte) string {
	var envelope struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && len(envelope.Errors) > 0 {
		return truncateExcerpt([]byte(strings.Join(envelope.Errors, "; ")))
	}
	return truncateExcerpt(body)
}

// truncateExcerpt bounds an arbitrary response body to a fixed-length,
// safe-to-log excerpt.
func truncateExcerpt(body []byte) string {
	s := strings.TrimSpace(string(body))
	if s == "" {
		return "(empty body)"
	}
	if len(s) > maxRawBodyExcerpt {
		return s[:maxRawBodyExcerpt] + "...(truncated)"
	}
	return s
}

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

	// Capped BEFORE any parsing decision is made — see maxResponseBodyBytes:
	// this is a memory bound on the read itself, independent of
	// maxRawBodyExcerpt's bound on the rendered error string.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return "", fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// OpenBao's error bodies for a failed JWT-auth login (bad signature,
		// unregistered subject) do not carry secret material — safe to
		// surface for diagnosis. This is exactly where the two negative
		// controls (untrusted key, bogus subject) surface their rejection.
		// parseOpenBaoErrors extracts OpenBao's documented {"errors":[...]}
		// envelope when the body matches that shape, or truncates when it
		// does not (e.g. an intervening proxy's own error page); both
		// outcomes are bounded to maxRawBodyExcerpt, and respBody itself was
		// already capped to maxResponseBodyBytes off the wire above.
		return "", &TransportError{Op: "jwt auth login", StatusCode: resp.StatusCode, detail: parseOpenBaoErrors(respBody)}
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

	// Capped BEFORE any parsing decision is made — see maxResponseBodyBytes.
	// The legitimate success payload here (a signed JWT in envelope.Data.Token)
	// is well within the cap; only an oversized/hostile body is affected.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return Token{}, fmt.Errorf("read oidc token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return Token{}, &TransportError{Op: "read identity/oidc/token/" + role, StatusCode: resp.StatusCode, detail: parseOpenBaoErrors(respBody)}
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
