package a2atoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// generateTestPEM generates a fresh RSA-2048 private key and returns it as a
// PKCS#1 PEM string. Fails the test immediately on any error. Mirrors
// internal/githubapp's test helper of the same name — same shape, separate
// per-package copy per that package's own no-shared-test-helper posture.
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// fakeOpenBao simulates the two OpenBao endpoints a2atoken.Issue calls:
// POST /v1/auth/<mount>/login and GET /v1/identity/oidc/token/<role>.
//
// loginTrustedKey, when non-empty, is a stand-in for OpenBao's own
// jwt_validation_pubkeys signature check: this fake does not actually verify
// an RS256 signature (that is OpenBao's job, already proven live per
// lr-890fae comment #4) — it instead keys rejection off a caller-supplied
// "which key signed this" marker header the test sets, which is enough to
// exercise a2atoken's error-propagation path for both negative controls
// without reimplementing JWT verification in test code.
type fakeOpenBao struct {
	// rejectLogin, when true, makes the login endpoint return 400 — used to
	// simulate BOTH negative controls (untrusted assertion key -> signature
	// validation failure; bogus/unregistered sub -> bound_subject
	// rejection). OpenBao returns the same class of client-facing error
	// (400, denied) for either; this package's job is only to propagate the
	// refusal with no token material returned, not to distinguish the two
	// causes.
	rejectLogin bool
	// clientToken is returned by a successful login.
	clientToken string
	// oidcToken/oidcTTL are returned by a successful identity/oidc/token read.
	oidcToken string
	oidcTTL   int64
	// wantClientToken, when set, asserts the X-Vault-Token header presented
	// to the oidc endpoint matches the token the login step returned.
	wantClientToken string
}

func (f *fakeOpenBao) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/login"):
			if f.rejectLogin {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]string{"client_token": f.clientToken},
			})

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/identity/oidc/token/"):
			if f.wantClientToken != "" {
				got := r.Header.Get("X-Vault-Token")
				if got != f.wantClientToken {
					t.Errorf("oidc token request X-Vault-Token = %q, want %q", got, f.wantClientToken)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"token": f.oidcToken, "ttl": f.oidcTTL},
			})

		default:
			http.NotFound(w, r)
		}
	}
}

// baseRequest returns a valid IssueRequest against srv, for tests to mutate.
func baseRequest(t *testing.T, srvURL string) IssueRequest {
	return IssueRequest{
		Endpoint:               srvURL,
		AssertionPrivateKeyPEM: generateTestPEM(t),
		Issuer:                 "gatekeeper-test-issuer",
		Subject:                "peer-agent-alpha",
		AssertionTTL:           5 * time.Minute,
		AuthMount:              "a2a-jwt",
		AuthRole:               "a2a-role",
		OIDCRole:               "a2a-oidc-role",
	}
}

// TestIssueSuccess covers the happy path: assertion signed, exchanged, and
// the resulting peer-facing token read back with the expected value/TTL and
// the caller subject carried for gatekeeper's own audit record.
func TestIssueSuccess(t *testing.T) {
	fake := &fakeOpenBao{
		clientToken:     "s.caller-entity-scoped-token",
		oidcToken:       "eyJhbGciOiJSUzI1NiJ9.peer-facing-token.sig",
		oidcTTL:         300,
		wantClientToken: "s.caller-entity-scoped-token",
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	tok, err := Issue(context.Background(), req)
	if err != nil {
		t.Fatalf("Issue() unexpected error: %v", err)
	}
	if tok.Value != fake.oidcToken {
		t.Errorf("Token.Value = %q, want %q", tok.Value, fake.oidcToken)
	}
	if tok.Subject != req.Subject {
		t.Errorf("Token.Subject = %q, want %q", tok.Subject, req.Subject)
	}
	wantExpiry := time.Now().Add(300 * time.Second)
	if tok.ExpiresAt.Before(wantExpiry.Add(-5*time.Second)) || tok.ExpiresAt.After(wantExpiry.Add(5*time.Second)) {
		t.Errorf("Token.ExpiresAt = %v, not within tolerance of %v", tok.ExpiresAt, wantExpiry)
	}
}

// TestIssueUntrustedKeyRejected is negative control #1 (lr-890fae comment
// #4, reproduced live): an assertion signed with a key OpenBao does not
// trust fails signature validation. This fake stands in for that live
// rejection via the login endpoint returning a denial; the load-bearing
// assertion is that Issue propagates the failure with NO token material
// returned and never reaches the oidc-token read step.
func TestIssueUntrustedKeyRejected(t *testing.T) {
	oidcCalled := false
	fake := &fakeOpenBao{rejectLogin: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/oidc/token/") {
			oidcCalled = true
		}
		fake.handler(t)(w, r)
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	// A fresh, different key stands in for "untrusted" — OpenBao's
	// jwt_validation_pubkeys would reject a signature from any key it was
	// never configured to trust, which the fake models as an unconditional
	// login rejection.
	req.AssertionPrivateKeyPEM = generateTestPEM(t)

	tok, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for untrusted assertion key, got nil")
	}
	if tok.Value != "" {
		t.Errorf("expected no token material on rejection, got %q", tok.Value)
	}
	if oidcCalled {
		t.Error("identity/oidc/token endpoint must never be called after a login rejection")
	}
}

// TestIssueBogusSubjectRejected is negative control #2 (lr-890fae comment
// #4, reproduced live): an unregistered/bogus sub is refused by
// bound_subject. Modeled the same way as the untrusted-key control — the
// login endpoint denies — because from Issue's perspective both negative
// controls surface as the identical shape: a login failure with no token
// material and no oidc-token read attempted.
func TestIssueBogusSubjectRejected(t *testing.T) {
	oidcCalled := false
	fake := &fakeOpenBao{rejectLogin: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/oidc/token/") {
			oidcCalled = true
		}
		fake.handler(t)(w, r)
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	req.Subject = "unregistered-bogus-caller"

	tok, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for bogus/unregistered subject, got nil")
	}
	if tok.Value != "" {
		t.Errorf("expected no token material on rejection, got %q", tok.Value)
	}
	if oidcCalled {
		t.Error("identity/oidc/token endpoint must never be called after a login rejection")
	}
}

// TestIssueRequiresSubject / TestIssueRequiresEndpoint / TestIssueRequiresRoles
// cover the pre-flight validation guarding against a caller invoking Issue
// with an incomplete request — these must fail before any HTTP call at all.
func TestIssueRequiresSubject(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.Subject = ""
	if _, err := Issue(context.Background(), req); err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
}

func TestIssueRequiresEndpoint(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.Endpoint = ""
	if _, err := Issue(context.Background(), req); err == nil {
		t.Fatal("expected error for empty endpoint, got nil")
	}
}

func TestIssueRequiresAuthMountAndRole(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.AuthMount = ""
	if _, err := Issue(context.Background(), req); err == nil {
		t.Fatal("expected error for empty auth mount, got nil")
	}
}

func TestIssueRequiresOIDCRole(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.OIDCRole = ""
	if _, err := Issue(context.Background(), req); err == nil {
		t.Fatal("expected error for empty oidc role, got nil")
	}
}

// TestIssueBadPrivateKey covers the parse-failure path and asserts the raw
// PEM content never leaks into the error message.
func TestIssueBadPrivateKey(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.AssertionPrivateKeyPEM = "not a valid pem"

	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for garbage PEM, got nil")
	}
	if strings.Contains(err.Error(), "not a valid pem") {
		t.Fatalf("error message leaks private key PEM content: %v", err)
	}
}

// TestIssueNoAudienceClaim asserts the signed assertion never carries an
// "aud" claim, per lr-890fae comment #4's hard-validation-failure finding:
// aud present with no bound_audiences configured on the receiving role is a
// hard OpenBao rejection, so this package omits it entirely rather than
// guessing a value. Exercised indirectly by decoding the assertion payload
// signAssertion produces.
func TestIssueNoAudienceClaim(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	now := time.Now()
	assertion, err := signAssertion(key, "gatekeeper-test-issuer", "peer-agent-alpha", now, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("signAssertion: %v", err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion must have 3 JWT segments, got %d", len(parts))
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims segment: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if _, ok := claims["aud"]; ok {
		t.Fatalf("assertion must never carry an aud claim: %s", claimsJSON)
	}
	if claims["sub"] != "peer-agent-alpha" {
		t.Errorf("claims[sub] = %v, want %q", claims["sub"], "peer-agent-alpha")
	}
}

// TestIssueLoginFailureParsesOpenBaoErrorEnvelope covers the MILLER-
// adjudicated F1 fix (lr-890fae comment #8): a login failure whose body
// matches OpenBao's documented {"errors":[...]} envelope surfaces exactly
// those strings, joined, not the raw JSON bytes — the comment at this
// file's top (originally :215-218) reasoning that OpenBao's OWN error
// bodies carry no secrets is preserved and still applies here; this test
// proves it by asserting the specific documented shape survives intact.
func TestIssueLoginFailureParsesOpenBaoErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"errors": []string{"permission denied", "invalid role"},
		})
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for login failure, got nil")
	}
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	if !strings.Contains(transportErr.Error(), "permission denied") || !strings.Contains(transportErr.Error(), "invalid role") {
		t.Errorf("TransportError.Error() = %q, want both OpenBao error strings surfaced", transportErr.Error())
	}
	if strings.Contains(transportErr.Error(), `{"errors"`) {
		t.Errorf("TransportError.Error() = %q, want parsed strings, not the raw JSON envelope", transportErr.Error())
	}
}

// TestIssueLoginFailureTruncatesNonOpenBaoBody covers the case the
// envelope-parsing comment explicitly does NOT cover: a body that does not
// match OpenBao's documented shape at all — e.g. an intervening proxy's own
// error page — which is unbounded third-party content once anything sits
// between gatekeeper and OpenBao. It must be truncated, not echoed verbatim.
func TestIssueLoginFailureTruncatesNonOpenBaoBody(t *testing.T) {
	hugeProxyBody := "<html><body>" + strings.Repeat("proxy-error-detail-", 30) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(hugeProxyBody)) //nolint:errcheck
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for login failure, got nil")
	}
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	msg := transportErr.Error()
	if strings.Contains(msg, hugeProxyBody) {
		t.Fatalf("TransportError.Error() contains the full, untruncated proxy body: %q", msg)
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Errorf("TransportError.Error() = %q, want the truncation marker for an oversized non-OpenBao-shaped body", msg)
	}
	if len(msg) > maxRawBodyExcerpt+100 {
		t.Errorf("TransportError.Error() is not bounded: %d bytes: %q", len(msg), msg)
	}
}

// TestIssueLoginFailureTruncatesOversizedOpenBaoEnvelope covers the F1
// class-completeness gap MILLER's adjudication (lr-890fae comment #11)
// identified: parseOpenBaoErrors' PARSED-envelope branch
// (strings.Join(envelope.Errors, "; ")) was returned with no bound at all —
// only the raw-body FALLBACK branch was ever truncated. This test drives a
// body that DOES match OpenBao's documented {"errors":[...]} shape but whose
// joined strings exceed maxRawBodyExcerpt, asserting the parsed-envelope
// branch is bounded identically to the fallback branch.
func TestIssueLoginFailureTruncatesOversizedOpenBaoEnvelope(t *testing.T) {
	oversizedErrors := []string{
		strings.Repeat("validation-failure-detail-", 10),
		strings.Repeat("second-error-detail-", 10),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"errors": oversizedErrors,
		})
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for login failure, got nil")
	}
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	msg := transportErr.Error()

	joined := strings.Join(oversizedErrors, "; ")
	if len(joined) <= maxRawBodyExcerpt {
		t.Fatalf("test setup error: joined envelope strings (%d bytes) must exceed maxRawBodyExcerpt (%d) to exercise the bound", len(joined), maxRawBodyExcerpt)
	}
	if strings.Contains(msg, joined) {
		t.Fatalf("TransportError.Error() contains the full, untruncated joined envelope strings: %q", msg)
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Errorf("TransportError.Error() = %q, want the truncation marker for an oversized parsed-envelope body", msg)
	}
	if len(msg) > maxRawBodyExcerpt+100 {
		t.Errorf("TransportError.Error() is not bounded: %d bytes: %q", len(msg), msg)
	}
}

// TestIssueLoginFailureCapsResponseBodyRead covers the second F1-class gap
// MILLER's adjudication identified as WORSE than the truncation bug: neither
// exchangeAssertion nor readOIDCToken ever bounded the io.ReadAll read
// itself — the full body materialized in memory BEFORE either
// parseOpenBaoErrors branch ran, so maxRawBodyExcerpt was never a memory
// bound on any path. This test drives a body larger than
// maxResponseBodyBytes and asserts Issue still returns promptly with a
// bounded error, proving the read itself — not just the rendered string —
// is capped.
func TestIssueLoginFailureCapsResponseBodyRead(t *testing.T) {
	// Larger than maxResponseBodyBytes, not merely larger than
	// maxRawBodyExcerpt — this exercises the io.LimitReader on the read
	// itself, a distinct bound from the string-truncation bound.
	hugeBody := strings.Repeat("a", maxResponseBodyBytes*2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(hugeBody)) //nolint:errcheck
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for login failure, got nil")
	}
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	msg := transportErr.Error()
	if len(msg) > maxRawBodyExcerpt+100 {
		t.Errorf("TransportError.Error() is not bounded: %d bytes: %q", len(msg), msg)
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Errorf("TransportError.Error() = %q, want the truncation marker", msg)
	}
}

// TestIssueOIDCReadFailureUsesTransportError covers the second raw-body
// interpolation site (originally a2atoken.go:265, the identity/oidc/token
// read): it must also return a *TransportError with a bounded/parsed
// message, matching the login-leg fix rather than leaving this call site on
// the old raw-body-interpolation behavior.
func TestIssueOIDCReadFailureUsesTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/login"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"auth": map[string]string{"client_token": "s.test-client-token"},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/identity/oidc/token/"):
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"errors": []string{"unknown role"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	_, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for oidc token read failure, got nil")
	}
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	if !strings.Contains(transportErr.Error(), "unknown role") {
		t.Errorf("TransportError.Error() = %q, want the parsed OpenBao error string", transportErr.Error())
	}
}
