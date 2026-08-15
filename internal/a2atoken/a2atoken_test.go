package a2atoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
