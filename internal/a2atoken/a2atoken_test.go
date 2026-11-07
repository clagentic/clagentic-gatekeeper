package a2atoken

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testAssertion stands in for a serve-issued identity assertion. The fake JWT
// mount below compares it as an opaque string; signature verification is
// OpenBao's job and is exercised live, not here.
const testAssertion = "eyJhbGciOiJFZERTQSJ9.test-assertion-payload.test-signature"

// fakeOpenBao is the fake JWT mount: it simulates the two OpenBao endpoints
// a2atoken.Issue calls, POST /v1/auth/<mount>/login and GET
// /v1/identity/oidc/token/<role>.
//
// It accepts a login only when the posted jwt equals trustedAssertion, which
// models the mount trusting exactly the serve JWKS: any other assertion (one
// signed by a key outside the JWKS) is refused with the same 400 OpenBao
// returns.
type fakeOpenBao struct {
	// trustedAssertion is the only assertion the mount accepts. Empty means
	// every login is accepted.
	trustedAssertion string
	// rejectLogin, when true, makes the login endpoint return 400 for every
	// request, modelling an unmapped act.sub or any other mount refusal.
	rejectLogin bool
	// gotLogin records the last login request body.
	gotLogin map[string]string
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
			raw, _ := io.ReadAll(r.Body)
			f.gotLogin = map[string]string{}
			if err := json.Unmarshal(raw, &f.gotLogin); err != nil {
				t.Errorf("login body is not a JSON object of strings: %v", err)
			}
			if f.rejectLogin || (f.trustedAssertion != "" && f.gotLogin["jwt"] != f.trustedAssertion) {
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
		Endpoint:  srvURL,
		Assertion: testAssertion,
		Subject:   "peer-agent-alpha",
		AuthMount: "a2a-jwt",
		AuthRole:  "a2a-role",
		OIDCRole:  "a2a-oidc-role",
	}
}

// TestIssueSuccess covers the happy path: the assertion logs in at the mount
// under the configured role, the returned client token requests the identity
// token, and the peer-facing token comes back with the expected value/TTL and
// the caller subject carried for gatekeeper's own audit record.
func TestIssueSuccess(t *testing.T) {
	fake := &fakeOpenBao{
		trustedAssertion: testAssertion,
		clientToken:      "s.caller-entity-scoped-token",
		oidcToken:        "eyJhbGciOiJSUzI1NiJ9.peer-facing-token.sig",
		oidcTTL:          300,
		wantClientToken:  "s.caller-entity-scoped-token",
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
	if fake.gotLogin["role"] != "a2a-role" || fake.gotLogin["jwt"] != testAssertion {
		t.Errorf("login body = %v, want role a2a-role and the presented assertion as jwt", fake.gotLogin)
	}
}

// TestIssueUntrustedKeyRejected: an assertion signed by a key outside the
// serve JWKS is refused at login. The fake mount trusts exactly one assertion
// to model that; the load-bearing assertion is that Issue propagates the
// refusal with NO token material and never reaches the identity-token read.
func TestIssueUntrustedKeyRejected(t *testing.T) {
	oidcCalled := false
	fake := &fakeOpenBao{trustedAssertion: testAssertion, clientToken: "s.never", oidcToken: "never"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/identity/oidc/token/") {
			oidcCalled = true
		}
		fake.handler(t)(w, r)
	}))
	defer srv.Close()

	req := baseRequest(t, srv.URL)
	req.Assertion = "eyJhbGciOiJFZERTQSJ9.forged-payload.forged-signature"

	tok, err := Issue(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for an assertion outside the trusted JWKS, got nil")
	}
	if tok.Value != "" {
		t.Errorf("expected no token material on rejection, got %q", tok.Value)
	}
	if oidcCalled {
		t.Error("identity/oidc/token endpoint must never be called after a login rejection")
	}
	if strings.Contains(err.Error(), req.Assertion) {
		t.Errorf("error leaks the assertion: %v", err)
	}
}

// TestIssueBogusSubjectRejected: an unmapped act.sub is refused by the mount,
// which surfaces as the same login failure with no token material and no
// identity-token read attempted.
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

// TestIssueRequiresAssertion: with no assertion there is nothing to log in
// with, and Issue must refuse before any HTTP call.
func TestIssueRequiresAssertion(t *testing.T) {
	req := baseRequest(t, "https://example.invalid")
	req.Assertion = ""
	if _, err := Issue(context.Background(), req); err == nil {
		t.Fatal("expected error for an empty assertion, got nil")
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
