//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

// captureStderr redirects os.Stderr for the duration of fn and returns
// everything written to it. Mirrors captureStdout (main_test.go) — used here
// because runMintA2A's audit hook (Service.Audit in main.go) writes the mint
// audit record to os.Stderr specifically, never os.Stdout.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("captureStderr: create pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("captureStderr: close pipe writer: %v", err)
	}
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("captureStderr: read pipe: %v", err)
	}
	return buf.String()
}

// quoteAllJSONStrings renders each string in ss as a JSON string literal,
// joined by commas — used to hand-construct a raw OpenBao {"errors":[...]}
// response body without importing encoding/json purely for a one-off test
// literal.
func quoteAllJSONStrings(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ",")
}

const (
	a2aTestActor    = "agent:peer-agent-alpha"
	a2aTestAudience = "peer-project-x"
)

// a2aConfig is a config that trusts the fixture's issuer and maps a2aTestActor
// to the peer-builder role for a2aTestAudience, with the OpenBao endpoint at
// endpoint. extra is appended verbatim (e.g. a removed a2a_provider key).
func (f *assertionFixture) a2aConfig(endpoint, extra string) string {
	return "github:\n  owner: testorg\n  api_base: " + f.srv.URL + "\nbroker:\n  type: env\nroles: {}\n" +
		f.assertionBlock() +
		"a2a_mapping:\n  " + a2aTestActor + ":\n    role: peer-builder\n    audiences:\n      - " + a2aTestAudience + "\n" +
		"a2a_provider:\n  endpoint: " + endpoint + "\n  auth_mount: a2a-jwt\n  roles:\n    peer-builder:\n      auth_role: a2a-role\n      oidc_role: a2a-oidc-role\n" + extra
}

// jwtMount is the fake JWT mount: POST /v1/auth/<mount>/login and
// GET /v1/identity/oidc/token/<role>. It records the login body and the client
// token the identity-token read presented, and refuses every login whose jwt it
// does not trust.
type jwtMount struct {
	trusted  string
	logins   []map[string]string
	readWith string
}

func (m *jwtMount) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/a2a-jwt/login":
			body := map[string]string{}
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("login body: %v", err)
			}
			m.logins = append(m.logins, body)
			if body["jwt"] != m.trusted {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}}) //nolint:errcheck
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]string{"client_token": "s.test-client-token"}}) //nolint:errcheck
		case r.Method == http.MethodGet && r.URL.Path == "/v1/identity/oidc/token/a2a-oidc-role":
			m.readWith = r.Header.Get("X-Vault-Token")
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": "openbao-issued-peer-token", "ttl": 300}}) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRunMintA2A_NoProviderConfigured: a config.yaml with no a2a_provider
// stanza at all must refuse mint-a2a with a clear config error; the existing
// `gatekeeper mint` (GitHub-domain) path is exercised by main_test.go and
// mint_assertion_test.go and shares no state with this command.
func TestRunMintA2A_NoProviderConfigured(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}
`)

	err := runMintA2A([]string{"--audience", a2aTestAudience, "--config", path})
	if err == nil {
		t.Fatal("runMintA2A: expected config error when a2a_provider is not configured, got nil")
	}
	if !strings.Contains(err.Error(), "a2a_provider") {
		t.Errorf("runMintA2A error = %q, want it to mention a2a_provider", err.Error())
	}
}

// TestRunMintA2A_RequiresAudience verifies the required --audience flag is
// enforced before any config load.
func TestRunMintA2A_RequiresAudience(t *testing.T) {
	err := runMintA2A([]string{})
	if err == nil {
		t.Fatal("runMintA2A: expected error for missing --audience, got nil")
	}
}

// Without attestation.assertion there is no identity assertion to log in with,
// so mint-a2a refuses at config time, naming the missing section.
func TestRunMintA2A_AssertionNotConfigured(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg
broker:
  type: env
roles: {}
a2a_provider:
  endpoint: https://openbao.invalid.example
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)
	err := runMintA2A([]string{"--audience", a2aTestAudience, "--config", path})
	if err == nil || !strings.Contains(err.Error(), "attestation.assertion") {
		t.Fatalf("runMintA2A = %v, want a config error naming attestation.assertion", err)
	}
}

// Acceptance: a delivered assertion for a mapped actor logs in at the mount
// under the configured auth role, the returned client token requests the
// identity token, and the output is the OpenBao-issued token. --json carries
// the caller subject; the default output is the bare token.
func TestRunMintA2A_PermittedIssuesJSON(t *testing.T) {
	f := newAssertionFixture(t)
	token := f.deliverAs(a2aTestActor, "harness", "builder")
	mount := &jwtMount{trusted: token}
	srv := mount.server(t)
	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var jsonOut string
	stderr := captureStderr(t, func() {
		jsonOut = captureStdout(t, func() {
			if err := runMintA2A([]string{"--audience", a2aTestAudience, "--config", path, "--json"}); err != nil {
				t.Fatalf("runMintA2A --json unexpected error: %v", err)
			}
		})
	})

	var got struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Subject   string `json:"subject"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &got); err != nil {
		t.Fatalf("runMintA2A --json output is not valid JSON: %v\noutput: %q", err, jsonOut)
	}
	if got.Token != "openbao-issued-peer-token" || got.Subject != a2aTestActor {
		t.Errorf("json output token/subject = %q/%q, want openbao-issued-peer-token/%s", got.Token, got.Subject, a2aTestActor)
	}

	if len(mount.logins) != 1 || mount.logins[0]["role"] != "a2a-role" || mount.logins[0]["jwt"] != token {
		t.Errorf("login requests = %v, want one login for role a2a-role carrying the delivered assertion", mount.logins)
	}
	if mount.readWith != "s.test-client-token" {
		t.Errorf("identity token read presented %q, want the client token the login returned", mount.readWith)
	}
	if strings.Contains(stderr, token) || strings.Contains(jsonOut, token) {
		t.Error("the assertion appears in stdout or stderr")
	}
	if !strings.Contains(stderr, "permitted=true") {
		t.Errorf("stderr = %q, want a permitted audit line", stderr)
	}

	plainOut := captureStdout(t, func() {
		if err := runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}); err != nil {
			t.Fatalf("runMintA2A (default) unexpected error: %v", err)
		}
	})
	if strings.TrimSpace(plainOut) != "openbao-issued-peer-token" {
		t.Errorf("runMintA2A default output = %q, want bare token %q", strings.TrimSpace(plainOut), "openbao-issued-peer-token")
	}
}

// With no assertion delivered the A2A domain refuses rather than falling
// through to any other identity; no request reaches the mount.
func TestRunMintA2A_NoAssertionDeliveredRefusesBeforeIssuance(t *testing.T) {
	f := newAssertionFixture(t)
	os.Unsetenv("CLAGENTIC_IDENTITY_DIR")
	mount := &jwtMount{}
	srv := mount.server(t)
	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var err error
	captureStderr(t, func() { err = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
	if err == nil || !strings.Contains(err.Error(), "resolve attested identity") {
		t.Fatalf("runMintA2A = %v, want the attestation-resolution refusal", err)
	}
	if len(mount.logins) != 0 {
		t.Errorf("the mount saw %d login(s); attestation must refuse first", len(mount.logins))
	}
}

// An actor absent from a2a_mapping is refused before the mount is reached.
func TestRunMintA2A_NotEntitledRefusesBeforeIssuance(t *testing.T) {
	f := newAssertionFixture(t)
	token := f.deliverAs("agent:unmapped-caller", "harness", "builder")
	mount := &jwtMount{trusted: token}
	srv := mount.server(t)
	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var err error
	captureStderr(t, func() { err = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
	if err == nil || !strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("runMintA2A = %v, want the entitlement denial", err)
	}
	if len(mount.logins) != 0 {
		t.Errorf("the mount saw %d login(s); entitlement must refuse first", len(mount.logins))
	}
}

// Acceptance: an assertion signed by a key outside the configured key set is
// refused by the local verification, never presented at the mount.
func TestRunMintA2A_ForgedAssertionRefusesBeforeIssuance(t *testing.T) {
	f := newAssertionFixture(t)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.priv = other
	token := f.deliverAs(a2aTestActor, "harness", "builder")
	mount := &jwtMount{trusted: token}
	srv := mount.server(t)
	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var runErr error
	captureStderr(t, func() { runErr = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
	if runErr == nil || !strings.Contains(runErr.Error(), "signature_invalid") {
		t.Fatalf("runMintA2A = %v, want a signature_invalid refusal", runErr)
	}
	if len(mount.logins) != 0 {
		t.Errorf("the mount saw %d login(s); a forged assertion must never be presented", len(mount.logins))
	}
}

// The mount's own refusal (here: it trusts a different JWKS) surfaces as an
// error with no token on stdout, and the audit line carries the bounded
// OpenBao message.
func TestRunMintA2A_MountRefusalYieldsNoToken(t *testing.T) {
	f := newAssertionFixture(t)
	f.deliverAs(a2aTestActor, "harness", "builder")
	mount := &jwtMount{trusted: "some-other-assertion"}
	srv := mount.server(t)
	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var runErr error
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() { runErr = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "jwt auth login") {
		t.Fatalf("runMintA2A = %v, want the jwt auth login refusal", runErr)
	}
	if stdout != "" {
		t.Errorf("a token was printed: %q", stdout)
	}
	if mount.readWith != "" {
		t.Error("the identity token was requested after a refused login")
	}
	if !strings.Contains(stderr, "permitted=false") || !strings.Contains(stderr, "permission denied") {
		t.Errorf("stderr = %q, want a refused audit line carrying the mount's message", stderr)
	}
}

// A config still naming the removed a2a_provider keys starts: both commands
// warn on stderr naming each key, ignore the values, and mint as before.
func TestRemovedA2AKeysWarnAndProceedOnBothCommands(t *testing.T) {
	f := newAssertionFixture(t)
	token := f.deliverAs(a2aTestActor, "harness", "builder")
	mount := &jwtMount{trusted: token}
	srv := mount.server(t)
	removed := "  assertion_private_key_path: secret/gatekeeper/a2a/assertion-private-key\n  issuer: gatekeeper-example-issuer\n  assertion_ttl_seconds: 300\n"
	path := writeTempConfig(t, f.config(f.assertionBlock(), "", "")+
		"a2a_mapping:\n  "+a2aTestActor+":\n    role: peer-builder\n    audiences:\n      - "+a2aTestAudience+"\n"+
		"a2a_provider:\n  endpoint: "+srv.URL+"\n  auth_mount: a2a-jwt\n  roles:\n    peer-builder:\n      auth_role: a2a-role\n      oidc_role: a2a-oidc-role\n"+removed)

	for name, run := range map[string]func() (string, error){
		"mint-a2a": func() (out string, err error) {
			out = captureStdout(t, func() { err = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
			return out, err
		},
		"mint": func() (out string, err error) {
			out = captureStdout(t, func() { err = runMint([]string{"--role", "builder", "--config", path}) })
			return out, err
		},
	} {
		var out string
		var err error
		stderr := captureStderr(t, func() { out, err = run() })
		if err != nil {
			t.Errorf("%s = %v, want it to proceed", name, err)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s printed no token", name)
		}
		if !strings.Contains(stderr, "a2a_provider: deprecated config key(s) assertion_private_key_path, issuer, assertion_ttl_seconds have no effect") {
			t.Errorf("%s stderr = %q, want the deprecation warning naming each key", name, stderr)
		}
	}
}

// mint-a2a logs in as /act/sub, so an assertion without act is refused at
// gatekeeper with a named error and the mount is never called, while the plain
// mint still resolves the same assertion from sub.
func TestRunMintA2A_AssertionWithoutActRefusedBeforeMount(t *testing.T) {
	f := newAssertionFixture(t)
	token := f.deliverWithoutAct("runtime:peer-agent-alpha", "builder")
	mount := &jwtMount{trusted: token}
	srv := mount.server(t)
	path := writeTempConfig(t, f.config(f.assertionBlock(), "", "")+
		"a2a_mapping:\n  runtime:peer-agent-alpha:\n    role: peer-builder\n    audiences:\n      - "+a2aTestAudience+"\n"+
		"a2a_provider:\n  endpoint: "+srv.URL+"\n  auth_mount: a2a-jwt\n  roles:\n    peer-builder:\n      auth_role: a2a-role\n      oidc_role: a2a-oidc-role\n")

	var err error
	captureStderr(t, func() { err = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path}) })
	if err == nil || !strings.Contains(err.Error(), "carries no act.sub") {
		t.Fatalf("runMintA2A = %v, want the named act.sub refusal", err)
	}
	if len(mount.logins) != 0 || mount.readWith != "" {
		t.Errorf("the mount saw %d login(s) and read %q; the refusal must come first", len(mount.logins), mount.readWith)
	}

	var plainErr error
	captureStderr(t, func() {
		captureStdout(t, func() { plainErr = runMint([]string{"--role", "builder", "--config", path}) })
	})
	if plainErr != nil {
		t.Errorf("plain mint with the same assertion = %v, want it unchanged", plainErr)
	}
}

// TestRunMintA2A_MixedLegacyAndNewSidecarConfigRejected: config.Load rejects a
// config naming both the legacy `sidecar:` block and `sidecars:`; the
// rejection must reach the caller through runMintA2A.
func TestRunMintA2A_MixedLegacyAndNewSidecarConfigRejected(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}

attestation:
  sidecar:
    dir: `+sessionDir+`
    file_prefix: session-
    session_id_env: GATEKEEPER_TEST_MIXED_SESSION
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: GATEKEEPER_TEST_MIXED_SPAWN

a2a_provider:
  endpoint: https://openbao.invalid.example
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	err := runMintA2A([]string{"--audience", a2aTestAudience, "--config", path})
	if err == nil {
		t.Fatal("runMintA2A: expected config error for mixed legacy sidecar + sidecars, got nil")
	}
	if !strings.Contains(err.Error(), "sidecar") {
		t.Errorf("runMintA2A error = %q, want it to name the sidecar config conflict", err.Error())
	}
}

// TestRunMintA2A_StderrAuditBoundedForOversizedOpenBaoErrorEnvelope is the
// full cross-boundary sink test: a2atoken -> a2amint -> main.go's stderr
// Fprintf. A stub OpenBao returns an oversized {"errors":[...]} envelope on the
// jwt-auth-login leg and the bytes printed to os.Stderr by main.go's audit
// hook must be bounded, never an unbounded echo of the envelope.
func TestRunMintA2A_StderrAuditBoundedForOversizedOpenBaoErrorEnvelope(t *testing.T) {
	f := newAssertionFixture(t)
	f.deliverAs(a2aTestActor, "harness", "builder")

	oversizedErrors := []string{
		strings.Repeat("audit-sink-detail-", 15),
		strings.Repeat("second-detail-", 15),
	}
	joined := strings.Join(oversizedErrors, "; ")
	if len(joined) < 200 {
		t.Fatalf("test setup error: joined envelope strings (%d bytes) must exceed the a2atoken truncation bound to exercise it", len(joined))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"errors":[%s]}`, quoteAllJSONStrings(oversizedErrors)) //nolint:errcheck
	}))
	defer srv.Close()

	path := writeTempConfig(t, f.a2aConfig(srv.URL, ""))

	var runErr error
	stderrOut := captureStderr(t, func() {
		runErr = runMintA2A([]string{"--audience", a2aTestAudience, "--config", path})
	})
	if runErr == nil {
		t.Fatal("runMintA2A: expected error propagated from issuance, got nil")
	}

	if !strings.Contains(stderrOut, "a2a mint audit:") {
		t.Fatalf("stderr output = %q, want it to contain the audit record line", stderrOut)
	}
	if strings.Contains(stderrOut, joined) {
		t.Fatalf("stderr audit output contains the full, untruncated joined OpenBao envelope strings: %q", stderrOut)
	}
	if !strings.Contains(stderrOut, "truncated") {
		t.Errorf("stderr audit output = %q, want it to carry the truncation marker for an oversized OpenBao errors[] envelope", stderrOut)
	}
	// maxRawBodyExcerpt (200 bytes) run through the audit line's %q verb can
	// expand roughly 4x on control-heavy input, plus the fixed audit-line
	// scaffolding. 1500 bytes is above that worst case and still proves the
	// line is not an unbounded echo of a proxy-controlled body.
	if len(stderrOut) > 1500 {
		t.Errorf("stderr audit output is not bounded: %d bytes: %q", len(stderrOut), stderrOut)
	}
}
