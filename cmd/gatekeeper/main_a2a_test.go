package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

// writeSpawnSidecarFile writes an A2A-domain per-spawn sidecar identity
// file: attestation.DomainA2A REQUIRES a per-spawn-scoped resolver to
// succeed (docs/SETUP.md section 5, lr-2ca216) — a `configured` or
// session-only sidecar layer is never enough for mint-a2a, unlike the
// GitHub-domain command. Returns the config.yaml `attestation.sidecars`
// entry text plus the env var to set for the given identity/session id.
func writeSpawnSidecarFile(t *testing.T, dir, sessionID, identity string) {
	t.Helper()
	path := filepath.Join(dir, "spawn-"+sessionID)
	if err := os.WriteFile(path, []byte(identity), 0o600); err != nil {
		t.Fatalf("setup: write spawn sidecar file: %v", err)
	}
}

// TestRunMintA2A_NoProviderConfigured is the AC5/additive regression test:
// a config.yaml with no a2a_provider stanza at all must refuse mint-a2a with
// a clear config error, and this file's other tests below prove the
// existing `gatekeeper mint` (GitHub-domain) path in main_test.go is
// completely unaffected by mint-a2a's addition — no shared state, no
// behavior change, since this test only ever exercises runMintA2A.
func TestRunMintA2A_NoProviderConfigured(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}
`)

	err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path})
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

// TestRunMintA2A_PerSpawnMissRefusesBeforeIssuance covers the fail-closed
// attestation gate for the A2A domain: no per-spawn sidecar file present
// (the per-spawn env var is set — a harness IS active — but its sidecar
// file was never written) must refuse via ErrPerSpawnRequired, never
// falling through to any other identity source, and never reaching
// issuance. Proven here by NOT standing up any OpenBao stub server at all —
// if the mint path ever reached issuance, the request would fail to connect
// rather than return the expected attestation refusal.
func TestRunMintA2A_PerSpawnMissRefusesBeforeIssuance(t *testing.T) {
	const spawnEnv = "GATEKEEPER_TEST_A2A_SPAWN_MISS_LR890FAE"
	spawnDir := t.TempDir()
	t.Setenv(spawnEnv, "spawn-miss-1")
	// Deliberately no sidecar file written for this session id — the MISS.

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: `+spawnEnv+`

a2a_provider:
  endpoint: https://openbao.invalid.example
  assertion_private_key_path: GATEKEEPER_TEST_A2A_KEY_LR890FAE
  issuer: gatekeeper-test-issuer
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path})
	if err == nil {
		t.Fatal("runMintA2A: expected fail-closed refusal for a per-spawn attestation MISS, got nil")
	}
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		t.Fatalf("runMintA2A reached the network before attestation refused — fail-closed gate did not run first: %v", err)
	}
	if !strings.Contains(err.Error(), "resolve attested identity") {
		t.Errorf("runMintA2A error = %q, want it to name the attestation-resolution refusal", err.Error())
	}
}

// TestRunMintA2A_NotEntitledRefusesBeforeIssuance verifies the fail-closed
// entitlement gate: attestation resolves successfully (a real per-spawn
// sidecar file is present), but the resolved identity is absent from
// a2a_mapping — refuses before ever reaching OpenBao. Proven the same way
// as the attestation-MISS test above: no OpenBao stub server exists, so
// reaching issuance would surface as a network error instead of a denial.
func TestRunMintA2A_NotEntitledRefusesBeforeIssuance(t *testing.T) {
	const spawnEnv = "GATEKEEPER_TEST_A2A_NOT_ENTITLED_LR890FAE"
	spawnDir := t.TempDir()
	t.Setenv(spawnEnv, "spawn-notentitled-1")
	writeSpawnSidecarFile(t, spawnDir, "spawn-notentitled-1", "unmapped-caller")

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: `+spawnEnv+`

a2a_provider:
  endpoint: https://openbao.invalid.example
  assertion_private_key_path: GATEKEEPER_TEST_A2A_KEY_LR890FAE
  issuer: gatekeeper-test-issuer
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path})
	if err == nil {
		t.Fatal("runMintA2A: expected fail-closed refusal for unentitled identity, got nil")
	}
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		t.Fatalf("runMintA2A reached the network before entitlement refused — fail-closed gate did not run first: %v", err)
	}
	if !strings.Contains(err.Error(), "not entitled") {
		t.Errorf("runMintA2A error = %q, want it to name the entitlement denial", err.Error())
	}
}

// TestRunMintA2A_PermittedIssuesJSON is the end-to-end happy path: a real
// per-spawn sidecar attests the caller, a fully configured a2a_provider and
// an entitled a2a_mapping entry permit the request, and a stub OpenBao
// server stands in for the JWT-auth login + identity/oidc/token endpoints.
// Verifies --json emits {token, expires_at, subject} and default output
// stays the bare token string, mirroring runMint's own contract.
func TestRunMintA2A_PermittedIssuesJSON(t *testing.T) {
	const spawnEnv = "GATEKEEPER_TEST_A2A_PERMIT_LR890FAE"
	const keyEnv = "GATEKEEPER_TEST_A2A_KEY_PERMIT_LR890FAE"
	spawnDir := t.TempDir()
	t.Setenv(spawnEnv, "spawn-permit-1")
	t.Setenv(keyEnv, generateTestPEM(t))
	writeSpawnSidecarFile(t, spawnDir, "spawn-permit-1", "peer-agent-alpha")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/login"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"auth": map[string]string{"client_token": "s.test-client-token"},
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/identity/oidc/token/"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"data": map[string]any{"token": "openbao-issued-peer-token", "ttl": 300},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: `+spawnEnv+`

a2a_mapping:
  peer-agent-alpha:
    role: peer-builder
    audiences:
      - peer-project-x

a2a_provider:
  endpoint: `+srv.URL+`
  assertion_private_key_path: `+keyEnv+`
  issuer: gatekeeper-test-issuer
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	jsonOut := captureStdout(t, func() {
		if err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path, "--json"}); err != nil {
			t.Fatalf("runMintA2A --json unexpected error: %v", err)
		}
	})

	var got struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		Subject   string `json:"subject"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonOut)), &got); err != nil {
		t.Fatalf("runMintA2A --json output is not valid JSON: %v\noutput: %q", err, jsonOut)
	}
	if got.Token != "openbao-issued-peer-token" {
		t.Errorf("json output token = %q, want %q", got.Token, "openbao-issued-peer-token")
	}
	if got.Subject != "peer-agent-alpha" {
		t.Errorf("json output subject = %q, want %q", got.Subject, "peer-agent-alpha")
	}

	plainOut := captureStdout(t, func() {
		if err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path}); err != nil {
			t.Fatalf("runMintA2A (default) unexpected error: %v", err)
		}
	})
	if strings.TrimSpace(plainOut) != "openbao-issued-peer-token" {
		t.Errorf("runMintA2A default output = %q, want bare token %q", strings.TrimSpace(plainOut), "openbao-issued-peer-token")
	}
}

// TestRunMintA2A_MixedLegacyAndNewSidecarConfigRejected is the cmd-level
// wiring test for the MILLER-adjudicated defect (lr-890fae comment #8, item
// F2): config_test.go's TestAttestationConfig_ResolveSidecars_BackCompat
// covers the legacy+new MERGE in isolation only — it never traces the
// merged value across the config -> cmd boundary to see which entry lands
// in the domain-scoped PerSpawn resolver mint-a2a actually uses.
//
// Without this test, a deployment could set the legacy `attestation.sidecar`
// block to a SESSION namespace and `attestation.sidecars[0]` to the
// per-spawn namespace; ResolveSidecars' documented, deliberate prepend
// ordering (legacy first) would then put the SESSION entry at index 0, and
// main.go's chainSidecars[0] wiring would install the session sidecar AS
// PerSpawn — DomainA2A fail-closes correctly, but against the wrong
// namespace, a confused-deputy outcome.
//
// config.Load now rejects this combination outright (internal/config's
// AttestationConfig.validate) rather than silently accepting whichever
// entry ordering the merge happens to produce, so this test asserts the
// REJECTION reaches the caller through runMintA2A specifically — the same
// code path that used to install chainSidecars[0] as PerSpawn — rather than
// re-testing the merge or the validation rule in isolation again.
func TestRunMintA2A_MixedLegacyAndNewSidecarConfigRejected(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	// Legacy `sidecar:` names a SESSION namespace; `sidecars[0]` names the
	// per-spawn namespace — exactly the inversion MILLER's adjudication
	// names as the real defect underneath the reviewer's refuted claim.
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
    session_id_env: GATEKEEPER_TEST_MIXED_SESSION_LR890FAE
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: GATEKEEPER_TEST_MIXED_SPAWN_LR890FAE

a2a_provider:
  endpoint: https://openbao.invalid.example
  assertion_private_key_path: GATEKEEPER_TEST_A2A_KEY_LR890FAE
  issuer: gatekeeper-test-issuer
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	err := runMintA2A([]string{"--audience", "peer-project-x", "--config", path})
	if err == nil {
		t.Fatal("runMintA2A: expected config error for mixed legacy sidecar + sidecars, got nil")
	}
	if !strings.Contains(err.Error(), "sidecar") {
		t.Errorf("runMintA2A error = %q, want it to name the sidecar config conflict", err.Error())
	}
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		t.Fatalf("runMintA2A reached the network before the mixed-config rejection ran: %v", err)
	}
}

// TestRunMintA2A_StderrAuditBoundedForOversizedOpenBaoErrorEnvelope is the
// full cross-boundary sink test MILLER's adjudication (lr-890fae comment
// #11) called for: a2atoken -> a2amint -> main.go's stderr Fprintf, not just
// an in-package or a2amint-package-boundary assertion. A stub OpenBao server
// returns an oversized (>200 byte joined) {"errors":[...]} envelope on the
// jwt-auth-login leg — the parsed-envelope branch of
// a2atoken.parseOpenBaoErrors, the specific branch the F1 defect left
// unbounded. Asserts the actual bytes printed to os.Stderr by main.go's
// audit hook are bounded, never an unbounded echo of the envelope.
func TestRunMintA2A_StderrAuditBoundedForOversizedOpenBaoErrorEnvelope(t *testing.T) {
	const spawnEnv = "GATEKEEPER_TEST_A2A_SINK_LR890FAE"
	const keyEnv = "GATEKEEPER_TEST_A2A_SINK_KEY_LR890FAE"
	spawnDir := t.TempDir()
	t.Setenv(spawnEnv, "spawn-sink-1")
	t.Setenv(keyEnv, generateTestPEM(t))
	writeSpawnSidecarFile(t, spawnDir, "spawn-sink-1", "peer-agent-alpha")

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

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: `+spawnEnv+`

a2a_mapping:
  peer-agent-alpha:
    role: peer-builder
    audiences:
      - peer-project-x

a2a_provider:
  endpoint: `+srv.URL+`
  assertion_private_key_path: `+keyEnv+`
  issuer: gatekeeper-test-issuer
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
`)

	var runErr error
	stderrOut := captureStderr(t, func() {
		runErr = runMintA2A([]string{"--audience", "peer-project-x", "--config", path})
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
	// Bounded per main.go's own documented expansion: maxRawBodyExcerpt (200
	// bytes) run through the audit line's %q verb (Go strconv.Quote
	// semantics) can expand roughly 4x on control-heavy input, plus the
	// fixed audit-line scaffolding (identity/role/audience/etc fields). 1500
	// bytes is comfortably above that worst case and still proves the line
	// is not an unbounded echo of an attacker/proxy-controlled body.
	if len(stderrOut) > 1500 {
		t.Errorf("stderr audit output is not bounded: %d bytes: %q", len(stderrOut), stderrOut)
	}
}
