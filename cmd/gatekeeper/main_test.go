package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// testAttestedIdentity is the attested identity used by tests that need a
// resolver but do not exercise the entitlement failure path itself. It is
// wired as the sole entitled identity on any test RoleBinding below.
const testAttestedIdentity = "test-attested-caller"

// testResolver returns an attestation.Resolver that always resolves to
// testAttestedIdentity, via a single-provider chain. Mint requires a
// non-nil AttestationResolver (fail-closed by contract); tests exercising
// the mint happy path use this to satisfy that requirement without
// depending on the real OS/env/sidecar providers.
func testResolver() *attestation.Resolver {
	return attestation.NewResolver(fixedIdentityProvider{})
}

// fixedIdentityProvider is a stub attestation.Provider that always resolves
// to testAttestedIdentity.
type fixedIdentityProvider struct{}

func (fixedIdentityProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	return attestation.Identity{Subject: testAttestedIdentity, Source: "test"}, nil
}

// generateTestPEM returns a freshly generated RSA-2048 private key in PKCS#1
// PEM format, suitable for use in tests that exercise the GitHub API path.
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

// TestParseRepoName exercises parseRepoName with the full set of valid and
// invalid inputs, including all edge cases documented in the function comment.
func TestParseRepoName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "owner/name returns bare name",
			input: "clagentic/clagentic-directory",
			want:  "clagentic-directory",
		},
		{
			name:  "bare name passes through",
			input: "clagentic-gatekeeper",
			want:  "clagentic-gatekeeper",
		},
		{
			name:    "empty string is rejected",
			input:   "",
			wantErr: true,
		},
		{
			name:    "multiple slashes are rejected",
			input:   "clagentic/foo/bar",
			wantErr: true,
		},
		{
			name:    "leading slash (empty owner) is rejected",
			input:   "/foo",
			wantErr: true,
		},
		{
			name:    "trailing slash (empty name) is rejected",
			input:   "foo/",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRepoName(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRepoName(%q) = %q, nil; want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRepoName(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseRepoName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// fakeGitHubBroker implements broker.Broker using a fixed set of values.
type fakeGitHubBroker struct {
	vals map[string]string
}

func (f *fakeGitHubBroker) Get(_ context.Context, path string) (string, error) {
	if v, ok := f.vals[path]; ok {
		return v, nil
	}
	return "", nil
}

// TestMintWithRepoCapturesBareRepoName verifies that when --repo is supplied as
// "owner/name", the repositories[] field sent in the GitHub access_tokens
// request body contains only the bare name (without the owner prefix).
func TestMintWithRepoCapturesBareRepoName(t *testing.T) {
	var capturedRepos []string

	// httptest server acts as a stub GitHub API and captures the request body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		capturedRepos = body.Repositories

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"token":      "ghs_test",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	const (
		fakeAppIDPath      = "secret/app/id"
		fakeInstallIDPath  = "secret/app/install_id"
		fakePrivateKeyPath = "secret/app/private_key"
		fakeAppSlugPath    = "secret/app/slug"
		fakeAppSlug        = "clagentic-merger"
	)

	broker := &fakeGitHubBroker{vals: map[string]string{
		fakeAppIDPath:      "12345",
		fakeInstallIDPath:  "67890",
		fakePrivateKeyPath: generateTestPEM(t),
		fakeAppSlugPath:    fakeAppSlug,
	}}

	svc := &mint.Service{
		APIBase:             srv.URL,
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
		Bindings: map[string]mint.RoleBinding{
			"merger": {
				AppIDPath:          fakeAppIDPath,
				InstallationIDPath: fakeInstallIDPath,
				PrivateKeyPath:     fakePrivateKeyPath,
				EntitledIdentities: []string{testAttestedIdentity},
				AppSlug:            fakeAppSlug,
				AppSlugPath:        fakeAppSlugPath,
			},
		},
		// Use real MintFunc (githubapp.Mint) so we actually hit the stub server.
		MintFunc: nil,
	}

	// Simulate the CLI parsing "owner/name" and converting to bare name before
	// passing to svc.Mint — exactly as runMint does after parseRepoName.
	bare, err := parseRepoName("clagentic/clagentic-directory")
	if err != nil {
		t.Fatalf("parseRepoName unexpected error: %v", err)
	}

	_, err = svc.Mint(context.Background(), "merger", []string{bare})
	if err != nil {
		t.Fatalf("svc.Mint unexpected error: %v", err)
	}

	if len(capturedRepos) != 1 {
		t.Fatalf("repositories[] len = %d, want 1", len(capturedRepos))
	}
	if capturedRepos[0] != "clagentic-directory" {
		t.Errorf("repositories[0] = %q, want %q", capturedRepos[0], "clagentic-directory")
	}
}

// writeTempConfig writes content to a temp dir as config.yaml and returns the path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

// TestRunMint_InvalidRoleNoPermissions verifies that a config role that is not
// a reference role and has no permissions block causes runMint to return a clear
// config error at startup, before any broker call.
func TestRunMint_InvalidRoleNoPermissions(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles:
  ghostrole:
    app_id_path: secret/gk/ghost/app-id
    installation_id_path: secret/gk/ghost/install-id
    private_key_path: secret/gk/ghost/key
`)
	// ghostrole has no permissions and is not a reference role — startup must fail.
	err := runMint([]string{"--role", "ghostrole", "--config", path})
	if err == nil {
		t.Fatal("runMint: expected config error for role with no permissions, got nil")
	}
	if !strings.Contains(err.Error(), "ghostrole") {
		t.Errorf("runMint error = %q; want it to mention the offending role name", err.Error())
	}
	if !strings.Contains(err.Error(), "config error") {
		t.Errorf("runMint error = %q; want it to contain \"config error\"", err.Error())
	}
}

// TestRunMint_ReferenceRoleWithoutConfigPermissions verifies that a reference
// role (builder, reviewer, merger, security) listed in config without a
// permissions block is accepted — it resolves from the reference definition.
//
// This test does not exercise the broker or GitHub API; it checks only that
// runMint passes the startup validation step. It expects an error from the
// broker (env broker returns empty strings for unknown paths, which causes a
// downstream failure in the app-id parse), but NOT the config-validation error.
func TestRunMint_ReferenceRoleWithoutConfigPermissions(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles:
  builder:
    app_id_path: secret/gk/builder/app-id
    installation_id_path: secret/gk/builder/install-id
    private_key_path: secret/gk/builder/key
`)
	// builder is a reference role — startup validation must pass.
	// The env broker returns "" for unknown paths, which causes a downstream
	// error in githubapp (not in our validation). We only care that the error
	// is NOT the config-validation error.
	err := runMint([]string{"--role", "builder", "--config", path})
	if err != nil && strings.Contains(err.Error(), "config error") {
		t.Errorf("runMint returned config-validation error for reference role builder: %v", err)
	}
	// Any non-config-validation error (e.g. broker/app error) is acceptable —
	// it means validation passed and execution advanced to the broker/mint path.
}

// TestRunMint_CustomRoleWithPermissions verifies that a non-reference role that
// declares a permissions block passes startup validation (error, if any, is not
// a config-validation error).
func TestRunMint_CustomRoleWithPermissions(t *testing.T) {
	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles:
  releaser:
    app_id_path: secret/gk/releaser/app-id
    installation_id_path: secret/gk/releaser/install-id
    private_key_path: secret/gk/releaser/key
    permissions:
      contents: write
      pull_requests: read
`)
	// releaser has explicit permissions — startup validation must pass.
	err := runMint([]string{"--role", "releaser", "--config", path})
	if err != nil && strings.Contains(err.Error(), "config error") {
		t.Errorf("runMint returned config-validation error for custom role with permissions: %v", err)
	}
}

// TestRunMint_MultipleSidecarsConfig_SecondResolves verifies the config ->
// attestation wiring end to end (lr-86779f): a config.yaml with a
// `attestation.sidecars` list of two independent sidecar namespaces builds
// a resolver where the second entry can resolve an identity even though the
// first entry's session env is unset for this process — i.e. runMint does
// not truncate the chain to a single sidecar provider.
func TestRunMint_MultipleSidecarsConfig_SecondResolves(t *testing.T) {
	sessionDir := t.TempDir()
	spawnDir := t.TempDir()

	const spawnEnv = "GATEKEEPER_TEST_MAIN_SPAWN_LR86779F"
	t.Setenv(spawnEnv, "spawn-main-1")
	spawnPath := filepath.Join(spawnDir, "spawn-spawn-main-1")
	if err := os.WriteFile(spawnPath, []byte("peaches"), 0o600); err != nil {
		t.Fatalf("setup: write spawn sidecar file: %v", err)
	}

	path := writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles:
  reader:
    app_id_path: secret/gk/reader/app-id
    installation_id_path: secret/gk/reader/install-id
    private_key_path: secret/gk/reader/key
    entitled_identities:
      - peaches

attestation:
  sidecars:
    - dir: `+sessionDir+`
      file_prefix: lore-agent-name-
      session_id_env: GATEKEEPER_TEST_MAIN_SESSION_LR86779F_UNSET
    - dir: `+spawnDir+`
      file_prefix: spawn-
      session_id_env: `+spawnEnv+`
`)

	// The first sidecar's session env is deliberately never set: its
	// harness is not active in this test process. If runMint only wired a
	// single sidecar provider, this would fall through to the builtin
	// provider ("root"-equivalent) and fail entitlement for "peaches".
	// Reaching the reader role's broker call (not a config-validation or
	// entitlement error) proves the second sidecar entry resolved.
	err := runMint([]string{"--role", "reader", "--config", path})
	if err != nil && strings.Contains(err.Error(), "config error") {
		t.Fatalf("runMint returned config-validation error: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("runMint returned entitlement error; second sidecar entry did not resolve: %v", err)
	}
	// Any remaining error is expected (env broker returns empty paths,
	// causing a downstream App-id parse failure) — we only assert
	// attestation/entitlement was not the failure mode.
}

// ---------------------------------------------------------------------------
// lr-2a8653: runMint's domain-aware per-spawn MISS wiring. The deployed
// config shape (subagent-/CLAGENTIC_SUBAGENT_ID as sidecars[0], then
// lore-agent-name-/CLAUDE_CODE_SESSION_ID as sidecars[1]) is exactly the
// shape that let a subagent's per-spawn MISS silently fall through to the
// session sidecar and mint the PARENT lead's identity — the confused-deputy
// hole this task closes. Both directions are exercised through runMint
// itself, not just the lower internal/attestation and internal/mint layers,
// so the CLI's env-var-driven domain selection is covered end to end.
// ---------------------------------------------------------------------------

// writeSpawnFirstConfig writes a config.yaml with the deployed two-sidecar
// shape (spawn-scoped entry first, session-scoped entry second) plus a
// single role entitled only to "subagent-self" — never the session/parent
// identity "holden" — so a wrongly-resolved parent identity fails
// entitlement (belt) in addition to whatever attestation-layer refusal is
// under test (suspenders).
func writeSpawnFirstConfig(t *testing.T, spawnDir, sessionDir, spawnEnv, sessionEnv string) string {
	t.Helper()
	return writeTempConfig(t, `
github:
  owner: testorg

broker:
  type: env

roles:
  builder:
    app_id_path: secret/gk/builder/app-id
    installation_id_path: secret/gk/builder/install-id
    private_key_path: secret/gk/builder/key
    entitled_identities:
      - subagent-self

attestation:
  sidecars:
    - dir: `+spawnDir+`
      file_prefix: subagent-
      session_id_env: `+spawnEnv+`
    - dir: `+sessionDir+`
      file_prefix: lore-agent-name-
      session_id_env: `+sessionEnv+`
`)
}

// TestRunMint_SubagentPerSpawnMiss_RefusesNeverParentIdentity is direction
// (T+): CLAGENTIC_SUBAGENT_ID (the per-spawn env) IS set for this process —
// signaling a per-spawn harness is active and this invocation is a subagent
// — but its sidecar file is absent (the MISS). The session sidecar file IS
// present and holds the PARENT identity "holden". runMint must refuse
// fail-closed and must NEVER reach the broker/mint path as "holden".
func TestRunMint_SubagentPerSpawnMiss_RefusesNeverParentIdentity(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "GATEKEEPER_TEST_MAIN_LR2A8653_SUBAGENT_SPAWN"
	const sessionEnv = "GATEKEEPER_TEST_MAIN_LR2A8653_SUBAGENT_SESSION"

	// Per-spawn env IS set (this is a subagent invocation) but its sidecar
	// file is never written — the MISS.
	t.Setenv(spawnEnv, "spawn-lr2a8653-1")

	// Session sidecar IS present and resolves to the parent lead identity —
	// exactly what a subagent process inherits from its parent's
	// environment (CLAUDE_CODE_SESSION_ID stays the parent's session id
	// inside a subagent).
	t.Setenv(sessionEnv, "session-lead-lr2a8653-1")
	sessionPath := filepath.Join(sessionDir, "lore-agent-name-session-lead-lr2a8653-1")
	if err := os.WriteFile(sessionPath, []byte("holden"), 0o600); err != nil {
		t.Fatalf("setup: write session sidecar file: %v", err)
	}

	path := writeSpawnFirstConfig(t, spawnDir, sessionDir, spawnEnv, sessionEnv)

	err := runMint([]string{"--role", "builder", "--config", path})
	if err == nil {
		t.Fatal("runMint: expected a fail-closed refusal for a subagent per-spawn MISS, got nil")
	}
	if strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("runMint refused via entitlement (%q) rather than the attestation-layer fail-closed refusal — the subagent must never even resolve to the parent identity to reach the entitlement gate", err.Error())
	}
	if strings.Contains(err.Error(), "config error") {
		t.Fatalf("runMint returned a config-validation error, not the expected attestation refusal: %v", err)
	}
}

// TestRunMint_LeadSession_PerSpawnMiss_StillResolvesViaSession is direction
// (T-): the per-spawn env var is UNSET (no per-spawn harness active — this
// is a lead/director session invocation with no per-spawn sidecar of its own
// by design). The session sidecar IS present. runMint must still resolve via
// the session sidecar exactly as before lr-2a8653 (lr-86779f) — reaching the
// broker/mint path as the session identity, not refusing.
func TestRunMint_LeadSession_PerSpawnMiss_StillResolvesViaSession(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "GATEKEEPER_TEST_MAIN_LR2A8653_LEAD_SPAWN_UNSET"
	const sessionEnv = "GATEKEEPER_TEST_MAIN_LR2A8653_LEAD_SESSION"

	// Per-spawn env is deliberately never set: no per-spawn harness is
	// active for this invocation.
	os.Unsetenv(spawnEnv)

	t.Setenv(sessionEnv, "session-lead-lr2a8653-2")
	sessionPath := filepath.Join(sessionDir, "lore-agent-name-session-lead-lr2a8653-2")
	if err := os.WriteFile(sessionPath, []byte("subagent-self"), 0o600); err != nil {
		t.Fatalf("setup: write session sidecar file: %v", err)
	}

	path := writeSpawnFirstConfig(t, spawnDir, sessionDir, spawnEnv, sessionEnv)

	err := runMint([]string{"--role", "builder", "--config", path})
	// The env broker returns "" for unknown paths, which causes a downstream
	// error reading app-id — expected and fine. We only assert the failure
	// mode is NOT an attestation/entitlement refusal, proving resolution
	// reached the broker read using the session-resolved identity.
	if err != nil && strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("runMint returned an entitlement refusal; session-sidecar fallback did not resolve (lr-86779f regression): %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "resolve attested identity") {
		t.Fatalf("runMint returned an attestation refusal for a lead-session invocation with no per-spawn source by design: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "config error") {
		t.Fatalf("runMint returned a config-validation error: %v", err)
	}
}

// TestMintWithoutRepoSendsEmptyRepos verifies that omitting --repo results in
// an empty repositories[] field (GitHub interprets absence as all repos).
func TestMintWithoutRepoSendsEmptyRepos(t *testing.T) {
	var capturedRepos []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		capturedRepos = body.Repositories

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
			"token":      "ghs_test",
			"expires_at": "2099-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	const (
		fakeAppIDPath      = "secret/app/id"
		fakeInstallIDPath  = "secret/app/install_id"
		fakePrivateKeyPath = "secret/app/private_key"
		fakeAppSlugPath    = "secret/app/slug"
		fakeAppSlug        = "clagentic-merger"
	)

	broker := &fakeGitHubBroker{vals: map[string]string{
		fakeAppIDPath:      "12345",
		fakeInstallIDPath:  "67890",
		fakePrivateKeyPath: generateTestPEM(t),
		fakeAppSlugPath:    fakeAppSlug,
	}}

	svc := &mint.Service{
		APIBase:             srv.URL,
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
		Bindings: map[string]mint.RoleBinding{
			"merger": {
				AppIDPath:          fakeAppIDPath,
				InstallationIDPath: fakeInstallIDPath,
				PrivateKeyPath:     fakePrivateKeyPath,
				EntitledIdentities: []string{testAttestedIdentity},
				AppSlug:            fakeAppSlug,
				AppSlugPath:        fakeAppSlugPath,
			},
		},
	}

	// No repos argument — simulates omitting --repo.
	_, err := svc.Mint(context.Background(), "merger", nil)
	if err != nil {
		t.Fatalf("svc.Mint unexpected error: %v", err)
	}

	if len(capturedRepos) != 0 {
		t.Errorf("repositories[] = %v, want empty (GitHub all-repos)", capturedRepos)
	}
}
