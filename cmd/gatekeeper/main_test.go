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
		APIBase:              srv.URL,
		Roles:                roles.NewRegistry(),
		Broker:               broker,
		AttestationResolver:  testResolver(),
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
