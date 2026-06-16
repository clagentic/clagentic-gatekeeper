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
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

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
	)

	broker := &fakeGitHubBroker{vals: map[string]string{
		fakeAppIDPath:      "12345",
		fakeInstallIDPath:  "67890",
		fakePrivateKeyPath: generateTestPEM(t),
	}}

	svc := &mint.Service{
		APIBase: srv.URL,
		Roles:   roles.NewRegistry(),
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"merger": {
				AppIDPath:          fakeAppIDPath,
				InstallationIDPath: fakeInstallIDPath,
				PrivateKeyPath:     fakePrivateKeyPath,
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
	)

	broker := &fakeGitHubBroker{vals: map[string]string{
		fakeAppIDPath:      "12345",
		fakeInstallIDPath:  "67890",
		fakePrivateKeyPath: generateTestPEM(t),
	}}

	svc := &mint.Service{
		APIBase: srv.URL,
		Roles:   roles.NewRegistry(),
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"merger": {
				AppIDPath:          fakeAppIDPath,
				InstallationIDPath: fakeInstallIDPath,
				PrivateKeyPath:     fakePrivateKeyPath,
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
