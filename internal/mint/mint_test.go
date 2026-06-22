package mint_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// fakeBroker implements broker.Broker for tests. It returns values from a
// map or a fixed error when err is non-nil.
type fakeBroker struct {
	vals map[string]string
	err  error
}

func (f *fakeBroker) Get(_ context.Context, path string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.vals[path]
	if !ok {
		return "", fmt.Errorf("path not found: %s", path)
	}
	return v, nil
}

const (
	testAppIDPath      = "secret/app/id"
	testInstallIDPath  = "secret/app/install_id"
	testPrivateKeyPath = "secret/app/private_key"

	testAppID     = "12345"
	testInstallID = "67890"
	testFakeKey   = "fake-pem-value"
)

// builderBinding returns a RoleBinding pointing to the test broker paths.
func builderBinding() mint.RoleBinding {
	return mint.RoleBinding{
		AppIDPath:          testAppIDPath,
		InstallationIDPath: testInstallIDPath,
		PrivateKeyPath:     testPrivateKeyPath,
	}
}

// fakeToken is the stub token MintFunc returns.
var fakeToken = githubapp.Token{
	Value:     "ghs_faketoken",
	ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
}

// TestMintSuccess exercises the happy path: fakeBroker provides credentials,
// MintFunc is intercepted to capture the request, and the returned token
// matches what MintFunc returned.
func TestMintSuccess(t *testing.T) {
	broker := &fakeBroker{vals: map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
	}}

	var capturedReq githubapp.MintRequest
	svc := &mint.Service{
		APIBase: "https://api.github.com",
		TTL:     5 * time.Minute,
		Roles:   roles.NewRegistry(),
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"builder": builderBinding(),
		},
		MintFunc: func(_ context.Context, req githubapp.MintRequest) (githubapp.Token, error) {
			capturedReq = req
			return fakeToken, nil
		},
	}

	tok, err := svc.Mint(context.Background(), "builder", nil)
	if err != nil {
		t.Fatalf("Mint() unexpected error: %v", err)
	}

	// Returned token must match what MintFunc returned.
	if tok.Value != fakeToken.Value {
		t.Errorf("Token.Value = %q, want %q", tok.Value, fakeToken.Value)
	}

	// MintRequest must carry the permissions from the resolved role.
	role, _ := roles.NewRegistry().Resolve("builder")
	wantPerms := role.GitHubPermissions()
	for k, want := range wantPerms {
		if got := capturedReq.Permissions[k]; got != want {
			t.Errorf("MintRequest.Permissions[%q] = %q, want %q", k, got, want)
		}
	}

	// AppID must be the value the broker returned.
	if capturedReq.AppID != testAppID {
		t.Errorf("MintRequest.AppID = %q, want %q", capturedReq.AppID, testAppID)
	}

	// PrivateKeyPEM must not be empty — the broker value was passed through.
	if capturedReq.PrivateKeyPEM == "" {
		t.Error("MintRequest.PrivateKeyPEM is empty; expected broker value to be passed")
	}
}

// TestMintUnknownRole asserts that requesting an unregistered role returns an
// error that includes the role name.
func TestMintUnknownRole(t *testing.T) {
	svc := &mint.Service{
		Roles:    roles.NewRegistry(),
		Broker:   &fakeBroker{},
		Bindings: map[string]mint.RoleBinding{},
	}

	_, err := svc.Mint(context.Background(), "nonexistent-role", nil)
	if err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent-role") {
		t.Errorf("error %q does not contain role name %q", err.Error(), "nonexistent-role")
	}
}

// TestMintMissingBinding asserts that a valid role with no Bindings entry
// returns an error rather than panicking or making network calls.
func TestMintMissingBinding(t *testing.T) {
	svc := &mint.Service{
		Roles:    roles.NewRegistry(),
		Broker:   &fakeBroker{},
		Bindings: map[string]mint.RoleBinding{}, // no binding for "builder"
		MintFunc: func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
			t.Fatal("MintFunc must not be called when binding is missing")
			return githubapp.Token{}, nil
		},
	}

	_, err := svc.Mint(context.Background(), "builder", nil)
	if err == nil {
		t.Fatal("expected error for missing binding, got nil")
	}
}

// brokerFailOnKey is a broker that succeeds for all paths except the private
// key path, where it fails. This lets us verify that a previously-read secret
// value (e.g. app-id) doesn't leak into the error when a later read fails.
type brokerFailOnKey struct {
	vals    map[string]string
	failKey string
}

func (b *brokerFailOnKey) Get(_ context.Context, path string) (string, error) {
	if path == b.failKey {
		return "", errors.New("broker: permission denied on key path")
	}
	if v, ok := b.vals[path]; ok {
		return v, nil
	}
	return "", fmt.Errorf("path not found: %s", path)
}

// TestMintBrokerError asserts that a broker failure on the private-key read
// surfaces through Mint and that the app-id value does not leak into the error.
func TestMintBrokerError(t *testing.T) {
	const sensitiveAppID = "secret-app-id-value"

	broker := &brokerFailOnKey{
		vals: map[string]string{
			testAppIDPath:     sensitiveAppID,
			testInstallIDPath: testInstallID,
		},
		failKey: testPrivateKeyPath,
	}

	svc := &mint.Service{
		Roles:  roles.NewRegistry(),
		Broker: broker,
		Bindings: map[string]mint.RoleBinding{
			"builder": builderBinding(),
		},
	}

	_, err := svc.Mint(context.Background(), "builder", nil)
	if err == nil {
		t.Fatal("expected error when broker fails on private key, got nil")
	}

	// The previously-read app-id value must not appear in the error message.
	if strings.Contains(err.Error(), sensitiveAppID) {
		t.Errorf("error message leaks app-id value: %v", err)
	}
}

// TestMintCustomRoleExactPermissions asserts that a config-supplied custom role
// mints with exactly the permissions declared in the registry, using the
// default GitHub renderer (the zero-value Renderer field).
func TestMintCustomRoleExactPermissions(t *testing.T) {
	reg := roles.NewRegistry()
	// "releaser": push release tags, read PR context only.
	reg.Add("releaser", map[string]roles.Permission{
		"contents":      roles.Write,
		"pull_requests": roles.Read,
	})

	broker := &fakeBroker{vals: map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
	}}

	var capturedPerms map[string]string
	svc := &mint.Service{
		APIBase: "https://api.github.com",
		TTL:     5 * time.Minute,
		Roles:   reg,
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"releaser": builderBinding(),
		},
		// Renderer is nil — defaults to DefaultGitHubRenderer.
		MintFunc: func(_ context.Context, req githubapp.MintRequest) (githubapp.Token, error) {
			capturedPerms = req.Permissions
			return fakeToken, nil
		},
	}

	_, err := svc.Mint(context.Background(), "releaser", nil)
	if err != nil {
		t.Fatalf("Mint() unexpected error: %v", err)
	}

	want := map[string]string{
		"contents":      "write",
		"pull_requests": "read",
	}
	if len(capturedPerms) != len(want) {
		t.Errorf("Permissions length = %d, want %d; got %v", len(capturedPerms), len(want), capturedPerms)
	}
	for k, wantV := range want {
		if got := capturedPerms[k]; got != wantV {
			t.Errorf("Permissions[%q] = %q, want %q", k, got, wantV)
		}
	}
	// "issues" must not be present — it was not declared in the custom role.
	if v, present := capturedPerms["issues"]; present {
		t.Errorf("Permissions[\"issues\"] = %q, should be absent for releaser role", v)
	}
}

// TestMintRendererFieldOverridesDefault asserts that setting Service.Renderer
// replaces the default GitHub renderer. This is the seam lr-bb2f uses to plug
// in the Forgejo scope-string renderer without touching Service.Mint logic.
func TestMintRendererFieldOverridesDefault(t *testing.T) {
	broker := &fakeBroker{vals: map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
	}}

	var capturedPerms map[string]string
	svc := &mint.Service{
		APIBase: "https://api.github.com",
		TTL:     5 * time.Minute,
		Roles:   roles.NewRegistry(),
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"builder": builderBinding(),
		},
		// Override the renderer with a stub that prefixes values.
		Renderer: stubRenderer{prefix: "stub:"},
		MintFunc: func(_ context.Context, req githubapp.MintRequest) (githubapp.Token, error) {
			capturedPerms = req.Permissions
			return fakeToken, nil
		},
	}

	_, err := svc.Mint(context.Background(), "builder", nil)
	if err != nil {
		t.Fatalf("Mint() unexpected error: %v", err)
	}

	for k, v := range capturedPerms {
		if !strings.HasPrefix(v, "stub:") {
			t.Errorf("Permissions[%q] = %q; expected stub renderer output (prefix \"stub:\")", k, v)
		}
	}
}

// stubRenderer is a minimal roles.Renderer used to verify the Service.Renderer
// seam. It prefixes all permission values with a configurable string.
type stubRenderer struct{ prefix string }

func (s stubRenderer) RenderPermissions(role roles.Role) map[string]string {
	out := make(map[string]string, len(role.Permissions))
	for k, v := range role.Permissions {
		out[k] = s.prefix + string(v)
	}
	return out
}

// TestMintReposPassedThrough asserts that the repos slice provided to Mint is
// forwarded unchanged to MintFunc.
func TestMintReposPassedThrough(t *testing.T) {
	broker := &fakeBroker{vals: map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
	}}

	wantRepos := []string{"clagentic/clagentic-gatekeeper", "clagentic/lore"}

	var capturedRepos []string
	svc := &mint.Service{
		APIBase: "https://api.github.com",
		TTL:     5 * time.Minute,
		Roles:   roles.NewRegistry(),
		Broker:  broker,
		Bindings: map[string]mint.RoleBinding{
			"builder": builderBinding(),
		},
		MintFunc: func(_ context.Context, req githubapp.MintRequest) (githubapp.Token, error) {
			capturedRepos = req.Repositories
			return fakeToken, nil
		},
	}

	_, err := svc.Mint(context.Background(), "builder", wantRepos)
	if err != nil {
		t.Fatalf("Mint() unexpected error: %v", err)
	}

	if len(capturedRepos) != len(wantRepos) {
		t.Fatalf("MintRequest.Repositories length = %d, want %d", len(capturedRepos), len(wantRepos))
	}
	for i, want := range wantRepos {
		if capturedRepos[i] != want {
			t.Errorf("MintRequest.Repositories[%d] = %q, want %q", i, capturedRepos[i], want)
		}
	}
}
