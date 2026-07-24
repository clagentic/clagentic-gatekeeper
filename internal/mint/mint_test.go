package mint_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// testIdentity is the attested identity used by tests that need a resolver
// but are not themselves exercising the entitlement gate.
const testIdentity = "test-attested-caller"

// testResolver returns a Resolver that always resolves to testIdentity.
func testResolver() *attestation.Resolver {
	return attestation.NewResolver(fixedIdentityProvider{})
}

// fixedIdentityProvider is a stub attestation.Provider used to satisfy
// Service.AttestationResolver in tests without depending on the real
// OS/env/sidecar providers.
type fixedIdentityProvider struct{}

func (fixedIdentityProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	return attestation.Identity{Subject: testIdentity, Source: "test"}, nil
}

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
	testAppSlugPath    = "secret/app/slug"

	testAppID     = "12345"
	testInstallID = "67890"
	testFakeKey   = "fake-pem-value"
	testAppSlug   = "clagentic-builder"
)

// builderBinding returns a RoleBinding pointing to the test broker paths,
// entitled to testIdentity, and bound to testAppSlug.
func builderBinding() mint.RoleBinding {
	return mint.RoleBinding{
		AppIDPath:          testAppIDPath,
		InstallationIDPath: testInstallIDPath,
		PrivateKeyPath:     testPrivateKeyPath,
		EntitledIdentities: []string{testIdentity},
		AppSlug:            testAppSlug,
		AppSlugPath:        testAppSlugPath,
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
		testAppSlugPath:    testAppSlug,
	}}

	var capturedReq githubapp.MintRequest
	svc := &mint.Service{
		APIBase:             "https://api.github.com",
		TTL:                 5 * time.Minute,
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
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
			testAppSlugPath:   testAppSlug,
		},
		failKey: testPrivateKeyPath,
	}

	svc := &mint.Service{
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
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
		testAppSlugPath:    testAppSlug,
	}}

	var capturedPerms map[string]string
	svc := &mint.Service{
		APIBase:             "https://api.github.com",
		TTL:                 5 * time.Minute,
		Roles:               reg,
		Broker:              broker,
		AttestationResolver: testResolver(),
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
		testAppSlugPath:    testAppSlug,
	}}

	var capturedPerms map[string]string
	svc := &mint.Service{
		APIBase:             "https://api.github.com",
		TTL:                 5 * time.Minute,
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
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
		testAppSlugPath:    testAppSlug,
	}}

	wantRepos := []string{"clagentic/clagentic-gatekeeper", "clagentic/lore"}

	var capturedRepos []string
	svc := &mint.Service{
		APIBase:             "https://api.github.com",
		TTL:                 5 * time.Minute,
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: testResolver(),
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

// ---------------------------------------------------------------------------
// lr-116b57: entitlement (attested identity -> role) and verifiable
// App-slug binding (role -> App) gates at mint.
// ---------------------------------------------------------------------------

// fullBrokerVals returns a broker value map with all four broker-sourced
// fields present and valid: App ID, installation ID, private key, App slug.
// Tests mutate a copy to introduce the specific gap under test.
func fullBrokerVals() map[string]string {
	return map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
		testAppSlugPath:    testAppSlug,
	}
}

// errIdentityUnresolvable is returned by a stub Provider to simulate an
// attestation-chain failure distinct from ErrNoIdentity — a hard failure
// that must also result in a fail-closed Mint.
var errIdentityUnresolvable = errors.New("attestation provider: hard failure")

// erroringProvider is a stub attestation.Provider that always returns err.
type erroringProvider struct{ err error }

func (p erroringProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	return attestation.Identity{}, p.err
}

// TestMintEntitlementGate is a table-driven test covering the entitlement
// gate (attested identity -> role): pass, mismatch, and unresolvable
// identity. In every failing case, MintFunc must never be invoked — the
// gate must fail before any broker read or provider call.
func TestMintEntitlementGate(t *testing.T) {
	cases := []struct {
		name        string
		resolver    *attestation.Resolver
		entitled    []string
		wantErr     bool
		wantErrText string
	}{
		{
			name:     "entitled identity mints successfully",
			resolver: attestation.NewResolver(fixedIdentityProvider{}),
			entitled: []string{testIdentity},
			wantErr:  false,
		},
		{
			name:        "identity not in entitled list fails closed",
			resolver:    attestation.NewResolver(fixedIdentityProvider{}),
			entitled:    []string{"someone-else"},
			wantErr:     true,
			wantErrText: "not entitled",
		},
		{
			name:        "empty entitled list fails closed even for a resolvable identity",
			resolver:    attestation.NewResolver(fixedIdentityProvider{}),
			entitled:    nil,
			wantErr:     true,
			wantErrText: "not entitled",
		},
		{
			name:        "unresolvable identity (no provider offers one) fails closed",
			resolver:    attestation.NewResolver(), // empty chain: always ErrNoIdentity
			entitled:    []string{testIdentity},
			wantErr:     true,
			wantErrText: "resolve attested identity",
		},
		{
			name:        "hard provider failure fails closed",
			resolver:    attestation.NewResolver(erroringProvider{err: errIdentityUnresolvable}),
			entitled:    []string{testIdentity},
			wantErr:     true,
			wantErrText: "resolve attested identity",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			broker := &fakeBroker{vals: fullBrokerVals()}

			mintCalled := false
			binding := builderBinding()
			binding.EntitledIdentities = tc.entitled

			svc := &mint.Service{
				APIBase:             "https://api.github.com",
				TTL:                 5 * time.Minute,
				Roles:               roles.NewRegistry(),
				Broker:              broker,
				AttestationResolver: tc.resolver,
				Bindings: map[string]mint.RoleBinding{
					"builder": binding,
				},
				MintFunc: func(_ context.Context, req githubapp.MintRequest) (githubapp.Token, error) {
					mintCalled = true
					return fakeToken, nil
				},
			}

			_, err := svc.Mint(context.Background(), "builder", nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrText)
				}
				if mintCalled {
					t.Error("MintFunc was called despite entitlement gate failure; must fail before minting")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !mintCalled {
				t.Error("MintFunc was not called on the entitled path")
			}
		})
	}
}

// TestMintNilAttestationResolverFailsClosed asserts that a Service with no
// AttestationResolver configured refuses to mint — a nil resolver must never
// be treated as "entitlement not required."
func TestMintNilAttestationResolverFailsClosed(t *testing.T) {
	broker := &fakeBroker{vals: fullBrokerVals()}

	mintCalled := false
	svc := &mint.Service{
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: nil,
		Bindings: map[string]mint.RoleBinding{
			"builder": builderBinding(),
		},
		MintFunc: func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
			mintCalled = true
			return fakeToken, nil
		},
	}

	_, err := svc.Mint(context.Background(), "builder", nil)
	if err == nil {
		t.Fatal("expected error for nil AttestationResolver, got nil")
	}
	if !strings.Contains(err.Error(), "attestation resolver") {
		t.Errorf("error %q does not mention the missing attestation resolver", err.Error())
	}
	if mintCalled {
		t.Error("MintFunc was called despite missing AttestationResolver")
	}
}

// TestMintAppSlugBindingGate is a table-driven test covering the verifiable
// App-slug binding gate (role -> App): pass, mismatch (wrong App resolved),
// and missing/ambiguous configuration. On every failure, MintFunc must never
// be invoked and the token must never be minted through a fallback App.
func TestMintAppSlugBindingGate(t *testing.T) {
	cases := []struct {
		name           string
		configuredSlug string // RoleBinding.AppSlug
		configuredPath string // RoleBinding.AppSlugPath
		brokerSlug     string // value the broker returns at AppSlugPath ("" = path absent)
		wantErr        bool
		wantErrText    string
	}{
		{
			name:           "matching slug mints successfully",
			configuredSlug: testAppSlug,
			configuredPath: testAppSlugPath,
			brokerSlug:     testAppSlug,
			wantErr:        false,
		},
		{
			name:           "mismatched slug (wrong App resolved) fails closed, no fallback",
			configuredSlug: testAppSlug,
			configuredPath: testAppSlugPath,
			brokerSlug:     "some-other-app",
			wantErr:        true,
			wantErrText:    "does not match configured App slug",
		},
		{
			name:           "missing AppSlug (only path set) fails closed",
			configuredSlug: "",
			configuredPath: testAppSlugPath,
			brokerSlug:     testAppSlug,
			wantErr:        true,
			wantErrText:    "no App-slug binding configured",
		},
		{
			name:           "missing AppSlugPath (only slug set) fails closed",
			configuredSlug: testAppSlug,
			configuredPath: "",
			brokerSlug:     testAppSlug,
			wantErr:        true,
			wantErrText:    "no App-slug binding configured",
		},
		{
			name:           "neither slug nor path configured fails closed (bare install)",
			configuredSlug: "",
			configuredPath: "",
			brokerSlug:     testAppSlug,
			wantErr:        true,
			wantErrText:    "no App-slug binding configured",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			vals := map[string]string{
				testAppIDPath:      testAppID,
				testInstallIDPath:  testInstallID,
				testPrivateKeyPath: testFakeKey,
			}
			if tc.brokerSlug != "" {
				vals[testAppSlugPath] = tc.brokerSlug
			}
			broker := &fakeBroker{vals: vals}

			mintCalled := false
			svc := &mint.Service{
				APIBase:             "https://api.github.com",
				TTL:                 5 * time.Minute,
				Roles:               roles.NewRegistry(),
				Broker:              broker,
				AttestationResolver: testResolver(),
				Bindings: map[string]mint.RoleBinding{
					"builder": {
						AppIDPath:          testAppIDPath,
						InstallationIDPath: testInstallIDPath,
						PrivateKeyPath:     testPrivateKeyPath,
						EntitledIdentities: []string{testIdentity},
						AppSlug:            tc.configuredSlug,
						AppSlugPath:        tc.configuredPath,
					},
				},
				MintFunc: func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
					mintCalled = true
					return fakeToken, nil
				},
			}

			_, err := svc.Mint(context.Background(), "builder", nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrText)
				}
				if mintCalled {
					t.Error("MintFunc was called despite App-slug gate failure; must never fall back to a wrong/different App")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !mintCalled {
				t.Error("MintFunc was not called on the matching-slug path")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// lr-2a8653: domain-aware per-spawn MISS policy at the mint boundary. A
// subagent invocation whose per-spawn attestation source misses must never
// resolve to its parent session's identity via a lower-priority provider in
// the shared chain (the confused-deputy class); a lead/director session with
// no per-spawn source by design must keep resolving via the session sidecar
// exactly as before (lr-86779f) — DomainResolver + Domain is the mechanism,
// reused unmodified from lr-2ca216's DomainA2A substrate.
// ---------------------------------------------------------------------------

// spawnThenSessionIdentityProvider is a stub attestation.Provider standing in
// for the per-spawn sidecar entry: it resolves when spawnHit is true, and
// declines (ErrNoIdentity) otherwise — modeling a per-spawn sidecar file
// that is present (hit) or absent (miss) for the current invocation.
type spawnThenSessionIdentityProvider struct {
	hit      bool
	identity string
}

func (p spawnThenSessionIdentityProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	if !p.hit {
		return attestation.Identity{}, attestation.ErrNoIdentity
	}
	return attestation.Identity{Subject: p.identity, Source: "sidecar"}, nil
}

// buildDomainMintService returns a mint.Service wired the way cmd/gatekeeper
// wires it (lr-2a8653): DomainResolver.Chain is the full ordered chain
// [per-spawn provider, session provider], and DomainResolver.PerSpawn is
// scoped to ONLY the per-spawn provider — mirroring main.go's
// chainSidecars[0]-scoped PerSpawn resolver.
func buildDomainMintService(t *testing.T, spawnHit bool, sessionIdentity string) *mint.Service {
	t.Helper()

	spawnProvider := spawnThenSessionIdentityProvider{hit: spawnHit, identity: "subagent-self"}
	sessionProvider := spawnThenSessionIdentityProvider{hit: true, identity: sessionIdentity}

	chain := attestation.NewResolver(spawnProvider, sessionProvider)
	domainResolver := &attestation.DomainResolver{
		Chain:    chain,
		PerSpawn: attestation.NewResolver(spawnProvider),
	}

	broker := &fakeBroker{vals: fullBrokerVals()}
	binding := builderBinding()
	binding.EntitledIdentities = []string{sessionIdentity, "subagent-self"}

	return &mint.Service{
		APIBase:        "https://api.github.com",
		TTL:            5 * time.Minute,
		Roles:          roles.NewRegistry(),
		Broker:         broker,
		DomainResolver: domainResolver,
		Bindings: map[string]mint.RoleBinding{
			"builder": binding,
		},
		MintFunc: func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
			return fakeToken, nil
		},
	}
}

// TestMintForDomain_Subagent_PerSpawnMiss_RefusesNeverParentIdentity is
// direction (T+) of the mandatory lr-2a8653 regression test: a subagent
// invocation (DomainLocalSubagent) whose per-spawn attestation source MISSES,
// with the session sidecar present and holding the PARENT identity, must
// refuse fail-closed — MintFunc must never be called, and the mint must never
// succeed as the parent's identity.
func TestMintForDomain_Subagent_PerSpawnMiss_RefusesNeverParentIdentity(t *testing.T) {
	const parentIdentity = "holden"
	svc := buildDomainMintService(t, false /* spawnHit */, parentIdentity)

	mintCalled := false
	svc.MintFunc = func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
		mintCalled = true
		return fakeToken, nil
	}

	_, err := svc.MintForDomain(context.Background(), attestation.DomainLocalSubagent, "builder", nil)
	if err == nil {
		t.Fatal("MintForDomain(DomainLocalSubagent) succeeded on a per-spawn MISS; want a fail-closed refusal")
	}
	if !errors.Is(err, attestation.ErrPerSpawnRequired) {
		t.Errorf("MintForDomain(DomainLocalSubagent) error = %v, want it to wrap attestation.ErrPerSpawnRequired", err)
	}
	if mintCalled {
		t.Error("MintFunc was called on a subagent per-spawn MISS — the confused-deputy regression lr-2a8653 exists to close")
	}
}

// TestMintForDomain_Lead_PerSpawnMiss_StillResolvesViaSession is direction
// (T-) of the mandatory lr-2a8653 regression test: the SAME per-spawn MISS,
// for a lead/director invocation (DomainLocal, no per-spawn source by
// design), must still resolve via the session sidecar and mint successfully
// — no regression of lr-86779f.
func TestMintForDomain_Lead_PerSpawnMiss_StillResolvesViaSession(t *testing.T) {
	const leadIdentity = "holden"
	svc := buildDomainMintService(t, false /* spawnHit */, leadIdentity)

	mintCalled := false
	svc.MintFunc = func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
		mintCalled = true
		return fakeToken, nil
	}

	_, err := svc.MintForDomain(context.Background(), attestation.DomainLocal, "builder", nil)
	if err != nil {
		t.Fatalf("MintForDomain(DomainLocal) unexpected error: %v", err)
	}
	if !mintCalled {
		t.Error("MintFunc was not called on the lead-session DomainLocal path; session-sidecar fallback must still work (lr-86779f)")
	}
}

// TestMintBareInstallFailsClosed asserts the combined bare-install case: a
// Service constructed with zero-value RoleBinding verification fields (no
// EntitledIdentities, no AppSlug/AppSlugPath) — the state a config with no
// entitlement/App-slug settings produces — refuses to mint rather than
// falling open. This is the regression guard for "absent config = most
// restrictive posture."
func TestMintBareInstallFailsClosed(t *testing.T) {
	broker := &fakeBroker{vals: fullBrokerVals()}

	mintCalled := false
	svc := &mint.Service{
		Roles:               roles.NewRegistry(),
		Broker:              broker,
		AttestationResolver: attestation.NewResolver(fixedIdentityProvider{}),
		Bindings: map[string]mint.RoleBinding{
			// Bare binding: broker paths only, no verification config at all —
			// exactly what a role block gets when a deployer never sets
			// entitled_identities/app_slug/app_slug_path.
			"builder": {
				AppIDPath:          testAppIDPath,
				InstallationIDPath: testInstallIDPath,
				PrivateKeyPath:     testPrivateKeyPath,
			},
		},
		MintFunc: func(_ context.Context, _ githubapp.MintRequest) (githubapp.Token, error) {
			mintCalled = true
			return fakeToken, nil
		},
	}

	_, err := svc.Mint(context.Background(), "builder", nil)
	if err == nil {
		t.Fatal("expected error for bare-install RoleBinding (no entitlement, no App-slug binding), got nil")
	}
	if mintCalled {
		t.Error("MintFunc was called for a bare-install RoleBinding; a bare install must fail closed, not open")
	}
}
