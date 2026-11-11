package mint_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/mintrecord"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

const recordTestToken = "ghs_planted_token_value"

func recordService(t *testing.T, br *fakeBroker, mintFn func(context.Context, githubapp.MintRequest) (githubapp.Token, error), binding mint.RoleBinding) (*mint.Service, string) {
	t.Helper()
	reg := roles.NewRegistry()
	reg.Add("tester", map[string]roles.Permission{"contents": "write", "pull_requests": "read"})
	sinkPath := filepath.Join(t.TempDir(), "mints.jsonl")
	sink := mintrecord.Sink{Path: sinkPath}
	svc := &mint.Service{
		Roles:               reg,
		Broker:              br,
		AttestationResolver: testResolver(),
		Bindings:            map[string]mint.RoleBinding{"tester": binding},
		MintFunc:            mintFn,
		Now:                 func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) },
		Record: func(r mintrecord.Record) {
			if err := sink.Write(r); err != nil {
				t.Errorf("sink write: %v", err)
			}
		},
	}
	return svc, sinkPath
}

func fullBroker() *fakeBroker {
	return &fakeBroker{vals: map[string]string{
		testAppIDPath:      testAppID,
		testInstallIDPath:  testInstallID,
		testPrivateKeyPath: testFakeKey,
		testAppSlugPath:    testAppSlug,
	}}
}

func readRecord(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	if strings.Count(string(data), "\n") != 1 {
		t.Fatalf("want exactly one record line, got %q", data)
	}
	return strings.TrimSuffix(string(data), "\n")
}

const recordCaller = `"caller":{"subject":"test-attested-caller","source":"test"}`

func TestMintRecordOK(t *testing.T) {
	svc, path := recordService(t, fullBroker(), func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
		return githubapp.Token{
			Value:               recordTestToken,
			ExpiresAt:           time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC),
			Permissions:         map[string]string{"contents": "write", "metadata": "read"},
			RepositorySelection: "selected",
			Status:              201,
			RequestID:           "A1B2:3C4D:5E6F",
		}, nil
	}, builderBinding())

	if _, err := svc.Mint(context.Background(), "tester", []string{"widgets"}); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	got := readRecord(t, path)
	want := `{"time":"2026-11-11T12:00:00Z","role":"tester",` + recordCaller +
		`,"app_slug":"clagentic-builder","installation_id":"67890","requested_repositories":["widgets"],` +
		`"requested_permissions":{"contents":"write","pull_requests":"read"},"outcome":"ok","status":201,` +
		`"request_id":"A1B2:3C4D:5E6F","permissions":{"contents":"write","metadata":"read"},` +
		`"repository_selection":"selected","expires_at":"2026-11-11T13:00:00Z","token_fingerprint":"` +
		mintrecord.Fingerprint(recordTestToken) + `"}`
	if got != want {
		t.Errorf("record =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, recordTestToken) || strings.Contains(got, testFakeKey) {
		t.Errorf("record carries token or key material: %s", got)
	}
}

// One row per failure category.
func TestMintRecordFailureCategories(t *testing.T) {
	brokenKey := fullBroker()
	delete(brokenKey.vals, testInstallIDPath)

	cases := []struct {
		name     string
		role     string
		broker   *fakeBroker
		binding  mint.RoleBinding
		mintFn   func(context.Context, githubapp.MintRequest) (githubapp.Token, error)
		wantTail string // from "outcome" on
	}{
		{
			name: "repo_not_in_installation", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.RepoNotInInstallationError{Repos: []string{"widgets"}, Path: "/p", RequestID: "REQ-422"}
			},
			wantTail: `"outcome":"error","failure_category":"repo_not_in_installation","status":422,"request_id":"REQ-422"}`,
		},
		{
			name: "github_api 403", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.APIError{Status: 403, Path: "/p", RequestID: "REQ-403", Body: "denied"}
			},
			wantTail: `"outcome":"error","failure_category":"github_api","status":403,"request_id":"REQ-403"}`,
		},
		{
			name: "github_api 500 without request id", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.APIError{Status: 500, Path: "/p", RequestID: githubapp.NoRequestID, Body: "boom"}
			},
			wantTail: `"outcome":"error","failure_category":"github_api","status":500}`,
		},
		{
			name: "github_response malformed json", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.ResponseError{Op: "parse response", Status: 201, RequestID: "REQ-201", Err: errors.New("invalid character")}
			},
			wantTail: `"outcome":"error","failure_category":"github_response","status":201,"request_id":"REQ-201"}`,
		},
		{
			name: "github_response bad expires_at without request id", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.ResponseError{Op: `parse expires_at "soon"`, Status: 201, RequestID: githubapp.NoRequestID, Err: errors.New("bad time")}
			},
			wantTail: `"outcome":"error","failure_category":"github_response","status":201}`,
		},
		{
			name: "transport", role: "tester", broker: fullBroker(), binding: builderBinding(),
			mintFn: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
				return githubapp.Token{}, &githubapp.TransportError{Op: "call GitHub API", Path: "/p", Err: errors.New("connection refused")}
			},
			wantTail: `"outcome":"error","failure_category":"transport"}`,
		},
		{
			name: "broker", role: "tester", broker: brokenKey, binding: builderBinding(),
			wantTail: `"outcome":"error","failure_category":"broker"}`,
		},
		{
			name: "entitlement", role: "tester", broker: fullBroker(),
			binding: mint.RoleBinding{
				AppIDPath: testAppIDPath, InstallationIDPath: testInstallIDPath, PrivateKeyPath: testPrivateKeyPath,
				EntitledIdentities: []string{"someone-else"}, AppSlug: testAppSlug, AppSlugPath: testAppSlugPath,
			},
			wantTail: `"outcome":"error","failure_category":"entitlement"}`,
		},
		{
			name: "config", role: "tester", broker: fullBroker(),
			binding: mint.RoleBinding{
				AppIDPath: testAppIDPath, InstallationIDPath: testInstallIDPath, PrivateKeyPath: testPrivateKeyPath,
				EntitledIdentities: []string{testIdentity},
			},
			wantTail: `"outcome":"error","failure_category":"config"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, path := recordService(t, tc.broker, tc.mintFn, tc.binding)
			if _, err := svc.Mint(context.Background(), tc.role, nil); err == nil {
				t.Fatal("Mint succeeded, want an error")
			}
			got := readRecord(t, path)
			if !strings.HasSuffix(got, tc.wantTail) {
				t.Errorf("record = %s\nwant suffix %s", got, tc.wantTail)
			}
			if strings.Contains(got, "token_fingerprint") {
				t.Errorf("a failed mint carries a token fingerprint: %s", got)
			}
		})
	}
}

// An entitlement refusal comes before any broker read, so the record has no
// installation id; a refusal after the identity resolves names the caller.
func TestMintRecordEntitlementRefusalNamesCallerNotInstallation(t *testing.T) {
	svc, path := recordService(t, fullBroker(), nil, mint.RoleBinding{
		AppIDPath: testAppIDPath, InstallationIDPath: testInstallIDPath, PrivateKeyPath: testPrivateKeyPath,
		EntitledIdentities: []string{"someone-else"}, AppSlug: testAppSlug, AppSlugPath: testAppSlugPath,
	})
	if _, err := svc.Mint(context.Background(), "tester", nil); err == nil {
		t.Fatal("want refusal")
	}
	got := readRecord(t, path)
	if !strings.Contains(got, recordCaller) || strings.Contains(got, "installation_id") {
		t.Errorf("record = %s", got)
	}
}

func TestMintRecordUnknownRoleIsConfig(t *testing.T) {
	svc, path := recordService(t, fullBroker(), nil, builderBinding())
	if _, err := svc.Mint(context.Background(), "no-such-role", nil); err == nil {
		t.Fatal("want error")
	}
	got := readRecord(t, path)
	if !strings.Contains(got, `"failure_category":"config"`) {
		t.Errorf("record = %s", got)
	}
}

// A service with no Record hook behaves as it did before records existed.
func TestMintWithoutRecordHook(t *testing.T) {
	svc := &mint.Service{
		Roles: roles.NewRegistry(), Broker: fullBroker(), AttestationResolver: testResolver(),
		Bindings: map[string]mint.RoleBinding{"builder": builderBinding()},
		MintFunc: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) { return fakeToken, nil },
	}
	if _, err := svc.Mint(context.Background(), "builder", nil); err != nil {
		t.Fatalf("Mint: %v", err)
	}
}
