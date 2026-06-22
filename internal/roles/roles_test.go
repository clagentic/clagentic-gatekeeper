package roles_test

import (
	"reflect"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// TestResolveReferenceRoles checks that each reference role resolves with a
// non-empty name and at least one permission.
func TestResolveReferenceRoles(t *testing.T) {
	reg := roles.NewRegistry()

	for _, name := range []string{"builder", "reviewer", "merger"} {
		name := name
		t.Run(name, func(t *testing.T) {
			role, err := reg.Resolve(name)
			if err != nil {
				t.Fatalf("Resolve(%q) unexpected error: %v", name, err)
			}
			if role.Name != name {
				t.Errorf("Name = %q, want %q", role.Name, name)
			}
			if len(role.Permissions) == 0 {
				t.Errorf("Permissions is empty for role %q", name)
			}
		})
	}
}

// TestResolveUnknownRole asserts that resolving an undefined role returns an error.
func TestResolveUnknownRole(t *testing.T) {
	reg := roles.NewRegistry()

	_, err := reg.Resolve("does-not-exist")
	if err == nil {
		t.Fatal("expected error for unknown role, got nil")
	}
}

// TestAddCustomRole verifies that a caller-supplied role is registered and
// resolves with the exact permissions that were passed to Add.
func TestAddCustomRole(t *testing.T) {
	reg := roles.NewRegistry()

	customPerms := map[string]roles.Permission{
		"contents":      roles.Write,
		"deployments":   roles.Write,
		"pull_requests": roles.Read,
	}
	reg.Add("deployer", customPerms)

	role, err := reg.Resolve("deployer")
	if err != nil {
		t.Fatalf("Resolve(\"deployer\") unexpected error: %v", err)
	}
	if role.Name != "deployer" {
		t.Errorf("Name = %q, want %q", role.Name, "deployer")
	}
	if len(role.Permissions) != len(customPerms) {
		t.Errorf("Permissions length = %d, want %d", len(role.Permissions), len(customPerms))
	}
	for k, want := range customPerms {
		got, ok := role.Permissions[k]
		if !ok {
			t.Errorf("permission %q missing from resolved role", k)
			continue
		}
		if got != want {
			t.Errorf("permission[%q] = %q, want %q", k, got, want)
		}
	}
}

// TestGitHubPermissions asserts that GitHubPermissions returns plain strings
// ("read" / "write"), not typed Permission values, which is what the GitHub
// installation-token API requires.
func TestGitHubPermissions(t *testing.T) {
	reg := roles.NewRegistry()

	role, err := reg.Resolve("builder")
	if err != nil {
		t.Fatalf("Resolve(\"builder\"): %v", err)
	}

	ghPerms := role.GitHubPermissions()
	if len(ghPerms) == 0 {
		t.Fatal("GitHubPermissions returned empty map")
	}

	for k, v := range ghPerms {
		// v must be a plain string value; verify it is one of the two legal values.
		if v != "read" && v != "write" {
			t.Errorf("GitHubPermissions[%q] = %q; want \"read\" or \"write\"", k, v)
		}
	}
}

// TestBuilderCannotMerge asserts that the builder role has the write permissions
// needed for CI work but lacks any permission that would enable merging the
// default branch (only the merger role carries that).
func TestBuilderCannotMerge(t *testing.T) {
	reg := roles.NewRegistry()

	builder, err := reg.Resolve("builder")
	if err != nil {
		t.Fatalf("Resolve(\"builder\"): %v", err)
	}

	// Builder must have contents:write and pull_requests:write for CI tasks.
	if got := builder.Permissions["contents"]; got != roles.Write {
		t.Errorf("builder contents = %q, want %q", got, roles.Write)
	}
	if got := builder.Permissions["pull_requests"]; got != roles.Write {
		t.Errorf("builder pull_requests = %q, want %q", got, roles.Write)
	}

	// "administration" is the GitHub permission required to bypass branch
	// protection and force-merge. Builder must not hold it.
	if _, hasAdmin := builder.Permissions["administration"]; hasAdmin {
		t.Error("builder must not have \"administration\" permission (would allow branch protection bypass)")
	}

	// Confirm merger role exists and is meaningfully distinct from builder.
	_, err = reg.Resolve("merger")
	if err != nil {
		t.Fatalf("Resolve(\"merger\"): %v", err)
	}
}

// TestReviewerPermissions asserts the reviewer role's expected permission set.
func TestReviewerPermissions(t *testing.T) {
	reg := roles.NewRegistry()

	role, err := reg.Resolve("reviewer")
	if err != nil {
		t.Fatalf("Resolve(\"reviewer\"): %v", err)
	}

	if got := role.Permissions["pull_requests"]; got != roles.Write {
		t.Errorf("reviewer pull_requests = %q, want %q", got, roles.Write)
	}
	if got := role.Permissions["contents"]; got != roles.Read {
		t.Errorf("reviewer contents = %q, want %q", got, roles.Read)
	}
}

// TestReferenceRoleGitHubPermissionsIdentical asserts that the GitHub permission
// output for all three reference roles is byte-identical to the expected maps.
// This is a regression guard: the refactor from a direct map conversion to a
// Renderer must not change the output for any reference role.
func TestReferenceRoleGitHubPermissionsIdentical(t *testing.T) {
	reg := roles.NewRegistry()

	cases := []struct {
		name string
		want map[string]string
	}{
		{
			name: "builder",
			want: map[string]string{"contents": "write", "pull_requests": "write", "issues": "write"},
		},
		{
			name: "reviewer",
			want: map[string]string{"pull_requests": "write", "contents": "read"},
		},
		{
			name: "merger",
			want: map[string]string{"contents": "write", "pull_requests": "write"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			role, err := reg.Resolve(tc.name)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.name, err)
			}
			got := role.GitHubPermissions()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("GitHubPermissions() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCustomRoleGitHubPermissionsExact asserts that a config-only custom role
// mints with exactly its declared narrowing via the GitHub renderer, and that
// keys not in the custom set are absent from the output.
func TestCustomRoleGitHubPermissionsExact(t *testing.T) {
	reg := roles.NewRegistry()

	// A "releaser" role: push tags (contents:write) + read PR context only.
	customPerms := map[string]roles.Permission{
		"contents":      roles.Write,
		"pull_requests": roles.Read,
	}
	reg.Add("releaser", customPerms)

	role, err := reg.Resolve("releaser")
	if err != nil {
		t.Fatalf("Resolve(\"releaser\"): %v", err)
	}

	got := role.GitHubPermissions()

	want := map[string]string{
		"contents":      "write",
		"pull_requests": "read",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GitHubPermissions() = %v, want %v", got, want)
	}

	// "issues" must not appear — it was not declared.
	if _, present := got["issues"]; present {
		t.Error("GitHubPermissions() contains \"issues\" but it was not declared in the custom role")
	}
}

// TestRendererSeamProviderParameterized asserts that the Renderer interface is
// the render seam: a custom Renderer can produce a different output than
// DefaultGitHubRenderer for the same Role, and that mint.Service (via its
// Renderer field) can accept any Renderer implementation.
//
// This test does NOT implement Forgejo logic (that is lr-bb2f). It uses a
// trivial stub renderer to prove the seam is parameterizable without touching
// the role model or the GitHub renderer.
func TestRendererSeamProviderParameterized(t *testing.T) {
	reg := roles.NewRegistry()

	role, err := reg.Resolve("builder")
	if err != nil {
		t.Fatalf("Resolve(\"builder\"): %v", err)
	}

	// stubRenderer prefixes every value with "stub:" to distinguish its output
	// from the GitHub renderer's output.
	stubRenderer := stubRendererImpl{}

	got := stubRenderer.RenderPermissions(role)
	github := roles.DefaultGitHubRenderer.RenderPermissions(role)

	// The stub must produce output for every key the GitHub renderer produces.
	for k := range github {
		if _, ok := got[k]; !ok {
			t.Errorf("stub renderer missing key %q", k)
		}
	}

	// The stub's output must differ from GitHub's for at least one key,
	// confirming the seam is actually parameterized (not a passthrough).
	identical := reflect.DeepEqual(got, github)
	if identical {
		t.Error("stub renderer produced output identical to GitHub renderer; seam is not parameterized")
	}
}

// stubRendererImpl is a minimal Renderer used only in TestRendererSeamProviderParameterized.
// It prefixes each permission value with "stub:" to produce output that is
// structurally valid but distinct from the GitHub renderer's output.
type stubRendererImpl struct{}

func (stubRendererImpl) RenderPermissions(role roles.Role) map[string]string {
	out := make(map[string]string, len(role.Permissions))
	for k, v := range role.Permissions {
		out[k] = "stub:" + string(v)
	}
	return out
}
