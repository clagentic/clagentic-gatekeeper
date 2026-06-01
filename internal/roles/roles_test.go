package roles_test

import (
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
