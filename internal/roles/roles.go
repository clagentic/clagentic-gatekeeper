// Package roles defines the generic role model: a role name maps to a
// provider-neutral permission set. Pure data, no I/O. See docs/ROLES.md for
// the reference permission tables. Consumers may extend roles via config
// without forking.
//
// Provider rendering is performed by a Renderer implementation. Today only the
// GitHub installation-token renderer (GitHubRenderer) is wired. The Forgejo
// scope-string renderer is the next consumer: see lr-bb2f.
package roles

import "fmt"

// Permission is a GitHub installation permission level: "read" or "write".
// These two values cover all providers supported today (GitHub read/write maps
// directly; Forgejo distinguishes read vs write in its scope strings as well).
type Permission string

const (
	Read  Permission = "read"
	Write Permission = "write"
)

// Role is the narrowed capability set Gatekeeper mints a token for.
type Role struct {
	// Name is the role identifier ("builder", "reviewer", "merger", ...).
	Name string
	// Permissions is the permission map applied to the minted token.
	// Keys are logical resource names ("contents", "pull_requests", "issues",
	// "deployments", ...). The mapping to provider-specific strings is the
	// responsibility of the Renderer, not the Role.
	Permissions map[string]Permission
}

// reference holds the five shipped roles. It is the reference model, not a
// hard limit — Resolve also accepts roles supplied from config (see Registry).
var reference = map[string]map[string]Permission{
	"builder":  {"contents": Write, "pull_requests": Write, "issues": Write, "workflows": Write},
	"reviewer": {"pull_requests": Write, "contents": Read},
	"merger":   {"contents": Write, "pull_requests": Write},
	// security: reads code and diffs, posts review comments / requests changes.
	// pull_requests:write — submit reviews (REQUEST_CHANGES event).
	// contents:read       — read the diff and file tree under review.
	// issues:read         — read linked issues for security context.
	// No contents:write (no push), no merge action (that is merger's exclusive).
	"security": {"pull_requests": Write, "contents": Read, "issues": Read},
	// reader: read-only access for leads and observers that need to verify
	// repo state (diffs, PR status, linked issues) without any write
	// capability. No contents:write, no merge action.
	"reader": {"contents": Read, "pull_requests": Read, "issues": Read},
}

// IsReference reports whether name is one of the five shipped reference roles
// (builder, reviewer, merger, security, reader). Callers that must distinguish
// a reference role from a purely config-defined role use this rather than
// duplicating the name list.
func IsReference(name string) bool {
	_, ok := reference[name]
	return ok
}

// Registry resolves role definitions. Built from the reference roles plus any
// roles declared in config. No deployment-specific data lives here.
type Registry struct {
	defs map[string]map[string]Permission
}

// NewRegistry returns a registry seeded with the reference roles. Extra roles
// from config are merged in by the caller via Add before use.
func NewRegistry() *Registry {
	defs := make(map[string]map[string]Permission, len(reference))
	for name, perms := range reference {
		copyPerms := make(map[string]Permission, len(perms))
		for k, v := range perms {
			copyPerms[k] = v
		}
		defs[name] = copyPerms
	}
	return &Registry{defs: defs}
}

// Add registers or overrides a role definition (e.g. a custom role from config).
func (r *Registry) Add(name string, perms map[string]Permission) {
	r.defs[name] = perms
}

// Resolve returns the Role for name, or an error if unknown.
func (r *Registry) Resolve(name string) (Role, error) {
	perms, ok := r.defs[name]
	if !ok {
		return Role{}, fmt.Errorf("unknown role %q", name)
	}
	return Role{Name: name, Permissions: perms}, nil
}

// GitHubPermissions renders the role's permissions as the string map the GitHub
// installation-token API expects. It is a convenience wrapper around
// GitHubRenderer.RenderPermissions and is preserved for call-site compatibility.
func (role Role) GitHubPermissions() map[string]string {
	return DefaultGitHubRenderer.RenderPermissions(role)
}

// ---------------------------------------------------------------------------
// Provider render seam
// ---------------------------------------------------------------------------

// Renderer translates a Role's provider-neutral permission set into the
// token-request payload a specific provider expects.
//
// Today only GitHubRenderer is implemented. lr-bb2f adds ForgejoRenderer:
// it maps the same resource keys to Forgejo scope strings
// ("read:repository", "write:repository", "read:issue", "write:issue", ...).
// Adding that renderer does not require changes to Role, Registry, or
// GitHubRenderer — only a new Renderer value and provider-specific config.
type Renderer interface {
	// RenderPermissions converts the role's abstract permission map into the
	// provider's expected key/value format. For GitHub this is the
	// installation-token `permissions` object; for Forgejo it will be a flat
	// scope-string slice (encoded as a map for uniformity here, with Forgejo
	// rendering choosing its own key convention — see lr-bb2f).
	RenderPermissions(role Role) map[string]string
}

// ---------------------------------------------------------------------------
// GitHub renderer
// ---------------------------------------------------------------------------

// githubRenderer implements Renderer for GitHub App installation tokens.
// It passes the permission map through verbatim: GitHub API field names
// (e.g. "contents", "pull_requests") are the keys, and "read"/"write" are the
// values, which is exactly what the GitHub POST /app/installations/{id}/access_tokens
// `permissions` field expects.
type githubRenderer struct{}

// RenderPermissions renders the role's permissions as the string map the
// GitHub installation-token API expects. Output is byte-for-byte identical to
// the former Role.GitHubPermissions() implementation, so reference roles
// (builder/reviewer/merger) produce unchanged permission maps.
func (githubRenderer) RenderPermissions(role Role) map[string]string {
	out := make(map[string]string, len(role.Permissions))
	for k, v := range role.Permissions {
		out[k] = string(v)
	}
	return out
}

// DefaultGitHubRenderer is the package-level GitHub renderer. mint.Service
// uses this when no renderer is configured. lr-bb2f will introduce a parallel
// DefaultForgejoRenderer without changing this value or its consumers.
var DefaultGitHubRenderer Renderer = githubRenderer{}
