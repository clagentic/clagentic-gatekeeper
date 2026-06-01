// Package roles defines the generic role model: a role name maps to a GitHub
// App permission set. Pure data, no I/O. See docs/ROLES.md for the reference
// permission tables. Consumers may extend roles via config without forking.
package roles

import "fmt"

// Permission is a GitHub installation permission level: "read" or "write".
type Permission string

const (
	Read  Permission = "read"
	Write Permission = "write"
)

// Role is the narrowed capability set Gatekeeper mints a token for.
type Role struct {
	// Name is the role identifier ("builder", "reviewer", "merger", ...).
	Name string
	// Permissions is the GitHub permissions map applied to the minted token,
	// e.g. {"contents": "write", "pull_requests": "write"}.
	Permissions map[string]Permission
}

// reference holds the three shipped roles. It is the reference model, not a
// hard limit — Resolve also accepts roles supplied from config (see Registry).
var reference = map[string]map[string]Permission{
	"builder":  {"contents": Write, "pull_requests": Write, "issues": Write},
	"reviewer": {"pull_requests": Write, "contents": Read},
	"merger":   {"contents": Write, "pull_requests": Write},
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
// installation-token API expects.
func (role Role) GitHubPermissions() map[string]string {
	out := make(map[string]string, len(role.Permissions))
	for k, v := range role.Permissions {
		out[k] = string(v)
	}
	return out
}
