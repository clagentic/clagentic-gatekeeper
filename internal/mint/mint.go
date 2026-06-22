// Package mint orchestrates token minting: resolve role -> read App credentials
// from the broker -> sign + exchange via githubapp. It has no I/O of its own
// beyond its injected dependencies, which keeps it unit-testable with fakes.
package mint

import (
	"context"
	"fmt"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/broker"
	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// RoleBinding maps a role name to the broker paths holding its App credentials.
// Sourced from config.yaml; no values hardcoded.
type RoleBinding struct {
	AppIDPath          string
	InstallationIDPath string
	PrivateKeyPath     string
}

// Service mints role-scoped installation tokens.
type Service struct {
	APIBase  string
	TTL      time.Duration
	Roles    *roles.Registry
	Broker   broker.Broker
	Bindings map[string]RoleBinding // role name -> broker paths

	// Renderer translates a role's permission set into the provider's expected
	// format. When nil, roles.DefaultGitHubRenderer is used, which preserves
	// the existing GitHub installation-token behaviour for all callers that do
	// not set this field.
	//
	// lr-bb2f: set this to a ForgejoRenderer to produce Forgejo scope strings
	// instead. The rest of Service.Mint is provider-agnostic.
	Renderer roles.Renderer

	// MintFunc overrides the githubapp.Mint call. When nil, githubapp.Mint is
	// used. Set in tests to intercept the outbound GitHub API call.
	MintFunc func(context.Context, githubapp.MintRequest) (githubapp.Token, error)
}

// Mint resolves the role, reads its App credentials from the broker, and returns
// a short-lived installation token narrowed to the role's permissions and the
// requested repositories. The App private key never leaves this call.
func (s *Service) Mint(ctx context.Context, roleName string, repos []string) (githubapp.Token, error) {
	role, err := s.Roles.Resolve(roleName)
	if err != nil {
		return githubapp.Token{}, err
	}

	binding, ok := s.Bindings[roleName]
	if !ok {
		return githubapp.Token{}, fmt.Errorf("no broker binding configured for role %q", roleName)
	}

	appID, err := s.Broker.Get(ctx, binding.AppIDPath)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("read app id for role %q: %w", roleName, err)
	}
	installID, err := s.Broker.Get(ctx, binding.InstallationIDPath)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("read installation id for role %q: %w", roleName, err)
	}
	privateKey, err := s.Broker.Get(ctx, binding.PrivateKeyPath)
	if err != nil {
		// Do not wrap with the value — only the path/role.
		return githubapp.Token{}, fmt.Errorf("read private key for role %q: %w", roleName, err)
	}

	renderer := s.Renderer
	if renderer == nil {
		renderer = roles.DefaultGitHubRenderer
	}

	mintFn := s.MintFunc
	if mintFn == nil {
		mintFn = githubapp.Mint
	}
	return mintFn(ctx, githubapp.MintRequest{
		APIBase:        s.APIBase,
		AppID:          appID,
		InstallationID: installID,
		PrivateKeyPEM:  privateKey,
		Permissions:    renderer.RenderPermissions(role),
		Repositories:   repos,
		TTL:            s.TTL,
	})
}
