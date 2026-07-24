// Package mint orchestrates token minting: resolve the attested invoking
// identity -> verify role entitlement -> resolve role -> read App credentials
// from the broker -> verify the App-slug binding -> sign + exchange via
// githubapp. It has no I/O of its own beyond its injected dependencies, which
// keeps it unit-testable with fakes.
//
// Mint enforces the (2)->(3) layer of tome #700's three-layer trust model —
// attested invoking identity -> crew role -> credential grantor (App) — at
// the mint boundary itself:
//
//  1. Entitlement: the attested identity resolved via AttestationResolver
//     must be listed in the role's configured EntitledIdentities. An
//     unresolvable identity, or an identity not entitled to the requested
//     role, fails closed before any broker read.
//  2. Verifiable App-slug binding: after the broker resolves App credentials
//     for the role, the App's actual slug (also broker-sourced) must match
//     the role's configured expected slug. This is a verified equality
//     check, not a silent map-key fallback — it is the safeguard against a
//     role's broker paths quietly resolving to the wrong App installation
//     (the lr-e41f class of bug).
package mint

import (
	"context"
	"fmt"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/broker"
	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// RoleBinding maps a role name to the broker paths holding its App
// credentials plus the mint-time entitlement and App-slug verification
// settings for that role. Sourced from config.yaml; no values hardcoded.
type RoleBinding struct {
	AppIDPath          string
	InstallationIDPath string
	PrivateKeyPath     string

	// EntitledIdentities is the set of attested identities permitted to mint
	// this role. Empty means no identity is entitled — Mint fails closed
	// rather than treating an unconfigured role as open to everyone.
	EntitledIdentities []string

	// AppSlug is the expected GitHub App slug this role's broker-resolved
	// App must match. AppSlugPath is the broker path holding the App's
	// actual slug. Both must be set together to enable the App-slug
	// verification gate; a role that sets only one fails closed at mint
	// time rather than silently skipping verification.
	AppSlug     string
	AppSlugPath string
}

// entitled reports whether identity is listed in b.EntitledIdentities.
func (b RoleBinding) entitled(identity string) bool {
	for _, id := range b.EntitledIdentities {
		if id == identity {
			return true
		}
	}
	return false
}

// appSlugConfigured reports whether b has a complete App-slug verification
// setting. Both fields are required together: a partial setting (one set,
// one empty) is a config error, not "verification disabled".
func (b RoleBinding) appSlugConfigured() bool {
	return b.AppSlug != "" && b.AppSlugPath != ""
}

// Service mints role-scoped installation tokens.
type Service struct {
	APIBase  string
	TTL      time.Duration
	Roles    *roles.Registry
	Broker   broker.Broker
	Bindings map[string]RoleBinding // role name -> broker paths + verification config

	// AttestationResolver resolves the ATTESTED invoking identity
	// (internal/attestation) for the entitlement check, for an invocation
	// whose Domain applies no additional MISS constraint (attestation.
	// DomainLocal semantics). Required: Mint fails closed with no broker
	// reads and no token minted if both this and DomainResolver are nil,
	// since no resolver at all means no identity can ever be attested.
	//
	// Deprecated in favor of DomainResolver + Domain for any caller that can
	// distinguish a per-spawn-expected invocation (attestation.
	// DomainLocalSubagent) from a lead/director session with none by design
	// (attestation.DomainLocal) — see lr-2a8653. Retained so an existing
	// caller that only ever sets AttestationResolver keeps compiling and
	// behaving exactly as before: when DomainResolver is nil, Mint wraps
	// AttestationResolver in a DomainResolver whose Chain is
	// AttestationResolver itself, which is behaviorally identical to calling
	// AttestationResolver.Resolve directly for DomainLocal.
	AttestationResolver *attestation.Resolver

	// DomainResolver resolves the ATTESTED invoking identity via the
	// domain-aware MISS policy (internal/attestation.DomainResolver,
	// lr-2ca216/lr-2a8653): a per-spawn attestation MISS on an invocation
	// whose Domain is DomainA2A or DomainLocalSubagent fails closed rather
	// than falling through to a lower-priority provider such as the session
	// sidecar, while DomainLocal preserves today's session-sidecar fallback
	// for a lead/director session with no per-spawn source by design
	// (lr-86779f). When set, this takes precedence over AttestationResolver.
	DomainResolver *attestation.DomainResolver

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

// Mint is MintForDomain scoped to attestation.DomainLocal — the default mint
// domain for an invocation with no per-spawn attestation expectation of its
// own (e.g. a lead/director session, lr-86779f). Existing callers that only
// need today's behavior (a per-spawn MISS falls through to the session
// sidecar exactly as before) keep using this method unchanged.
func (s *Service) Mint(ctx context.Context, roleName string, repos []string) (githubapp.Token, error) {
	return s.MintForDomain(ctx, attestation.DomainLocal, roleName, repos)
}

// MintForDomain resolves the attested invoking identity under domain's MISS
// policy, verifies it is entitled to mint roleName, reads the role's App
// credentials from the broker, verifies the resolved App's slug matches the
// role's configured binding, and returns a short-lived installation token
// narrowed to the role's permissions and the requested repositories. The App
// private key never leaves this call.
//
// domain selects the attestation.DomainResolver MISS policy applied to this
// invocation (lr-2a8653): pass attestation.DomainLocalSubagent for a spawned
// subagent invocation that expects its own per-spawn attestation source, so
// a per-spawn MISS fails closed rather than silently resolving to the
// PARENT session's identity via the session sidecar — the confused-deputy
// class this method exists to close. Pass attestation.DomainLocal (or use
// Mint) for an invocation with no per-spawn source by design.
//
// Every failure mode here is fail-closed: an unresolvable identity, an
// identity not entitled to the role, or a missing/mismatched App-slug
// binding all return an error with no token minted.
func (s *Service) MintForDomain(ctx context.Context, domain attestation.Domain, roleName string, repos []string) (githubapp.Token, error) {
	role, err := s.Roles.Resolve(roleName)
	if err != nil {
		return githubapp.Token{}, err
	}

	binding, ok := s.Bindings[roleName]
	if !ok {
		return githubapp.Token{}, fmt.Errorf("no broker binding configured for role %q", roleName)
	}

	// Gap 1: entitlement — attested identity -> role. Resolved and checked
	// before any broker read, so an unentitled caller never touches secrets.
	//
	// DomainResolver takes precedence when set (lr-2a8653): it applies
	// domain's MISS policy, which for DomainLocalSubagent/DomainA2A refuses
	// rather than falling through to a lower-priority provider such as the
	// session sidecar on a per-spawn MISS. A caller that only ever sets the
	// legacy AttestationResolver keeps its exact prior behavior — resolved
	// via the shared chain with no domain constraint, regardless of domain —
	// since it never gets a DomainLocalSubagent-capable resolver in the
	// first place.
	domainResolver := s.DomainResolver
	if domainResolver == nil {
		if s.AttestationResolver == nil {
			return githubapp.Token{}, fmt.Errorf("mint role %q: no attestation resolver configured; cannot verify entitlement", roleName)
		}
		domainResolver = &attestation.DomainResolver{Chain: s.AttestationResolver}
	}
	identity, err := domainResolver.Resolve(ctx, domain)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("mint role %q: resolve attested identity: %w", roleName, err)
	}
	if !binding.entitled(identity.Subject) {
		return githubapp.Token{}, fmt.Errorf("mint role %q: attested identity %q is not entitled to this role", roleName, identity.Subject)
	}

	// Gap 2: verifiable App-slug binding — role -> App. Required for every
	// role; a role without a configured slug binding cannot be verified and
	// therefore cannot mint.
	if !binding.appSlugConfigured() {
		return githubapp.Token{}, fmt.Errorf("mint role %q: no App-slug binding configured (app_slug and app_slug_path are both required)", roleName)
	}

	appID, err := s.Broker.Get(ctx, binding.AppIDPath)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("read app id for role %q: %w", roleName, err)
	}
	installID, err := s.Broker.Get(ctx, binding.InstallationIDPath)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("read installation id for role %q: %w", roleName, err)
	}
	actualSlug, err := s.Broker.Get(ctx, binding.AppSlugPath)
	if err != nil {
		return githubapp.Token{}, fmt.Errorf("read app slug for role %q: %w", roleName, err)
	}
	if actualSlug != binding.AppSlug {
		// Never fall back to whatever App the broker paths happened to
		// resolve to — a mismatch here means the role's broker paths point
		// at a different App than the one legitimately configured for it.
		return githubapp.Token{}, fmt.Errorf("mint role %q: resolved App slug %q does not match configured App slug %q", roleName, actualSlug, binding.AppSlug)
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
