// Package a2amint orchestrates the A2A (agent-to-agent, remote-facing) mint
// path: resolve the attested caller identity under the A2A domain's
// fail-closed MISS policy -> check role/audience entitlement
// (internal/a2apolicy) -> on permit, broker issuance via internal/a2atoken's
// documented JWT login flow (the caller's serve-issued identity assertion logs
// in at the OpenBao JWT auth mount, and the returned client token requests the
// identity token). It has no I/O of its own beyond its injected dependencies,
// mirroring internal/mint's shape for the GitHub domain.
//
// Every mint decision is recorded in GATEKEEPER'S OWN audit record — caller
// identity, resolved A2A role, requested audience, and parent session id —
// because the peer-facing token itself carries only a native "sub" claim (the
// caller's OpenBao entity id) and a TTL bound, nothing else: OpenBao's
// identity/oidc role template cannot carry additional custom claims today.
// OpenBao's own audit device remains the mint-of-record for the issuance
// event; this package's audit hook is a SEPARATE, additional record of the
// authorization decision gatekeeper itself made, not a restatement of the wire
// token.
//
// Fail-closed by construction: an unresolvable attestation, an identity not
// entitled to the requested audience, or an identity that did not come from an
// identity assertion refuses BEFORE any OpenBao call — no token material is
// ever returned, and the refusal is audited exactly like a permit.
package a2amint

import (
	"context"
	"errors"
	"fmt"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2atoken"
	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// AuditEvent is one record of an A2A mint decision — permitted or refused —
// for gatekeeper's own audit trail (internal/mint's local audit, distinct
// from OpenBao's audit device which records the issuance leg only).
type AuditEvent struct {
	// Identity is the resolved attested caller identity, or empty when
	// attestation itself could not be resolved.
	Identity string
	// Role is the A2A caller role a2apolicy resolved, empty on a denial
	// where no role was ever resolved (identity absent from the mapping).
	Role string
	// Audience is the requested peer audience/scope.
	Audience string
	// ParentSessionID carries attribution context from the resolved
	// Identity when the attestation source captured one (structured
	// sidecar record) — empty when the source did not carry it.
	ParentSessionID string
	// Permitted reports whether this event is a successful mint (true) or
	// a fail-closed refusal (false).
	Permitted bool
	// Reason is a short description of the outcome — the granted role for
	// a permit, or the refusal cause for a denial. When the refusal
	// originates from an a2atoken.TransportError (an OpenBao HTTP call),
	// this is that error's own already-bounded/redacted message — never the
	// raw third-party response body — see auditReason.
	Reason string
}

// AuditFunc records one AuditEvent. Service.Mint calls this for every
// outcome, permitted or refused, so a refusal is always audited exactly like
// a permit. A nil AuditFunc is valid and simply discards events — audit wiring
// is the caller's choice, not a hard dependency of this package's control flow.
type AuditFunc func(AuditEvent)

// Service mints A2A peer-facing tokens. Configured entirely from deployment
// values; holds no signing key of any kind and performs no in-process signing
// — OpenBao is the exclusive issuer.
type Service struct {
	// DomainResolver resolves the attested caller identity under
	// attestation.DomainA2A's fail-closed MISS policy: a per-spawn
	// attestation miss refuses outright rather than falling through to a
	// lower-priority provider, closing the confused-deputy path a
	// remote-facing mint cannot tolerate. The identity it returns must carry
	// the verified assertion (attestation.Identity.Assertion), which is what
	// OpenBao logs in with.
	DomainResolver *attestation.DomainResolver
	// Policy is the config-driven A2A entitlement gate (identity -> role ->
	// permitted audiences). A nil or empty-built Policy fails every
	// request closed, matching a deployment with no a2a_mapping configured.
	Policy *a2apolicy.Policy

	// Endpoint is the OpenBao server URL.
	Endpoint string
	// AuthMount is OpenBao's dedicated JWT auth mount path (e.g.
	// "a2a-jwt").
	AuthMount string
	// AuthRoleForRole maps an A2A caller role (a2apolicy's resolved Role)
	// to the JWT auth role name to authenticate against under AuthMount.
	// Config-driven — no role name is hardcoded in this package.
	AuthRoleForRole map[string]string
	// OIDCRoleForRole maps an A2A caller role to the identity/oidc role
	// name to read for the peer-facing token
	// (identity/oidc/token/<OIDCRole>). Config-driven, same shape as
	// AuthRoleForRole.
	OIDCRoleForRole map[string]string

	// Audit records every mint decision, permitted or refused. Optional;
	// a nil value discards events.
	Audit AuditFunc

	// IssueFunc overrides the a2atoken.Issue call. When nil, a2atoken.Issue
	// is used. Set in tests to intercept the outbound OpenBao calls.
	IssueFunc func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error)
}

// audit calls s.Audit if set, so every call site can unconditionally report
// an event without a nil check of its own.
func (s *Service) audit(ev AuditEvent) {
	if s.Audit != nil {
		s.Audit(ev)
	}
}

// auditReason derives the Reason field for a failed-issuance AuditEvent from
// err.
//
// a2atoken.Issue's own errors are already bounded/redacted at the source for
// the specific case that carries third-party content (a non-2xx OpenBao
// response body): *a2atoken.TransportError's detail is bounded to
// a2atoken.maxRawBodyExcerpt on BOTH the parsed-envelope and raw-fallback
// paths (see a2atoken.parseOpenBaoErrors), and the underlying response body
// was itself capped to a2atoken.maxResponseBodyBytes before either path ever
// ran — this function does not need to re-truncate that content, only route
// on the error's *class*: a *a2atoken.TransportError is reported by its own
// already-bounded Error() string, kept short and free of any higher-level
// wrapping; every OTHER error (attestation resolution, entitlement denial,
// missing config) keeps its full, unredacted message, because none of those
// originate from third-party response content and full diagnosability matters
// for them.
//
// This targeted routing — rather than a blanket truncation of every Reason
// string — is deliberate: a blanket redaction would degrade diagnosability
// of gatekeeper's own errors for no security benefit, since only the
// a2atoken transport-error class can ever carry third-party response
// content, and that class is already bounded at its own source.
func auditReason(err error) string {
	var te *a2atoken.TransportError
	if errors.As(err, &te) {
		return te.Error()
	}
	return err.Error()
}

// Mint resolves the attested A2A caller identity, checks it is entitled to
// request audience, and — only on permit — brokers issuance of a
// peer-facing token scoped to that caller's own OpenBao entity via
// internal/a2atoken.
//
// Fail-closed at every gate, in order, each BEFORE any OpenBao call:
//  1. Attestation: an unresolvable identity (attestation.ErrPerSpawnRequired
//     or any other attestation error) refuses immediately.
//  2. Entitlement: a *a2apolicy.DeniedError (identity absent from the
//     mapping, or its role does not cover audience) refuses immediately.
//  3. Config completeness: a requested role with no configured AuthRole/
//     OIDCRole mapping refuses immediately — an incomplete config is a
//     refusal, never a silent fallback to some other role's mapping.
//  4. Assertion: an identity that did not come from an identity assertion has
//     nothing to log in with and refuses immediately.
//  5. Actor: an assertion without act.sub refuses immediately; the JWT mount
//     logs in as /act/sub and there is no sub fallback.
//
// Every outcome — permit or refusal at any gate — is reported to s.Audit
// before Mint returns.
func (s *Service) Mint(ctx context.Context, audience string) (a2atoken.Token, error) {
	if s.DomainResolver == nil {
		err := fmt.Errorf("a2amint: no attestation domain resolver configured; cannot resolve caller identity")
		s.audit(AuditEvent{Audience: audience, Permitted: false, Reason: err.Error()})
		return a2atoken.Token{}, err
	}

	identity, err := s.DomainResolver.Resolve(ctx, attestation.DomainA2A)
	if err != nil {
		s.audit(AuditEvent{Audience: audience, Permitted: false, Reason: fmt.Sprintf("resolve attested identity: %v", err)})
		return a2atoken.Token{}, fmt.Errorf("a2amint: resolve attested identity: %w", err)
	}

	refuse := func(role string, err error) (a2atoken.Token, error) {
		s.audit(AuditEvent{
			Identity:        identity.Subject,
			Role:            role,
			Audience:        audience,
			ParentSessionID: identity.ParentSessionID,
			Permitted:       false,
			Reason:          err.Error(),
		})
		return a2atoken.Token{}, err
	}

	role, err := s.Policy.Check(identity.Subject, audience)
	if err != nil {
		return refuse("", fmt.Errorf("a2amint: %w", err))
	}

	authRole, ok := s.AuthRoleForRole[role]
	if !ok || authRole == "" {
		return refuse(role, fmt.Errorf("a2amint: no jwt auth role configured for A2A caller role %q", role))
	}
	oidcRole, ok := s.OIDCRoleForRole[role]
	if !ok || oidcRole == "" {
		return refuse(role, fmt.Errorf("a2amint: no identity/oidc role configured for A2A caller role %q", role))
	}

	if identity.Assertion == "" {
		return refuse(role, fmt.Errorf("a2amint: caller identity %q did not come from an identity assertion; the OpenBao JWT mount logs in with the assertion, so there is nothing to present", identity.Subject))
	}

	// The JWT mount binds the entity to /act/sub (user_claim_json_pointer), so
	// an assertion without act.sub has no entity to log in as. There is no
	// fallback to sub: that would name a different entity than the contract.
	if identity.ActSub == "" {
		return refuse(role, fmt.Errorf("a2amint: identity assertion for %q carries no act.sub; mint-a2a logs in as /act/sub and has no sub fallback, so the caller must present an assertion with an act claim", identity.Subject))
	}

	issueFn := s.IssueFunc
	if issueFn == nil {
		issueFn = a2atoken.Issue
	}

	token, err := issueFn(ctx, a2atoken.IssueRequest{
		Endpoint:  s.Endpoint,
		Assertion: identity.Assertion,
		Subject:   identity.Subject,
		AuthMount: s.AuthMount,
		AuthRole:  authRole,
		OIDCRole:  oidcRole,
	})
	if err != nil {
		s.audit(AuditEvent{
			Identity:        identity.Subject,
			Role:            role,
			Audience:        audience,
			ParentSessionID: identity.ParentSessionID,
			Permitted:       false,
			Reason:          auditReason(err),
		})
		return a2atoken.Token{}, fmt.Errorf("a2amint: %w", err)
	}

	s.audit(AuditEvent{
		Identity:        identity.Subject,
		Role:            role,
		Audience:        audience,
		ParentSessionID: identity.ParentSessionID,
		Permitted:       true,
		Reason:          fmt.Sprintf("issued for role %q", role),
	})
	return token, nil
}
