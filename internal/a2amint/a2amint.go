// Package a2amint orchestrates the A2A (agent-to-agent, remote-facing) mint
// path: resolve the attested caller identity under the A2A domain's
// fail-closed MISS policy -> check role/audience entitlement
// (internal/a2apolicy) -> on permit, broker issuance via internal/a2atoken's
// B3 exchange (gatekeeper-signed assertion -> OpenBao JWT-auth login ->
// identity/oidc/token/<role> read). It has no I/O of its own beyond its
// injected dependencies, mirroring internal/mint's shape for the GitHub
// domain.
//
// Every mint decision is recorded in GATEKEEPER'S OWN audit record — caller
// identity, resolved A2A role, requested audience, and parent session id —
// per lr-890fae comment #5 (AC4-successor): the peer-facing token itself
// carries only a native "sub" claim (the caller's OpenBao entity id) and a
// TTL bound, nothing else, because OpenBao's identity/oidc role template
// cannot carry additional custom claims today (openbao lr-fbbf32 comment
// #12 / lr-1e7c97, an unresolved upstream parser bug). OpenBao's own audit
// device remains the mint-of-record for the issuance event; this package's
// audit hook is a SEPARATE, additional record of the authorization decision
// gatekeeper itself made, not a restatement of the wire token.
//
// Fail-closed by construction: an unresolvable attestation, or an identity
// not entitled to the requested audience, refuses BEFORE any broker read and
// BEFORE any OpenBao issuance call — no token material is ever returned, and
// the refusal is audited exactly like a permit.
package a2amint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2atoken"
	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/broker"
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
// a permit (lr-890fae's fail-closed AC). A nil AuditFunc is valid and simply
// discards events — audit wiring is the caller's choice, not a hard
// dependency of this package's control flow.
type AuditFunc func(AuditEvent)

// Service mints A2A peer-facing tokens via the B3 attest-and-route
// mechanism. Configured entirely from deployment values; holds no signing
// key of its own for the peer-facing token and performs no in-process
// signing of it (AC3) — OpenBao is the exclusive issuer.
type Service struct {
	// DomainResolver resolves the attested caller identity under
	// attestation.DomainA2A's fail-closed MISS policy: a per-spawn
	// attestation miss refuses outright rather than falling through to a
	// lower-priority (e.g. session) provider, closing the confused-deputy
	// path a remote-facing mint cannot tolerate.
	DomainResolver *attestation.DomainResolver
	// Policy is the config-driven A2A entitlement gate (identity -> role ->
	// permitted audiences). A nil or empty-built Policy fails every
	// request closed, matching a deployment with no a2a_mapping configured.
	Policy *a2apolicy.Policy
	// Broker reads the assertion signing key. Never asked for the
	// peer-facing token's own credentials — OpenBao issues those directly.
	Broker broker.Broker

	// AssertionPrivateKeyPath is the broker path holding gatekeeper's own
	// assertion signing key (the bearer-of-attestation key, distinct from
	// and never conflated with OpenBao's OIDC signing key).
	AssertionPrivateKeyPath string
	// Issuer is stamped into the assertion's "iss" claim; must match the
	// JWT auth mount's configured bound_issuer.
	Issuer string
	// AssertionTTL bounds the gatekeeper-signed assertion's own lifetime,
	// independent of the peer-facing token's TTL (which OpenBao's
	// identity/oidc role controls).
	AssertionTTL time.Duration

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
// missing broker/config, key-parse failure) keeps its full, unredacted
// message, because none of those originate from third-party response
// content and full diagnosability matters for them.
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

	role, err := s.Policy.Check(identity.Subject, audience)
	if err != nil {
		s.audit(AuditEvent{
			Identity:        identity.Subject,
			Audience:        audience,
			ParentSessionID: identity.ParentSessionID,
			Permitted:       false,
			Reason:          err.Error(),
		})
		return a2atoken.Token{}, fmt.Errorf("a2amint: %w", err)
	}

	authRole, ok := s.AuthRoleForRole[role]
	if !ok || authRole == "" {
		err := fmt.Errorf("a2amint: no jwt auth role configured for A2A caller role %q", role)
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
	oidcRole, ok := s.OIDCRoleForRole[role]
	if !ok || oidcRole == "" {
		err := fmt.Errorf("a2amint: no identity/oidc role configured for A2A caller role %q", role)
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

	if s.Broker == nil {
		err := fmt.Errorf("a2amint: no broker configured; cannot read assertion signing key")
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

	privateKey, err := s.Broker.Get(ctx, s.AssertionPrivateKeyPath)
	if err != nil {
		// Do not wrap with the value — only the path context, never key
		// material.
		wrapped := fmt.Errorf("a2amint: read assertion private key: %w", err)
		s.audit(AuditEvent{
			Identity:        identity.Subject,
			Role:            role,
			Audience:        audience,
			ParentSessionID: identity.ParentSessionID,
			Permitted:       false,
			Reason:          wrapped.Error(),
		})
		return a2atoken.Token{}, wrapped
	}

	issueFn := s.IssueFunc
	if issueFn == nil {
		issueFn = a2atoken.Issue
	}

	token, err := issueFn(ctx, a2atoken.IssueRequest{
		Endpoint:               s.Endpoint,
		AssertionPrivateKeyPEM: privateKey,
		Issuer:                 s.Issuer,
		Subject:                identity.Subject,
		AssertionTTL:           s.AssertionTTL,
		AuthMount:              s.AuthMount,
		AuthRole:               authRole,
		OIDCRole:               oidcRole,
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
