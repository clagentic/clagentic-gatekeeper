// Package a2apolicy maps an attested A2A (agent-to-agent, remote-facing)
// caller identity to a caller role and the peer audience(s)/scope(s) that
// role is permitted to request a mint for. It is pure policy: a config-driven
// entitlement gate, analogous to the existing role -> App-slug gate in
// internal/mint (lr-116b57), but for the A2A caller domain instead of the
// GitHub-App-role domain.
//
// This package runs AFTER attestation (internal/attestation, lr-a850d0's
// required-fields contract resolves WHO is asking) and BEFORE issuance
// (lr-890fae, the token-provider child that will consume an approved role +
// audience). It does not mint or issue anything itself — it only decides
// whether a resolved identity may proceed for a given requested audience,
// and if so, which role to pass to issuance.
//
// Fail-closed by construction: an identity absent from the mapping, or an
// identity whose role does not cover the requested audience, is refused. A
// deployment with no A2A mapping configured at all has an empty Policy,
// which refuses every request — the mapping is additive and off by default
// (AC 4); it can never widen what the existing GitHub-domain mint gate in
// internal/mint already governs.
//
// ROSTER-AGNOSTIC: no agent names or org-specific identities appear in this
// package. Callers supply their own identity/role/audience strings via
// config (see config.example.yaml's a2a_mapping stanza).
package a2apolicy

import "fmt"

// Entitlement binds one attested identity to one caller role and the set of
// peer audiences that role may request a mint for. Config-sourced; no
// defaults, no wildcard "open" entry — an identity/role/audience triple must
// be explicitly listed to be permitted.
type Entitlement struct {
	// Role is the A2A caller role name passed to issuance once permitted
	// (e.g. "peer-builder", "peer-reviewer" — deployment-defined, generic
	// vocabulary; never a specific agent's proper name).
	Role string
	// Audiences is the set of peer audience/scope identifiers this
	// Entitlement's Role is permitted to request a mint for. Empty means
	// no audience is permitted — a role with no configured audiences fails
	// closed the same as an absent identity.
	Audiences []string
}

// hasAudience reports whether audience is present in e.Audiences.
func (e Entitlement) hasAudience(audience string) bool {
	for _, a := range e.Audiences {
		if a == audience {
			return true
		}
	}
	return false
}

// Policy is the config-driven A2A entitlement map: attested identity ->
// Entitlement (role + permitted audiences). The zero value (nil map) is a
// valid, fully-closed Policy — every Check call refuses — which is exactly
// the behavior a deployment with no A2A mapping stanza configured gets
// (AC 4): additive, off by default, no accidental widening.
type Policy struct {
	entitlements map[string]Entitlement
}

// NewPolicy builds a Policy from a config-sourced identity -> Entitlement
// map. A nil or empty map produces a fully-closed Policy.
func NewPolicy(entitlements map[string]Entitlement) *Policy {
	return &Policy{entitlements: entitlements}
}

// EntitlementSource is the minimal shape a config-layer entry must expose to
// build an Entitlement. internal/config.A2AEntitlementConfig satisfies this
// interface without a2apolicy importing internal/config — this package stays
// a peer of config, not a consumer of its internals, matching the project's
// no-cross-layer-imports rule. A caller (e.g. cmd/gatekeeper) supplies its
// own adapter over its config type.
type EntitlementSource interface {
	// EntitlementRole returns the A2A caller role name.
	EntitlementRole() string
	// EntitlementAudiences returns the permitted peer audience(s)/scope(s).
	EntitlementAudiences() []string
}

// NewPolicyFromEntries builds a Policy from any config-sourced identity ->
// EntitlementSource map, sparing every caller from re-implementing the same
// per-entry conversion loop. A nil or empty map produces a fully-closed
// Policy, same as NewPolicy.
func NewPolicyFromEntries[T EntitlementSource](entries map[string]T) *Policy {
	if len(entries) == 0 {
		return NewPolicy(nil)
	}
	out := make(map[string]Entitlement, len(entries))
	for identity, e := range entries {
		out[identity] = Entitlement{
			Role:      e.EntitlementRole(),
			Audiences: e.EntitlementAudiences(),
		}
	}
	return NewPolicy(out)
}

// DeniedError is returned by Check when a request is refused. It always
// names the RESOLVED identity and requested audience — never a stale or
// guessed value — and, when the identity was found in the mapping but its
// role does not cover the requested audience, the resolved role as well
// (AC 2, AC 3).
type DeniedError struct {
	// Identity is the resolved attested identity that was checked.
	Identity string
	// Audience is the peer audience/scope that was requested.
	Audience string
	// Role is the resolved caller role for Identity, when the identity was
	// found in the mapping. Empty when the identity itself was not found
	// (AC 2) — there is no role to name in that case.
	Role string
}

// Error renders a DeniedError. The message shape differs depending on
// whether the identity was found in the mapping at all (AC 2: identity
// absent) or found but not entitled to the requested audience (AC 3: role
// resolved, audience denied) — the two refusal modes are deliberately
// distinguishable, not collapsed into one generic "denied" string.
func (e *DeniedError) Error() string {
	if e.Role == "" {
		return fmt.Sprintf("a2a mint denied: attested identity %q is not entitled to any A2A role (requested audience %q)", e.Identity, e.Audience)
	}
	return fmt.Sprintf("a2a mint denied: attested identity %q (role %q) is not entitled to audience %q", e.Identity, e.Role, e.Audience)
}

// Check resolves identity's Entitlement and verifies it covers audience.
//
//   - Given a config mapping entitling identity to role R for audience P,
//     when identity requests P, Check returns (R, nil) (AC 1).
//   - Given identity absent from the mapping, Check returns a *DeniedError
//     with Role empty, naming the resolved identity and requested audience
//     (AC 2).
//   - Given identity present but entitled to a role that does not cover
//     audience, Check returns a *DeniedError naming the resolved role and
//     the denied audience (AC 3).
//
// Check never mutates p and never has any I/O of its own — pure policy
// evaluation over the map supplied at construction.
func (p *Policy) Check(identity, audience string) (role string, err error) {
	if p == nil {
		return "", &DeniedError{Identity: identity, Audience: audience}
	}
	ent, ok := p.entitlements[identity]
	if !ok {
		return "", &DeniedError{Identity: identity, Audience: audience}
	}
	if !ent.hasAudience(audience) {
		return "", &DeniedError{Identity: identity, Audience: audience, Role: ent.Role}
	}
	return ent.Role, nil
}
