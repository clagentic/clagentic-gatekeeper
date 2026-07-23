package attestation

import (
	"context"
	"fmt"
)

// This file owns ONE concern: per-MINT-DOMAIN resolution policy layered on
// top of the shared, fixed-order provider chain built by NewChain. It does
// NOT reorder or remove that chain (attestation.go / chain.go own the
// shared order and stay untouched by domain policy) — it wraps a Resolver
// with a required-source constraint so a specific mint domain (today: the
// A2A/remote-facing domain, lr-2ca216) can require that the per-spawn
// sidecar provider itself resolve, rather than accepting a fallthrough to
// a lower-priority provider such as the session sidecar.
//
// WHY THIS IS NOT A GLOBAL CHAIN CHANGE (MILLER lr-2ca216 comment #2, conf
// 0.9): a per-spawn attestation MISS falling through to the session
// sidecar is CORRECT for local GitHub/reader mints (lr-86779f) — a director
// session legitimately has no per-spawn sidecar and must resolve via its
// own session sidecar. The same fallthrough is a confused-deputy hole for
// a REMOTE-facing (A2A) mint: the minted token crosses a trust boundary,
// so a wrong-identity mint silently over-grants the parent lead's role to a
// peer that never earned it. The discriminator is the MINT DOMAIN, not the
// provider order — so the fix is a domain-scoped wrapper, not a reorder.

// Domain identifies which mint-request context a Resolve call is being made
// for, so the correct MISS policy can be applied. Domain is roster-agnostic
// and describes only the TRUST BOUNDARY of the credential being minted, not
// any specific agent, tool, or harness.
type Domain string

const (
	// DomainLocal is the default mint domain: local GitHub/reader-style
	// mints. A per-spawn attestation MISS falls through to the next
	// provider in the shared chain exactly as today (lr-86779f) — this
	// domain applies NO additional constraint.
	DomainLocal Domain = "local"

	// DomainA2A is the remote-facing, agent-to-agent mint domain. A
	// per-spawn attestation MISS in this domain must fail closed and must
	// never resolve to a lower-priority provider such as the session
	// sidecar (lr-2ca216). This is the substrate DomainResolver enforces;
	// the A2A mint path itself (lr-a850d0, lr-890fae) is NOT implemented by
	// this change — only the domain-aware resolution policy it depends on.
	DomainA2A Domain = "a2a"
)

// ErrPerSpawnRequired is returned by DomainResolver.Resolve when domain
// requires a per-spawn (subagent-namespace) provider to resolve the
// identity, and no such provider is configured, or none of the configured
// per-spawn providers resolved for this invocation. It signals a definite,
// fail-closed refusal — never a silent fallthrough to a lower-priority
// provider such as the session sidecar.
var ErrPerSpawnRequired = fmt.Errorf("attestation: mint domain requires per-spawn attestation; refusing rather than falling through to a lower-priority provider")

// RequiredSourceConstraint names the Provider.Resolve-time Source value
// that must be present for a given mint Domain. Only DomainA2A currently
// carries a constraint; DomainLocal (and any unrecognized/empty Domain)
// carries none, so it is a pass-through to the shared chain's ordinary
// first-match-wins behavior.
//
// today the only per-spawn-namespace provider is the sidecar adapter
// (Source == "sidecar"), and there is currently no way to distinguish a
// per-spawn sidecar entry's resolved identity from a session sidecar
// entry's resolved identity purely by Source string, since both report
// "sidecar". DomainResolver therefore requires the CALLER to identify
// which configured provider index(es) are the per-spawn namespace(s) —
// see PerSpawnProviders on DomainResolver.
type RequiredSourceConstraint struct {
	// Domain this constraint applies to.
	Domain Domain
	// Description is a short human-readable name for what "per-spawn" means
	// in this deployment, used only in error messages (e.g. "per-spawn
	// subagent sidecar").
	Description string
}

// DomainResolver applies a per-mint-domain MISS policy on top of a shared
// attestation.Resolver. It never reorders or duplicates the shared chain —
// Chain is the same *Resolver every mint domain uses. For DomainA2A, it
// additionally requires that PerSpawn (a Resolver built from ONLY the
// per-spawn-namespace provider(s), a subset of Chain's own providers) find
// an identity; if PerSpawn declines, DomainResolver refuses fail-closed
// rather than falling through to Chain's remaining providers (e.g. the
// session sidecar or built-in fallback).
type DomainResolver struct {
	// Chain is the full, ordered provider chain built by NewChain — the
	// same resolution every local/default mint uses, unmodified.
	Chain *Resolver
	// PerSpawn is a Resolver scoped to ONLY the per-spawn-namespace
	// provider(s) within Chain's configuration (e.g. the first entry of a
	// spawn-first-then-session Sidecars list). Required for DomainA2A;
	// unused for DomainLocal. Building this as an independent Resolver
	// (rather than a special-cased index into Chain) keeps the domain
	// policy decoupled from Chain's internal provider ordering.
	PerSpawn *Resolver
}

// Resolve applies domain's MISS policy and returns the attested identity.
//
//   - DomainLocal (or any Domain other than DomainA2A): delegates straight
//     to d.Chain.Resolve — no change from today's behavior (lr-86779f's
//     session-sidecar fallback for a per-spawn miss keeps working).
//   - DomainA2A: requires d.PerSpawn.Resolve to succeed. If PerSpawn
//     declines (ErrNoIdentity) or is nil, Resolve returns
//     ErrPerSpawnRequired — a definite refusal, never a fallthrough to
//     d.Chain's remaining (lower-priority) providers such as the session
//     sidecar. Any hard error from PerSpawn is returned as-is (fail closed,
//     consistent with Resolver.Resolve's own hard-error semantics).
func (d *DomainResolver) Resolve(ctx context.Context, domain Domain) (Identity, error) {
	if domain != DomainA2A {
		return d.Chain.Resolve(ctx)
	}

	if d.PerSpawn == nil {
		return Identity{}, ErrPerSpawnRequired
	}
	id, err := d.PerSpawn.Resolve(ctx)
	if err != nil {
		if err == ErrNoIdentity {
			return Identity{}, ErrPerSpawnRequired
		}
		// A hard error from the per-spawn provider (e.g. a malformed
		// structured sidecar, lr-f1bfe8) is a hard failure here too — never
		// downgraded to a soft "try the session sidecar instead".
		return Identity{}, err
	}
	return id, nil
}
