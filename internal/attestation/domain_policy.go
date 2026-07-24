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
// sidecar is CORRECT for local GitHub/reader mints made by an invocation
// that legitimately has no per-spawn sidecar of its own (lr-86779f) — e.g. a
// director/lead session. The same fallthrough is a confused-deputy hole
// both for a REMOTE-facing (A2A) mint, where the minted token crosses a
// trust boundary to a peer with no way to detect a parent/spawn
// substitution, AND for a LOCAL mint requested by an invocation that DOES
// expect its own per-spawn source — a spawned subagent whose per-spawn
// sidecar read misses and, absent this policy, falls through to the
// session-keyed sidecar and silently mints its PARENT's role instead
// (lr-2a8653). The discriminator is the MINT DOMAIN — specifically, whether
// THIS invocation was expected to have a per-spawn source — not the
// provider order, so the fix is a domain-scoped wrapper (DomainA2A,
// DomainLocalSubagent), not a chain reorder.

// Domain identifies which mint-request context a Resolve call is being made
// for, so the correct MISS policy can be applied. Domain is roster-agnostic
// and describes only the TRUST BOUNDARY of the credential being minted, not
// any specific agent, tool, or harness.
type Domain string

const (
	// DomainLocal is the default mint domain: a local GitHub/reader-style
	// mint requested by an invocation that has no per-spawn attestation
	// source by design — a long-lived lead/director session, which
	// legitimately has no per-spawn sidecar of its own (lr-86779f). A
	// per-spawn attestation MISS falls through to the next provider in the
	// shared chain exactly as today — this domain applies NO additional
	// constraint.
	DomainLocal Domain = "local"

	// DomainLocalSubagent is a local GitHub/reader-style mint requested by
	// an invocation that DOES expect a per-spawn attestation source — a
	// spawned subagent whose harness is supposed to have written its own
	// per-spawn sidecar file. Unlike DomainLocal, a per-spawn MISS in this
	// domain must fail closed rather than fall through to a lower-priority
	// provider such as the session sidecar: that fallthrough is exactly the
	// confused-deputy mechanism (lr-2a8653) where a subagent's per-spawn
	// read MISS resolves to its PARENT session's identity via the
	// session-keyed sidecar, silently minting the parent's role for the
	// subagent's request. The trust boundary here is narrower than DomainA2A
	// (a local over-grant, not a credential crossing to a remote peer), but
	// the read-miss mechanism and the required fix are identical, so this
	// domain reuses the same PerSpawn-required policy DomainA2A already
	// established (lr-2ca216).
	DomainLocalSubagent Domain = "local-subagent"

	// DomainA2A is the remote-facing, agent-to-agent mint domain. A
	// per-spawn attestation MISS in this domain must fail closed and must
	// never resolve to a lower-priority provider such as the session
	// sidecar (lr-2ca216). This is the substrate DomainResolver enforces;
	// the A2A mint path itself (lr-a850d0, lr-890fae) is NOT implemented by
	// this change — only the domain-aware resolution policy it depends on.
	DomainA2A Domain = "a2a"
)

// requiresPerSpawn reports whether d's MISS policy requires the PerSpawn
// resolver to succeed rather than allowing DomainResolver.Resolve to fall
// through to d.Chain's remaining (lower-priority) providers. DomainLocal (and
// any unrecognized/empty Domain) is the only pass-through case.
func (d Domain) requiresPerSpawn() bool {
	return d == DomainA2A || d == DomainLocalSubagent
}

// ErrPerSpawnRequired is returned by DomainResolver.Resolve when domain
// requires a per-spawn (subagent-namespace) provider to resolve the
// identity, and no such provider is configured, or none of the configured
// per-spawn providers resolved for this invocation. It signals a definite,
// fail-closed refusal — never a silent fallthrough to a lower-priority
// provider such as the session sidecar.
var ErrPerSpawnRequired = fmt.Errorf("attestation: mint domain requires per-spawn attestation; refusing rather than falling through to a lower-priority provider")

// RequiredSourceConstraint names the Provider.Resolve-time Source value
// that must be present for a given mint Domain. DomainA2A and
// DomainLocalSubagent carry a constraint (Domain.requiresPerSpawn());
// DomainLocal (and any unrecognized/empty Domain) carries none, so it is a
// pass-through to the shared chain's ordinary first-match-wins behavior.
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
// Chain is the same *Resolver every mint domain uses. For a domain where
// Domain.requiresPerSpawn() is true (DomainA2A, DomainLocalSubagent), it
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
//   - DomainLocal (or any Domain whose requiresPerSpawn() is false):
//     delegates straight to d.Chain.Resolve — no change from today's
//     behavior (lr-86779f's session-sidecar fallback for a per-spawn miss
//     keeps working, for an invocation that legitimately has no per-spawn
//     source by design, e.g. a lead/director session).
//   - DomainA2A / DomainLocalSubagent (domain.requiresPerSpawn()): requires
//     d.PerSpawn.Resolve to succeed. If PerSpawn declines (ErrNoIdentity) or
//     is nil, Resolve returns ErrPerSpawnRequired — a definite refusal,
//     never a fallthrough to d.Chain's remaining (lower-priority) providers
//     such as the session sidecar (lr-2a8653's confused-deputy fix reuses
//     this exact policy for the local-subagent case). Any hard error from
//     PerSpawn is returned as-is (fail closed, consistent with
//     Resolver.Resolve's own hard-error semantics).
func (d *DomainResolver) Resolve(ctx context.Context, domain Domain) (Identity, error) {
	if !domain.requiresPerSpawn() {
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
