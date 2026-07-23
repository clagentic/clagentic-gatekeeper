// Package attestation resolves the ATTESTED invoking identity for a
// Gatekeeper caller: the identity a deployment's own attestation source
// vouches for, not a value the caller self-declares. It is the (1) layer of
// the three-layer trust model — attested invoking identity -> crew role
// (--caller) -> credential grantor — documented in tome #700. Binding layer
// (1)->(2) and fail-closed enforcement on mismatch are the consumer's job
// (forgejo-curl / guard-hook, lr-0029bf T2-fc/T3-gh); this package only
// resolves what the identity IS.
//
// Resolution order, per deployment:
//
//  1. Configured provider — a deployment points Resolver at its own
//     identity source (env var or file) via config.yaml. Takes precedence
//     when configured.
//  2. Sidecar adapter — reads a session-scoped identity file written by an
//     external harness (e.g. the crew-manifest plugin), when present. This
//     package does not assume any specific harness exists; the sidecar path
//     itself is supplied by config, never hardcoded.
//  3. Built-in fallback — the OS-reported invoking user. Always available,
//     so a bare install has an attested source rather than failing open.
//
// No agent names, org names, or other deployment-specific identities are
// hardcoded anywhere in this package (workspace rule 11 / build-to-share).
package attestation

import (
	"context"
	"fmt"
)

// Identity is the attested invoking identity resolved by a Provider.
type Identity struct {
	// Subject is the attested identity value (e.g. an agent name, a service
	// account, an OS username). Its meaning is defined by whichever Provider
	// resolved it, not by this package.
	Subject string
	// Source names the provider that resolved Subject (e.g. "configured",
	// "sidecar", "builtin"), for audit/debugging. It is not itself part of
	// the trust decision.
	Source string

	// The fields below carry structured-sidecar ATTRIBUTION context
	// (lr-f1bfe8) for audit/observability — which parent session spawned
	// which unit of work. They are populated only by a provider that reads
	// a structured sidecar record (see SidecarConfig.IdentityField); every
	// other provider leaves them empty. None of them are part of the trust
	// decision (Subject/Source remain the only fields mint's entitlement
	// check consults) — they exist purely so a resolved Identity can carry
	// cross-attribution context through to whatever logs or audits the
	// mint decision, without gatekeeper needing any crew-specific
	// knowledge of what these values mean.

	// ParentSessionID is the id of the session/process that spawned the
	// caller this Identity attests, when the sidecar record carries one.
	ParentSessionID string
	// SpawnID is the id of this specific spawn/invocation, when the
	// sidecar record carries one.
	SpawnID string
	// AgentType is a generic, roster-agnostic classification of the caller
	// (e.g. "builder", "reviewer"), when the sidecar record carries one.
	// Never an agent's proper name — that lives in Subject.
	AgentType string
	// SpawnedAt is the sidecar record's own timestamp string for when the
	// spawn started, when the record carries one. Passed through verbatim;
	// this package does not parse or validate its format.
	SpawnedAt string
}

// Provider resolves the attested invoking identity from one identity
// source. A Provider that finds no identity returns ErrNoIdentity so
// Resolver can fall through to the next provider in order; any other error
// is treated as a hard failure of that provider.
type Provider interface {
	// Resolve returns the attested identity, or ErrNoIdentity if this
	// provider has no identity to offer for the current invocation.
	Resolve(ctx context.Context) (Identity, error)
}

// ErrNoIdentity is returned by a Provider when it has no identity to offer,
// signaling Resolver to fall through to the next provider in order. It is
// not a failure of the provider itself.
var ErrNoIdentity = fmt.Errorf("attestation: no identity available")

// Resolver tries a fixed, ordered chain of Providers and returns the first
// attested identity found. The order is fixed by NewResolver: configured
// provider, then sidecar adapter, then built-in fallback — a deployment
// customizes each layer's behavior (or omits it) via config, but never
// reorders the chain.
type Resolver struct {
	providers []Provider
}

// NewResolver builds a Resolver from an ordered provider chain. Callers
// construct the chain via config (see Config/NewChain in this package) so
// no provider is ever assumed to exist.
func NewResolver(providers ...Provider) *Resolver {
	return &Resolver{providers: providers}
}

// Resolve walks the provider chain in order and returns the first attested
// identity found. If every configured provider declines (ErrNoIdentity),
// Resolve returns ErrNoIdentity. Any non-ErrNoIdentity error from a
// provider is returned immediately as a hard failure — a misconfigured
// provider fails closed rather than silently falling through.
func (r *Resolver) Resolve(ctx context.Context) (Identity, error) {
	for _, p := range r.providers {
		id, err := p.Resolve(ctx)
		if err == nil {
			return id, nil
		}
		if err != ErrNoIdentity {
			return Identity{}, err
		}
	}
	return Identity{}, ErrNoIdentity
}
