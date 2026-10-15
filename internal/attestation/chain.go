package attestation

import (
	"context"
	"fmt"
)

// ChainConfig carries the deployment-specific settings for the full
// attestation chain: the optional identity assertion layer, layer (a)
// configured provider, layer (b) one or more sidecar adapters, and the
// deprecated layer (c) OS-user fallback.
type ChainConfig struct {
	// Assertion is the already-built assertion provider (NewAssertionProvider),
	// or nil when the deployment configures none. It is tried before every
	// other layer. The caller builds it so it can also place the same provider
	// in a per-spawn resolver.
	Assertion Provider

	Configured ConfiguredConfig
	// Sidecars is an ordered list of layer (b) sidecar adapters. A
	// deployment with multiple independent sidecar namespaces (e.g. a
	// per-session namespace for a lead process and a per-spawn namespace
	// for its subagents) configures one entry per namespace; the resolver
	// tries each in the given order and uses the first that resolves. A
	// single-entry list is the common case.
	Sidecars []SidecarConfig

	// OmitOSUser leaves the built-in OS-user fallback out of the chain. The
	// zero value keeps it, so a caller that never sets this field resolves
	// exactly as before.
	OmitOSUser bool
	// OSUserWarn, when set, is called each time the OS-user fallback is the
	// layer that answered, so a deployment can see which mints still depend
	// on a layer that is going away.
	OSUserWarn func(Identity)
}

// NewChain builds the fixed-order Resolver: assertion (when configured),
// configured provider (a), each configured sidecar adapter (b) in order, then
// the OS-user fallback (c) unless OmitOSUser. Any layer is omitted from the
// chain — not stubbed, not assumed — when its config is absent.
func NewChain(cfg ChainConfig) (*Resolver, error) {
	var providers []Provider

	if cfg.Assertion != nil {
		providers = append(providers, cfg.Assertion)
	}

	configured, err := NewConfiguredProvider(cfg.Configured)
	if err != nil {
		return nil, fmt.Errorf("attestation: build configured provider: %w", err)
	}
	if configured != nil {
		providers = append(providers, configured)
	}

	for i, sidecarCfg := range cfg.Sidecars {
		sidecar, err := NewSidecarProvider(sidecarCfg)
		if err != nil {
			return nil, fmt.Errorf("attestation: build sidecar provider [%d]: %w", i, err)
		}
		if sidecar != nil {
			providers = append(providers, sidecar)
		}
	}

	if !cfg.OmitOSUser {
		builtin := NewBuiltinProvider()
		if cfg.OSUserWarn != nil {
			builtin = &warnProvider{inner: builtin, warn: cfg.OSUserWarn}
		}
		providers = append(providers, builtin)
	}

	return NewResolver(providers...), nil
}

// warnProvider reports each identity its inner provider resolves, then passes
// it through unchanged.
type warnProvider struct {
	inner Provider
	warn  func(Identity)
}

func (w *warnProvider) Resolve(ctx context.Context) (Identity, error) {
	id, err := w.inner.Resolve(ctx)
	if err == nil {
		w.warn(id)
	}
	return id, err
}
