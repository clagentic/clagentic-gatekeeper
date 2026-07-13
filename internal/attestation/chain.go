package attestation

import "fmt"

// ChainConfig carries the deployment-specific settings for the full
// attestation chain: layer (a) configured provider, layer (b) one or more
// sidecar adapters. Layer (c), the built-in fallback, requires no
// configuration and is always appended last.
type ChainConfig struct {
	Configured ConfiguredConfig
	// Sidecars is an ordered list of layer (b) sidecar adapters. A
	// deployment with multiple independent sidecar namespaces (e.g. a
	// per-session namespace for a lead process and a per-spawn namespace
	// for its subagents) configures one entry per namespace; the resolver
	// tries each in the given order and uses the first that resolves. A
	// single-entry list is the common case.
	Sidecars []SidecarConfig
}

// NewChain builds the fixed-order Resolver: configured provider (a), then
// each configured sidecar adapter (b) in order, then the built-in fallback
// (c). Layer (a) and any individual sidecar entry are omitted from the
// chain — not stubbed, not assumed — when its config is absent, so a bare
// install still resolves via (c) rather than failing open.
func NewChain(cfg ChainConfig) (*Resolver, error) {
	var providers []Provider

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

	providers = append(providers, NewBuiltinProvider())

	return NewResolver(providers...), nil
}
