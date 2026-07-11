package attestation

import "fmt"

// ChainConfig carries the deployment-specific settings for the full
// attestation chain: layer (a) configured provider, layer (b) sidecar
// adapter. Layer (c), the built-in fallback, requires no configuration and
// is always appended last.
type ChainConfig struct {
	Configured ConfiguredConfig
	Sidecar    SidecarConfig
}

// NewChain builds the fixed-order Resolver: configured provider (a), then
// sidecar adapter (b) when configured, then the built-in fallback (c). Each
// of (a) and (b) is omitted from the chain — not stubbed, not assumed —
// when its config is absent, so a bare install still resolves via (c)
// rather than failing open.
func NewChain(cfg ChainConfig) (*Resolver, error) {
	var providers []Provider

	configured, err := NewConfiguredProvider(cfg.Configured)
	if err != nil {
		return nil, fmt.Errorf("attestation: build configured provider: %w", err)
	}
	if configured != nil {
		providers = append(providers, configured)
	}

	sidecar, err := NewSidecarProvider(cfg.Sidecar)
	if err != nil {
		return nil, fmt.Errorf("attestation: build sidecar provider: %w", err)
	}
	if sidecar != nil {
		providers = append(providers, sidecar)
	}

	providers = append(providers, NewBuiltinProvider())

	return NewResolver(providers...), nil
}
