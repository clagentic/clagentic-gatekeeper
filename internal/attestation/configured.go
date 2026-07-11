package attestation

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// ConfiguredType selects which built-in configured-provider implementation
// backs layer (a): a deployment's own identity source. "" (unset) disables
// the configured provider — Resolver falls through to the next layer.
type ConfiguredType string

const (
	// ConfiguredNone disables the configured provider.
	ConfiguredNone ConfiguredType = ""
	// ConfiguredEnv reads the identity from an environment variable.
	ConfiguredEnv ConfiguredType = "env"
	// ConfiguredFile reads the identity from a file (trimmed of whitespace).
	ConfiguredFile ConfiguredType = "file"
)

// ConfiguredConfig carries the deployment-specific settings for layer (a),
// the config-selectable provider a deployment points at its own identity
// source. Sourced from config.yaml; no values hardcoded.
type ConfiguredConfig struct {
	// Type selects the implementation: "env" or "file". Empty disables the
	// configured provider entirely.
	Type ConfiguredType
	// Source is the env var name (Type: env) or file path (Type: file) to
	// read the attested identity from. Its meaning is Type-dependent.
	Source string
}

// NewConfiguredProvider builds the layer (a) provider from cfg. It returns
// nil (no provider, not an error) when cfg.Type is ConfiguredNone, so
// callers can omit this layer from the chain when a deployment has not
// pointed it at anything yet.
func NewConfiguredProvider(cfg ConfiguredConfig) (Provider, error) {
	switch cfg.Type {
	case ConfiguredNone:
		return nil, nil
	case ConfiguredEnv:
		if cfg.Source == "" {
			return nil, fmt.Errorf("attestation: configured provider type %q requires source (env var name)", cfg.Type)
		}
		return &envProvider{varName: cfg.Source}, nil
	case ConfiguredFile:
		if cfg.Source == "" {
			return nil, fmt.Errorf("attestation: configured provider type %q requires source (file path)", cfg.Type)
		}
		return &fileProvider{path: cfg.Source}, nil
	default:
		return nil, fmt.Errorf("attestation: unknown configured provider type %q", cfg.Type)
	}
}

// envProvider resolves the attested identity from an environment variable
// named by the deployment's config. Suitable for harnesses that already
// export the invoking identity into the process environment.
type envProvider struct {
	varName string
}

func (p *envProvider) Resolve(_ context.Context) (Identity, error) {
	v := strings.TrimSpace(os.Getenv(p.varName))
	if v == "" {
		return Identity{}, ErrNoIdentity
	}
	return Identity{Subject: v, Source: "configured"}, nil
}

// fileProvider resolves the attested identity from a file path named by the
// deployment's config. Suitable for harnesses that write the invoking
// identity to a known file outside the process environment.
type fileProvider struct {
	path string
}

func (p *fileProvider) Resolve(_ context.Context) (Identity, error) {
	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Identity{}, ErrNoIdentity
		}
		return Identity{}, fmt.Errorf("attestation: read configured identity file %q: %w", p.path, err)
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return Identity{}, ErrNoIdentity
	}
	return Identity{Subject: v, Source: "configured"}, nil
}
