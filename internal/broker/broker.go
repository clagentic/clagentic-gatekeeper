// Package broker is the pluggable secret-read seam. It is the ONLY place
// Gatekeeper reads secret material. Implementations: openbao, vault, env, file.
// The concrete broker is selected by config.broker.type at startup.
package broker

import (
	"context"
	"fmt"
)

// Broker reads a secret value by path. It never writes, never caches to disk,
// and never logs values.
type Broker interface {
	// Get returns the secret value stored at path, or an error. The returned
	// string may be sensitive (e.g. a PEM private key); callers must not log it.
	Get(ctx context.Context, path string) (string, error)
}

// Config carries the deployment-specific broker settings from config.yaml.
// No values are hardcoded; everything arrives from the consumer's config.
type Config struct {
	Type     string // "openbao" | "vault" | "env" | "file"
	Endpoint string // broker URL; ignored for env|file
	Auth     string // "approle" | "token"; ignored for env|file
}

// New constructs the configured Broker. AppRole/token credentials are read from
// the environment by the implementation, never from config or the repo.
//
// TODO(build): implement openbao, vault, env, and file brokers in sibling files.
func New(cfg Config) (Broker, error) {
	switch cfg.Type {
	case "openbao", "vault", "env", "file":
		return nil, fmt.Errorf("broker %q: not yet implemented", cfg.Type)
	default:
		return nil, fmt.Errorf("unknown broker type %q", cfg.Type)
	}
}
