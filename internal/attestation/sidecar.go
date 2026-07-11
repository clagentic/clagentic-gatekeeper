package attestation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SidecarConfig carries the deployment-specific settings for layer (b), the
// crew-sidecar adapter. It is ONE adapter behind the Provider interface —
// this package never assumes the sidecar exists; a deployment opts in by
// setting Dir and SessionIDEnv in config.yaml.
type SidecarConfig struct {
	// Dir is the directory the sidecar writes its identity file into (e.g.
	// "/tmp" for the crew-manifest plugin's
	// /tmp/lore-agent-name-<session_id> convention). Empty disables the
	// sidecar adapter.
	Dir string
	// FilePrefix is the filename prefix before the session ID
	// (e.g. "lore-agent-name-"). Empty disables the sidecar adapter.
	FilePrefix string
	// SessionIDEnv is the name of the environment variable holding the
	// current session ID, used to build the sidecar filename
	// (Dir/FilePrefix<value of SessionIDEnv>). Empty disables the sidecar
	// adapter.
	SessionIDEnv string
}

// enabled reports whether cfg has enough information to build a sidecar
// path. All three fields are required; a partially configured sidecar is
// treated as disabled rather than guessed at.
func (cfg SidecarConfig) enabled() bool {
	return cfg.Dir != "" && cfg.FilePrefix != "" && cfg.SessionIDEnv != ""
}

// NewSidecarProvider builds the layer (b) provider from cfg. It returns nil
// (no provider, not an error) when cfg is not fully configured, so a
// deployment without the sidecar's harness simply omits this layer from the
// chain rather than the chain assuming it exists.
func NewSidecarProvider(cfg SidecarConfig) (Provider, error) {
	if !cfg.enabled() {
		return nil, nil
	}
	return &sidecarProvider{cfg: cfg}, nil
}

// sidecarProvider resolves the attested identity from a session-scoped file
// written by an external harness. The file path is entirely config-driven:
// this package hardcodes no agent names and no specific harness's file
// location.
type sidecarProvider struct {
	cfg SidecarConfig
}

func (p *sidecarProvider) Resolve(_ context.Context) (Identity, error) {
	sessionID := strings.TrimSpace(os.Getenv(p.cfg.SessionIDEnv))
	if sessionID == "" {
		// No session ID in this invocation's environment means the sidecar's
		// harness is not active here — decline, do not error.
		return Identity{}, ErrNoIdentity
	}

	path := filepath.Join(p.cfg.Dir, p.cfg.FilePrefix+sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The sidecar file is absent for this session — used only when
			// present, per the interface contract. Decline, do not error.
			return Identity{}, ErrNoIdentity
		}
		return Identity{}, fmt.Errorf("attestation: read sidecar identity file %q: %w", path, err)
	}

	v := strings.TrimSpace(string(data))
	if v == "" {
		return Identity{}, ErrNoIdentity
	}
	return Identity{Subject: v, Source: "sidecar"}, nil
}
