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
	// IdentityField is OPTIONAL and per-entry (lr-f1bfe8). When unset
	// (""), Resolve preserves the original behavior exactly: the whole
	// sidecar file, TrimSpace'd, is Identity.Subject. When set, Resolve
	// instead parses the file as a structured (JSON or YAML) object — see
	// structured_sidecar.go — and reads the named field as Identity.Subject;
	// the remaining recognized attribution fields (parent_session_id,
	// spawn_id, agent_type, spawned_at) are captured onto the resolved
	// Identity when present. A structured parse failure, or IdentityField
	// missing/empty in the parsed object, is a hard failure distinct from
	// an absent file (which stays ErrNoIdentity) — see parseStructuredSidecar.
	IdentityField string
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
	if !isSafePathSegment(sessionID) {
		// A session ID is an opaque token from the environment, never a path.
		// Refuse anything that could redirect the read (separators, "..",
		// absolute paths) rather than trying to sanitize it — decline, do
		// not read.
		return Identity{}, ErrNoIdentity
	}

	path := filepath.Join(p.cfg.Dir, p.cfg.FilePrefix+sessionID)
	if err := requireContained(p.cfg.Dir, path); err != nil {
		return Identity{}, fmt.Errorf("attestation: sidecar identity path escapes configured dir: %w", err)
	}

	// Lstat (not Stat) so a symlink is detected as itself, not resolved
	// through to its target. A planted symlink in cfg.Dir (e.g. the
	// world-writable /tmp) must not be able to redirect the read to an
	// arbitrary file.
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// The sidecar file is absent for this session — used only when
			// present, per the interface contract. Decline, do not error.
			return Identity{}, ErrNoIdentity
		}
		return Identity{}, fmt.Errorf("attestation: stat sidecar identity file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		// Symlink, device, socket, etc. — refuse rather than follow.
		return Identity{}, fmt.Errorf("attestation: sidecar identity path %q is not a regular file", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Identity{}, ErrNoIdentity
		}
		return Identity{}, fmt.Errorf("attestation: read sidecar identity file %q: %w", path, err)
	}

	if p.cfg.IdentityField != "" {
		// Structured-record path (lr-f1bfe8): parse the file and read the
		// named field, rather than treating the whole file as the subject.
		// A malformed/incomplete structured record is a hard failure, not
		// ErrNoIdentity — the file IS present, it just does not satisfy the
		// structured-sidecar contract this entry opted into.
		return parseStructuredSidecar(path, p.cfg.IdentityField, data)
	}

	v := strings.TrimSpace(string(data))
	if v == "" {
		return Identity{}, ErrNoIdentity
	}
	return Identity{Subject: v, Source: "sidecar"}, nil
}

// isSafePathSegment reports whether s is safe to use as a single path
// component: non-empty, no path separators (either OS form), and not the
// "." or ".." special names. A session ID is an opaque identifier, never a
// path — this rejects anything that could traverse out of cfg.Dir.
func isSafePathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	if strings.ContainsRune(s, '/') || strings.ContainsRune(s, '\\') {
		return false
	}
	// filepath.Clean does not change a genuine single segment; if it does,
	// the input encoded something path-like our explicit checks missed.
	if filepath.Clean(s) != s {
		return false
	}
	return true
}

// requireContained verifies that target, once resolved, is a direct child
// of dir — not a path that escapes dir via "..", a symlinked ancestor
// component, or an absolute path substitution. Both paths are cleaned
// before comparison.
func requireContained(dir, target string) error {
	cleanDir := filepath.Clean(dir)
	cleanTarget := filepath.Clean(target)

	rel, err := filepath.Rel(cleanDir, cleanTarget)
	if err != nil {
		return fmt.Errorf("compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("path %q escapes directory %q", cleanTarget, cleanDir)
	}
	// The sidecar filename must be a single path component directly under
	// dir — reject anything that resolved to a nested path.
	if strings.ContainsRune(rel, filepath.Separator) {
		return fmt.Errorf("path %q is not a direct child of %q", cleanTarget, cleanDir)
	}
	return nil
}
