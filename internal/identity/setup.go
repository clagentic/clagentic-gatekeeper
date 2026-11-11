//go:build linux

package identity

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
)

// Settings is everything NewIssuer needs, already resolved from config and
// flags.
type Settings struct {
	Issuer         string
	SocketPath     string
	KeyPath        string
	Alg            string
	JWKSPath       string
	RuntimeRoles   []string
	DefinitionsDir string
	DelegableRoles []string
	SpawnRoot      string
	SessionTTL     time.Duration
	// HelperExe is the path of the gatekeeper client binary; see Issuer.HelperExe.
	HelperExe string
	// RetiredKeys are previous signing keys published beside the current one;
	// see LoadKeyringRetired.
	RetiredKeys []JWK
}

// NewIssuer validates s, verifies every trust root it names (signing key,
// definitions, socket directory, key set directory, spawn root), loads the keys
// and returns a ready Issuer. Any root another uid could write to refuses the
// start and names the path; nothing is published first.
func NewIssuer(s Settings) (*Issuer, error) {
	if s.KeyPath == "" {
		return nil, errors.New("identity.key_path is required to serve")
	}
	// The length limit is enforced where the path is bound (Listen) and where it
	// is named (config load, the socket flags); a Settings that only derives the
	// default issuer and spawn root from it is not bound here.
	if err := config.CheckAbsPath("socket path", s.SocketPath); err != nil {
		return nil, err
	}
	if s.SocketPath == "" {
		return nil, errors.New("socket path is empty")
	}
	ttl := s.SessionTTL
	if ttl == 0 {
		ttl = MaxLifetimeSeconds * time.Second
	}
	if ttl < time.Minute || ttl > MaxLifetimeSeconds*time.Second {
		return nil, fmt.Errorf("identity.session_ttl_seconds must be between 60 and %d", MaxLifetimeSeconds)
	}
	for _, list := range [][]string{s.RuntimeRoles, s.DelegableRoles} {
		for _, r := range list {
			if !reRole.MatchString(r) {
				return nil, fmt.Errorf("role %q does not match %s", r, reRole)
			}
		}
	}
	root := s.SpawnRoot
	if root == "" {
		root = filepath.Join(filepath.Dir(s.SocketPath), "spawn")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("identity.spawn_root %q must be absolute", root)
	}

	keys, err := LoadKeyringRetired(s.KeyPath, s.Alg, s.RetiredKeys)
	if err != nil {
		return nil, err
	}
	// The socket and key set directories are verified now so a bad one stops the
	// start before anything is created; Listen and WriteJWKS verify again at use.
	sockDir, err := openTrustedDir(filepath.Dir(s.SocketPath), 0o755)
	if err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}
	sockDir.Close()
	if s.JWKSPath != "" {
		jwksDir, err := openTrustedDir(filepath.Dir(s.JWKSPath), 0)
		if err != nil {
			return nil, fmt.Errorf("identity.jwks_path directory: %w", err)
		}
		jwksDir.Close()
	}
	defs, err := NewDefinitions(s.DefinitionsDir)
	if err != nil {
		return nil, err
	}
	dirs, err := NewSpawnDirs(filepath.Clean(root))
	if err != nil {
		defs.Close()
		return nil, err
	}
	issuer := s.Issuer
	if issuer == "" {
		issuer = "unix://" + s.SocketPath
	}
	return &Issuer{
		Issuer: issuer, Keys: keys, Defs: defs, Dirs: dirs,
		Registry: NewRegistry(), Proc: ReadProc, Now: time.Now,
		RuntimeRoles:   s.RuntimeRoles,
		DelegableRoles: s.DelegableRoles, SessionTTL: ttl, HelperExe: s.HelperExe,
	}, nil
}

// WriteJWKS publishes the key set at path atomically, readable by everyone. The
// directory is a trust root; the temporary file is created in it relative to the
// directory handle and renamed over path with the same handle.
func (k *Keyring) WriteJWKS(path string) error {
	body, err := k.MarshalJWKS()
	if err != nil {
		return err
	}
	dir, err := openTrustedDir(filepath.Dir(path), 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	// The bytes are written as they are served, with no trailing newline, so
	// the file and the socket answer can be compared byte for byte.
	return publishFileAt(int(dir.Fd()), filepath.Base(path), body, 0o644, true)
}
