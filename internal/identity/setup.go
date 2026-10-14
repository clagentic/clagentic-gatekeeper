package identity

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// Settings is everything NewIssuer needs, already resolved from config and
// flags.
type Settings struct {
	Issuer         string
	SocketPath     string
	KeyPath        string
	Alg            string
	JWKSPath       string
	OperatorUID    *uint32
	OperatorName   string
	OperatorRoles  []string
	RuntimeRoles   []string
	DefinitionsDir string
	DelegableRoles []string
	SpawnRoot      string
	SessionTTL     time.Duration
}

// NewIssuer validates s, loads the keys, prepares the spawn root and returns
// a ready Issuer.
func NewIssuer(s Settings) (*Issuer, error) {
	if s.KeyPath == "" {
		return nil, errors.New("identity.key_path is required to serve")
	}
	if !filepath.IsAbs(s.SocketPath) {
		return nil, fmt.Errorf("socket path %q must be absolute", s.SocketPath)
	}
	ttl := s.SessionTTL
	if ttl == 0 {
		ttl = MaxLifetimeSeconds * time.Second
	}
	if ttl < time.Minute || ttl > MaxLifetimeSeconds*time.Second {
		return nil, fmt.Errorf("identity.session_ttl_seconds must be between 60 and %d", MaxLifetimeSeconds)
	}
	for _, list := range [][]string{s.OperatorRoles, s.RuntimeRoles, s.DelegableRoles} {
		for _, r := range list {
			if !reRole.MatchString(r) {
				return nil, fmt.Errorf("role %q does not match %s", r, reRole)
			}
		}
	}
	name := s.OperatorName
	if name == "" && s.OperatorUID != nil {
		u, err := user.LookupId(strconv.FormatUint(uint64(*s.OperatorUID), 10))
		if err != nil {
			return nil, fmt.Errorf("identity.operator_name is unset and uid %d has no account name: %w", *s.OperatorUID, err)
		}
		name = u.Username
	}
	if s.OperatorUID != nil && !reName.MatchString(name) {
		return nil, fmt.Errorf("operator name %q does not match %s", name, reName)
	}
	root := s.SpawnRoot
	if root == "" {
		root = filepath.Join(filepath.Dir(s.SocketPath), "spawn")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("identity.spawn_root %q must be absolute", root)
	}
	keys, err := LoadKeyring(s.KeyPath, s.Alg)
	if err != nil {
		return nil, err
	}
	issuer := s.Issuer
	if issuer == "" {
		issuer = "unix://" + s.SocketPath
	}
	dirs := SpawnDirs{Root: filepath.Clean(root)}
	if err := dirs.Ensure(); err != nil {
		return nil, fmt.Errorf("spawn root: %w", err)
	}
	return &Issuer{
		Issuer: issuer, Keys: keys, Defs: Definitions{Dir: s.DefinitionsDir}, Dirs: dirs,
		Registry: NewRegistry(), Proc: ReadProc, Now: time.Now,
		OperatorUID: s.OperatorUID, OperatorName: name,
		OperatorRoles: s.OperatorRoles, RuntimeRoles: s.RuntimeRoles,
		DelegableRoles: s.DelegableRoles, SessionTTL: ttl,
	}, nil
}

// WriteJWKS publishes the key set at path atomically, readable by everyone.
func (k *Keyring) WriteJWKS(path string) error {
	body, err := k.MarshalJWKS()
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".jwks-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
