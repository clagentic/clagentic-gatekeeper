package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadIdentity(t *testing.T, body string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestIdentityDelegableRolesAbsentVersusEmpty(t *testing.T) {
	absent := loadIdentity(t, "identity:\n  key_path: /k\n")
	if absent.Identity.DelegableRoles != nil {
		t.Fatalf("absent delegable_roles should be nil (all delegable), got %#v", absent.Identity.DelegableRoles)
	}
	empty := loadIdentity(t, "identity:\n  key_path: /k\n  delegable_roles: []\n")
	if empty.Identity.DelegableRoles == nil || len(empty.Identity.DelegableRoles) != 0 {
		t.Fatalf("empty delegable_roles should be non-nil and empty (none delegable), got %#v", empty.Identity.DelegableRoles)
	}
}

func TestIdentityOnlyConfigLoads(t *testing.T) {
	cfg := loadIdentity(t, "identity:\n  key_path: /k\n  operator_uid: 1000\n")
	if !cfg.Identity.Enabled() || cfg.Identity.OperatorUID == nil || *cfg.Identity.OperatorUID != 1000 {
		t.Fatalf("%+v", cfg.Identity)
	}
	if len(cfg.Roles) != 0 {
		t.Fatalf("roles appeared from nowhere: %v", cfg.Roles)
	}
	if loadIdentity(t, "github:\n  owner: example-org\n").Identity.Enabled() {
		t.Fatal("identity enabled without a section")
	}
}
