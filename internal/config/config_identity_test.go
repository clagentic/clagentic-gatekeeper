package config

import (
	"os"
	"path/filepath"
	"strings"
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

func TestIdentityWrittenPathsMustBeAbsoluteAndNameTheKey(t *testing.T) {
	for _, key := range []string{"socket_path", "jwks_path", "spawn_root"} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(p, []byte("identity:\n  key_path: /k\n  "+key+": relative/dir\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), "identity."+key) || !strings.Contains(err.Error(), "absolute") {
			t.Errorf("%s: got %v", key, err)
		}
	}
	loadIdentity(t, "identity:\n  key_path: /k\n  socket_path: /run/x.sock\n  jwks_path: /var/j.json\n  spawn_root: /run/spawn\n")
}

func TestIdentityAllowListParsesAndIsAbsentByDefault(t *testing.T) {
	cfg := loadIdentity(t, "identity:\n  key_path: /k\n  allowed_uids: [1001, 1002]\n  allowed_gids: [2000]\n")
	if got := cfg.Identity.AllowedUIDs; len(got) != 2 || got[0] != 1001 || got[1] != 1002 {
		t.Fatalf("allowed_uids %v", got)
	}
	if got := cfg.Identity.AllowedGIDs; len(got) != 1 || got[0] != 2000 {
		t.Fatalf("allowed_gids %v", got)
	}
	absent := loadIdentity(t, "identity:\n  key_path: /k\n")
	if absent.Identity.AllowedUIDs != nil || absent.Identity.AllowedGIDs != nil {
		t.Fatalf("an absent allow-list is not empty: %+v", absent.Identity)
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
