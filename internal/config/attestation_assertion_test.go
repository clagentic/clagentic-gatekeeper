package config

import (
	"os"
	"path/filepath"
	"testing"
)

func loadYAML(t *testing.T, body string) *Config {
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

func TestAssertionAbsentByDefaultAndOSUserOn(t *testing.T) {
	cfg := loadYAML(t, "broker:\n  type: env\n")
	if cfg.Attestation.Assertion != nil {
		t.Error("assertion is configured without an attestation.assertion section")
	}
	if !cfg.Attestation.OSUserAllowed() {
		t.Error("the OS-user provider must stay on when allow_os_user is unset")
	}
}

func TestAssertionEmptyMappingEnablesLocalOnly(t *testing.T) {
	cfg := loadYAML(t, "attestation:\n  assertion: {}\n")
	if cfg.Attestation.Assertion == nil || len(cfg.Attestation.Assertion.Issuers) != 0 {
		t.Errorf("assertion = %+v, want enabled with no extra issuers", cfg.Attestation.Assertion)
	}
}

func TestAssertionIssuersAndAllowOSUserParse(t *testing.T) {
	cfg := loadYAML(t, `
attestation:
  allow_os_user: false
  assertion:
    issuers:
      - iss: https://issuer.example
      - iss: urn:example:other
        jwks: /etc/example/jwks.json
roles:
  merger:
    min_grade: workload
`)
	if cfg.Attestation.OSUserAllowed() {
		t.Error("allow_os_user: false was not honoured")
	}
	is := cfg.Attestation.Assertion.Issuers
	if len(is) != 2 || is[0].Iss != "https://issuer.example" || is[1].JWKS != "/etc/example/jwks.json" {
		t.Errorf("issuers = %+v", is)
	}
	if cfg.Roles["merger"].MinGrade != "workload" {
		t.Errorf("min_grade = %q", cfg.Roles["merger"].MinGrade)
	}
}
