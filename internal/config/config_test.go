package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return p
}

func TestLoad_FullConfig(t *testing.T) {
	path := writeTemp(t, `
github:
  owner: myorg
  api_base: https://api.example.com

broker:
  type: openbao
  endpoint: https://bao.example.com
  auth: approle

token:
  ttl_minutes: 30

roles:
  builder:
    app_id_path: secret/gk/builder/app-id
    installation_id_path: secret/gk/builder/install-id
    private_key_path: secret/gk/builder/key
  custom:
    app_id_path: secret/gk/custom/app-id
    installation_id_path: secret/gk/custom/install-id
    private_key_path: secret/gk/custom/key
    permissions:
      contents: write
      issues: read
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.GitHub.Owner != "myorg" {
		t.Errorf("GitHub.Owner = %q, want %q", cfg.GitHub.Owner, "myorg")
	}
	if cfg.GitHub.APIBase != "https://api.example.com" {
		t.Errorf("GitHub.APIBase = %q, want %q", cfg.GitHub.APIBase, "https://api.example.com")
	}
	if cfg.Broker.Type != "openbao" {
		t.Errorf("Broker.Type = %q, want %q", cfg.Broker.Type, "openbao")
	}
	if cfg.Broker.Endpoint != "https://bao.example.com" {
		t.Errorf("Broker.Endpoint = %q, want %q", cfg.Broker.Endpoint, "https://bao.example.com")
	}
	if cfg.Broker.Auth != "approle" {
		t.Errorf("Broker.Auth = %q, want %q", cfg.Broker.Auth, "approle")
	}
	if cfg.Token.TTLMinutes != 30 {
		t.Errorf("Token.TTLMinutes = %d, want 30", cfg.Token.TTLMinutes)
	}

	builder, ok := cfg.Roles["builder"]
	if !ok {
		t.Fatal("Roles[builder] not found")
	}
	if builder.AppIDPath != "secret/gk/builder/app-id" {
		t.Errorf("builder.AppIDPath = %q, want %q", builder.AppIDPath, "secret/gk/builder/app-id")
	}
	if builder.InstallationIDPath != "secret/gk/builder/install-id" {
		t.Errorf("builder.InstallationIDPath = %q, want %q", builder.InstallationIDPath, "secret/gk/builder/install-id")
	}
	if builder.PrivateKeyPath != "secret/gk/builder/key" {
		t.Errorf("builder.PrivateKeyPath = %q, want %q", builder.PrivateKeyPath, "secret/gk/builder/key")
	}

	custom, ok := cfg.Roles["custom"]
	if !ok {
		t.Fatal("Roles[custom] not found")
	}
	if custom.Permissions["contents"] != "write" {
		t.Errorf("custom.Permissions[contents] = %q, want %q", custom.Permissions["contents"], "write")
	}
	if custom.Permissions["issues"] != "read" {
		t.Errorf("custom.Permissions[issues] = %q, want %q", custom.Permissions["issues"], "read")
	}
}

func TestLoad_Defaults(t *testing.T) {
	// api_base omitted → defaults to https://api.github.com
	// ttl_minutes omitted → defaults to 60
	path := writeTemp(t, `
github:
  owner: testorg

broker:
  type: env

roles: {}
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.GitHub.APIBase != defaultAPIBase {
		t.Errorf("GitHub.APIBase = %q, want %q (default)", cfg.GitHub.APIBase, defaultAPIBase)
	}
	if cfg.Token.TTLMinutes != defaultTTLMinutes {
		t.Errorf("Token.TTLMinutes = %d, want %d (default)", cfg.Token.TTLMinutes, defaultTTLMinutes)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, "not: valid: yaml: [unclosed")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}
