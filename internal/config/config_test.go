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
    entitled_identities:
      - crew-agent-amos
      - crew-agent-naomi
    app_slug: clagentic-builder
    app_slug_path: secret/gk/builder/app-slug
  custom:
    app_id_path: secret/gk/custom/app-id
    installation_id_path: secret/gk/custom/install-id
    private_key_path: secret/gk/custom/key
    permissions:
      contents: write
      issues: read

attestation:
  configured:
    type: env
    source: GATEKEEPER_ATTESTED_IDENTITY
  sidecar:
    dir: /tmp
    file_prefix: lore-agent-name-
    session_id_env: LORE_SESSION_ID
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
	wantEntitled := []string{"crew-agent-amos", "crew-agent-naomi"}
	if len(builder.EntitledIdentities) != len(wantEntitled) {
		t.Fatalf("builder.EntitledIdentities = %v, want %v", builder.EntitledIdentities, wantEntitled)
	}
	for i, want := range wantEntitled {
		if builder.EntitledIdentities[i] != want {
			t.Errorf("builder.EntitledIdentities[%d] = %q, want %q", i, builder.EntitledIdentities[i], want)
		}
	}
	if builder.AppSlug != "clagentic-builder" {
		t.Errorf("builder.AppSlug = %q, want %q", builder.AppSlug, "clagentic-builder")
	}
	if builder.AppSlugPath != "secret/gk/builder/app-slug" {
		t.Errorf("builder.AppSlugPath = %q, want %q", builder.AppSlugPath, "secret/gk/builder/app-slug")
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
	// "custom" declares no entitlement or App-slug settings — the schema
	// leaves both optional-with-safe-default (zero value), and it is
	// internal/mint's job to fail closed on the zero value rather than
	// config assuming a default that opens access.
	if len(custom.EntitledIdentities) != 0 {
		t.Errorf("custom.EntitledIdentities = %v, want empty (not declared in config)", custom.EntitledIdentities)
	}
	if custom.AppSlug != "" || custom.AppSlugPath != "" {
		t.Errorf("custom.AppSlug/AppSlugPath = %q/%q, want both empty (not declared in config)", custom.AppSlug, custom.AppSlugPath)
	}

	if cfg.Attestation.Configured.Type != "env" {
		t.Errorf("Attestation.Configured.Type = %q, want %q", cfg.Attestation.Configured.Type, "env")
	}
	if cfg.Attestation.Configured.Source != "GATEKEEPER_ATTESTED_IDENTITY" {
		t.Errorf("Attestation.Configured.Source = %q, want %q", cfg.Attestation.Configured.Source, "GATEKEEPER_ATTESTED_IDENTITY")
	}
	if cfg.Attestation.Sidecar.Dir != "/tmp" {
		t.Errorf("Attestation.Sidecar.Dir = %q, want %q", cfg.Attestation.Sidecar.Dir, "/tmp")
	}
	if cfg.Attestation.Sidecar.FilePrefix != "lore-agent-name-" {
		t.Errorf("Attestation.Sidecar.FilePrefix = %q, want %q", cfg.Attestation.Sidecar.FilePrefix, "lore-agent-name-")
	}
	if cfg.Attestation.Sidecar.SessionIDEnv != "LORE_SESSION_ID" {
		t.Errorf("Attestation.Sidecar.SessionIDEnv = %q, want %q", cfg.Attestation.Sidecar.SessionIDEnv, "LORE_SESSION_ID")
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
	// attestation omitted entirely → zero-value config, meaning both
	// configurable layers are disabled and a bare install relies solely on
	// the attestation package's built-in fallback (see internal/attestation).
	if cfg.Attestation.Configured.Type != "" {
		t.Errorf("Attestation.Configured.Type = %q, want %q (default, disabled)", cfg.Attestation.Configured.Type, "")
	}
	if cfg.Attestation.Sidecar.Dir != "" {
		t.Errorf("Attestation.Sidecar.Dir = %q, want %q (default, disabled)", cfg.Attestation.Sidecar.Dir, "")
	}

	if cfg.Token.TTLMinutes != defaultTTLMinutes {
		t.Errorf("Token.TTLMinutes = %d, want %d (default)", cfg.Token.TTLMinutes, defaultTTLMinutes)
	}
}

func TestLoad_SidecarsList(t *testing.T) {
	path := writeTemp(t, `
github:
  owner: myorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: /tmp
      file_prefix: lore-agent-name-
      session_id_env: CLAUDE_CODE_SESSION_ID
    - dir: /tmp
      file_prefix: spawn-
      session_id_env: MY_HARNESS_SPAWN_ID
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if len(cfg.Attestation.Sidecars) != 2 {
		t.Fatalf("Attestation.Sidecars = %+v, want 2 entries", cfg.Attestation.Sidecars)
	}
	if cfg.Attestation.Sidecars[0].FilePrefix != "lore-agent-name-" {
		t.Errorf("Sidecars[0].FilePrefix = %q, want %q", cfg.Attestation.Sidecars[0].FilePrefix, "lore-agent-name-")
	}
	if cfg.Attestation.Sidecars[1].FilePrefix != "spawn-" {
		t.Errorf("Sidecars[1].FilePrefix = %q, want %q", cfg.Attestation.Sidecars[1].FilePrefix, "spawn-")
	}

	resolved := cfg.Attestation.ResolveSidecars()
	if len(resolved) != 2 {
		t.Fatalf("ResolveSidecars() = %+v, want 2 entries (no legacy sidecar block set)", resolved)
	}
	if resolved[0].SessionIDEnv != "CLAUDE_CODE_SESSION_ID" {
		t.Errorf("ResolveSidecars()[0].SessionIDEnv = %q, want %q", resolved[0].SessionIDEnv, "CLAUDE_CODE_SESSION_ID")
	}
}

// TestAttestationConfig_ResolveSidecars_BackCompat verifies the back-compat
// merge: a deployment still using the legacy singular `sidecar:` block gets
// it as the first entry, ahead of any entries in the `sidecars:` list.
func TestAttestationConfig_ResolveSidecars_BackCompat(t *testing.T) {
	cfg := AttestationConfig{
		Sidecar: AttestationSidecarConfig{
			Dir:          "/tmp",
			FilePrefix:   "legacy-",
			SessionIDEnv: "LEGACY_SESSION_ID",
		},
		Sidecars: []AttestationSidecarConfig{
			{Dir: "/tmp", FilePrefix: "new-", SessionIDEnv: "NEW_SESSION_ID"},
		},
	}

	resolved := cfg.ResolveSidecars()
	if len(resolved) != 2 {
		t.Fatalf("ResolveSidecars() = %+v, want 2 entries", resolved)
	}
	if resolved[0].FilePrefix != "legacy-" {
		t.Errorf("ResolveSidecars()[0].FilePrefix = %q, want %q (legacy block first)", resolved[0].FilePrefix, "legacy-")
	}
	if resolved[1].FilePrefix != "new-" {
		t.Errorf("ResolveSidecars()[1].FilePrefix = %q, want %q", resolved[1].FilePrefix, "new-")
	}
}

// TestAttestationConfig_ResolveSidecars_PartialLegacyBlockOmitted verifies
// that a partially configured legacy `sidecar:` block (not all three fields
// set) is treated as disabled and omitted from the merged list, matching
// the existing single-sidecar "all or nothing" semantics.
func TestAttestationConfig_ResolveSidecars_PartialLegacyBlockOmitted(t *testing.T) {
	cfg := AttestationConfig{
		Sidecar: AttestationSidecarConfig{
			Dir: "/tmp",
			// FilePrefix and SessionIDEnv left empty.
		},
	}

	resolved := cfg.ResolveSidecars()
	if len(resolved) != 0 {
		t.Errorf("ResolveSidecars() = %+v, want empty (partial legacy block must be omitted)", resolved)
	}
}

// TestLoad_SidecarsList_IdentityField verifies identity_field parses as an
// OPTIONAL, PER-ENTRY setting (lr-f1bfe8): one entry sets it, the other
// omits it, and both are preserved independently through ResolveSidecars.
func TestLoad_SidecarsList_IdentityField(t *testing.T) {
	path := writeTemp(t, `
github:
  owner: myorg

broker:
  type: env

roles: {}

attestation:
  sidecars:
    - dir: /tmp
      file_prefix: spawn-
      session_id_env: MY_HARNESS_SPAWN_ID
      identity_field: attested_name
    - dir: /tmp
      file_prefix: lore-agent-name-
      session_id_env: CLAUDE_CODE_SESSION_ID
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	resolved := cfg.Attestation.ResolveSidecars()
	if len(resolved) != 2 {
		t.Fatalf("ResolveSidecars() = %+v, want 2 entries", resolved)
	}
	if resolved[0].IdentityField != "attested_name" {
		t.Errorf("ResolveSidecars()[0].IdentityField = %q, want %q", resolved[0].IdentityField, "attested_name")
	}
	if resolved[1].IdentityField != "" {
		t.Errorf("ResolveSidecars()[1].IdentityField = %q, want empty (per-entry, not set for this entry)", resolved[1].IdentityField)
	}
}

// TestLoad_ExampleConfigParses guards against config.example.yaml drifting
// out of sync with the schema (e.g. a future field rename breaking the
// shipped reference file silently, since Load does not reject unknown
// keys). Also asserts the lr-f1bfe8/lr-2ca216 schema-version bump and the
// structured-sidecar example this PR adds are both present and load
// correctly.
func TestLoad_ExampleConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) returned error: %v", path, err)
	}
	if cfg.SchemaVersion != 2 {
		t.Errorf("SchemaVersion = %d, want 2", cfg.SchemaVersion)
	}

	resolved := cfg.Attestation.ResolveSidecars()
	if len(resolved) != 2 {
		t.Fatalf("ResolveSidecars() = %+v, want 2 entries", resolved)
	}
	if resolved[0].IdentityField != "" {
		t.Errorf("ResolveSidecars()[0].IdentityField = %q, want empty (whole-file example entry)", resolved[0].IdentityField)
	}
	if resolved[1].IdentityField != "attested_name" {
		t.Errorf("ResolveSidecars()[1].IdentityField = %q, want %q (structured example entry)", resolved[1].IdentityField, "attested_name")
	}

	// lr-0ae541: the shipped example's a2a_mapping stanza is commented out —
	// the reference config must load with A2AMapping empty, proving the
	// stanza is genuinely additive/off-by-default rather than merely
	// documented as such.
	if len(cfg.A2AMapping) != 0 {
		t.Errorf("A2AMapping = %v, want empty (example stanza is commented out)", cfg.A2AMapping)
	}
}

// TestLoad_A2AMapping verifies the OPTIONAL a2a_mapping stanza (lr-0ae541)
// parses identity -> {role, audiences} entries.
func TestLoad_A2AMapping(t *testing.T) {
	path := writeTemp(t, `
github:
  owner: myorg

broker:
  type: env

roles: {}

a2a_mapping:
  peer-agent-alpha:
    role: peer-builder
    audiences:
      - peer-project-x
      - peer-project-y
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	ent, ok := cfg.A2AMapping["peer-agent-alpha"]
	if !ok {
		t.Fatal("A2AMapping[peer-agent-alpha] not found")
	}
	if ent.Role != "peer-builder" {
		t.Errorf("A2AMapping[peer-agent-alpha].Role = %q, want %q", ent.Role, "peer-builder")
	}
	wantAudiences := []string{"peer-project-x", "peer-project-y"}
	if len(ent.Audiences) != len(wantAudiences) {
		t.Fatalf("A2AMapping[peer-agent-alpha].Audiences = %v, want %v", ent.Audiences, wantAudiences)
	}
	for i, want := range wantAudiences {
		if ent.Audiences[i] != want {
			t.Errorf("A2AMapping[peer-agent-alpha].Audiences[%d] = %q, want %q", i, ent.Audiences[i], want)
		}
	}
}

// TestLoad_A2AMappingAbsent verifies AC 4's config-shape half: a config with
// no a2a_mapping stanza at all loads with a nil/empty A2AMapping, matching
// the fail-closed default a2apolicy.NewPolicy expects for "no A2A mapping
// configured."
func TestLoad_A2AMappingAbsent(t *testing.T) {
	path := writeTemp(t, `
github:
  owner: myorg

broker:
  type: env

roles: {}
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.A2AMapping) != 0 {
		t.Errorf("A2AMapping = %v, want empty (stanza not configured)", cfg.A2AMapping)
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
