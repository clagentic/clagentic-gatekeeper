// Package config loads and validates gatekeeper's config.yaml. It is the
// single point of entry for deployment-specific values — no other package
// reads files or env vars for config.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	defaultAPIBase    = "https://api.github.com"
	defaultTTLMinutes = 60
)

// Config is the top-level configuration structure for gatekeeper.
type Config struct {
	// SchemaVersion is an informational marker of the config.yaml shape a
	// deployment was authored against (see config.example.yaml). Gatekeeper
	// does not currently reject an unset or mismatched value — every field
	// added to the schema so far (including identity_field, lr-f1bfe8) is
	// additive and optional, so an old config.yaml keeps loading and
	// behaving exactly as before. This field exists so that stops being
	// true for a future breaking change: Load has one place to add a
	// version check.
	SchemaVersion int                   `yaml:"config_schema_version,omitempty"`
	GitHub        GitHubConfig          `yaml:"github"`
	Broker        BrokerConfig          `yaml:"broker"`
	Token         TokenConfig           `yaml:"token"`
	Roles         map[string]RoleConfig `yaml:"roles"`
	Attestation   AttestationConfig     `yaml:"attestation"`
}

// GitHubConfig holds GitHub connectivity settings.
type GitHubConfig struct {
	// Owner is the org or user login that owns the target repositories.
	Owner string `yaml:"owner"`
	// APIBase is the GitHub API root. Defaults to https://api.github.com.
	// Override for GitHub Enterprise Server.
	APIBase string `yaml:"api_base"`
}

// BrokerConfig selects and configures the secret broker.
type BrokerConfig struct {
	// Type is one of: "openbao", "vault", "env", "file".
	Type string `yaml:"type"`
	// Endpoint is the broker URL. Ignored for type env and file.
	Endpoint string `yaml:"endpoint"`
	// Auth is the auth method: "approle" or "token". Ignored for env and file.
	Auth string `yaml:"auth"`
}

// TokenConfig governs minted token policy.
type TokenConfig struct {
	// TTLMinutes is the requested installation token lifetime. GitHub caps at 60.
	TTLMinutes int `yaml:"ttl_minutes"`
}

// AttestationConfig selects and configures the attestation-provider chain
// (internal/attestation) that resolves the ATTESTED invoking identity. All
// layers are optional in config: an unconfigured layer is omitted from the
// chain rather than assumed, and the built-in fallback (layer c) requires
// no config at all — see internal/attestation for the resolution order and
// rationale.
type AttestationConfig struct {
	// Configured selects layer (a): a deployment's own identity source.
	Configured AttestationConfiguredConfig `yaml:"configured"`
	// Sidecar configures a single layer (b) crew-sidecar adapter. Retained
	// for back-compat with single-sidecar deployments; a deployment with
	// exactly one sidecar namespace may use this block instead of Sidecars.
	// If both Sidecar and Sidecars are set, Sidecar is tried first (see
	// Resolve). Used only when fully configured and only when its file is
	// present at resolve time — never assumed to exist.
	Sidecar AttestationSidecarConfig `yaml:"sidecar"`
	// Sidecars configures an ordered list of layer (b) crew-sidecar
	// adapters, for deployments that resolve identity from more than one
	// independent sidecar namespace (e.g. a per-session namespace for a
	// lead process and a per-spawn namespace for its subagents). Resolved
	// in list order; the first entry whose file is present wins.
	Sidecars []AttestationSidecarConfig `yaml:"sidecars"`
}

// ResolveSidecars returns the effective ordered list of sidecar layer (b)
// configs: the legacy single Sidecar block (when set) followed by the
// Sidecars list. This is the one place the Sidecar/Sidecars back-compat
// merge happens, so callers (cmd/gatekeeper) never need to know about the
// legacy field.
func (a AttestationConfig) ResolveSidecars() []AttestationSidecarConfig {
	var out []AttestationSidecarConfig
	if a.Sidecar.enabled() {
		out = append(out, a.Sidecar)
	}
	out = append(out, a.Sidecars...)
	return out
}

// AttestationConfiguredConfig configures layer (a) of the attestation
// chain. Type is "env" or "file"; empty disables this layer.
type AttestationConfiguredConfig struct {
	// Type selects the provider implementation: "env" | "file". Empty
	// disables the configured provider.
	Type string `yaml:"type"`
	// Source is the env var name (Type: env) or file path (Type: file)
	// to read the attested identity from.
	Source string `yaml:"source"`
}

// AttestationSidecarConfig configures layer (b) of the attestation chain,
// the crew-sidecar adapter. All three fields are required together; a
// partially configured sidecar is treated as disabled.
type AttestationSidecarConfig struct {
	// Dir is the directory the sidecar writes its identity file into.
	Dir string `yaml:"dir"`
	// FilePrefix is the filename prefix before the session ID.
	FilePrefix string `yaml:"file_prefix"`
	// SessionIDEnv names the environment variable holding the current
	// session ID, used to build the sidecar filename.
	SessionIDEnv string `yaml:"session_id_env"`
	// IdentityField is OPTIONAL and PER-ENTRY (lr-f1bfe8). When unset, this
	// entry preserves the original whole-file-as-subject behavior exactly.
	// When set, the sidecar file for this entry is parsed as a structured
	// (JSON or YAML) object and the named field is read as Identity.Subject;
	// the remaining recognized attribution fields (parent_session_id,
	// spawn_id, agent_type, spawned_at) are captured for audit onto the
	// resolved Identity. See internal/attestation/structured_sidecar.go.
	IdentityField string `yaml:"identity_field,omitempty"`
}

// enabled reports whether cfg has enough information to be a usable sidecar
// entry. All three fields are required together; a partially configured
// entry is treated as disabled rather than guessed at — mirrors
// internal/attestation.SidecarConfig.enabled().
func (cfg AttestationSidecarConfig) enabled() bool {
	return cfg.Dir != "" && cfg.FilePrefix != "" && cfg.SessionIDEnv != ""
}

// RoleConfig binds a role name to broker paths for its GitHub App credentials.
// Permissions is optional; when set it overrides the reference permission set
// for that role name.
//
// Two mint-time gates are configured here (tome #700, layer (2)->(3)):
//
//  1. Entitlement: EntitledIdentities lists the attested invoking identities
//     (internal/attestation) allowed to mint this role. An identity not in
//     this list — or an empty list — is fail-closed: Mint refuses rather
//     than assuming an unconfigured role is open to everyone.
//  2. Verifiable App-slug binding: AppSlug is the App slug this role is
//     legitimately bound to, and AppSlugPath is the broker path holding the
//     ACTUAL slug of the App the broker paths above resolve to. Mint reads
//     both and requires they match — this is the safeguard against the
//     lr-e41f class of bug (a role's broker paths silently resolving to the
//     wrong App installation). A role missing either half of this pair fails
//     closed rather than skipping the check.
type RoleConfig struct {
	AppIDPath          string            `yaml:"app_id_path"`
	InstallationIDPath string            `yaml:"installation_id_path"`
	PrivateKeyPath     string            `yaml:"private_key_path"`
	Permissions        map[string]string `yaml:"permissions,omitempty"`

	// EntitledIdentities is the set of attested identities (internal/attestation
	// Identity.Subject values) permitted to mint this role. No identity is
	// entitled by default — an empty or absent list fails closed.
	EntitledIdentities []string `yaml:"entitled_identities,omitempty"`

	// AppSlug is the expected GitHub App slug this role's broker-resolved App
	// must match. Required together with AppSlugPath to enable the App-slug
	// verification gate; a role that sets one without the other fails closed
	// at mint time rather than silently skipping verification.
	AppSlug string `yaml:"app_slug,omitempty"`

	// AppSlugPath is the broker path holding the actual slug of the App the
	// role's AppIDPath/InstallationIDPath/PrivateKeyPath resolve to. Read
	// at mint time and compared against AppSlug.
	AppSlugPath string `yaml:"app_slug_path,omitempty"`
}

// Load reads path, unmarshals it as YAML, applies defaults, and returns the
// parsed Config. It returns a clear error if the file is missing or malformed.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

// applyDefaults fills in zero-value fields with their documented defaults.
func applyDefaults(cfg *Config) {
	if cfg.GitHub.APIBase == "" {
		cfg.GitHub.APIBase = defaultAPIBase
	}
	if cfg.Token.TTLMinutes == 0 {
		cfg.Token.TTLMinutes = defaultTTLMinutes
	}
}
