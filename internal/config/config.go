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
	// A2AMapping is the OPTIONAL A2A caller entitlement mapping
	// (attested identity -> caller role -> permitted peer audiences,
	// lr-0ae541). Absent/empty means no A2A mapping is configured at all:
	// the A2A mint path (built on internal/a2apolicy) refuses every
	// request, and every existing GitHub-domain mint (internal/mint) is
	// entirely unaffected — this stanza is additive and off by default.
	A2AMapping map[string]A2AEntitlementConfig `yaml:"a2a_mapping,omitempty"`
	// A2AProvider is the OPTIONAL A2A token-provider configuration
	// (lr-890fae): the OpenBao B3 attest-and-route issuance surface this
	// mapping's permitted requests are brokered through. Absent/zero-value
	// means the A2A provider is not configured at all — the A2A mint
	// command refuses with a clear config error, and every existing
	// GitHub-domain mint (internal/mint) is entirely unaffected. Additive,
	// off by default.
	A2AProvider A2AProviderConfig `yaml:"a2a_provider,omitempty"`
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

// validate rejects a deployment that configures BOTH the legacy singular
// `sidecar:` block and the `sidecars:` list.
//
// ResolveSidecars' prepend ordering (legacy first, deliberately — see that
// method and config_test.go's BackCompat test) is correct on its own and
// stays unchanged. The hazard is what a caller does with the MERGED result:
// cmd/gatekeeper passes ONLY the first entry of the resolved list into the
// domain-scoped PerSpawn resolver (docs/SIDECAR-READ-CONTRACT.md section 2
// mandates spawn-first: the first `sidecars:` entry is meant to be the
// per-spawn namespace). If an operator's legacy `sidecar:` block actually
// names a SESSION namespace while `sidecars[0]` names the per-spawn
// namespace, the merge silently puts the session entry first, and it gets
// installed as PerSpawn — DomainA2A then fail-closes correctly against the
// WRONG namespace (a session identity accepted as if per-spawn), a
// confused-deputy outcome. config.example.yaml already deprecates the
// legacy block in favor of `sidecars:`, so rejecting the combination —
// rather than silently accepting an ordering nothing enforces — is the
// fail-closed choice consistent with the rest of this repo's posture, and
// costs nothing for any deployment already following the documented
// single-block-OR-list convention.
func (a AttestationConfig) validate() error {
	if a.Sidecar.enabled() && len(a.Sidecars) > 0 {
		return fmt.Errorf("attestation: both the legacy `sidecar:` block and `sidecars:` are configured; " +
			"use `sidecars:` alone (with the per-spawn namespace first, per docs/SIDECAR-READ-CONTRACT.md " +
			"section 2) — mixing the two makes which namespace lands in the per-spawn resolver depend on " +
			"merge order rather than explicit config")
	}
	return nil
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

// A2AEntitlementConfig binds one attested A2A caller identity (the map key
// under a2a_mapping in config.yaml) to a caller role and the peer
// audience(s)/scope(s) that role may request a mint for
// (internal/a2apolicy.Entitlement is built directly from this). This is a
// separate, additive mapping from roles.<name> (internal/mint's GitHub-domain
// role -> App-slug gate, lr-116b57): the A2A domain maps identity -> role ->
// audience, not role -> App.
type A2AEntitlementConfig struct {
	// Role is the A2A caller role name passed to issuance once a request is
	// permitted. Generic, deployment-defined vocabulary — never a specific
	// agent's proper name.
	Role string `yaml:"role"`
	// Audiences is the set of peer audience/scope identifiers this identity's
	// Role may request a mint for. No default: an absent or empty list means
	// this identity is entitled to no audience, mirroring RoleConfig's
	// EntitledIdentities fail-closed default.
	Audiences []string `yaml:"audiences,omitempty"`
}

// EntitlementRole satisfies internal/a2apolicy.EntitlementSource, so
// A2AEntitlementConfig can be passed directly to
// a2apolicy.NewPolicyFromEntries without config importing a2apolicy or vice
// versa (structural interface satisfaction, no cross-layer import).
func (c A2AEntitlementConfig) EntitlementRole() string { return c.Role }

// EntitlementAudiences satisfies internal/a2apolicy.EntitlementSource.
func (c A2AEntitlementConfig) EntitlementAudiences() []string { return c.Audiences }

// A2AProviderConfig configures the B3 OpenBao issuance surface (lr-890fae,
// mechanism settled at that task's comment #4, live-provisioned per openbao
// lr-fbbf32 comment #12). It is a SEPARATE stanza from Broker: Broker's
// existing openbao/vault implementations satisfy the generic
// Get(path)-shaped secret-read interface every role's App credentials use,
// while A2AProvider configures a materially different, A2A-specific
// operation — a signed-assertion exchange against a dedicated JWT auth
// mount, followed by an identity/oidc/token read. Both may point at the
// same OpenBao server; they are still logically distinct surfaces.
//
// Every field here is deployment-specific; nothing is hardcoded in source.
// Absent/zero-value (the default) means the A2A provider is not configured
// — the A2A mint path refuses with a clear config error rather than
// guessing at a partially-configured surface, and every existing
// GitHub-domain mint is entirely unaffected (additive, off by default).
type A2AProviderConfig struct {
	// Endpoint is the OpenBao server URL. May be the same server as Broker,
	// or a different one — this package does not assume they coincide.
	Endpoint string `yaml:"endpoint"`

	// AssertionPrivateKeyPath is the broker path holding gatekeeper's own
	// assertion signing key — the bearer-of-attestation key used ONLY to
	// sign the short-lived assertion exchanged at AuthMount. This key is
	// never OpenBao's own OIDC signing key and is read via the SAME broker
	// configured under `broker:`, not a second credential source.
	AssertionPrivateKeyPath string `yaml:"assertion_private_key_path"`
	// Issuer is stamped into the assertion's "iss" claim. Must match the
	// JWT auth mount's configured bound_issuer.
	Issuer string `yaml:"issuer"`
	// AssertionTTLSeconds bounds the gatekeeper-signed assertion's own
	// lifetime (distinct from the peer-facing token's TTL, which OpenBao's
	// identity/oidc role controls independently). Defaults to 300 (5m)
	// when unset.
	AssertionTTLSeconds int `yaml:"assertion_ttl_seconds,omitempty"`

	// AuthMount is the path segment of OpenBao's dedicated JWT auth mount
	// (e.g. "a2a-jwt").
	AuthMount string `yaml:"auth_mount"`

	// Roles maps an A2A caller role (the role name internal/a2apolicy
	// resolves from a2a_mapping) to the specific JWT auth role and
	// identity/oidc role that role should be issued through. Every
	// entitled role referenced in a2a_mapping must have a matching entry
	// here for a mint request to succeed — a resolved role with no entry
	// refuses closed rather than falling back to some other role's
	// mapping.
	Roles map[string]A2AProviderRoleConfig `yaml:"roles,omitempty"`
}

// A2AProviderRoleConfig binds one A2A caller role name to the specific
// OpenBao role names its issuance flows through.
type A2AProviderRoleConfig struct {
	// AuthRole is the JWT auth role name to authenticate against under
	// A2AProviderConfig.AuthMount (role_type=jwt, user_claim=sub).
	AuthRole string `yaml:"auth_role"`
	// OIDCRole is the identity/oidc role name to read for the peer-facing
	// token: GET /v1/identity/oidc/token/<OIDCRole>.
	OIDCRole string `yaml:"oidc_role"`
}

// enabled reports whether cfg has enough information to drive an A2A mint.
// All of Endpoint, AssertionPrivateKeyPath, AuthMount are required together
// for the provider to be usable; Issuer is deployment-specific but may
// legitimately be empty (the assertion's "iss" claim is then simply
// omitted — see internal/a2atoken). A partially configured provider (e.g.
// AuthMount set but AssertionPrivateKeyPath empty) is treated as NOT
// enabled — fail closed with a config error rather than attempting a
// request that cannot succeed.
func (cfg A2AProviderConfig) enabled() bool {
	return cfg.Endpoint != "" && cfg.AssertionPrivateKeyPath != "" && cfg.AuthMount != ""
}

// Enabled reports whether cfg is configured enough for the A2A mint path to
// run at all. Exported so cmd/gatekeeper can decide whether to wire the A2A
// command without duplicating the required-fields list.
func (cfg A2AProviderConfig) Enabled() bool { return cfg.enabled() }

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

	if err := cfg.Attestation.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
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
