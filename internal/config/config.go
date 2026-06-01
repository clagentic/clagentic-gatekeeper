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
	GitHub GitHubConfig          `yaml:"github"`
	Broker BrokerConfig          `yaml:"broker"`
	Token  TokenConfig           `yaml:"token"`
	Roles  map[string]RoleConfig `yaml:"roles"`
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

// RoleConfig binds a role name to broker paths for its GitHub App credentials.
// Permissions is optional; when set it overrides the reference permission set
// for that role name.
type RoleConfig struct {
	AppIDPath          string            `yaml:"app_id_path"`
	InstallationIDPath string            `yaml:"installation_id_path"`
	PrivateKeyPath     string            `yaml:"private_key_path"`
	Permissions        map[string]string `yaml:"permissions,omitempty"`
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
