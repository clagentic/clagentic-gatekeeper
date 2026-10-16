package config

import (
	"fmt"
	"strings"
)

// removedA2AProviderKeys are the a2a_provider keys that configured gatekeeper's
// own A2A assertion signing. Gatekeeper no longer signs an assertion: the
// caller's serve-issued identity assertion logs in at the OpenBao JWT mount,
// which trusts the serve JWKS. A config that still names one keeps loading, as
// with the removed identity keys; RemovedA2AKeysWarning names them and the
// values are ignored.
var removedA2AProviderKeys = []string{"assertion_private_key_path", "issuer", "assertion_ttl_seconds"}

// removedA2AKeysPresent returns the removed a2a_provider keys the decoded YAML
// document carries, whatever their values.
func removedA2AKeysPresent(data []byte) ([]string, error) {
	return sectionKeysPresent(data, "a2a_provider", removedA2AProviderKeys)
}

// RemovedA2AKeysWarning returns the single deprecation line for removed
// a2a_provider keys the config still carries, or "" when it carries none.
func (c *Config) RemovedA2AKeysWarning() string {
	if len(c.removedA2AKeys) == 0 {
		return ""
	}
	return fmt.Sprintf("a2a_provider: deprecated config key(s) %s have no effect; gatekeeper no longer signs an A2A assertion, the OpenBao JWT mount trusts the serve JWKS (see docs/SETUP.md, A2A token flow)",
		strings.Join(c.removedA2AKeys, ", "))
}
