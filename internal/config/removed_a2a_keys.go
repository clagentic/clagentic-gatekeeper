package config

import (
	"fmt"
	"strings"
)

// removedA2AProviderKeys are the a2a_provider keys that configured gatekeeper's
// own A2A assertion signing. Gatekeeper no longer signs an assertion: the
// caller's serve-issued identity assertion logs in at the OpenBao JWT mount,
// which trusts the serve JWKS. A key that is still present would silently do
// nothing and let a deployment believe the old key material still matters, so
// Load refuses it by name instead.
var removedA2AProviderKeys = []string{"assertion_private_key_path", "issuer", "assertion_ttl_seconds"}

// refuseRemovedA2AKeys returns a named error when the a2a_provider section
// still carries a removed key, whatever its value.
func refuseRemovedA2AKeys(data []byte) error {
	found, err := sectionKeysPresent(data, "a2a_provider", removedA2AProviderKeys)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return nil
	}
	qualified := make([]string, len(found))
	for i, k := range found {
		qualified[i] = "a2a_provider." + k
	}
	return fmt.Errorf("%s removed: gatekeeper no longer signs an A2A assertion, the OpenBao JWT mount trusts the serve JWKS; delete the key (see docs/SETUP.md, A2A token flow)",
		strings.Join(qualified, ", "))
}
