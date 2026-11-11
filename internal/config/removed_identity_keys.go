package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// removedIdentityKeys are identity keys an earlier release read and this one
// does not. They are listed in this order in the warning.
var removedIdentityKeys = []string{"operator_uid", "operator_name", "operator_roles"}

// removedKeysPresent returns the removed identity keys the decoded YAML
// document carries, whatever their values. The scan reads what the decoder
// produced, so a key named only inside a comment or a string value is not
// counted and a key that arrives through an anchor or merge key is.
func removedKeysPresent(data []byte) ([]string, error) {
	var doc struct {
		Identity map[string]yaml.Node `yaml:"identity"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var found []string
	for _, want := range removedIdentityKeys {
		if _, ok := doc.Identity[want]; ok {
			found = append(found, want)
		}
	}
	return found, nil
}

// RemovedIdentityKeysWarning returns the single deprecation line for removed
// identity keys the config still carries, or "" when it carries none.
func (c *Config) RemovedIdentityKeysWarning() string {
	if len(c.removedIdentityKeys) == 0 {
		return ""
	}
	return fmt.Sprintf("identity: deprecated config key(s) %s have no effect; serve issues no human assertions",
		strings.Join(c.removedIdentityKeys, ", "))
}
