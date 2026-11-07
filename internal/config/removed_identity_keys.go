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
// document carries, whatever their values. The document is walked as a tree,
// so a key named only inside a comment or a string value is not counted.
func removedKeysPresent(data []byte) ([]string, error) {
	return sectionKeysPresent(data, "identity", removedIdentityKeys)
}

// sectionKeysPresent returns, in the order of want, the keys of want that the
// top-level mapping section carries, whatever their values. The document is
// walked as a tree, so a key named only inside a comment or a string value is
// not counted.
func sectionKeysPresent(data []byte, sectionName string, want []string) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0].Content
	var found []string
	for i := 0; i+1 < len(root); i += 2 {
		if root[i].Value != sectionName || root[i+1].Kind != yaml.MappingNode {
			continue
		}
		section := root[i+1].Content
		for _, key := range want {
			for j := 0; j+1 < len(section); j += 2 {
				if section[j].Value == key {
					found = append(found, key)
					break
				}
			}
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
