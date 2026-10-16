package config

import (
	"strings"
	"testing"
)

const a2aProviderBase = "github:\n  owner: myorg\nbroker:\n  type: env\nroles: {}\n"

// A config still naming a removed assertion-signing key is refused at load and
// the error names the key, so an operator knows exactly what to delete.
func TestLoad_RemovedA2AProviderKeysAreRefusedByName(t *testing.T) {
	cases := map[string]string{
		"assertion_private_key_path": "  assertion_private_key_path: secret/gatekeeper/a2a/assertion-private-key\n",
		"issuer":                     "  issuer: gatekeeper-example-issuer\n",
		"assertion_ttl_seconds":      "  assertion_ttl_seconds: 300\n",
		"empty value still counts":   "  assertion_private_key_path:\n",
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeTemp(t, a2aProviderBase+"a2a_provider:\n  endpoint: https://bao.example.com\n  auth_mount: a2a-jwt\n"+extra)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load accepted a config naming a removed a2a_provider key")
			}
			key := strings.TrimSpace(strings.SplitN(extra, ":", 2)[0])
			if !strings.Contains(err.Error(), "a2a_provider."+key) {
				t.Fatalf("error %q does not name a2a_provider.%s", err, key)
			}
		})
	}
}

// Every removed key present is named in one error.
func TestLoad_RemovedA2AProviderKeysAllNamed(t *testing.T) {
	path := writeTemp(t, a2aProviderBase+"a2a_provider:\n  assertion_private_key_path: x\n  issuer: y\n  assertion_ttl_seconds: 5\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a config naming removed a2a_provider keys")
	}
	for _, key := range removedA2AProviderKeys {
		if !strings.Contains(err.Error(), "a2a_provider."+key) {
			t.Errorf("error %q does not name a2a_provider.%s", err, key)
		}
	}
}

// The same names outside a2a_provider, in a comment, or as a value are not
// removed keys: identity.issuer is a live key and must keep loading.
func TestLoad_RemovedA2AProviderKeysDoNotMatchElsewhere(t *testing.T) {
	body := a2aProviderBase +
		"identity:\n  key_path: /k\n  issuer: https://issuer.example\n" +
		"a2a_provider:\n  endpoint: https://bao.example.com\n  auth_mount: a2a-jwt\n  # issuer: gone\n"
	if _, err := Load(writeTemp(t, body)); err != nil {
		t.Fatalf("Load refused a config with no removed key: %v", err)
	}
}
