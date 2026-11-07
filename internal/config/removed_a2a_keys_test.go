package config

import "testing"

const a2aProviderBase = "github:\n  owner: myorg\nbroker:\n  type: env\nroles: {}\n"

const a2aProviderHead = "a2a_provider:\n  endpoint: https://bao.example.com\n  auth_mount: a2a-jwt\n"

const a2aWarningTail = " have no effect; gatekeeper no longer signs an A2A assertion, the OpenBao JWT mount trusts the serve JWKS (see docs/SETUP.md, A2A token flow)"

// A config still naming a removed assertion-signing key loads, and the warning
// names the key so an operator knows exactly what to delete.
func TestLoad_RemovedA2AProviderKeysLoadAndWarnByName(t *testing.T) {
	cases := []struct{ name, extra, want string }{
		{"assertion_private_key_path", "  assertion_private_key_path: secret/gatekeeper/a2a/assertion-private-key\n", "assertion_private_key_path"},
		{"issuer", "  issuer: gatekeeper-example-issuer\n", "issuer"},
		{"assertion_ttl_seconds", "  assertion_ttl_seconds: 300\n", "assertion_ttl_seconds"},
		{"empty value still counts", "  assertion_private_key_path:\n", "assertion_private_key_path"},
		{"all three", "  assertion_ttl_seconds: 5\n  issuer: y\n  assertion_private_key_path: x\n", "assertion_private_key_path, issuer, assertion_ttl_seconds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, a2aProviderBase+a2aProviderHead+c.extra))
			if err != nil {
				t.Fatalf("Load refused a config naming a removed a2a_provider key: %v", err)
			}
			want := "a2a_provider: deprecated config key(s) " + c.want + a2aWarningTail
			if got := cfg.RemovedA2AKeysWarning(); got != want {
				t.Fatalf("warning = %q, want %q", got, want)
			}
			if !cfg.A2AProvider.Enabled() {
				t.Error("the live a2a_provider keys must still configure the provider")
			}
		})
	}
}

// The same names outside a2a_provider, in a comment, or as a value are not
// removed keys: identity.issuer is a live key and must keep loading silently.
func TestLoad_RemovedA2AProviderKeysDoNotMatchElsewhere(t *testing.T) {
	body := a2aProviderBase +
		"identity:\n  key_path: /k\n  issuer: https://issuer.example\n" +
		a2aProviderHead + "  # issuer: gone\n"
	cfg, err := Load(writeTemp(t, body))
	if err != nil {
		t.Fatalf("Load refused a config with no removed key: %v", err)
	}
	if w := cfg.RemovedA2AKeysWarning(); w != "" {
		t.Fatalf("warning = %q, want none", w)
	}
	if cfg.Identity.Issuer != "https://issuer.example" {
		t.Errorf("identity.issuer = %q, want it untouched", cfg.Identity.Issuer)
	}
}
