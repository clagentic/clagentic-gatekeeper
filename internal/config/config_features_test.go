package config

import (
	"strings"
	"testing"
)

func TestCheckPaths(t *testing.T) {
	at := func(n int) string { return "/" + strings.Repeat("a", n-1) }
	for _, c := range []struct {
		name         string
		check        func(name, value string) error
		value        string
		wantContains string // empty: accepted
	}{
		{"abs: unset is accepted", CheckAbsPath, "", ""},
		{"abs: absolute is accepted", CheckAbsPath, "/run/x.sock", ""},
		{"abs: relative", CheckAbsPath, "x.sock", "must be an absolute path"},
		{"abs: dot-relative", CheckAbsPath, "./x.sock", "must be an absolute path"},
		{"socket: unset is accepted", CheckSocketPath, "", ""},
		{"socket: at the limit", CheckSocketPath, at(MaxSocketPathBytes), ""},
		{"socket: one over the limit", CheckSocketPath, at(MaxSocketPathBytes + 1), "limit"},
		{"socket: relative", CheckSocketPath, "x.sock", "must be an absolute path"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.check("--socket", c.value)
			switch {
			case c.wantContains == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.wantContains != "" && (err == nil || !strings.Contains(err.Error(), c.wantContains) || !strings.Contains(err.Error(), "--socket") || !strings.Contains(err.Error(), c.value)):
				t.Fatalf("got %v, want a refusal naming --socket and %q that says %q", err, c.value, c.wantContains)
			}
		})
	}
}

func TestLoad_IdentitySocketPathLengthIsRefusedAtLoadNamingTheKey(t *testing.T) {
	ok := "/" + strings.Repeat("s", MaxSocketPathBytes-1)
	loadIdentity(t, "identity:\n  key_path: /k\n  socket_path: "+ok+"\n")
	over := ok + "s"
	_, err := Load(writeTemp(t, "identity:\n  key_path: /k\n  socket_path: "+over+"\n"))
	if err == nil || !strings.Contains(err.Error(), "identity.socket_path") || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("got %v", err)
	}
	// Only the socket is held to the length limit.
	loadIdentity(t, "identity:\n  key_path: /k\n  jwks_path: "+over+"\n")
}

func TestLoad_AttestationPathsMustBeAbsolute(t *testing.T) {
	for name, c := range map[string]struct{ body, want string }{
		"sidecars dir":      {"attestation:\n  sidecars:\n    - dir: /tmp\n      file_prefix: a-\n      session_id_env: X\n    - dir: rel\n      file_prefix: b-\n      session_id_env: Y\n", "attestation.sidecars[1].dir"},
		"legacy sidecar":    {"attestation:\n  sidecar:\n    dir: rel\n    file_prefix: a-\n    session_id_env: X\n", "attestation.sidecar.dir"},
		"configured file":   {"attestation:\n  configured:\n    type: file\n    source: rel/identity\n", "attestation.configured.source"},
		"partial sidecar":   {"attestation:\n  sidecars:\n    - dir: rel\n", "attestation.sidecars[0].dir"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeTemp(t, c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "absolute") {
				t.Fatalf("got %v, want a refusal naming %s", err, c.want)
			}
		})
	}
	// An env source is a variable name, not a path.
	loadIdentity(t, "attestation:\n  configured:\n    type: env\n    source: SOME_VARIABLE\n")
	loadIdentity(t, "attestation:\n  configured:\n    type: file\n    source: /run/identity\n")
}

func TestLoad_SchemaVersionNewerThanSupportedIsRefused(t *testing.T) {
	for _, v := range []string{"", "config_schema_version: 1\n", "config_schema_version: 2\n"} {
		loadIdentity(t, v+"token:\n  ttl_minutes: 30\n")
	}
	_, err := Load(writeTemp(t, "config_schema_version: 3\n"))
	if err == nil || !strings.Contains(err.Error(), "config_schema_version 3") {
		t.Fatalf("got %v", err)
	}
}

// Presence of the identity section is what the decoder produced, so a section
// that arrives through a YAML merge key counts, and so do the removed keys in it.
func TestLoad_IdentitySectionThroughAMergeKeyIsPresent(t *testing.T) {
	cfg := loadIdentity(t, "shared: &shared\n  identity:\n    key_path: /k\n    operator_name: example\n<<: *shared\n")
	if !cfg.IdentityEnabled() || cfg.Identity.KeyPath != "/k" {
		t.Fatalf("the merged identity section is not present: enabled=%v %+v", cfg.IdentityEnabled(), cfg.Identity)
	}
	if w := cfg.RemovedIdentityKeysWarning(); !strings.Contains(w, "operator_name") {
		t.Fatalf("a removed key arriving through the merge was not seen: %q", w)
	}
	// An empty section through the merge is a present section, refused for its
	// missing key_path rather than treated as absent.
	_, err := Load(writeTemp(t, "shared: &shared\n  identity: {}\n<<: *shared\n"))
	if err == nil || !strings.Contains(err.Error(), "identity.key_path") {
		t.Fatalf("got %v", err)
	}
	// Absent stays absent.
	if loadIdentity(t, "shared: &shared\n  token: {ttl_minutes: 5}\n<<: *shared\n").IdentityEnabled() {
		t.Fatal("identity enabled without a section")
	}
}

func TestLoad_RetiredKeys(t *testing.T) {
	const entry = "    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1, x: AAAA}\n"
	cfg := loadIdentity(t, "identity:\n  key_path: /k\n  retired_keys:\n"+entry+
		"    - {kty: EC, crv: P-256, alg: ES256, use: sig, kid: k2, x: AAAA, y: BBBB}\n")
	got := cfg.Identity.RetiredKeys
	if len(got) != 2 || got[0].Kid != "k1" || got[0].X != "AAAA" || got[1].Y != "BBBB" || got[1].Use != "sig" {
		t.Fatalf("%+v", got)
	}

	for name, c := range map[string]struct{ entries, want string }{
		"a private member d":    {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1, x: AAAA, d: CCCC}\n", "identity.retired_keys[0] (kid \"k1\") has a private member d"},
		"a private member in a later entry": {entry + "    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k2, x: AAAA, d: CCCC}\n", "identity.retired_keys[1] (kid \"k2\") has a private member d"},
		"an unknown member":     {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1, x: AAAA, extra: 1}\n", "unknown member \"extra\""},
		"an rsa private member": {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1, x: AAAA, p: CCCC}\n", "unknown member \"p\""},
		"a missing kid":         {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, x: AAAA}\n", "identity.retired_keys[0] is missing member kid"},
		"a missing x":           {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1}\n", "is missing member x"},
		"a repeated kid":        {entry + entry, "identity.retired_keys[1] (kid \"k1\") repeats the kid of identity.retired_keys[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeTemp(t, "identity:\n  key_path: /k\n  retired_keys:\n"+c.entries))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	if _, err := Load(writeTemp(t, "identity:\n  key_path: /k\n  retired_keys: not-a-list\n")); err == nil {
		t.Fatal("a retired_keys that is not a list was accepted")
	}
}
