package config

import (
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestUnknownKeys(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string
		warning    string // substring the stderr warning line must carry, when set
	}{
		{"clean", "github:\n  owner: o\nidentity:\n  key_path: /k\n", nil, ""},
		{"top level", "githb:\n  owner: o\n", []string{"githb"}, ""},
		{"nested section", "identity:\n  key_path: /k\n  socket_pth: /s\n", []string{"identity.socket_pth"}, "identity.socket_pth"},
		{"role entry name is free-form, its keys are checked",
			"roles:\n  any-name:\n    app_id_path: a\n    app_id_pth: b\n", []string{"roles.any-name.app_id_pth"}, ""},
		{"permissions is free-form", "roles:\n  r:\n    permissions:\n      whatever: read\n", nil, ""},
		{"a2a_mapping entry", "a2a_mapping:\n  who:\n    role: r\n    audiencez: [a]\n", []string{"a2a_mapping.who.audiencez"}, ""},
		{"a2a_provider role entry", "a2a_provider:\n  roles:\n    r:\n      auth_role: a\n      oidc_rol: b\n", []string{"a2a_provider.roles.r.oidc_rol"}, ""},
		{"list item", "attestation:\n  sidecars:\n    - dir: /d\n    - dirr: /d\n", []string{"attestation.sidecars[1].dirr"}, ""},
		{"pointer section", "attestation:\n  assertion:\n    issuerz: []\n", []string{"attestation.assertion.issuerz"}, ""},
		{"merge key", "base: &b\n  owner: o\n  ownr: x\ngithub:\n  <<: *b\n", []string{"github.ownr"}, ""},
		{"merge key sequence", "x: &a {ownr: 1}\ny: &b {api_basee: 2}\ngithub:\n  <<: [*a, *b]\n", []string{"github.ownr", "github.api_basee"}, ""},
		{"merge key at top level", "shared: &s\n  githb: {owner: o}\n<<: *s\n", []string{"githb"}, ""},
		{"anchor holder that nothing uses is unknown", "base: &b\n  owner: o\n", []string{"base"}, ""},
		{"anchored section", "identity: &i\n  key_path: /k\n  bad: 1\n", []string{"identity.bad"}, ""},
		{"removed identity key is not double-reported", "identity:\n  key_path: /k\n  operator_uid: 1\n", nil, ""},
		{"each key once", "identity:\n  key_path: /k\n  bad: 1\n", []string{"identity.bad"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := loadIdentity(t, c.body)
			if got := cfg.UnknownKeys(); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			if c.warning != "" {
				w := cfg.UnknownKeyWarnings()
				if len(w) != 1 || !strings.Contains(w[0], c.warning) {
					t.Fatalf("warnings %v, want one naming %q", w, c.warning)
				}
			}
		})
	}
}

// loadErrorFixtures names shipped YAML files that exist to exercise a load
// error, so they cannot be loaded here. Keyed by path relative to the repo
// root; the value is the reason.
var loadErrorFixtures = map[string]string{}

// TestShippedConfigsHaveNoUnknownKeys guards against a real key being missing
// from the known-key set: every shipped config must load without a warning.
func TestShippedConfigsHaveNoUnknownKeys(t *testing.T) {
	root := "../.."
	files := []string{"config.example.yaml"}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(p)
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if !slices.Contains(strings.Split(filepath.ToSlash(p), "/"), "testdata") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range files {
		t.Run(rel, func(t *testing.T) {
			if reason, skip := loadErrorFixtures[rel]; skip {
				t.Skip(reason)
			}
			cfg, err := Load(filepath.Join(root, rel))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.UnknownKeys(); len(got) != 0 {
				t.Fatalf("%s carries unknown keys: %v", rel, got)
			}
		})
	}
}
