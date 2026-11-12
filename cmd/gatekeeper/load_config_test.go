package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigWarnsOnUnknownKeysAndStillLoads(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"clean config writes nothing", "github:\n  owner: example\n", ""},
		{"unknown key is named and the load succeeds", "github:\n  owner: example\n  ownr: x\n",
			"config: unknown key github.ownr has no effect; check its spelling against config.example.yaml\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			var warn bytes.Buffer
			cfg, err := loadConfig(p, &warn)
			if err != nil || cfg == nil {
				t.Fatalf("load refused: %v", err)
			}
			if got := warn.String(); got != c.want {
				t.Fatalf("stderr %q, want %q", got, strings.TrimSpace(c.want))
			}
		})
	}
}
