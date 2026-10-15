//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/hook"
)

// A token the flag package takes as another flag's value is never a flag, and the
// scan stops where Parse stops.
func TestFindComposeNeverReadsAValueOrATrailingArgumentAsAFlag(t *testing.T) {
	for name, rest := range map[string][]string{
		"value of --origin":     {"--origin", "--compose", "/up"},
		"value of --state-dir":  {"--state-dir", "-compose", "/up"},
		"value of --socket":     {"--socket", "--compose=/up"},
		"after a bare argument": {"word", "--compose", "/up"},
		"after a lone dash":     {"-", "--compose", "/up"},
	} {
		if exe, _, ok := findCompose(hook.EventPreToolUseBash, rest); ok {
			t.Errorf("%s: found %q", name, exe)
		}
	}
	if _, b, ok := findCompose(hook.EventPreToolUseBash, []string{"--origin", "--upstream-timeout", "--compose", "/up", "--upstream-timeout=9s"}); !ok || b != 9*time.Second {
		t.Errorf("budget %s ok %v", b, ok)
	}
	if exe, _, ok := findCompose(hook.EventPreToolUseBash, []string{"--origin", "agent", "--mode=enforce", "--compose", "/up"}); !ok || exe != "/up" {
		t.Errorf("%q %v", exe, ok)
	}
}
