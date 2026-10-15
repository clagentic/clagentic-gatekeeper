//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/hook"
)

// A hand-written registration may put --compose after a flag that does not
// parse; the upstream still runs and its result is the process result.
func TestHandWrittenRegistrationKeepsTheUpstreamVerdictInAnyFlagOrder(t *testing.T) {
	deny := upstreamScript(t, "echo blocked; echo why >&2; exit 2")
	cases := map[string][]string{
		"bogus flag first":         {"--bogus", "--compose", deny},
		"bad value first":          {"--timeout", "forever", "--compose", deny},
		"bad value then both":      {"--timeout", "forever", "--upstream-timeout", "5s", "--compose", deny},
		"equals form":              {"--bogus", "--compose=" + deny},
		"single dash":              {"--bogus", "-compose", deny},
		"budget before the path":   {"--socket", "/x", "--upstream-timeout", "5s", "--bogus", "--compose", deny},
		"state dir then unknown":   {"--state-dir", "/nonexistent-dir", "--nope", "--compose", deny, "--mode", "enforce"},
		"compose before bad value": {"--socket", "/x", "--compose", deny, "--timeout", "forever"},
	}
	for name, args := range cases {
		stdout, stderr, code := runComposed(t, bashCall, args...)
		if stdout != "blocked\n" || stderr != "why\n" || code != 2 {
			t.Errorf("%s: stdout %q stderr %q exit %d", name, stdout, stderr, code)
		}
	}
}

func TestFindComposeReadsAnyPositionAndTheSameSpellingsAsTheFlagPackage(t *testing.T) {
	exe, budget, ok := findCompose(hook.EventPreToolUseBash, []string{"--socket", "/s", "-upstream-timeout=7s", "--compose", "/up", "--bogus"})
	if !ok || exe != "/up" || budget != 7*time.Second {
		t.Fatalf("%q %s %v", exe, budget, ok)
	}
	if exe, _, _ := findCompose(hook.EventPreToolUseBash, []string{"--compose", "/a", "--compose=/b"}); exe != "/b" {
		t.Errorf("last occurrence did not win: %q", exe)
	}
	if _, b, _ := findCompose(hook.EventPreToolUseBash, []string{"--compose", "/up", "--upstream-timeout", "-1s"}); b != hook.DefaultUpstreamTimeout {
		t.Errorf("bad budget -> %s, want the default", b)
	}
	for name, rest := range map[string][]string{
		"no value":       {"--compose"},
		"empty value":    {"--compose", ""},
		"none":           nil,
		"after the stop": {"--", "--compose", "/up"},
		"three dashes":   {"---compose", "/up"},
		"bare word":      {"compose", "/up"},
	} {
		if _, _, ok := findCompose(hook.EventPreToolUseBash, rest); ok {
			t.Errorf("%s: found", name)
		}
	}
	if _, _, ok := findCompose(hook.EventSessionStart, []string{"--compose", "/up"}); ok {
		t.Error("found on another event")
	}
}
