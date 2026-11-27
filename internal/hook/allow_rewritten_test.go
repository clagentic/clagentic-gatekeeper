//go:build linux

package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// decisionOf returns the permissionDecision of a reply, "" when it has none.
func decisionOf(t *testing.T, res Result) string {
	t.Helper()
	var out struct {
		Specific map[string]any `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(res.Stdout, &out); err != nil {
		t.Fatalf("reply %q: %v", res.Stdout, err)
	}
	d, _ := out.Specific["permissionDecision"].(string)
	return d
}

// With the setting on, a rewrite carries allow and nothing else changes; every
// path that does not rewrite emits exactly what it emits with the setting off.
func TestAllowRewrittenStandalonePaths(t *testing.T) {
	cases := map[string]struct {
		mode    Mode
		payload map[string]any
		session bool
		allowed bool
	}{
		"rewrite":           {ModeEnforce, bashPayload("", "", programCommand), true, true},
		"piped":             {ModeEnforce, bashPayload("", "", "find . -name x | wc -l && make"), true, true},
		"read-only":         {ModeEnforce, bashPayload("", "", "ls -la"), true, false},
		"already delivered": {ModeEnforce, bashPayload("", "", "export "+EnvDir+"=/x; ls"), true, false},
		"no session":        {ModeEnforce, bashPayload("", "", programCommand), false, false},
		"warn mode":         {ModeWarn, bashPayload("", "", programCommand), true, false},
		"not bash": {ModeEnforce, map[string]any{
			"session_id": testSession, "tool_name": "Read", "tool_input": map[string]any{"file_path": "/x"},
		}, true, false},
	}
	for name, c := range cases {
		off, on := newHarness(t, c.mode), newHarness(t, c.mode)
		on.hook.AllowRewritten = true
		if c.session {
			startSession(t, off, "")
			startSession(t, on, "")
		}
		resOff, resOn := off.fire(EventPreToolUseBash, c.payload), on.fire(EventPreToolUseBash, c.payload)
		if c.allowed {
			if decisionOf(t, resOff) != "" || decisionOf(t, resOn) != "allow" {
				t.Errorf("%s: off %q on %q", name, resOff.Stdout, resOn.Stdout)
			}
			continue
		}
		if len(resOff.Stdout) != 0 || len(resOn.Stdout) != 0 || resOn.ExitCode != 0 {
			t.Errorf("%s: off %q on %q", name, resOff.Stdout, resOn.Stdout)
		}
	}
}

// Composed, gatekeeper adds allow only where it adds its statement to an
// upstream that gave no decision; every other verdict is the upstream's bytes.
func TestAllowRewrittenComposedVerdicts(t *testing.T) {
	cases := map[string]struct {
		body     string
		decision string
		passthru bool
	}{
		"allow kept":      {printing(upstreamRewrite), "allow", false},
		"silent":          {"true", "allow", false},
		"empty object":    {printing(`{}`), "allow", false},
		"deny":            {printing(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"no"}}`), "deny", true},
		"ask":             {printing(`{"hookSpecificOutput":{"permissionDecision":"ask","updatedInput":{"command":"x"}}}`), "ask", true},
		"defer":           {printing(`{"hookSpecificOutput":{"permissionDecision":"defer"}}`), "defer", true},
		"legacy block":    {printing(`{"decision":"block","reason":"r"}`), "", true},
		"exit 2":          {`echo out; echo err >&2; exit 2`, "", true},
		"no verdict":      {`sleep 5`, "", true},
		"specific broken": {printing(`{"hookSpecificOutput":3}`), "", true},
	}
	for name, c := range cases {
		off := composedHarness(t, ModeEnforce, c.body)
		on := composedHarness(t, ModeEnforce, c.body)
		on.hook.AllowRewritten = true
		payload := bashPayload("", "", programCommand)
		resOff, resOn := off.fire(EventPreToolUseBash, payload), on.fire(EventPreToolUseBash, payload)
		if c.passthru {
			if !bytes.Equal(resOff.Stdout, resOn.Stdout) || !bytes.Equal(resOff.Stderr, resOn.Stderr) || resOff.ExitCode != resOn.ExitCode {
				t.Errorf("%s: setting changed a pass-through: off %+v on %+v", name, resOff, resOn)
			}
			if strings.Contains(string(resOn.Stdout), EnvDir) {
				t.Errorf("%s: statement added to a verdict that must pass through", name)
			}
			continue
		}
		if got := decisionOf(t, resOn); got != c.decision {
			t.Errorf("%s: decision %q, want %q", name, got, c.decision)
		}
		if command, _ := rewrittenCommand(t, resOn); !strings.HasSuffix(command, "; "+programCommand) && name != "allow kept" {
			t.Errorf("%s: command %q", name, command)
		}
	}
}

// The registration carries the flag only when asked, adds no export rule with
// it, leaves an existing rule alone, and --remove still deletes that rule.
func TestAllowRewrittenInstall(t *testing.T) {
	in := testInstall(t)
	if strings.Contains(in.Command(EventPreToolUseBash), AllowRewrittenFlag) {
		t.Fatal("flag present by default")
	}
	on := in
	on.AllowRewritten = true
	if !strings.HasSuffix(on.Command(EventPreToolUseBash), " "+AllowRewrittenFlag) {
		t.Fatalf("command %q", on.Command(EventPreToolUseBash))
	}
	for _, ev := range []string{EventSessionStart, EventSubagentStart, EventSubagentStop, EventUserPromptSubmit} {
		if strings.Contains(on.Command(ev), AllowRewrittenFlag) {
			t.Errorf("%s carries the flag", ev)
		}
	}

	path := writeSettings(t, foreignSettings)
	if _, _, err := ApplySettingsFile(path, &on, false, false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Contains(got, AllowRule) || !strings.Contains(got, AllowRewrittenFlag) {
		t.Fatalf("on-run settings:\n%s", got)
	}
	if changed, _, err := ApplySettingsFile(path, &on, false, false); err != nil || changed {
		t.Fatalf("second identical run: changed=%v err=%v", changed, err)
	}
	// Off again: the entry goes back in place and the rule comes back.
	if _, _, err := ApplySettingsFile(path, &in, false, false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if strings.Contains(got, AllowRewrittenFlag) || !strings.Contains(got, AllowRule) {
		t.Fatalf("off-run settings:\n%s", got)
	}
	// On over an existing rule leaves it; --remove deletes it.
	if _, _, err := ApplySettingsFile(path, &on, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, path), AllowRule) {
		t.Fatal("the on-run removed an existing rule")
	}
	if _, _, err := ApplySettingsFile(path, nil, true, false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); strings.Contains(got, AllowRule) || strings.Contains(got, "claude-code") {
		t.Fatalf("after --remove:\n%s", got)
	}
}
