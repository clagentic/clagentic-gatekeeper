//go:build linux

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeUpstream(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "upstream.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ncat >/dev/null\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Two hooks that both rewrite the same call race, and the last to finish wins.
// Composed, the upstream's rewrite is the base and the statement goes in front.
func TestComposedUpstreamRewriteIsKeptAndTheStatementPrefixed(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Compose = writeUpstream(t, `cat <<'EOF'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"upstream","updatedInput":{"command":"export UPSTREAM=1; ls -l","timeout":5}}}
EOF`)
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls -l"))
	command, out := rewrittenCommand(t, res)
	dir := dirOf(t, command)
	if want := "export " + EnvDir + "=" + dir + "; export UPSTREAM=1; ls -l"; command != want {
		t.Fatalf("composed command\n got %q\nwant %q", command, want)
	}
	hso := out["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "allow" || hso["permissionDecisionReason"] != "upstream" {
		t.Fatalf("the upstream reply was not kept: %+v", hso)
	}
	if hso["updatedInput"].(map[string]any)["timeout"] != float64(5) {
		t.Fatalf("upstream tool_input members were lost: %+v", hso["updatedInput"])
	}
}

func TestComposedUpstreamDenyPassesThroughUnchanged(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Compose = writeUpstream(t, `echo "not allowed" >&2; exit 2`)
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	if res.ExitCode != 2 || !strings.Contains(string(res.Stderr), "not allowed") || len(res.Stdout) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestComposedUpstreamWithoutRewritePassesItsReplyThrough(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	reply := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask"}}`
	h.hook.Compose = writeUpstream(t, "printf '%s' '"+reply+"'")
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	if string(res.Stdout) != reply || res.ExitCode != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestComposedUpstreamSilentFallsBackToTheStandaloneRewrite(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Compose = writeUpstream(t, "true")
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", "ls")))
	if !strings.HasSuffix(command, "; ls") {
		t.Fatalf("%q", command)
	}
}

func TestComposedUpstreamThatCannotRunNeverCostsTheDelivery(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	for name, exe := range map[string]string{
		"missing":  filepath.Join(t.TempDir(), "absent"),
		"relative": "upstream.sh",
	} {
		h.hook.Compose = exe
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if command, _ := rewrittenCommand(t, res); !strings.HasSuffix(command, "; ls") {
			t.Errorf("%s: %q", name, command)
		}
	}
}

func TestComposedUpstreamThatHangsIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the upstream timeout")
	}
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Compose = writeUpstream(t, "sleep 30")
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	if command, _ := rewrittenCommand(t, res); !strings.HasSuffix(command, "; ls") {
		t.Fatalf("%q", command)
	}
}

func TestComposedWarnModeStillReturnsTheUpstreamReply(t *testing.T) {
	h := newHarness(t, ModeWarn)
	startSession(t, h, "")
	reply := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"export U=1; ls"}}}`
	h.hook.Compose = writeUpstream(t, "printf '%s' '"+reply+"'")
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	if string(res.Stdout) != reply {
		t.Fatalf("warn mode altered the upstream reply: %q", res.Stdout)
	}
}
