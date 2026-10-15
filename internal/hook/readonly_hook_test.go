//go:build linux

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A command that provably cannot use the identity behaves exactly as the
// no-decision paths do: empty output, exit 0, no permission decision.
func TestReadOnlyCommandIsNotRewritten(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	for _, command := range []string{"date", "ls -la", "pwd", "cat README.md", "head -n 3 f", "wc -l f", "echo hi", "ls | wc -l"} {
		res := h.fire(EventPreToolUseBash, bashPayload("", "", command))
		if len(res.Stdout) != 0 || len(res.Stderr) != 0 || res.ExitCode != 0 {
			t.Errorf("%q: %+v", command, res)
		}
	}
}

// A subagent's read-only call neither rewrites nor issues a child: nothing about
// the call needs a directory.
func TestReadOnlyCommandOfASubagentIssuesNothing(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	res := h.fire(EventPreToolUseBash, bashPayload("late-agent", "example-builder", "date"))
	if len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Fatalf("%+v", res)
	}
	if n := len(h.fake.childRequests()); n != 0 {
		t.Fatalf("%d children issued for a command that needs none", n)
	}
	// The same agent's next program call still gets its own directory.
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("late-agent", "example-builder", programCommand)))
	if dirOf(t, command) == "" || len(h.fake.childRequests()) != 1 {
		t.Fatalf("children %+v", h.fake.childRequests())
	}
}

// A command that mixes a read-only utility with anything that can run a program
// or expand a variable keeps the delivery statement, byte for byte in front.
func TestMixedCommandStillGetsTheStatement(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	for _, original := range []string{
		"date; gatekeeper mint --role builder",
		"gatekeeper mint --role builder | head",
		"ls && ./build.sh",
		"echo $(gatekeeper mint --role builder)",
		"cat f | xargs rm",
		"echo hi > out.txt",
		"printenv CLAGENTIC_IDENTITY_DIR",
		"ls; find . -exec sh -c x {} +",
	} {
		command, out := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", original)))
		if want := "export " + EnvDir + "=" + dirOf(t, command) + "; " + original; command != want {
			t.Errorf("rewritten command\n got %q\nwant %q", command, want)
		}
		if _, has := out["hookSpecificOutput"].(map[string]any)["permissionDecision"]; has {
			t.Errorf("%q: a permission decision was added", original)
		}
	}
}

// Warn mode records that the command did not need the identity.
func TestWarnModeRecordsTheSkipDecision(t *testing.T) {
	h := newHarness(t, ModeWarn)
	startSession(t, h, "")
	h.fire(EventPreToolUseBash, bashPayload("", "", "date"))
	raw, err := os.ReadFile(filepath.Join(h.state, "shapes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"identity-not-needed"`) {
		t.Fatalf("capture %s", raw)
	}
}

// Composed: a read-only command with an upstream that made no decision, or that
// allowed, yields the upstream's own bytes and exit code unchanged. The skipped
// rewrite is the same outcome as every other path that adds nothing.
func TestComposedReadOnlyCommandYieldsTheUpstreamBytes(t *testing.T) {
	allow := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"theirs"}}`
	rewrite := `{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"ls -l","timeout":5}}}`
	cases := map[string]struct{ body, want string }{
		"silent":            {"true", ""},
		"empty object":      {printing(`{}`), "{}"},
		"allow no rewrite":  {printing(allow), allow},
		"allow and rewrite": {printing(rewrite), rewrite},
	}
	for name, c := range cases {
		h := composedHarness(t, ModeEnforce, c.body)
		got := h.fire(EventPreToolUseBash, bashPayload("", "", "date"))
		if string(got.Stdout) != c.want || got.ExitCode != 0 {
			t.Errorf("%s: got %q exit %d, want the upstream's %q", name, got.Stdout, got.ExitCode, c.want)
		}
	}
}

// Composed: an upstream that rewrites a read-only command into one that runs a
// program gets the statement, because the decision is made on the command that
// will run.
func TestComposedDecisionIsOnTheCommandThatWillRun(t *testing.T) {
	body := printing(`{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"ls; gatekeeper mint --role builder"}}}`)
	h := composedHarness(t, ModeEnforce, body)
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", "ls")))
	if !strings.HasSuffix(command, "; ls; gatekeeper mint --role builder") || strings.Count(command, "export ") != 1 {
		t.Fatalf("%q", command)
	}
}
