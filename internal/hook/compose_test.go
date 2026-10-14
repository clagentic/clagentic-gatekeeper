//go:build linux

package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeUpstream(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "upstream.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ncat >/dev/null\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// printing returns a script body that prints reply exactly, without a newline.
func printing(reply string) string {
	return "printf '%s' '" + strings.ReplaceAll(reply, "'", `'\''`) + "'"
}

func composedHarness(t *testing.T, mode Mode, body string) *harness {
	t.Helper()
	h := newHarness(t, mode)
	startSession(t, h, "")
	h.hook.Compose = writeUpstream(t, body)
	h.hook.UpstreamTimeout = 2 * time.Second
	return h
}

const upstreamRewrite = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"upstream","updatedInput":{"command":"export UPSTREAM=1; ls -l","timeout":5}}}`

// Two hooks that both rewrite the same call race, and the last to finish wins.
// Composed, the upstream's rewrite is the base and the statement goes in front.
func TestComposedUpstreamRewriteIsKeptAndTheStatementPrefixed(t *testing.T) {
	h := composedHarness(t, ModeEnforce, printing(upstreamRewrite))
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

// One rewrite carries both exports, with no shell wrapper and one decision.
func TestComposedRewriteCarriesBothExportsAndNoWrapper(t *testing.T) {
	h := composedHarness(t, ModeEnforce, printing(upstreamRewrite))
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls -l"))
	command, _ := rewrittenCommand(t, res)
	if strings.Count(command, "export ") != 2 || !strings.Contains(command, EnvDir) || !strings.Contains(command, "UPSTREAM=1") {
		t.Fatalf("not one rewrite with both exports: %q", command)
	}
	for _, banned := range []string{"sh -c", "bash -c", "TMPDIR"} {
		if strings.Contains(command, banned) {
			t.Fatalf("%q in %q", banned, command)
		}
	}
	if strings.Count(string(res.Stdout), "permissionDecision\"") != 1 {
		t.Fatalf("more than one decision: %s", res.Stdout)
	}
}

// The upstream registered alone would have produced exactly these outcomes, and
// the composed hook must produce the same bytes: nothing added, nothing allowed.
func TestComposedUpstreamOutcomesPassThroughByteForByte(t *testing.T) {
	cases := map[string]struct {
		body     string
		stdout   string
		wantExit int
	}{
		"deny":                    {printing(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}`), `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}`, 0},
		"ask":                     {printing(`{"hookSpecificOutput":{"permissionDecision":"ask"}}`), `{"hookSpecificOutput":{"permissionDecision":"ask"}}`, 0},
		"ask+rewrite":             {printing(`{"hookSpecificOutput":{"permissionDecision":"ask","updatedInput":{"command":"x"}}}`), `{"hookSpecificOutput":{"permissionDecision":"ask","updatedInput":{"command":"x"}}}`, 0},
		"defer":                   {printing(`{"hookSpecificOutput":{"permissionDecision":"defer"}}`), `{"hookSpecificOutput":{"permissionDecision":"defer"}}`, 0},
		"unknown":                 {printing(`{"hookSpecificOutput":{"permissionDecision":7}}`), `{"hookSpecificOutput":{"permissionDecision":7}}`, 0},
		"legacy block":            {printing(`{"decision":"block","reason":"r"}`), `{"decision":"block","reason":"r"}`, 0},
		"legacy approve":          {printing(`{"decision":"approve"}`), `{"decision":"approve"}`, 0},
		"stop":                    {printing(`{"continue":false,"stopReason":"s"}`), `{"continue":false,"stopReason":"s"}`, 0},
		"not json":                {printing(`plain text`), `plain text`, 0},
		"json array":              {printing(`[1,2]`), `[1,2]`, 0},
		"json null":               {printing(`null`), `null`, 0},
		"specific not object":     {printing(`{"hookSpecificOutput":3}`), `{"hookSpecificOutput":3}`, 0},
		"rewrite without command": {printing(`{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"timeout":3}}}`), `{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"timeout":3}}}`, 0},
		"updatedInput not object": {printing(`{"hookSpecificOutput":{"updatedInput":"x"}}`), `{"hookSpecificOutput":{"updatedInput":"x"}}`, 0},
		"exit 1":                  {`echo out; echo err >&2; exit 1`, "out\n", 1},
		"exit 2":                  {`echo out; echo err >&2; exit 2`, "out\n", 2},
		"exit 127":                {`exit 127`, "", 127},
		"killed by signal":        {`kill -9 $$`, "", 1},
	}
	for name, c := range cases {
		h := composedHarness(t, ModeEnforce, c.body)
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if string(res.Stdout) != c.stdout || res.ExitCode != c.wantExit {
			t.Errorf("%s: stdout %q exit %d, want %q exit %d", name, res.Stdout, res.ExitCode, c.stdout, c.wantExit)
		}
		if strings.Contains(string(res.Stdout), EnvDir) {
			t.Errorf("%s: the statement was added to a verdict that must pass through", name)
		}
		if c.wantExit == 2 && !strings.Contains(string(res.Stderr), "err") {
			t.Errorf("%s: stderr %q", name, res.Stderr)
		}
	}
}

// An upstream that allows, or that made no decision, gets the statement; an
// allow the upstream did not give appears only as the rewrite's own.
func TestComposedAllowedOrUndecidedUpstreamGetsTheStatement(t *testing.T) {
	cases := map[string]struct {
		body         string
		wantDecision string
		wantReason   string
		wantExtra    string
	}{
		"allow without a rewrite": {printing(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"theirs"}}`), "allow", "theirs", ""},
		"silent":                  {"true", "allow", rewriteReason, ""},
		"empty object":            {printing(`{}`), "allow", rewriteReason, ""},
		"context only":            {printing(`{"systemMessage":"note","hookSpecificOutput":{"additionalContext":"c"}}`), "allow", rewriteReason, "note"},
	}
	for name, c := range cases {
		h := composedHarness(t, ModeEnforce, c.body)
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "echo hi"))
		command, out := rewrittenCommand(t, res)
		if !strings.HasSuffix(command, "; echo hi") || strings.Count(command, "export ") != 1 {
			t.Errorf("%s: %q", name, command)
		}
		hso := out["hookSpecificOutput"].(map[string]any)
		if hso["permissionDecision"] != c.wantDecision || hso["permissionDecisionReason"] != c.wantReason {
			t.Errorf("%s: %+v", name, hso)
		}
		if c.wantExtra != "" && out["systemMessage"] != c.wantExtra {
			t.Errorf("%s: an upstream member was lost: %+v", name, out)
		}
	}
}

// When the upstream has nothing to say, the composed reply is the reply of the
// hook running alone.
func TestComposedSilentUpstreamEqualsTheStandaloneReply(t *testing.T) {
	alone := newHarness(t, ModeEnforce)
	startSession(t, alone, "")
	want := alone.fire(EventPreToolUseBash, bashPayload("", "", "ls -l"))
	h := composedHarness(t, ModeEnforce, "true")
	got := h.fire(EventPreToolUseBash, bashPayload("", "", "ls -l"))
	cmdWant, outWant := rewrittenCommand(t, want)
	cmdGot, outGot := rewrittenCommand(t, got)
	if strings.Replace(cmdWant, dirOf(t, cmdWant), "D", 1) != strings.Replace(cmdGot, dirOf(t, cmdGot), "D", 1) {
		t.Fatalf("commands differ: %q %q", cmdWant, cmdGot)
	}
	a, _ := json.Marshal(outWant["hookSpecificOutput"].(map[string]any)["permissionDecision"])
	b, _ := json.Marshal(outGot["hookSpecificOutput"].(map[string]any)["permissionDecision"])
	if !bytes.Equal(a, b) {
		t.Fatalf("decision differs: %s %s", a, b)
	}
}

// Warn mode, an issuer that fails, a session that does not exist, a command the
// hook already delivers: whatever the gatekeeper part does, the composed output is
// the upstream's own bytes, so the other hook's stamp is never lost.
func TestComposedOutputIsTheUpstreamsOwnWhenTheGatekeeperPartDoesNothing(t *testing.T) {
	stamp := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":{"command":"export STAMP=7; ls"}}}`
	t.Run("warn mode", func(t *testing.T) {
		h := composedHarness(t, ModeWarn, "echo e >&2; "+printing(stamp))
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if string(res.Stdout) != stamp || string(res.Stderr) != "e\n" || res.ExitCode != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("issuer failing", func(t *testing.T) {
		h := composedHarness(t, ModeEnforce, printing(stamp))
		h.hook.Issuer = UnavailableIssuer{Err: os.ErrPermission}
		res := h.fire(EventPreToolUseBash, bashPayload("agent-x", "example-builder", "ls"))
		if string(res.Stdout) != stamp {
			t.Fatalf("%q", res.Stdout)
		}
	})
	t.Run("no session", func(t *testing.T) {
		h := newHarness(t, ModeEnforce)
		h.hook.Compose = writeUpstream(t, printing(stamp))
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if string(res.Stdout) != stamp {
			t.Fatalf("%q", res.Stdout)
		}
	})
	t.Run("expired", func(t *testing.T) {
		h := composedHarness(t, ModeEnforce, printing(stamp))
		h.hook.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if string(res.Stdout) != stamp {
			t.Fatalf("%q", res.Stdout)
		}
	})
	t.Run("already delivered", func(t *testing.T) {
		own := `{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"export CLAGENTIC_IDENTITY_DIR=/x; ls"}}}`
		h := composedHarness(t, ModeEnforce, printing(own))
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if string(res.Stdout) != own {
			t.Fatalf("%q", res.Stdout)
		}
	})
	t.Run("agent without a record or a type", func(t *testing.T) {
		h := composedHarness(t, ModeEnforce, printing(stamp))
		res := h.fire(EventPreToolUseBash, map[string]any{
			"session_id": testSession, "tool_name": "Bash", "agent_id": "ghost", "tool_input": map[string]any{"command": "ls"},
		})
		if string(res.Stdout) != stamp {
			t.Fatalf("%q", res.Stdout)
		}
	})
}

func TestComposedHoldsTheUpstreamVerdictForAHookThatIsCutShort(t *testing.T) {
	h := composedHarness(t, ModeEnforce, printing(upstreamRewrite))
	if _, ok := h.hook.Held(); ok {
		t.Fatal("a verdict before any upstream ran")
	}
	h.fire(EventPreToolUseBash, bashPayload("", "", "ls -l"))
	held, ok := h.hook.Held()
	if !ok || string(held.Stdout) != upstreamRewrite {
		t.Fatalf("held %+v %v", held, ok)
	}
}

// An upstream that cannot start or has no verdict in time produces nothing, as a
// failed hook does: the call proceeds unchanged and nothing is blocked.
func TestComposedUpstreamWithoutAVerdictYieldsNothing(t *testing.T) {
	h := composedHarness(t, ModeEnforce, "true")
	dir := t.TempDir()
	notRegular := filepath.Join(dir, "adir")
	if err := os.Mkdir(notRegular, 0o755); err != nil {
		t.Fatal(err)
	}
	noExec := filepath.Join(dir, "noexec")
	if err := os.WriteFile(noExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, exe := range map[string]string{
		"missing":        filepath.Join(dir, "absent"),
		"relative":       "upstream.sh",
		"directory":      notRegular,
		"not executable": noExec,
	} {
		h.hook.Compose = exe
		res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
		if len(res.Stdout) != 0 || res.ExitCode != 0 {
			t.Errorf("%s: %+v", name, res)
		}
		if _, ok := h.hook.Held(); ok {
			t.Errorf("%s: a verdict was held", name)
		}
	}
	if !strings.Contains(h.log(), "composed hook") {
		t.Fatalf("the failures were not logged: %q", h.log())
	}
}

// The upstream gets exactly its budget: not cut off earlier, not allowed longer.
func TestComposedUpstreamBudgetIsExactlyTheRegisteredTimeout(t *testing.T) {
	h := composedHarness(t, ModeEnforce, "sleep 30")
	h.hook.UpstreamTimeout = 700 * time.Millisecond
	start := time.Now()
	res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	took := time.Since(start)
	if len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Fatalf("%+v", res)
	}
	if took < 700*time.Millisecond || took > 700*time.Millisecond+2*time.Second {
		t.Fatalf("the upstream was held for %s, budget 700ms", took)
	}

	// A hook that finishes inside the budget is waited for, however long it takes.
	h2 := composedHarness(t, ModeEnforce, "sleep 1; "+printing(upstreamRewrite))
	h2.hook.UpstreamTimeout = 4 * time.Second
	command, _ := rewrittenCommand(t, h2.fire(EventPreToolUseBash, bashPayload("", "", "ls -l")))
	if !strings.Contains(command, "UPSTREAM=1") {
		t.Fatalf("a slow upstream inside its budget lost its rewrite: %q", command)
	}
}

// A descendant that keeps the output pipe open after the upstream exited does not
// discard the upstream's reply.
func TestComposedUpstreamWaitDelayKeepsTheReply(t *testing.T) {
	h := composedHarness(t, ModeEnforce, "sleep 5 & "+printing(upstreamRewrite))
	start := time.Now()
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", "ls -l")))
	if !strings.Contains(command, "UPSTREAM=1") || time.Since(start) > 3*time.Second {
		t.Fatalf("%q after %s", command, time.Since(start))
	}
}

// The upstream is run directly from the registered path: no argument, no shell.
func TestComposedUpstreamGetsNoArguments(t *testing.T) {
	out := filepath.Join(t.TempDir(), "argc")
	h := composedHarness(t, ModeEnforce, "echo $# > "+out)
	h.fire(EventPreToolUseBash, bashPayload("", "", "ls; rm -rf $(echo x) {0,600}"))
	raw, err := os.ReadFile(out)
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("argc %q %v", raw, err)
	}
}

func TestPassThroughReturnsTheUpstreamVerdictOrNothing(t *testing.T) {
	exe := writeUpstream(t, "echo out; echo err >&2; exit 2")
	got := PassThrough(exe, strings.NewReader("{}"), 2*time.Second, Log{})
	if string(got.Stdout) != "out\n" || string(got.Stderr) != "err\n" || got.ExitCode != 2 {
		t.Fatalf("%+v", got)
	}
	got = PassThrough(filepath.Join(t.TempDir(), "absent"), strings.NewReader("{}"), time.Second, Log{})
	if len(got.Stdout) != 0 || got.ExitCode != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestCheckUpstreamRefusesWhatIsNotAnAbsoluteRegularFile(t *testing.T) {
	dir := t.TempDir()
	ok := writeUpstream(t, "true")
	if err := CheckUpstream(ok); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "rel/x", dir, filepath.Join(dir, "absent")} {
		if err := CheckUpstream(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
