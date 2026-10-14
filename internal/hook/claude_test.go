//go:build linux

package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

func startSession(t *testing.T, h *harness, agentType string) {
	t.Helper()
	p := map[string]any{"hook_event_name": "SessionStart", "session_id": testSession, "source": "startup"}
	if agentType != "" {
		p["agent_type"] = agentType
	}
	if res := h.fire(EventSessionStart, p); len(res.Stdout) != 0 {
		t.Fatalf("session-start printed %q: stdout of a SessionStart hook becomes model context", res.Stdout)
	}
}

func startAgent(t *testing.T, h *harness, id, typ string) {
	t.Helper()
	res := h.fire(EventSubagentStart, map[string]any{"hook_event_name": "SubagentStart", "session_id": testSession, "agent_id": id, "agent_type": typ})
	if len(res.Stdout) != 0 {
		t.Fatalf("subagent-start printed %q", res.Stdout)
	}
}

func TestSessionStartIssuesForTheHarnessAgentNameOnly(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.hook.Origin = "agent"
	startSession(t, h, "example-builder")
	got := h.fake.sessionRequests()
	if len(got) != 1 || got[0].Definition != "example-builder" || got[0].Origin != "agent" || got[0].Runtime != nil {
		t.Fatalf("session requests %+v", got)
	}

	h2 := newHarness(t, ModeEnforce)
	startSession(t, h2, "")
	if s := h2.fake.sessionRequests(); len(s) != 1 || s[0].Definition != "" || s[0].Origin != "" {
		t.Fatalf("no harness agent name: %+v", s)
	}
}

func TestAdapterNeverRequestsAHumanGrade(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "example-builder")
	startAgent(t, h, "a1", "example-builder")
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": testSession})
	for _, s := range h.fake.sessionRequests() {
		if s.Origin == "human" {
			t.Fatalf("a request asked for origin human: %+v", s)
		}
	}
}

// A hook configured with origin human sends nothing and logs the one constant
// message; the process adapter refuses before it opens a connection.
func TestOriginHumanIsRefusedLocallyAndNeverSent(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.hook.Origin = "human"
	startSession(t, h, "")
	if n := len(h.fake.sessionRequests()); n != 0 {
		t.Fatalf("%d requests left the process", n)
	}
	if !strings.Contains(h.log(), ErrOriginHuman.Error()) {
		t.Fatalf("log %q", h.log())
	}
	if _, err := ProcessAssignment(h.hook.Issuer, "example-builder", "human"); err == nil || err.Error() != ErrOriginHuman.Error() {
		t.Fatalf("got %v", err)
	}
	if n := len(h.fake.sessionRequests()); n != 0 {
		t.Fatalf("the process adapter sent a request: %d", n)
	}
}

func TestSubagentGetsAChildOfTheSessionAndItsOwnDirectory(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	children := h.fake.childRequests()
	if len(children) != 1 {
		t.Fatalf("children %+v", children)
	}
	c := children[0]
	if c.AgentID != "agent-one" || c.AgentType != "example-builder" || !strings.HasPrefix(c.ParentToken, "session-token-") {
		t.Fatalf("child request %+v", c)
	}
}

// The reply for a rewritten call is the only place a permission decision appears.
func TestRewriteAddsExactlyOneExportStatementAndKeepsTheCommandByteForByte(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	commands := []string{
		"echo a; echo b",
		"make build && make test",
		"cat file | sort | uniq -c",
		"(cd /tmp && ls)",
		"cat <<'EOF'\nrm -rf /tmp/x {0,600}\nEOF",
		`grep -E 'a{1,3}' f; rm -f out; echo "{a..b}" > /dev/null`,
		"VAR=1 env | head",
		"echo $(date) `date`",
	}
	for _, original := range commands {
		res := h.fire(EventPreToolUseBash, bashPayload("", "", original))
		command, out := rewrittenCommand(t, res)
		dir := dirOf(t, command)
		if want := "export " + EnvDir + "=" + dir + "; " + original; command != want {
			t.Errorf("rewritten command\n got %q\nwant %q", command, want)
		}
		if strings.Contains(command, "sh -c") || strings.Contains(command, "bash -c") {
			t.Errorf("a shell wrapper was added: %q", command)
		}
		if strings.Count(command, EnvDir) != strings.Count(original, EnvDir)+1 {
			t.Errorf("more than one delivery statement: %q", command)
		}
		hso := out["hookSpecificOutput"].(map[string]any)
		if hso["permissionDecision"] != "allow" || hso["hookEventName"] != "PreToolUse" {
			t.Errorf("reply %+v", hso)
		}
		updated := hso["updatedInput"].(map[string]any)
		if updated["timeout"] != float64(60000) || updated["run_in_background"] != false || updated["description"] != "d" {
			t.Errorf("tool_input members were lost: %+v", updated)
		}
	}
}

// Every outcome that does not rewrite the call returns nothing at all, so the
// runtime's own permission flow is untouched.
func TestUnrewrittenCallsReturnNoPermissionDecision(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	cases := map[string]Result{}
	// No session yet.
	cases["no session"] = h.fire(EventPreToolUseBash, bashPayload("", "", "ls"))
	startSession(t, h, "")
	cases["not a bash tool"] = h.fire(EventPreToolUseBash, map[string]any{
		"session_id": testSession, "tool_name": "Read", "tool_input": map[string]any{"file_path": "/x"},
	})
	cases["no command"] = h.fire(EventPreToolUseBash, map[string]any{
		"session_id": testSession, "tool_name": "Bash", "tool_input": map[string]any{},
	})
	cases["command is not a string"] = h.fire(EventPreToolUseBash, map[string]any{
		"session_id": testSession, "tool_name": "Bash", "tool_input": map[string]any{"command": 7},
	})
	cases["already delivered"] = h.fire(EventPreToolUseBash, bashPayload("", "", "export "+EnvDir+"=/x; ls"))
	cases["agent without type"] = h.fire(EventPreToolUseBash, map[string]any{
		"session_id": testSession, "tool_name": "Bash", "agent_id": "a1", "tool_input": map[string]any{"command": "ls"},
	})
	cases["unsafe session id"] = h.fire(EventPreToolUseBash, map[string]any{
		"session_id": "../x", "tool_name": "Bash", "tool_input": map[string]any{"command": "ls"},
	})
	for name, res := range cases {
		if len(res.Stdout) != 0 || res.ExitCode != 0 {
			t.Errorf("%s: stdout %q exit %d", name, res.Stdout, res.ExitCode)
		}
	}
	if res := h.hook.Handle(EventPreToolUseBash, strings.NewReader("not json")); len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Errorf("a garbled payload: %+v", res)
	}
	if res := h.hook.Handle("no-such-event", strings.NewReader("{}")); len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Errorf("an unknown event: %+v", res)
	}
}

func TestEveryNonPreToolUseEventPrintsNothing(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "example-builder")
	startAgent(t, h, "a1", "example-builder")
	for _, ev := range []string{EventSubagentStop, EventUserPromptSubmit, EventSessionStart, EventSubagentStart} {
		res := h.fire(ev, map[string]any{"session_id": testSession, "agent_id": "a1", "agent_type": "example-builder"})
		if len(res.Stdout) != 0 || len(res.Stderr) != 0 || res.ExitCode != 0 {
			t.Errorf("%s: %+v", ev, res)
		}
	}
}

func TestTwoConcurrentSubagentsEachGetTheirOwnDirectory(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-a", "example-builder")
	startAgent(t, h, "agent-b", "example-merger")

	var wg sync.WaitGroup
	dirs := map[string]string{}
	var mu sync.Mutex
	for _, a := range []struct{ id, typ string }{{"agent-a", "example-builder"}, {"agent-b", "example-merger"}, {"", ""}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.fire(EventPreToolUseBash, bashPayload(a.id, a.typ, "echo hi"))
			command, _, err := commandOf(res)
			if err != nil {
				t.Errorf("agent %q: %v", a.id, err)
				return
			}
			dir, err := dirIn(command)
			if err != nil {
				t.Errorf("agent %q: %v", a.id, err)
				return
			}
			mu.Lock()
			dirs[a.id] = dir
			mu.Unlock()
		}()
	}
	wg.Wait()
	if dirs["agent-a"] == dirs["agent-b"] || dirs["agent-a"] == dirs[""] || dirs["agent-b"] == dirs[""] {
		t.Fatalf("agents share a directory: %v", dirs)
	}
	// Each directory holds the token issued for that agent's own definition.
	for id, typ := range map[string]string{"agent-a": "example-builder", "agent-b": "example-merger"} {
		tok, err := os.ReadFile(filepath.Join(dirs[id], identity.DeliveryFile))
		if err != nil || !strings.Contains(string(tok), "child-token-"+id) {
			t.Errorf("%s (%s): %q %v", id, typ, tok, err)
		}
	}
	types := map[string]string{}
	for _, c := range h.fake.childRequests() {
		types[c.AgentID] = c.AgentType
	}
	if types["agent-a"] != "example-builder" || types["agent-b"] != "example-merger" {
		t.Fatalf("child requests %v", types)
	}
}

// A spawn whose start event never arrived (or arrived without an id) is still
// delivered an assertion on its first Bash call.
func TestFirstBashCallIssuesTheChildWhenStartWasMissed(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	res := h.fire(EventPreToolUseBash, bashPayload("late-agent", "example-builder", "ls"))
	command, _ := rewrittenCommand(t, res)
	if dirOf(t, command) == "" || len(h.fake.childRequests()) != 1 {
		t.Fatalf("children %+v", h.fake.childRequests())
	}
	// A second call reuses the directory.
	res = h.fire(EventPreToolUseBash, bashPayload("late-agent", "example-builder", "ls"))
	again, _ := rewrittenCommand(t, res)
	if dirOf(t, again) != dirOf(t, command) || len(h.fake.childRequests()) != 1 {
		t.Fatalf("a second call issued again: %d children", len(h.fake.childRequests()))
	}
}

// The delivery lookup is keyed by the agent id alone: the type is needed only to
// issue, so a call that carries just the id finds the directory issued at start.
func TestPreToolUseWithOnlyAnAgentIDFindsTheDirectoryIssuedAtStart(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	issued, ok, err := h.hook.Store.Get(testSession, "agent-one")
	if err != nil || !ok {
		t.Fatalf("no record after start: %v", err)
	}
	res := h.fire(EventPreToolUseBash, map[string]any{
		"session_id": testSession, "tool_name": "Bash", "agent_id": "agent-one",
		"tool_input": map[string]any{"command": "ls"},
	})
	command, _ := rewrittenCommand(t, res)
	if dirOf(t, command) != issued.Dir {
		t.Fatalf("delivered %q, issued %q", dirOf(t, command), issued.Dir)
	}
	if n := len(h.fake.childRequests()); n != 1 {
		t.Fatalf("a second child was issued: %d", n)
	}
}

// Payload-derived keys are refused by the Store itself, so no call site can skip
// the check, and a refused key creates nothing on disk.
func TestStoreRefusesUnsafeKeysItself(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	s := Store{Root: root}
	rec := Record{Dir: "/x", ExpiresAt: 1}
	bad := []string{"", ".", "..", "../x", "a/b", `a\b`, "a\x00b", ".hidden", "-x", strings.Repeat("a", 129), "a b", "a\nb"}
	for _, key := range bad {
		pairs := [][2]string{{key, ""}, {key, "agent-ok"}}
		// An empty agent id names the session record, which is valid.
		if key != "" {
			pairs = append(pairs, [2]string{testSession, key})
		}
		for _, pair := range pairs {
			if _, _, err := s.Get(pair[0], pair[1]); err == nil {
				t.Errorf("Get(%q,%q) accepted", pair[0], pair[1])
			}
			if err := s.Put(pair[0], pair[1], rec); err == nil {
				t.Errorf("Put(%q,%q) accepted", pair[0], pair[1])
			}
			if _, err := s.PutNew(pair[0], pair[1], rec); err == nil {
				t.Errorf("PutNew(%q,%q) accepted", pair[0], pair[1])
			}
			if err := s.Delete(pair[0], pair[1]); err == nil {
				t.Errorf("Delete(%q,%q) accepted", pair[0], pair[1])
			}
		}
	}
	if entries, err := os.ReadDir(root); err == nil && len(entries) != 0 {
		t.Fatalf("a refused key left %v", entries)
	}
	if err := s.Put(testSession, "agent-ok", rec); err != nil {
		t.Fatal(err)
	}
}

// Parallel tool calls of one agent race to deliver; exactly one directory
// survives and every call names it.
func TestRacingCallsOfOneAgentConvergeOnOneDirectory(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := h.fire(EventPreToolUseBash, bashPayload("racer", "example-builder", "ls"))
			command, _, err := commandOf(res)
			if err != nil {
				t.Errorf("racer: %v", err)
				return
			}
			dir, err := dirIn(command)
			if err != nil {
				t.Errorf("racer: %v", err)
				return
			}
			mu.Lock()
			seen[dir] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(seen) != 1 {
		t.Fatalf("calls named %d directories: %v", len(seen), seen)
	}
	// The session directory and the winner's: every loser removed its own.
	if dirs := h.fake.deliveryDirs(); len(dirs) != 2 {
		t.Fatalf("delivery directories left: %v", dirs)
	}
}

func TestSubagentStopRemovesTheDirectoryAndTheRecord(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("agent-one", "example-builder", "ls")))
	dir := dirOf(t, command)
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	// The holder wrote into its scratch directory.
	if err := os.WriteFile(filepath.Join(dir, "tmp", "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.fire(EventSubagentStop, map[string]any{"session_id": testSession, "agent_id": "agent-one", "agent_type": "example-builder"})
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the directory is still there: %v", err)
	}
	if _, ok, _ := h.hook.Store.Get(testSession, "agent-one"); ok {
		t.Fatal("the record is still there")
	}
	// A stopped agent's old path is never handed out again: a resumed agent gets
	// a fresh child, not the removed directory.
	command, _ = rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("agent-one", "example-builder", "ls")))
	if dirOf(t, command) == dir {
		t.Fatal("the removed directory was delivered again")
	}
}

func TestSubagentStopLeavesTheSessionAndSiblingsAlone(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-a", "example-builder")
	startAgent(t, h, "agent-b", "example-builder")
	h.fire(EventSubagentStop, map[string]any{"session_id": testSession, "agent_id": "agent-a"})
	for _, id := range []string{"", "agent-b"} {
		typ := ""
		if id != "" {
			typ = "example-builder"
		}
		res := h.fire(EventPreToolUseBash, bashPayload(id, typ, "ls"))
		if len(res.Stdout) == 0 {
			t.Errorf("%q lost its delivery", id)
		}
	}
}

func TestRemoveDeliveryRefusesWhatTheIssuerDidNotCreate(t *testing.T) {
	base := t.TempDir()
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(victim, identity.DeliveryFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDelivery(victim); err == nil {
		t.Error("a directory not named like a delivery directory was removed")
	}
	named := filepath.Join(base, "6000000001-00000000000000000000000000000001")
	if err := os.Mkdir(named, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDelivery(named); err == nil {
		t.Error("a directory holding no assertion was removed")
	}
	link := filepath.Join(base, "6000000002-00000000000000000000000000000002")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDelivery(link); err == nil {
		t.Error("a symlink was followed")
	}
	if _, err := os.Stat(filepath.Join(victim, identity.DeliveryFile)); err != nil {
		t.Errorf("the symlink target lost its content: %v", err)
	}
	if err := RemoveDelivery("relative/6000000003-00000000000000000000000000000003"); err == nil {
		t.Error("a relative path was accepted")
	}
	if err := RemoveDelivery(filepath.Join(base, "gone", "6000000004-00000000000000000000000000000004")); err != nil {
		t.Errorf("an already-missing directory is not an error: %v", err)
	}
}

func TestStateRecordNamingAnotherPathCannotMakeStopDeleteIt(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	victim := t.TempDir()
	if err := os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.hook.Store.Put(testSession, "evil", Record{Dir: victim, ExpiresAt: time.Now().Unix() + 100}); err != nil {
		t.Fatal(err)
	}
	h.fire(EventSubagentStop, map[string]any{"session_id": testSession, "agent_id": "evil"})
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatalf("stop deleted a path outside the issuer's naming: %v", err)
	}
}

func TestUserPromptSubmitRefreshesOnlyBelowTheThreshold(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.hook.RefreshBelow = 10 * time.Minute
	h.fake.TTL = 3600
	startSession(t, h, "example-builder")
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": testSession})
	if s, _ := h.fake.counts(); s != 1 {
		t.Fatalf("refreshed with an hour left: %d session requests", s)
	}
	before, _, _ := h.hook.Store.Get(testSession, "")
	h.hook.Now = func() time.Time { return time.Now().Add(55 * time.Minute) }
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": testSession})
	if s, _ := h.fake.counts(); s != 2 {
		t.Fatalf("did not refresh with five minutes left: %d session requests", s)
	}
	after, _, _ := h.hook.Store.Get(testSession, "")
	if after.Dir == before.Dir || after.Definition != "example-builder" {
		t.Fatalf("record %+v -> %+v", before, after)
	}
	if h.fake.sessions[1].Definition != "example-builder" {
		t.Fatalf("the refresh asked for %+v", h.fake.sessions[1])
	}
	// A command already running under the old directory keeps working.
	if _, err := os.Stat(before.Dir); err != nil {
		t.Fatalf("the previous session directory was removed: %v", err)
	}
}

func TestUserPromptSubmitWithRefreshDisabledDoesNothing(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": testSession})
	if s, _ := h.fake.counts(); s != 1 {
		t.Fatalf("%d session requests", s)
	}
}

func TestExpiredAssertionIsNotDelivered(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	h.hook.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls")); len(res.Stdout) != 0 {
		t.Fatalf("an expired assertion was delivered: %q", res.Stdout)
	}
}

func TestWarnModeRewritesNothingAndCapturesShapesWithoutValues(t *testing.T) {
	h := newHarness(t, ModeWarn)
	startSession(t, h, "example-builder")
	startAgent(t, h, "agent-one", "example-builder")
	secret := "echo super-secret-value-12345"
	res := h.fire(EventPreToolUseBash, bashPayload("agent-one", "example-builder", secret))
	if len(res.Stdout) != 0 {
		t.Fatalf("warn mode rewrote a call: %q", res.Stdout)
	}
	raw, err := os.ReadFile(filepath.Join(h.state, "shapes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), "agent-one") || strings.Contains(string(raw), testSession) {
		t.Fatalf("a payload value reached the capture: %s", raw)
	}
	var entries []CaptureEntry
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e CaptureEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 3 {
		t.Fatalf("%d capture entries: %s", len(entries), raw)
	}
	last := entries[2]
	if last.Event != EventPreToolUseBash || last.Decision != "would-deliver" || last.Members["agent_id"] != "string" ||
		last.Members["tool_input"] != "object" || last.ToolInput["command"] != "string" || last.ToolInput["run_in_background"] != "boolean" {
		t.Fatalf("pre-tool-use capture %+v", last)
	}
	if len(last.Ancestry) == 0 || last.Ancestry[0].PID != os.Getpid() {
		t.Fatalf("the process tree was not captured: %+v", last.Ancestry)
	}
}

func TestEnforceModeDoesNotCapture(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	if _, err := os.Stat(filepath.Join(h.state, "shapes.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("enforce mode wrote a capture file: %v", err)
	}
}

func TestIssuerFailuresNeverBlockOrPrint(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.fake.Fail = true
	startSession(t, h, "example-unknown")
	if !strings.Contains(h.log(), "definition_unknown") {
		t.Fatalf("the failure was not logged: %q", h.log())
	}
	if res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls")); len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Fatalf("a call after a failed session start: %+v", res)
	}
	startAgent(t, h, "a1", "example-builder")
	if res := h.fire(EventPreToolUseBash, bashPayload("a1", "example-builder", "ls")); len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Fatalf("a call by an agent with no session: %+v", res)
	}
}

func TestIssuerDownIsLoggedAndHarmless(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.hook.Issuer = identity.Client{Socket: filepath.Join(t.TempDir(), "absent.sock"), Timeout: time.Second}
	startSession(t, h, "")
	if res := h.fire(EventPreToolUseBash, bashPayload("", "", "ls")); len(res.Stdout) != 0 || res.ExitCode != 0 {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(h.log(), "absent.sock") {
		t.Fatalf("log %q", h.log())
	}
}

func TestSlowIssuerIsBoundedByTheCallTimeout(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.fake.Delay = 3 * time.Second
	h.hook.Issuer = identity.Client{Socket: h.fake.Socket, Timeout: 300 * time.Millisecond}
	start := time.Now()
	startSession(t, h, "")
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("a slow issuer held the hook for %s", took)
	}
}

func TestUndeliverablePathIsRefusedNotQuoted(t *testing.T) {
	for _, dir := range []string{"/tmp/a b/6000000001-00000000000000000000000000000001", "/tmp/a;b", "/tmp/$(x)", "/tmp/a'b", "relative", "/tmp/../x", "/tmp/a{b,c}", "/tmp/a`b`"} {
		if _, err := ExportStatement(dir); err == nil {
			t.Errorf("%q was accepted", dir)
		}
	}
	if s, err := ExportStatement("/run/gk/spawn/6000000001-00000000000000000000000000000001"); err != nil || s != "export CLAGENTIC_IDENTITY_DIR=/run/gk/spawn/6000000001-00000000000000000000000000000001; " {
		t.Fatalf("%q %v", s, err)
	}
}

func TestPruneRemovesOnlyOldSessionState(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	old := filepath.Join(h.state, "old-session")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	h.hook.Store.Prune(time.Now(), pruneAfter)
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old state kept: %v", err)
	}
	if _, ok, _ := h.hook.Store.Get(testSession, ""); !ok {
		t.Error("the live session state was pruned")
	}
}

func TestStateDirectoryOthersCanWriteIsRefused(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	if err := os.MkdirAll(h.state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.state, 0o777); err != nil {
		t.Fatal(err)
	}
	startSession(t, h, "")
	if _, ok, _ := h.hook.Store.Get(testSession, ""); ok {
		t.Fatal("state was kept in a directory others can write")
	}
	if !strings.Contains(h.log(), "writable by group or other") {
		t.Fatalf("log %q", h.log())
	}
}
