//go:build linux

package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures under testdata/claude-2.1.316 are real hook payloads captured on
// Claude Code 2.1.316 with ids, paths, agent names and command text replaced by
// placeholders (docs/RUNTIME-HOOKS.md, "Capture provenance"). Key sets and the
// presence of each member are verbatim. replay feeds one fixture, event by event
// and in captured order, through the hook.

const fixtureDir = "testdata/claude-2.1.316"

type fixtureCall struct {
	AgentID string
	// Dir is the directory the call was rewritten to deliver, empty when the call
	// was left alone.
	Dir string
}

// replay returns one entry per PreToolUse event, in order. before is called with
// the index of the next event, so a test can look at state mid-sequence.
func replay(t *testing.T, h *harness, name string, before func(i int, event map[string]json.RawMessage)) []fixtureCall {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var events []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &events); err != nil {
		t.Fatal(err)
	}
	var calls []fixtureCall
	for i, ev := range events {
		if before != nil {
			before(i, ev)
		}
		body, _ := json.Marshal(ev)
		var kind string
		_ = json.Unmarshal(ev["hook_event_name"], &kind)
		event := map[string]string{
			"SessionStart": EventSessionStart, "SubagentStart": EventSubagentStart,
			"PreToolUse": EventPreToolUseBash, "SubagentStop": EventSubagentStop,
		}[kind]
		if event == "" {
			t.Fatalf("fixture %s event %d: unknown hook_event_name %q", name, i, kind)
		}
		res := h.hook.Handle(event, strings.NewReader(string(body)))
		if event != EventPreToolUseBash {
			if len(res.Stdout) != 0 {
				t.Fatalf("%s printed %q", event, res.Stdout)
			}
			continue
		}
		var id string
		_ = json.Unmarshal(ev["agent_id"], &id)
		call := fixtureCall{AgentID: id}
		if len(res.Stdout) != 0 {
			command, _, err := commandOf(res)
			if err != nil {
				t.Fatal(err)
			}
			call.Dir = dirOf(t, command)
		}
		calls = append(calls, call)
	}
	return calls
}

func sessionDir(t *testing.T, h *harness) string {
	t.Helper()
	rec, ok, err := h.hook.Store.Get(testSession, "")
	if err != nil || !ok {
		t.Fatalf("no session record: %v", err)
	}
	return rec.Dir
}

func childDir(t *testing.T, h *harness, id string) string {
	t.Helper()
	rec, ok, err := h.hook.Store.Get(testSession, id)
	if err != nil || !ok {
		t.Fatalf("no record for %s: %v", id, err)
	}
	return rec.Dir
}

// splitCalls checks every call with no agent_id received the session's
// directory, and returns the lead calls and the child calls.
func splitCalls(t *testing.T, calls []fixtureCall, session string) (lead, child []fixtureCall) {
	t.Helper()
	for _, c := range calls {
		if c.AgentID == "" {
			if c.Dir != session {
				t.Errorf("lead call got %q, want the session identity %q", c.Dir, session)
			}
			lead = append(lead, c)
			continue
		}
		child = append(child, c)
	}
	return lead, child
}

func TestFixtureLeadWithNoAgentGetsTheSessionIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	calls := replay(t, h, "lead-no-agent", nil)
	if lead, _ := splitCalls(t, calls, sessionDir(t, h)); len(lead) != 1 {
		t.Fatalf("calls %+v", calls)
	}
}

func TestFixtureLeadUnderAnAgentGetsTheSessionIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	calls := replay(t, h, "lead-agent", nil)
	if lead, _ := splitCalls(t, calls, sessionDir(t, h)); len(lead) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	if got := h.fake.sessionRequests(); len(got) != 1 || got[0].Definition != "example-lead" {
		t.Fatalf("session requests %+v", got)
	}
}

// The lead keeps its identity while a background child is live, with and without
// an agent definition.
func TestFixtureLeadKeepsItsIdentityWhileABackgroundChildIsLive(t *testing.T) {
	for _, name := range []string{"lead-agent-child-live", "lead-no-agent-child-live"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, ModeEnforce)
			liveDuringLeadCall := 0
			calls := replay(t, h, name, func(i int, ev map[string]json.RawMessage) {
				var kind string
				var id string
				_ = json.Unmarshal(ev["hook_event_name"], &kind)
				_ = json.Unmarshal(ev["agent_id"], &id)
				if kind != "PreToolUse" || id != "" {
					return
				}
				if _, ok, _ := h.hook.Store.Get(testSession, "a0000000000000001"); ok {
					liveDuringLeadCall++
				}
			})
			if liveDuringLeadCall == 0 {
				t.Fatal("no lead call was made while the child was live: the fixture does not test the case")
			}
			lead, child := splitCalls(t, calls, sessionDir(t, h))
			if len(lead) != 3 || len(child) != 1 {
				t.Fatalf("calls %+v", calls)
			}
		})
	}
}

func TestFixtureNamedChildGetsItsOwnIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	var childDirAtStop string
	calls := replay(t, h, "named-child", func(i int, ev map[string]json.RawMessage) {
		if string(ev["hook_event_name"]) == `"SubagentStop"` {
			childDirAtStop = childDir(t, h, "a0000000000000001")
		}
	})
	lead, child := splitCalls(t, calls, sessionDir(t, h))
	if len(lead) != 1 || len(child) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	if child[0].Dir == "" || child[0].Dir != childDirAtStop || child[0].Dir == sessionDir(t, h) {
		t.Fatalf("child got %q, its own is %q, the session's %q", child[0].Dir, childDirAtStop, sessionDir(t, h))
	}
	if reqs := h.fake.childRequests(); len(reqs) != 1 || reqs[0].AgentType != "example-child" || reqs[0].AgentID != "a0000000000000001" {
		t.Fatalf("child requests %+v", reqs)
	}
}

// A child that shares the lead's agent_type is told apart by its agent_id alone.
func TestFixtureSameTypeChildGetsItsOwnIdentityNeverTheSessions(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	calls := replay(t, h, "same-type-child", nil)
	lead, child := splitCalls(t, calls, sessionDir(t, h))
	if len(lead) != 1 || len(child) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	if child[0].Dir == "" || child[0].Dir == sessionDir(t, h) {
		t.Fatalf("child got %q, the session's is %q", child[0].Dir, sessionDir(t, h))
	}
}

// Fork outcome 1: a definition named fork exists, so the child is issued its own
// fork-typed identity.
func TestFixtureForkChildGetsItsOwnForkTypedIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	calls := replay(t, h, "fork-child", nil)
	lead, child := splitCalls(t, calls, sessionDir(t, h))
	if len(lead) != 1 || len(child) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	if child[0].Dir == "" || child[0].Dir == sessionDir(t, h) {
		t.Fatalf("fork child got %q, the session's is %q", child[0].Dir, sessionDir(t, h))
	}
	if reqs := h.fake.childRequests(); len(reqs) != 1 || reqs[0].AgentType != "fork" {
		t.Fatalf("child requests %+v", reqs)
	}
}

// Fork outcome 2: no definition of that name, so the issuer refuses and the child
// gets no identity. It never falls back to the session's.
func TestFixtureForkChildGetsNoIdentityWhenTheIssuerRefusesTheType(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.fake.RefuseChild = map[string]bool{"fork": true}
	calls := replay(t, h, "fork-child", nil)
	lead, child := splitCalls(t, calls, sessionDir(t, h))
	if len(lead) != 1 || len(child) != 1 {
		t.Fatalf("calls %+v", calls)
	}
	if child[0].Dir != "" {
		t.Fatalf("the refused fork child was given %q", child[0].Dir)
	}
	if !strings.Contains(h.log(), "definition_unknown") {
		t.Fatalf("the refusal was not logged: %q", h.log())
	}
}

func TestAgentlessCallClaimingAnotherAgentTypeGetsNoIdentity(t *testing.T) {
	leadPayload := func(t *testing.T) string {
		raw, err := os.ReadFile(filepath.Join(fixtureDir, "lead-agent.json"))
		if err != nil {
			t.Fatal(err)
		}
		var events []json.RawMessage
		if err := json.Unmarshal(raw, &events); err != nil {
			t.Fatal(err)
		}
		return string(events[1])
	}
	for _, tc := range []struct{ name, sessionType string }{
		{"session started under another type", "example-other"},
		{"session started without an agent_type", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, ModeEnforce)
			startSession(t, h, tc.sessionType)
			res := h.hook.Handle(EventPreToolUseBash, strings.NewReader(leadPayload(t)))
			if len(res.Stdout) != 0 {
				t.Fatalf("a call whose agent_type contradicts the session's got a rewrite: %s", res.Stdout)
			}
			if !strings.Contains(h.log(), "agentless-type-mismatch") {
				t.Fatalf("the decision was not logged: %q", h.log())
			}
		})
	}
}

// The session's recorded type is the one received, not the definition the
// issuer was asked for, so a type that is not a safe name is compared as sent.
func TestSessionAgentTypeIsComparedExactlyAsReceived(t *testing.T) {
	const odd = "Example Lead!"
	h := newHarness(t, ModeEnforce)
	startSession(t, h, odd)
	if got := h.fake.sessionRequests(); len(got) != 1 || got[0].Definition != "" {
		t.Fatalf("an unsafe name was sent as a definition: %+v", got)
	}
	payload := func(typ string) map[string]any {
		p := bashPayload("", "", programCommand)
		p["agent_type"] = typ
		return p
	}
	if res := h.fire(EventPreToolUseBash, payload(odd)); len(res.Stdout) == 0 {
		t.Fatal("the lead's own agent_type was refused")
	}
	if res := h.fire(EventPreToolUseBash, payload("example lead!")); len(res.Stdout) != 0 {
		t.Fatalf("a different agent_type was delivered to: %s", res.Stdout)
	}
	if res := h.fire(EventPreToolUseBash, bashPayload("", "", programCommand)); len(res.Stdout) == 0 {
		t.Fatal("a call without agent_type was refused")
	}
}

// Child records neither gate nor are consulted for the lead: an expired record, an
// unreadable one, or a session refresh that writes a new session record changes
// nothing about what the lead is given.
func TestLeadDeliveryDoesNotDependOnChildRecordsOrRefresh(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	h.hook.RefreshBelow = 24 * time.Hour
	startSession(t, h, "example-lead")
	if err := h.hook.Store.Put(testSession, "old-agent", Record{Dir: "/x", ExpiresAt: time.Now().Add(-time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.state, testSession, "agent-bad.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	lead := func() string {
		p := bashPayload("", "", programCommand)
		p["agent_type"] = "example-lead"
		res := h.fire(EventPreToolUseBash, p)
		command, _ := rewrittenCommand(t, res)
		return dirOf(t, command)
	}
	before := lead()
	h.fire(EventUserPromptSubmit, map[string]any{"session_id": testSession})
	after := lead()
	if after != sessionDir(t, h) || after == before {
		t.Fatalf("after a refresh the lead got %q (was %q), the session record names %q", after, before, sessionDir(t, h))
	}
	if rec, _, _ := h.hook.Store.Get(testSession, ""); rec.StartAgentType != "example-lead" {
		t.Fatalf("the refresh lost the session's agent_type: %+v", rec)
	}
}

func TestNoIdentityDecisionsAreLoggedInEnforceModeOnly(t *testing.T) {
	expire := func(t *testing.T, h *harness) {
		rec, _, _ := h.hook.Store.Get(testSession, "")
		rec.ExpiresAt = time.Now().Add(-time.Minute).Unix()
		if err := h.hook.Store.Put(testSession, "", rec); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		decision string
		setup    func(t *testing.T, h *harness) map[string]any
	}{
		{"agentless-type-mismatch", func(t *testing.T, h *harness) map[string]any {
			startSession(t, h, "example-lead")
			p := bashPayload("", "", programCommand)
			p["agent_type"] = "example-other"
			return p
		}},
		{"expired", func(t *testing.T, h *harness) map[string]any {
			startSession(t, h, "")
			expire(t, h)
			return bashPayload("", "", programCommand)
		}},
		{"no-session", func(t *testing.T, h *harness) map[string]any {
			return bashPayload("", "", programCommand)
		}},
	} {
		t.Run(tc.decision, func(t *testing.T) {
			h := newHarness(t, ModeEnforce)
			p := tc.setup(t, h)
			if res := h.fire(EventPreToolUseBash, p); len(res.Stdout) != 0 {
				t.Fatalf("rewrote: %s", res.Stdout)
			}
			if !strings.Contains(h.log(), tc.decision) {
				t.Fatalf("%s not logged: %q", tc.decision, h.log())
			}
		})
	}
	t.Run("dir-unusable", func(t *testing.T) {
		h := newHarness(t, ModeEnforce)
		startSession(t, h, "")
		if err := os.RemoveAll(sessionDir(t, h)); err != nil {
			t.Fatal(err)
		}
		if res := h.fire(EventPreToolUseBash, bashPayload("", "", programCommand)); len(res.Stdout) != 0 {
			t.Fatalf("rewrote: %s", res.Stdout)
		}
		if !strings.Contains(h.log(), "pre-tool-use-bash session="+testSession) || !strings.Contains(h.log(), "no such file") {
			t.Fatalf("dir-unusable not logged: %q", h.log())
		}
	})
	t.Run("a delivery is not logged as a refusal", func(t *testing.T) {
		h := newHarness(t, ModeEnforce)
		startSession(t, h, "")
		h.fire(EventPreToolUseBash, bashPayload("", "", programCommand))
		if strings.Contains(h.log(), "no identity delivered") {
			t.Fatalf("a delivery was logged as a refusal: %q", h.log())
		}
	})
}

// The chained path calls the same prefix, so it inherits the rule.
func TestComposedPathAppliesTheTypeMismatchRefusalAndKeepsTheLeadsIdentity(t *testing.T) {
	h := composedHarness(t, ModeEnforce, "true")
	h.fire(EventSessionStart, map[string]any{"hook_event_name": "SessionStart", "session_id": testSession, "agent_type": "example-lead"})
	startAgent(t, h, "agent-one", "example-child")

	p := bashPayload("", "", programCommand)
	p["agent_type"] = "example-other"
	if res := h.fire(EventPreToolUseBash, p); strings.Contains(string(res.Stdout), EnvDir) {
		t.Fatalf("the composed reply carries the identity: %s", res.Stdout)
	}
	p["agent_type"] = "example-lead"
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, p))
	if dirOf(t, command) != sessionDir(t, h) {
		t.Fatalf("the lead with a live child got %q, want the session's %q", dirOf(t, command), sessionDir(t, h))
	}
}
