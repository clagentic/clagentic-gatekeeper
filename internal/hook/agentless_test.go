//go:build linux

package hook

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The fixture is the sanitized shape of a PreToolUse Bash payload that carries an
// agent_type and no agent_id, captured on Claude Code 2.1.316 (see
// docs/RUNTIME-HOOKS.md): ids, paths and the agent name are placeholders.
const agentlessFixture = "testdata/pretooluse-bash-subagent-no-agent-id.json"

func fireFixture(t *testing.T, h *harness) Result {
	t.Helper()
	raw, err := os.ReadFile(agentlessFixture)
	if err != nil {
		t.Fatal(err)
	}
	return h.hook.Handle(EventPreToolUseBash, strings.NewReader(string(raw)))
}

func TestAgentlessSubagentPayloadWhileAChildIsLiveGetsNoIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	res := fireFixture(t, h)
	if len(res.Stdout) != 0 {
		t.Fatalf("an agent_id-less call got a rewrite: %s", res.Stdout)
	}
}

func TestAgentlessParentPayloadWithNoLiveChildStillGetsTheSessionIdentity(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	res := fireFixture(t, h)
	command, _ := rewrittenCommand(t, res)
	sess, ok, err := h.hook.Store.Get(testSession, "")
	if err != nil || !ok || dirOf(t, command) != sess.Dir {
		t.Fatalf("session identity not delivered: %q (%v)", command, err)
	}
}

func TestParentDeliveryResumesOnceTheChildStops(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	h.fire(EventSubagentStop, map[string]any{"hook_event_name": "SubagentStop", "session_id": testSession, "agent_id": "agent-one"})
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", programCommand)))
	if dirOf(t, command) == "" {
		t.Fatal("no delivery after the child stopped")
	}
}

func TestAnExpiredChildRecordIsNotLive(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	if err := h.hook.Store.Put(testSession, "old-agent", Record{Dir: "/x", ExpiresAt: time.Now().Add(-time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("", "", programCommand)))
}

func TestAnUnreadableChildRecordCountsAsLive(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	if _, ok, _ := h.hook.Store.Get(testSession, "x"); ok {
		t.Fatal("unexpected record")
	}
	if err := os.WriteFile(h.state+"/"+testSession+"/agent-bad.json", []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := h.fire(EventPreToolUseBash, bashPayload("", "", programCommand)); len(res.Stdout) != 0 {
		t.Fatalf("delivered past an unreadable child record: %s", res.Stdout)
	}
}

func TestAgentIDPayloadStillGetsItsOwnIdentityWhileSiblingsAreLive(t *testing.T) {
	h := newHarness(t, ModeEnforce)
	startSession(t, h, "")
	startAgent(t, h, "agent-one", "example-builder")
	rec, _, _ := h.hook.Store.Get(testSession, "agent-one")
	command, _ := rewrittenCommand(t, h.fire(EventPreToolUseBash, bashPayload("agent-one", "example-builder", programCommand)))
	if dirOf(t, command) != rec.Dir {
		t.Fatalf("delivered %q, want %q", dirOf(t, command), rec.Dir)
	}
}

// The chained path calls the same prefix, so it inherits the rule.
func TestComposedPathAlsoWithholdsIdentityFromAnAgentlessCallWhileAChildIsLive(t *testing.T) {
	h := composedHarness(t, ModeEnforce, printing(upstreamRewrite))
	startAgent(t, h, "agent-one", "example-builder")
	res := fireFixture(t, h)
	if strings.Contains(string(res.Stdout), EnvDir) {
		t.Fatalf("the composed reply carries the identity: %s", res.Stdout)
	}
}
