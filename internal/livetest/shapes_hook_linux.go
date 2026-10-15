//go:build linux

package livetest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const deliveryPrefix = "export CLAGENTIC_IDENTITY_DIR="

func (e *Env) hookShapes() []shape {
	return []shape{
		{"adapter-claude-code/event-sequence-payload-driven", e.shapeHookSequence},
		{"adapter-claude-code/compose-synthetic-upstream", e.shapeHookCompose},
	}
}

// hookArgs is a hook invocation in enforce mode. rest follows the event
// directly, which is where a composed hook must be named.
func (e *Env) hookArgs(event, state string, rest ...string) []string {
	args := append([]string{"hook", "claude-code", event}, rest...)
	return append(args, "--socket", e.Sock, "--state-dir", state, "--mode", "enforce")
}

// hook runs one hook process with a payload on stdin, directly or under a
// command wrapper.
func (e *Env) hook(ctx context.Context, viaWrapper bool, payload string, args []string) (procResult, error) {
	if !viaWrapper {
		return e.gkIn(ctx, payload, args...)
	}
	sh, err := lookShell()
	if err != nil {
		return procResult{}, err
	}
	return e.gkIn2(ctx, payload, sh, append([]string{"-c", `"$0" "$@"; echo wrapped >&2`, e.Bin}, args...)...)
}

func (e *Env) gkIn(ctx context.Context, stdin string, args ...string) (procResult, error) {
	return e.gkIn2(ctx, stdin, e.Bin, args...)
}

func (e *Env) gkIn2(ctx context.Context, stdin, name string, args ...string) (procResult, error) {
	ctx, cancel := context.WithTimeout(ctx, minute)
	defer cancel()
	return e.run(ctx, runOpts{Stdin: stdin}, name, args...)
}

// silent requires a hook that must print nothing and not fail.
func silent(what string, res procResult, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if res.Code != 0 || res.Stdout != "" {
		return fmt.Errorf("%s: exit %d stdout %.200q stderr %.200q", what, res.Code, res.Stdout, res.Stderr)
	}
	return nil
}

// rewrite is the reply of a pre-tool-use-bash hook that changed the command.
type rewrite struct {
	Specific struct {
		Decision string `json:"permissionDecision"`
		Updated  struct {
			Command string `json:"command"`
		} `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

func decodeRewrite(stdout string) (rewrite, error) {
	var r rewrite
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		return r, fmt.Errorf("reply %.200q is not a rewrite: %w", stdout, err)
	}
	return r, nil
}

// splitDelivery separates the one statement the hook adds from the command it
// was added to.
func splitDelivery(command string) (dir, rest string, ok bool) {
	after, ok := strings.CutPrefix(command, deliveryPrefix)
	if !ok {
		return "", "", false
	}
	dir, rest, ok = strings.Cut(after, "; ")
	return dir, rest, ok
}

// bashCall runs a pre-tool-use-bash hook for one command and returns the
// delivery directory it prefixed, checking that the original text follows byte
// for byte and that the reply carries no permission decision.
func (e *Env) bashCall(ctx context.Context, state, agentID, command string) (string, error) {
	payload := map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "live-s1", "tool_name": "Bash",
		"tool_input": map[string]any{"command": command},
	}
	if agentID != "" {
		payload["agent_id"], payload["agent_type"] = agentID, defBuilder
	}
	raw, _ := json.Marshal(payload)
	res, err := e.hook(ctx, false, string(raw), e.hookArgs("pre-tool-use-bash", state))
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", fmt.Errorf("exit %d: %.200s", res.Code, res.Stderr)
	}
	r, err := decodeRewrite(res.Stdout)
	if err != nil {
		return "", err
	}
	dir, rest, ok := splitDelivery(r.Specific.Updated.Command)
	if !ok || rest != command {
		return "", fmt.Errorf("rewrite %.200q does not prefix exactly one statement to %q", r.Specific.Updated.Command, command)
	}
	if r.Specific.Decision != "" {
		return "", fmt.Errorf("the hook returned a permission decision %q", r.Specific.Decision)
	}
	return dir, nil
}

// shapeHookSequence drives the adapter's events as separate hook processes with
// the payload shapes the runtime sends, against the live issuer. It needs no
// runtime, so it covers the adapter on every host.
func (e *Env) shapeHookSequence(ctx context.Context) error {
	state := filepath.Join(e.Dir, "hook-state")
	const command = "echo one; rm -f x && echo {0,600}"

	err := e.hookEvent(ctx, false, state, "session-start", `{"hook_event_name":"SessionStart","session_id":"live-s1","source":"startup","agent_type":"`+defLead+`"}`)
	if err != nil {
		return err
	}
	if err := e.hookEvent(ctx, false, state, "subagent-start", `{"hook_event_name":"SubagentStart","session_id":"live-s1","agent_id":"live-a1","agent_type":"`+defBuilder+`"}`); err != nil {
		return err
	}
	// A second subagent starts through a command wrapper.
	if err := e.hookEvent(ctx, true, state, "subagent-start", `{"hook_event_name":"SubagentStart","session_id":"live-s1","agent_id":"live-a2","agent_type":"`+defBuilder+`"}`); err != nil {
		return err
	}

	mainDir, err := e.bashCall(ctx, state, "", command)
	if err != nil {
		return fmt.Errorf("main session call: %w", err)
	}
	a1, err := e.bashCall(ctx, state, "live-a1", command)
	if err != nil {
		return fmt.Errorf("first subagent call: %w", err)
	}
	a2, err := e.bashCall(ctx, state, "live-a2", command)
	if err != nil {
		return fmt.Errorf("second subagent call: %w", err)
	}
	if mainDir == a1 || a1 == a2 || mainDir == a2 {
		return fmt.Errorf("delivery directories are shared: %s %s %s", mainDir, a1, a2)
	}

	mc, err := e.claimsIn(mainDir)
	if err != nil {
		return err
	}
	ac, err := e.claimsIn(a1)
	if err != nil {
		return err
	}
	if mc.Grade != "workload" || ac.Grade != "harness" || ac.Spawn != "live-a1" || mc.Sid != ac.Sid || ac.Act == nil || ac.Act.Sub != "agent:"+defBuilder {
		return fmt.Errorf("claims main=%+v child=%+v", mc, ac)
	}
	if id, err := runtimeID(); err != nil || mc.RT.ID != id {
		return fmt.Errorf("the session is bound to %q, want the runtime process %q", mc.RT.ID, id)
	}

	// A tool that is not Bash is left alone.
	res, err := e.hook(ctx, false, `{"hook_event_name":"PreToolUse","session_id":"live-s1","tool_name":"Read","tool_input":{"file_path":"x"}}`, e.hookArgs("pre-tool-use-bash", state))
	if err := silent("non-Bash tool", res, err); err != nil {
		return err
	}

	if err := e.hookEvent(ctx, false, state, "subagent-stop", `{"hook_event_name":"SubagentStop","session_id":"live-s1","agent_id":"live-a1"}`); err != nil {
		return err
	}
	if _, err := os.Stat(a1); !os.IsNotExist(err) {
		return fmt.Errorf("the stopped agent's directory remains (%v)", err)
	}
	if _, err := os.Stat(a2); err != nil {
		return fmt.Errorf("a sibling's directory was removed: %w", err)
	}
	return nil
}

func (e *Env) hookEvent(ctx context.Context, viaWrapper bool, state, event, payload string) error {
	res, err := e.hook(ctx, viaWrapper, payload, e.hookArgs(event, state))
	return silent(event, res, err)
}

// claimsIn reads and verifies the assertion in a delivery directory.
func (e *Env) claimsIn(dir string) (Claims, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "identity.jwt"))
	if err != nil {
		return Claims{}, err
	}
	return e.verify(string(raw))
}

// shapeHookCompose composes the adapter after a synthetic upstream hook the
// harness writes itself: an allowing upstream gets the statement added in front
// of its command, a denying one passes through byte for byte.
func (e *Env) shapeHookCompose(ctx context.Context) error {
	if _, err := lookShell(); err != nil {
		return err
	}
	state := filepath.Join(e.Dir, "compose-state")
	if err := e.hookEvent(ctx, false, state, "session-start", `{"hook_event_name":"SessionStart","session_id":"live-s2","source":"startup","agent_type":"`+defLead+`"}`); err != nil {
		return err
	}
	allow := `{"hookSpecificOutput":{"permissionDecision":"allow","updatedInput":{"command":"export UPSTREAM_STAMP=1; ls"}}}`
	deny := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"synthetic"}}`
	payload := `{"hook_event_name":"PreToolUse","session_id":"live-s2","tool_name":"Bash","tool_input":{"command":"ls"}}`

	call := func(name, reply string) (procResult, error) {
		script := filepath.Join(e.Dir, name+".sh")
		body := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + reply + "'\n"
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			return procResult{}, err
		}
		return e.hook(ctx, false, payload, e.hookArgs("pre-tool-use-bash", state, "--compose", script, "--upstream-timeout", "5s"))
	}

	res, err := call("upstream-allow", allow)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return fmt.Errorf("allowing upstream: exit %d: %.200s", res.Code, res.Stderr)
	}
	r, err := decodeRewrite(res.Stdout)
	if err != nil {
		return err
	}
	dir, rest, ok := splitDelivery(r.Specific.Updated.Command)
	if !ok || rest != "export UPSTREAM_STAMP=1; ls" || r.Specific.Decision != "allow" {
		return fmt.Errorf("composed reply %.300q: want the statement in front of the upstream's command and its own decision kept", res.Stdout)
	}
	if _, err := e.claimsIn(dir); err != nil {
		return err
	}

	res, err = call("upstream-deny", deny)
	if err != nil {
		return err
	}
	if res.Code != 0 || res.Stdout != deny {
		return fmt.Errorf("denying upstream was not passed through byte for byte: exit %d stdout %.200q", res.Code, res.Stdout)
	}
	return nil
}
