package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// upstreamTimeout bounds the composed hook. It is below the timeout the
// registration gives the whole process, so a slow upstream costs the delivery
// and nothing else.
const upstreamTimeout = 3 * time.Second

type upstreamResult struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// runUpstream runs the composed hook with the same payload on stdin. The
// executable is run directly, with no arguments and no shell.
func runUpstream(exe string, payload []byte) (upstreamResult, error) {
	if !filepath.IsAbs(exe) {
		return upstreamResult{}, fmt.Errorf("composed hook %q must be an absolute path", exe)
	}
	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Stdin = bytes.NewReader(payload)
	// A grandchild that inherited stdout would otherwise hold Run open long
	// after the upstream itself was killed.
	cmd.WaitDelay = 250 * time.Millisecond
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := upstreamResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case ctx.Err() != nil:
		return upstreamResult{}, fmt.Errorf("composed hook %s: %w", exe, ctx.Err())
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
	default:
		return upstreamResult{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	return res, nil
}

// composedPreToolUse serves a deployment where another hook already rewrites
// Bash commands on the same matcher. Runtime hooks on one matcher run in
// parallel and the last rewrite to finish wins, so two registered rewriters
// silently drop each other's output. Registering this one hook with --compose
// makes the order deterministic: the upstream hook runs first on the same
// payload, and this hook prefixes its one statement to whatever command the
// upstream produced.
//
//   - upstream exits non-zero: its verdict, stdout and stderr pass through and
//     nothing is added, so an upstream deny stays a deny;
//   - upstream cannot be run or times out: the command is handled as if it were
//     not composed, so a broken upstream never costs the delivery or blocks a call;
//   - upstream returns no rewrite: its output, if any, passes through unchanged;
//   - upstream rewrites the command: the statement goes in front of that command
//     and the rest of its reply, its permission decision included, is kept.
func (h *ClaudeCode) composedPreToolUse(p Payload, raw []byte) (Result, string, error) {
	up, err := runUpstream(h.Compose, raw)
	if err != nil {
		h.Log.Printf("%s: %v; handling the call without it", EventPreToolUseBash, err)
		return h.standalone(p)
	}
	if up.ExitCode != 0 {
		return Result{Stdout: up.Stdout, Stderr: up.Stderr, ExitCode: up.ExitCode}, "upstream-exit", nil
	}
	if len(bytes.TrimSpace(up.Stdout)) == 0 {
		return h.standalone(p)
	}
	passthrough := Result{Stdout: up.Stdout, Stderr: up.Stderr}
	var reply map[string]json.RawMessage
	if json.Unmarshal(up.Stdout, &reply) != nil {
		return passthrough, "upstream-unparsed", nil
	}
	var specific map[string]json.RawMessage
	if json.Unmarshal(reply["hookSpecificOutput"], &specific) != nil {
		return passthrough, "upstream-passthrough", nil
	}
	var updated map[string]json.RawMessage
	if json.Unmarshal(specific["updatedInput"], &updated) != nil {
		return passthrough, "upstream-passthrough", nil
	}
	command := stringMember(updated, "command")
	if command == "" {
		return passthrough, "upstream-passthrough", nil
	}
	rewritten, decision, err := h.prefix(p, command)
	if rewritten == "" {
		return passthrough, decision, err
	}
	encoded, err := json.Marshal(rewritten)
	if err != nil {
		return passthrough, "encode-failed", err
	}
	updated["command"] = encoded
	if specific["updatedInput"], err = json.Marshal(updated); err != nil {
		return passthrough, "encode-failed", err
	}
	if reply["hookSpecificOutput"], err = json.Marshal(specific); err != nil {
		return passthrough, "encode-failed", err
	}
	out, err := json.Marshal(reply)
	if err != nil {
		return passthrough, "encode-failed", err
	}
	return Result{Stdout: out, Stderr: up.Stderr}, decision, nil
}

// standalone is the non-composed handling of one Bash call.
func (h *ClaudeCode) standalone(p Payload) (Result, string, error) {
	command, ok := p.Command()
	if !ok {
		return Result{}, "no-command", nil
	}
	rewritten, decision, err := h.prefix(p, command)
	if rewritten == "" {
		return Result{}, decision, err
	}
	out, err := rewriteOutput(p.ToolInput, rewritten)
	if err != nil {
		return Result{}, "encode-failed", err
	}
	return Result{Stdout: out}, decision, nil
}
