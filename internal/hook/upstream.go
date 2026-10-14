package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// DefaultUpstreamTimeout is the composed hook's budget when a registration
// names none. A registration always does: it is the timeout the upstream hook
// had when it was registered alone.
const DefaultUpstreamTimeout = 5 * time.Second

// upstreamWaitDelay bounds the wait for pipes a descendant of the upstream still
// holds once the upstream itself has exited.
const upstreamWaitDelay = 250 * time.Millisecond

type upstreamResult struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// CheckUpstream refuses a composed-hook path that is not absolute or does not
// name a regular file. The path is fixed at registration and run directly: no
// shell, no argument, nothing from a payload.
func CheckUpstream(exe string) error {
	if !filepath.IsAbs(exe) {
		return fmt.Errorf("composed hook %q must be an absolute path", exe)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("composed hook: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("composed hook %s is not a regular file", exe)
	}
	return nil
}

func (h *ClaudeCode) upstreamBudget() time.Duration {
	if h.UpstreamTimeout > 0 {
		return h.UpstreamTimeout
	}
	return DefaultUpstreamTimeout
}

// runUpstream runs the composed hook with the same payload on stdin and the
// runtime's environment, with budget as its whole lifetime. An error means the
// hook produced no verdict: it could not start or it ran out of time. Any exit
// status, including a signal death, is a verdict and is returned in the result.
func runUpstream(exe string, payload []byte, budget time.Duration) (upstreamResult, error) {
	if err := CheckUpstream(exe); err != nil {
		return upstreamResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.WaitDelay = upstreamWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := upstreamResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, exec.ErrWaitDelay):
		// The hook exited successfully and a descendant kept its pipes open. What
		// was read is the verdict; the descendant is not waited for.
	case ctx.Err() != nil:
		return upstreamResult{}, fmt.Errorf("composed hook %s: no verdict within %s", exe, budget)
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
		if res.ExitCode < 0 {
			// Killed by a signal. The runtime treats that as a failed hook that does
			// not block, which is what any non-zero code other than 2 is.
			res.ExitCode = 1
		}
	default:
		return upstreamResult{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	return res, nil
}

// PassThrough runs the composed hook on the payload and returns its verdict
// byte for byte, adding nothing. It is what a composed registration does when
// gatekeeper itself cannot do its part: the other hook's output is never lost to
// a gatekeeper failure. An upstream with no verdict yields an empty result.
func PassThrough(exe string, payload io.Reader, budget time.Duration, log Log) Result {
	raw, err := io.ReadAll(io.LimitReader(payload, maxPayloadBytes+1))
	if err != nil || len(raw) > maxPayloadBytes {
		log.Printf("pass-through: cannot read the payload: %v", err)
		return Result{}
	}
	up, err := runUpstream(exe, raw, budget)
	if err != nil {
		log.Printf("pass-through: %v", err)
		return Result{}
	}
	return Result{Stdout: up.Stdout, Stderr: up.Stderr, ExitCode: up.ExitCode}
}

// composedPreToolUse serves a deployment where another hook already rewrites
// Bash commands on the same matcher. Runtime hooks on one matcher run in
// parallel and the last rewrite to finish wins, so two registered rewriters
// silently drop each other's output. Registering this one hook with --compose
// makes the order deterministic: the upstream hook runs first on the same
// payload, and this hook adds its one statement in front of the command that
// results.
//
// The composition is transparent. For every outcome of the upstream the reply is
// what the runtime would have received had the upstream been registered alone,
// with one addition at most:
//
//   - upstream cannot start or has no verdict within its budget: nothing is
//     emitted and the call proceeds unchanged, as it does for a failed hook;
//   - upstream exits non-zero (2 included, or a signal): its stdout, stderr and
//     exit code pass through byte for byte;
//   - upstream output that is not one JSON object, or that denies, asks, defers,
//     names any decision other than allow, or stops the run: passes through byte
//     for byte;
//   - upstream allows or makes no decision and its command is known (its
//     updatedInput.command, else the payload's): the statement is added in front
//     of that command. Its reply is kept, its decision included. Where it made
//     no decision the reply carries allow with the rewrite, as it does when this
//     hook runs alone.
//
// Warn mode, an issuer failure, an already-delivered command: byte for byte the
// upstream's own output.
func (h *ClaudeCode) composedPreToolUse(p Payload, raw []byte) (Result, string, error) {
	up, err := runUpstream(h.Compose, raw, h.upstreamBudget())
	if err != nil {
		return Result{}, "upstream-failed", err
	}
	pass := Result{Stdout: up.Stdout, Stderr: up.Stderr, ExitCode: up.ExitCode}
	h.hold(pass)
	if up.ExitCode != 0 {
		return pass, "upstream-exit", nil
	}

	reply := map[string]json.RawMessage{}
	if body := bytes.TrimSpace(up.Stdout); len(body) != 0 {
		if json.Unmarshal(body, &reply) != nil || reply == nil {
			return pass, "upstream-unparsed", nil
		}
	}
	if stopsOrDecides(reply) {
		return pass, "upstream-decision", nil
	}
	specific := map[string]json.RawMessage{}
	if rawSpecific, ok := reply["hookSpecificOutput"]; ok {
		if json.Unmarshal(rawSpecific, &specific) != nil || specific == nil {
			return pass, "upstream-passthrough", nil
		}
	}
	if rawDecision, ok := specific["permissionDecision"]; ok {
		var d string
		if json.Unmarshal(rawDecision, &d) != nil || (d != "" && d != "allow") {
			return pass, "upstream-decision", nil
		}
	}
	base := p.ToolInput
	if rawUpdated, ok := specific["updatedInput"]; ok {
		var updated map[string]json.RawMessage
		if json.Unmarshal(rawUpdated, &updated) != nil || updated == nil {
			return pass, "upstream-passthrough", nil
		}
		base = updated
	}
	command := stringMember(base, "command")
	if command == "" {
		return pass, "upstream-command-unknown", nil
	}
	rewritten, decision, err := h.prefix(p, command)
	if rewritten == "" {
		return pass, decision, err
	}
	out, err := mergeRewrite(reply, specific, base, rewritten)
	if err != nil {
		return pass, "encode-failed", err
	}
	return Result{Stdout: out, Stderr: up.Stderr}, decision, nil
}

// stopsOrDecides reports whether a top-level member of an upstream reply stops
// the run or carries a decision of the legacy form, either of which the composed
// hook must leave alone.
func stopsOrDecides(reply map[string]json.RawMessage) bool {
	if stringMember(reply, "decision") != "" {
		return true
	}
	if raw, ok := reply["continue"]; ok {
		var cont bool
		if json.Unmarshal(raw, &cont) == nil && !cont {
			return true
		}
	}
	return false
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
	out, err := mergeRewrite(map[string]json.RawMessage{}, map[string]json.RawMessage{}, p.ToolInput, rewritten)
	if err != nil {
		return Result{}, "encode-failed", err
	}
	return Result{Stdout: out}, decision, nil
}
