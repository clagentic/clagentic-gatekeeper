package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
//
// Known difference from the upstream registered alone: the runtime reads a hook's
// output until every holder of the pipe has closed it, so a background process
// the upstream leaves running delays or truncates that read; here the output
// read stops 250ms after the upstream exits and what was read is the verdict.
const upstreamWaitDelay = 250 * time.Millisecond

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
	return UpstreamBudget(h.UpstreamTimeout)
}

// UpstreamBudget is the budget to run the composed hook with: d when positive,
// else the registered default. A bad budget never costs the upstream its verdict.
func UpstreamBudget(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return DefaultUpstreamTimeout
}

// RunUpstream runs the composed hook with payload on stdin and the runtime's
// environment, with budget as its whole lifetime, and returns what it produced.
// An error means the hook produced no verdict: it could not start, or it was
// still running and was killed at the deadline. A process that exited has given
// its verdict whatever it exited with, including an exit that lands exactly on
// the deadline, and a signal death, which is reported as exit 1: the runtime
// treats that as a failed hook that does not block.
func RunUpstream(exe string, payload []byte, budget time.Duration) (Result, error) {
	if err := CheckUpstream(exe); err != nil {
		return Result{}, err
	}
	budget = UpstreamBudget(budget)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.WaitDelay = upstreamWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	res, err = upstreamOutcome(res, err, ctx.Err() != nil)
	if err != nil {
		return Result{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	return res, nil
}

// upstreamOutcome classifies how the upstream ended. runErr is what Run
// returned and expired whether the deadline had passed when it did.
func upstreamOutcome(res Result, runErr error, expired bool) (Result, error) {
	var exit *exec.ExitError
	switch {
	case runErr == nil:
	case errors.Is(runErr, exec.ErrWaitDelay):
		// The hook exited successfully and a descendant kept its pipes open. What
		// was read is the verdict; the descendant is not waited for.
	case errors.As(runErr, &exit) && exit.ExitCode() >= 0:
		// The process exited on its own. The deadline is not consulted: an exit that
		// races it is still the hook's verdict, a deny included.
		res.ExitCode = exit.ExitCode()
	case expired:
		return Result{}, errors.New("no verdict before the deadline")
	case exit != nil:
		res.ExitCode = 1
	default:
		return Result{}, runErr
	}
	return res, nil
}

// HandleComposed is the gatekeeper part of a composed pre-tool-use-bash hook.
// raw is the stdin the upstream was run with and up, upErr the outcome of
// RunUpstream on it; the caller logs upErr. An upstream that has no verdict
// (upErr set) yields an empty result: nothing is emitted, as for a failed hook,
// and no allow is ever produced from it.
func (h *ClaudeCode) HandleComposed(raw []byte, up Result, upErr error) Result {
	fallback := up
	if upErr != nil {
		fallback = Result{}
	}
	if len(raw) > maxPayloadBytes {
		h.Log.Printf("%s: the payload is too large to read", EventPreToolUseBash)
		return fallback
	}
	p, err := ParsePayload(bytes.NewReader(raw))
	if err != nil {
		h.Log.Printf("%s: %v", EventPreToolUseBash, err)
		return fallback
	}
	var res Result
	var decision string
	switch {
	case p.ToolName != "Bash":
		res, decision = fallback, "not-bash"
	case upErr != nil:
		res, decision = fallback, "upstream-failed"
	default:
		res, decision, err = h.composedPreToolUse(p, up)
	}
	h.finish(EventPreToolUseBash, p, decision, err)
	return res
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
//     of that command. Its reply is kept, its decision included; where it made
//     no decision the reply carries none either.
//
// Warn mode, an issuer failure, an already-delivered command, a payload that is
// oversized or unparseable, a tool that is not Bash: byte for byte the upstream's
// own output. The upstream always runs first, on the raw stdin, before any of
// those is decided; the process result is the upstream's unless the one addition
// above applies.
func (h *ClaudeCode) composedPreToolUse(p Payload, up Result) (Result, string, error) {
	pass := up
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
