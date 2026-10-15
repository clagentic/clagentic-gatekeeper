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
	"sync"
	"sync/atomic"
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
	return runUpstreamStream(exe, bytes.NewReader(payload), budget)
}

// runUpstreamStream is RunUpstream with the stdin streamed from in rather than
// held in memory.
func runUpstreamStream(exe string, in io.Reader, budget time.Duration) (Result, error) {
	if err := CheckUpstream(exe); err != nil {
		return Result{}, err
	}
	budget = UpstreamBudget(budget)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	// The stdin is fed through our own pipe, not cmd.Stdin: exec waits for a copy
	// goroutine it owns, and one blocked reading a source that never ends (the
	// upstream exited without reading) would hold Run past the upstream's exit.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	cmd.WaitDelay = upstreamWaitDelay
	// A kill is recorded where it is sent: on Windows a killed process reports an
	// ordinary non-negative exit code, so the exit code alone cannot tell a deadline
	// kill from a verdict. A Kill that returned nil is only a kill sent: a process
	// that had exited but was not yet reaped accepts it too, so the wait status
	// must also show the kill was what ended the process.
	var killSent atomic.Bool
	cmd.Cancel = func() error {
		err := cmd.Process.Kill()
		if err == nil {
			killSent.Store(true)
		}
		return err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	go func() {
		// A write to an upstream that has stopped reading fails; that ends the copy
		// and is not an error of the run.
		_, _ = io.Copy(stdin, in)
		_ = stdin.Close()
	}()
	err = cmd.Wait()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	killed := killSent.Load() && cmd.ProcessState != nil && endedByKill(cmd.ProcessState)
	res, err = classifyUpstream(res, err, ctx.Err() != nil, killed)
	if err != nil {
		return Result{}, fmt.Errorf("composed hook %s: %w", exe, err)
	}
	return res, nil
}

// classifyUpstream is upstreamOutcome with the one fact the exit code cannot
// carry on every GOOS: killed, that the process was killed by the deadline. A
// killed process has no verdict whatever code it reports.
func classifyUpstream(res Result, runErr error, expired, killed bool) (Result, error) {
	if killed {
		return Result{}, errors.New("no verdict before the deadline")
	}
	return upstreamOutcome(res, runErr, expired)
}

// capturedStdin passes the stdin through to the upstream while keeping a bounded
// copy for gatekeeper's own part, so memory stays bounded however much arrives.
type capturedStdin struct {
	r     io.Reader
	limit int
	// rmu serializes reads of the source, so the copy into the upstream and the
	// drain after it never interleave and the copy stays in order.
	rmu sync.Mutex
	// mu guards the rest: the copy into the upstream's stdin can outlive Run when
	// the upstream exits without reading and the source never ends.
	mu  sync.Mutex
	buf bytes.Buffer
	eof bool
	err error
}

// Read streams from the source. A read error is recorded and ends the stream as
// an EOF: the upstream still gets what arrived, as it did when stdin was read
// whole first.
func (c *capturedStdin) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	n, err := c.r.Read(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.limit - c.buf.Len(); n > 0 && room > 0 {
		c.buf.Write(p[:min(n, room)])
	}
	switch {
	case err == io.EOF:
		c.eof = true
	case err != nil:
		c.err = err
		err = io.EOF
	}
	return n, err
}

// drain reads what the upstream left unread, up to the cap, waiting at most wait
// for it. Gatekeeper's copy is thereby complete whenever the stdin reaches its end
// within the cap, however little the upstream read.
func (c *capturedStdin) drain(wait time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			c.mu.Lock()
			finished := c.eof || c.err != nil || c.buf.Len() >= c.limit
			c.mu.Unlock()
			if finished {
				return
			}
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// stdinDrainWait bounds the wait for the rest of a stdin the upstream stopped
// reading. A runtime writes the whole payload and closes the pipe before it waits
// on the hook, so the rest is normally already there.
const stdinDrainWait = 500 * time.Millisecond

// RunComposed runs the composed hook on the raw stdin in, streamed to it before
// any cap, parse or tool-name check, and returns gatekeeper's bounded copy of what
// was read. raw is one byte over maxPayloadBytes at most, so HandleComposed
// refuses an oversized payload without it being held. The copy is complete
// whenever the stdin ends within the cap, whatever the upstream read of it. raw is
// nil when the stdin did not end (it is over the cap, did not end in time, or the
// read failed), because a prefix of a payload must never be parsed as the
// payload; readErr is the read failure if there was one.
func RunComposed(exe string, in io.Reader, budget time.Duration) (raw []byte, up Result, upErr, readErr error) {
	c := &capturedStdin{r: in, limit: maxPayloadBytes + 1}
	up, upErr = runUpstreamStream(exe, c, budget)
	c.drain(stdinDrainWait)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eof {
		raw = c.buf.Bytes()
	}
	return raw, up, upErr, c.err
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
