package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// Mode selects what a registered hook does with what it learns.
type Mode string

const (
	// ModeWarn issues and records but rewrites nothing, and captures the shape of
	// every event and the process tree it ran in. A registration ships in this
	// mode first.
	ModeWarn Mode = "warn"
	// ModeEnforce additionally delivers the directory into Bash commands.
	ModeEnforce Mode = "enforce"
)

// ParseMode validates a mode name.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeWarn, ModeEnforce:
		return Mode(s), nil
	}
	return "", fmt.Errorf("mode %q is not warn or enforce", s)
}

// Issuer is the part of the issuer client a hook needs.
type Issuer interface {
	IssueSession(identity.SessionRequest) (*identity.Issued, error)
	IssueChild(identity.ChildRequest) (*identity.Issued, error)
}

// Event names the registered hook subcommands accept.
const (
	EventSessionStart     = "session-start"
	EventSubagentStart    = "subagent-start"
	EventPreToolUseBash   = "pre-tool-use-bash"
	EventSubagentStop     = "subagent-stop"
	EventUserPromptSubmit = "user-prompt-submit"
)

// Events lists every event name.
var Events = []string{EventSessionStart, EventSubagentStart, EventPreToolUseBash, EventSubagentStop, EventUserPromptSubmit}

// pruneAfter is how long an untouched session's state is kept.
const pruneAfter = 48 * time.Hour

// ClaudeCode handles Claude Code hook events.
type ClaudeCode struct {
	Issuer Issuer
	Store  Store
	Mode   Mode
	// Origin is sent on issue-session; empty lets the issuer choose. It is
	// configuration, never read from the payload.
	Origin string
	// RefreshBelow is the remaining lifetime under which user-prompt-submit
	// asks for a new session assertion; zero disables refresh.
	RefreshBelow time.Duration
	// Compose names an executable run first on pre-tool-use-bash; see composeUpstream.
	Compose string
	Log     Log
	Capture Capture
	Now     func() time.Time
	// HookPID is the pid whose ancestry is captured.
	HookPID int
}

func (h *ClaudeCode) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Result is what a hook process writes and exits with.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Handle processes one event. It fails open: every error is logged and yields an
// empty result, so a failing, erroring or slow hook never blocks a tool call. The
// one exception is a composed upstream hook that itself denies, whose verdict is
// passed through unchanged.
func (h *ClaudeCode) Handle(event string, in io.Reader) Result {
	raw, err := io.ReadAll(io.LimitReader(in, maxPayloadBytes+1))
	if err != nil || len(raw) > maxPayloadBytes {
		h.Log.Printf("%s: cannot read the payload: %v", event, err)
		return Result{}
	}
	p, err := ParsePayload(bytes.NewReader(raw))
	if err != nil {
		h.Log.Printf("%s: %v", event, err)
		return Result{}
	}
	var res Result
	var decision string
	switch event {
	case EventSessionStart:
		decision, err = h.sessionStart(p)
	case EventUserPromptSubmit:
		decision, err = h.userPromptSubmit(p)
	case EventSubagentStart:
		decision, err = h.subagentStart(p)
	case EventSubagentStop:
		decision, err = h.subagentStop(p)
	case EventPreToolUseBash:
		res, decision, err = h.preToolUseBash(p, raw)
	default:
		err = fmt.Errorf("unknown event %q", event)
	}
	if err != nil {
		h.Log.Printf("%s session=%s agent=%s: %v", event, p.SessionID, p.AgentID, err)
		if decision == "" {
			decision = "error"
		}
	}
	if h.Mode == ModeWarn {
		h.Capture.Record(event, p, decision, Ancestry(h.HookPID))
	}
	return res
}

// request asks the issuer for a session, always without a human grade: the
// adapter never requests or synthesises one.
func (h *ClaudeCode) requestSession(definition string) (*identity.Issued, error) {
	req := identity.SessionRequest{Origin: h.Origin}
	if definition != "" {
		req.Definition = definition
	}
	return h.Issuer.IssueSession(req)
}

func (h *ClaudeCode) sessionStart(p Payload) (string, error) {
	if !safeName.MatchString(p.SessionID) {
		return "skipped", errors.New("no usable session_id")
	}
	h.Store.Prune(h.now(), pruneAfter)
	definition := ""
	if safeName.MatchString(p.AgentType) {
		definition = p.AgentType
	}
	issued, err := h.requestSession(definition)
	if err != nil {
		return "issue-failed", err
	}
	if err := CheckDeliverable(issued.Dir); err != nil {
		return "undeliverable", err
	}
	// The previous directory, if any, is left for the issuer's reaper: a command
	// started under it may still be running.
	rec := Record{Dir: issued.Dir, ExpiresAt: issued.ExpiresAt, Definition: definition}
	if err := h.Store.Put(p.SessionID, "", rec); err != nil {
		return "state-failed", err
	}
	return "session-issued", nil
}

func (h *ClaudeCode) userPromptSubmit(p Payload) (string, error) {
	if h.RefreshBelow <= 0 || !safeName.MatchString(p.SessionID) {
		return "skipped", nil
	}
	rec, ok, err := h.Store.Get(p.SessionID, "")
	if err != nil || !ok {
		return "no-session", err
	}
	if rec.ExpiresAt-h.now().Unix() > int64(h.RefreshBelow/time.Second) {
		return "fresh", nil
	}
	issued, err := h.requestSession(rec.Definition)
	if err != nil {
		return "refresh-failed", err
	}
	if err := CheckDeliverable(issued.Dir); err != nil {
		return "undeliverable", err
	}
	rec.Dir, rec.ExpiresAt = issued.Dir, issued.ExpiresAt
	if err := h.Store.Put(p.SessionID, "", rec); err != nil {
		return "state-failed", err
	}
	return "session-refreshed", nil
}

func (h *ClaudeCode) subagentStart(p Payload) (string, error) {
	_, decision, err := h.ensureAgent(p)
	return decision, err
}

// ensureAgent returns the record of the payload's agent, issuing the child
// assertion when none exists. A payload without a usable agent_id is not an
// agent. The same path serves subagent-start and, as a fallback for a spawn whose
// start event never delivered an id, pre-tool-use-bash.
func (h *ClaudeCode) ensureAgent(p Payload) (Record, string, error) {
	if !safeName.MatchString(p.SessionID) {
		return Record{}, "skipped", errors.New("no usable session_id")
	}
	if !safeName.MatchString(p.AgentID) || !safeName.MatchString(p.AgentType) {
		return Record{}, "skipped", errors.New("no usable agent_id and agent_type")
	}
	if rec, ok, err := h.Store.Get(p.SessionID, p.AgentID); err != nil {
		return Record{}, "state-failed", err
	} else if ok {
		return rec, "agent-known", nil
	}
	parent, ok, err := h.Store.Get(p.SessionID, "")
	if err != nil {
		return Record{}, "state-failed", err
	}
	if !ok {
		return Record{}, "no-session", errors.New("no session assertion to issue a child from")
	}
	token, err := os.ReadFile(filepath.Join(parent.Dir, identity.DeliveryFile))
	if err != nil {
		return Record{}, "no-session", fmt.Errorf("read the session assertion: %w", err)
	}
	issued, err := h.Issuer.IssueChild(identity.ChildRequest{
		ParentToken: strings.TrimSpace(string(token)), AgentType: p.AgentType, AgentID: p.AgentID,
	})
	if err != nil {
		return Record{}, "issue-failed", err
	}
	if err := CheckDeliverable(issued.Dir); err != nil {
		return Record{}, "undeliverable", err
	}
	rec := Record{Dir: issued.Dir, ExpiresAt: issued.ExpiresAt, AgentType: p.AgentType}
	won, err := h.Store.PutNew(p.SessionID, p.AgentID, rec)
	if err != nil {
		_ = RemoveDelivery(issued.Dir)
		return Record{}, "state-failed", err
	}
	if !won {
		// Another hook of this agent delivered first; use its directory.
		_ = RemoveDelivery(issued.Dir)
		other, ok, err := h.Store.Get(p.SessionID, p.AgentID)
		if err != nil || !ok {
			return Record{}, "state-failed", fmt.Errorf("lost the delivery race and cannot read the winner: %v", err)
		}
		return other, "agent-known", nil
	}
	return rec, "child-issued", nil
}

func (h *ClaudeCode) subagentStop(p Payload) (string, error) {
	if !safeName.MatchString(p.SessionID) || !safeName.MatchString(p.AgentID) {
		return "skipped", errors.New("no usable session_id and agent_id")
	}
	rec, ok, err := h.Store.Get(p.SessionID, p.AgentID)
	if err != nil {
		return "state-failed", err
	}
	if !ok {
		return "no-record", nil
	}
	// The record goes first: a directory that cannot be removed must not be
	// delivered to a later command of this agent.
	if err := h.Store.Delete(p.SessionID, p.AgentID); err != nil {
		return "state-failed", err
	}
	if err := RemoveDelivery(rec.Dir); err != nil {
		return "remove-failed", err
	}
	return "agent-removed", nil
}

// preToolUseBash decides the rewrite of one Bash call. The reply carries a
// permission decision only when the command is rewritten; every other outcome is
// empty output, which leaves the runtime's own permission flow untouched.
func (h *ClaudeCode) preToolUseBash(p Payload, raw []byte) (Result, string, error) {
	if p.ToolName != "Bash" {
		return Result{}, "not-bash", nil
	}
	if h.Compose != "" {
		return h.composedPreToolUse(p, raw)
	}
	return h.standalone(p)
}

// prefix returns the command with the delivery statement in front, or "" when no
// rewrite applies. In warn mode it never rewrites.
func (h *ClaudeCode) prefix(p Payload, command string) (rewritten, decision string, err error) {
	if AlreadyDelivers(command) {
		return "", "already-delivered", nil
	}
	var rec Record
	if p.AgentID != "" {
		var d string
		rec, d, err = h.ensureAgent(p)
		if err != nil {
			return "", d, err
		}
	} else {
		var ok bool
		rec, ok, err = h.Store.Get(p.SessionID, "")
		if err != nil || !ok {
			return "", "no-session", err
		}
	}
	if rec.ExpiresAt <= h.now().Unix() {
		return "", "expired", nil
	}
	if err := dirUsable(rec.Dir); err != nil {
		return "", "dir-unusable", err
	}
	stmt, err := ExportStatement(rec.Dir)
	if err != nil {
		return "", "undeliverable", err
	}
	if h.Mode != ModeEnforce {
		return "", "would-deliver", nil
	}
	return stmt + command, "delivered", nil
}

type updatedOutput struct {
	HookSpecificOutput map[string]json.RawMessage `json:"hookSpecificOutput"`
}

// rewriteOutput builds the PreToolUse reply for a rewritten call. toolInput is
// copied whole so members other than the command (timeout, description,
// run_in_background) survive. Allow is the only decision this hook returns, and
// only here: the harness re-checks a rewritten command, so without it every
// rewritten call would fall into the operator's permission flow.
func rewriteOutput(toolInput map[string]json.RawMessage, command string) ([]byte, error) {
	updated := make(map[string]json.RawMessage, len(toolInput)+1)
	for k, v := range toolInput {
		updated[k] = v
	}
	cmd, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	updated["command"] = cmd
	body := map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "allow",
		"permissionDecisionReason": "gatekeeper: prefixed " + EnvDir + " for this call",
		"updatedInput":             updated,
	}
	return json.Marshal(map[string]any{"hookSpecificOutput": body})
}
