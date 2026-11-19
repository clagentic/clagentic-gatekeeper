// Package hook adapts a runtime's lifecycle events to the identity issuer. A
// hook process reads one event, asks the issuer socket for an assertion and
// delivers the directory that holds it. It never decides what an assertion
// grants and never holds a signing key.
//
// The package is the client half only: it builds on every platform and talks to
// the issuer through identity.Client.
package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const maxPayloadBytes = 4 << 20

// safeName admits the ids a hook uses as file names and passes to the issuer.
// It is stricter than the issuer's own pattern: the first character is
// alphanumeric, so no id can be a dot-name.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Payload is one hook event as the runtime delivers it. Only the members the
// adapter reads are extracted; every other member is left in Raw so the shape
// recorder can describe it.
type Payload struct {
	Raw       map[string]json.RawMessage
	Event     string
	SessionID string
	AgentID   string
	AgentType string
	ToolName  string
	ToolInput map[string]json.RawMessage
}

// ParsePayload reads one JSON object. A member of an unexpected type reads as
// absent rather than failing the event, so a runtime that changes a field type
// degrades to "no identity delivered", not to an error.
func ParsePayload(r io.Reader) (Payload, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxPayloadBytes+1))
	if err != nil {
		return Payload{}, err
	}
	if len(raw) > maxPayloadBytes {
		return Payload{}, errors.New("hook payload is too large")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return Payload{}, fmt.Errorf("hook payload is not a JSON object: %w", err)
	}
	p := Payload{Raw: m}
	p.Event = stringMember(m, "hook_event_name")
	p.SessionID = stringMember(m, "session_id")
	p.AgentID = stringMember(m, "agent_id")
	p.AgentType = stringMember(m, "agent_type")
	p.ToolName = stringMember(m, "tool_name")
	if in, ok := m["tool_input"]; ok {
		// A tool_input that is not an object reads as absent.
		_ = json.Unmarshal(in, &p.ToolInput)
	}
	return p, nil
}

func stringMember(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// Command returns tool_input.command and whether it is a non-empty string.
func (p Payload) Command() (string, bool) {
	s := stringMember(p.ToolInput, "command")
	return s, s != ""
}
