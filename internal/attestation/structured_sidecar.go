package attestation

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file owns ONE concern: parsing a structured (JSON or YAML) sidecar
// record and selecting a named field from it as the attested Identity.
// Whole-file (unstructured) sidecar reads stay in sidecar.go; this file is
// only reached when a SidecarConfig sets IdentityField.
//
// Trade-off named in the PR: JSON and YAML are both supported here (not
// JSON-only) because gopkg.in/yaml.v3 is already a go.mod dependency
// (config.go uses it) — accepting either costs no new dependency and no
// meaningful complexity, since both unmarshal into the same
// map[string]any shape.

// structuredSidecarRecord is the parsed shape of a structured sidecar file.
// Field names are generic and roster-agnostic: they describe the ATTRIBUTION
// concern (which parent session spawned which unit of work), never a
// specific agent, harness, or tool name.
type structuredSidecarRecord struct {
	// raw holds every parsed field, including IdentityField's target and any
	// attribution fields present. Parsed once via a generic
	// map[string]interface{} so callers are not coupled to a fixed schema
	// beyond the attribution fields this package understands.
	raw map[string]any
}

// attributionFieldNames are the generic structured-sidecar fields captured
// for cross-attribution/audit, independent of which field IdentityField
// names as the Subject. Names are deliberately generic (no agent/tool
// names) per the roster-agnostic rule.
const (
	fieldParentSessionID = "parent_session_id"
	fieldSpawnID         = "spawn_id"
	fieldAgentType       = "agent_type"
	fieldSpawnedAt       = "spawned_at"
)

// MalformedSidecarError is returned when a structured sidecar file is
// present but fails to satisfy the structured-read contract: the file could
// not be parsed as JSON or YAML, the configured IdentityField is absent
// from the parsed object, or the named field is present but not a non-empty
// string. This is always a hard failure (never ErrNoIdentity) — a
// malformed structured sidecar is distinct from an absent file, which
// stays a normal decline.
type MalformedSidecarError struct {
	// Path is the sidecar file that failed to satisfy the contract.
	Path string
	// Field is the IdentityField name involved, when the failure is
	// field-specific (absent or empty). Empty when the failure is a parse
	// failure that never reached field selection.
	Field string
	// Reason is a short, human-readable description of what went wrong.
	Reason string
}

func (e *MalformedSidecarError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("attestation: structured sidecar %q: field %q: %s", e.Path, e.Field, e.Reason)
	}
	return fmt.Sprintf("attestation: structured sidecar %q: %s", e.Path, e.Reason)
}

// parseStructuredSidecar parses data (the raw sidecar file contents) as a
// structured record and resolves identityField as Identity.Subject. It
// tries JSON first, then YAML, since a JSON document is also a subset of
// YAML 1.1/1.2 in the general case is NOT guaranteed — the two parsers are
// tried independently so either well-formed JSON or well-formed YAML is
// accepted.
//
// Fails closed (returns *MalformedSidecarError, never ErrNoIdentity) when:
//   - data parses as neither JSON nor YAML into an object;
//   - identityField is absent from the parsed object;
//   - the named field is present but empty or not a string.
//
// path is used only for error messages.
func parseStructuredSidecar(path, identityField string, data []byte) (Identity, error) {
	record, err := decodeStructuredRecord(data)
	if err != nil {
		return Identity{}, &MalformedSidecarError{
			Path:   path,
			Reason: fmt.Sprintf("not parseable as a structured (JSON or YAML) object: %v", err),
		}
	}

	rawSubject, ok := record.raw[identityField]
	if !ok {
		return Identity{}, &MalformedSidecarError{
			Path:   path,
			Field:  identityField,
			Reason: "identity_field is absent from the parsed sidecar record",
		}
	}
	subject, ok := rawSubject.(string)
	if !ok {
		return Identity{}, &MalformedSidecarError{
			Path:   path,
			Field:  identityField,
			Reason: fmt.Sprintf("identity_field value must be a string, got %T", rawSubject),
		}
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return Identity{}, &MalformedSidecarError{
			Path:   path,
			Field:  identityField,
			Reason: "identity_field value is empty",
		}
	}

	return Identity{
		Subject:         subject,
		Source:          "sidecar",
		ParentSessionID: stringField(record.raw, fieldParentSessionID),
		SpawnID:         stringField(record.raw, fieldSpawnID),
		AgentType:       stringField(record.raw, fieldAgentType),
		SpawnedAt:       stringField(record.raw, fieldSpawnedAt),
	}, nil
}

// decodeStructuredRecord attempts to unmarshal data as JSON, then as YAML,
// into a generic map. Both are tried because gopkg.in/yaml.v3 is already a
// project dependency (see the trade-off note at the top of this file) —
// there is no reason to force JSON-only once YAML parsing is free.
func decodeStructuredRecord(data []byte) (structuredSidecarRecord, error) {
	var m map[string]any

	jsonErr := json.Unmarshal(data, &m)
	if jsonErr == nil {
		return structuredSidecarRecord{raw: m}, nil
	}

	m = nil
	yamlErr := yaml.Unmarshal(data, &m)
	if yamlErr == nil && m != nil {
		return structuredSidecarRecord{raw: normalizeYAMLKeys(m)}, nil
	}

	return structuredSidecarRecord{}, fmt.Errorf("json: %v; yaml: %v", jsonErr, yamlErr)
}

// normalizeYAMLKeys is a no-op passthrough placeholder for map[string]any
// produced by yaml.v3 (which, unlike yaml.v2, already decodes mapping keys
// as string when the target is map[string]any). Kept as a named step so a
// future divergence in key typing is a one-place fix.
func normalizeYAMLKeys(m map[string]any) map[string]any {
	return m
}

// stringField returns the string value of key in m, or "" if key is absent
// or not a string. Used for the OPTIONAL attribution fields, which — unlike
// IdentityField — never fail the read when absent; they are best-effort
// audit context.
func stringField(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
