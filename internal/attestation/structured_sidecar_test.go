package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// TestSidecarProvider_IdentityFieldUnset_WholeFileBackCompat verifies that
// leaving IdentityField unset preserves the pre-lr-f1bfe8 behavior exactly:
// the whole file, TrimSpace'd, becomes Identity.Subject, with no attribution
// fields populated. This mirrors TestSidecarProvider_FilePresent_Resolves in
// sidecar_test.go and must keep passing unchanged.
func TestSidecarProvider_IdentityFieldUnset_WholeFileBackCompat(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_BACKCOMPAT_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "identity-"
	const sessionID = "session-backcompat"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:          dir,
		FilePrefix:   prefix,
		SessionIDEnv: sessionEnv,
		// IdentityField intentionally left unset.
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte("agent-z\n"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "agent-z" || id.Source != "sidecar" {
		t.Errorf("Resolve() = %+v, want Subject=agent-z Source=sidecar", id)
	}
	if id.ParentSessionID != "" || id.SpawnID != "" || id.AgentType != "" || id.SpawnedAt != "" {
		t.Errorf("Resolve() = %+v, want all attribution fields empty for whole-file mode", id)
	}
}

// TestSidecarProvider_StructuredJSON_HappyPath verifies the structured read
// path: IdentityField set, a JSON sidecar record, the named field becomes
// Subject, and the recognized attribution fields are captured.
func TestSidecarProvider_StructuredJSON_HappyPath(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_JSON_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-42"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	record := `{
		"attested_name": "builder-agent",
		"parent_session_id": "session-abc",
		"spawn_id": "spawn-42",
		"agent_type": "builder",
		"spawned_at": "2026-07-23T00:00:00Z"
	}`
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write structured sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "builder-agent" || id.Source != "sidecar" {
		t.Errorf("Resolve() = %+v, want Subject=builder-agent Source=sidecar", id)
	}
	if id.ParentSessionID != "session-abc" {
		t.Errorf("ParentSessionID = %q, want %q", id.ParentSessionID, "session-abc")
	}
	if id.SpawnID != "spawn-42" {
		t.Errorf("SpawnID = %q, want %q", id.SpawnID, "spawn-42")
	}
	if id.AgentType != "builder" {
		t.Errorf("AgentType = %q, want %q", id.AgentType, "builder")
	}
	if id.SpawnedAt != "2026-07-23T00:00:00Z" {
		t.Errorf("SpawnedAt = %q, want %q", id.SpawnedAt, "2026-07-23T00:00:00Z")
	}
}

// TestSidecarProvider_StructuredYAML_HappyPath verifies YAML is also
// accepted for a structured sidecar record (trade-off named in the PR body:
// both JSON and YAML are supported since gopkg.in/yaml.v3 is already a
// go.mod dependency).
func TestSidecarProvider_StructuredYAML_HappyPath(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_YAML_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-yaml-1"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	record := "attested_name: reviewer-agent\nparent_session_id: session-yaml\nspawn_id: spawn-yaml-1\n"
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write structured sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve(): unexpected error: %v", err)
	}
	if id.Subject != "reviewer-agent" {
		t.Errorf("Subject = %q, want %q", id.Subject, "reviewer-agent")
	}
	if id.ParentSessionID != "session-yaml" {
		t.Errorf("ParentSessionID = %q, want %q", id.ParentSessionID, "session-yaml")
	}
}

// TestSidecarProvider_StructuredFieldMissing_FailsClosed verifies that when
// IdentityField names a field absent from the parsed object, Resolve
// returns a *MalformedSidecarError (a hard failure), never ErrNoIdentity —
// a malformed structured sidecar is distinct from an absent file.
func TestSidecarProvider_StructuredFieldMissing_FailsClosed(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_MISSING_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-missing"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	record := `{"parent_session_id": "session-abc"}`
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write structured sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err == nil {
		t.Fatalf("Resolve() = %+v, nil; want a hard failure for missing identity_field", id)
	}
	if errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want a hard failure, NOT ErrNoIdentity", err)
	}
	var malformed *attestation.MalformedSidecarError
	if !errors.As(err, &malformed) {
		t.Fatalf("Resolve() error = %v (%T), want *attestation.MalformedSidecarError", err, err)
	}
	if malformed.Field != "attested_name" {
		t.Errorf("MalformedSidecarError.Field = %q, want %q", malformed.Field, "attested_name")
	}
}

// TestSidecarProvider_StructuredNotParseable_FailsClosed verifies that a
// sidecar file which is present but not parseable as JSON or YAML is a
// hard failure, never ErrNoIdentity.
func TestSidecarProvider_StructuredNotParseable_FailsClosed(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_UNPARSEABLE_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-bad"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	// `:::` is not valid JSON, and (unlike many strings) also not valid
	// YAML — chosen specifically so this test cannot pass by accidentally
	// parsing as a YAML scalar/mapping.
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(":::not valid: [structured"), 0o600); err != nil {
		t.Fatalf("setup: write sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err == nil {
		t.Fatalf("Resolve() = %+v, nil; want a hard failure for a non-parseable sidecar", id)
	}
	if errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want a hard failure, NOT ErrNoIdentity", err)
	}
	var malformed *attestation.MalformedSidecarError
	if !errors.As(err, &malformed) {
		t.Fatalf("Resolve() error = %v (%T), want *attestation.MalformedSidecarError", err, err)
	}
}

// TestSidecarProvider_StructuredFieldEmpty_FailsClosed verifies that when
// the named field is present but empty (or whitespace-only), Resolve fails
// closed rather than treating it as "no identity" or an empty Subject.
func TestSidecarProvider_StructuredFieldEmpty_FailsClosed(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_EMPTY_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-empty"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	record := `{"attested_name": "   "}`
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write structured sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err == nil {
		t.Fatalf("Resolve() = %+v, nil; want a hard failure for an empty identity_field value", id)
	}
	if errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want a hard failure, NOT ErrNoIdentity", err)
	}
}

// TestSidecarProvider_StructuredFieldNonString_FailsClosed verifies that a
// non-string identity_field value (e.g. a number or object) is a hard
// failure rather than being coerced.
func TestSidecarProvider_StructuredFieldNonString_FailsClosed(t *testing.T) {
	const sessionEnv = "ATTESTATION_TEST_STRUCTURED_NONSTRING_LRF1BFE8"
	dir := t.TempDir()
	const prefix = "spawn-"
	const sessionID = "spawn-nonstring"

	p, err := attestation.NewSidecarProvider(attestation.SidecarConfig{
		Dir:           dir,
		FilePrefix:    prefix,
		SessionIDEnv:  sessionEnv,
		IdentityField: "attested_name",
	})
	if err != nil {
		t.Fatalf("NewSidecarProvider: unexpected error: %v", err)
	}
	t.Setenv(sessionEnv, sessionID)

	record := `{"attested_name": 12345}`
	path := filepath.Join(dir, prefix+sessionID)
	if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write structured sidecar file: %v", err)
	}

	id, err := p.Resolve(context.Background())
	if err == nil {
		t.Fatalf("Resolve() = %+v, nil; want a hard failure for a non-string identity_field value", id)
	}
	if errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want a hard failure, NOT ErrNoIdentity", err)
	}
}
