package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// TestRequiredIdentityContractFields_MatchesPublishedContract pins the
// published required-fields contract (docs/A2A-ATTESTATION-CONTRACT.md) to
// its Go-level source of truth, so a future rename/removal of an
// attribution field is caught here rather than silently drifting from the
// doc.
func TestRequiredIdentityContractFields_MatchesPublishedContract(t *testing.T) {
	want := []string{"parent_session_id", "spawn_id", "agent_type", "spawned_at"}
	got := attestation.RequiredIdentityContractFields
	if len(got) != len(want) {
		t.Fatalf("RequiredIdentityContractFields = %v, want %v", got, want)
	}
	for i, name := range want {
		if got[i] != name {
			t.Errorf("RequiredIdentityContractFields[%d] = %q, want %q", i, got[i], name)
		}
	}
}

// TestDomainResolver_A2A_ConformingRecord_AllContractFieldsAvailable is the
// AC#4 regression test: given a per-spawn sidecar record that satisfies the
// published required-fields contract (identity field plus all four
// attribution fields), an A2A-domain resolve makes every contract field
// available on the resolved Identity, with no crew-specific knowledge
// anywhere in this package — the test only imports the generic
// attestation.SidecarConfig/DomainResolver surface.
func TestDomainResolver_A2A_ConformingRecord_AllContractFieldsAvailable(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "ATTESTATION_TEST_CONTRACT_A2A_SPAWN_LRA850D0"
	const sessionEnv = "ATTESTATION_TEST_CONTRACT_A2A_SESSION_LRA850D0"

	t.Setenv(spawnEnv, "spawn-contract-1")
	os.Unsetenv(sessionEnv)

	record := `{
		"attested_name": "producer-agent",
		"parent_session_id": "session-contract-1",
		"spawn_id": "spawn-contract-1",
		"agent_type": "builder",
		"spawned_at": "2026-07-23T00:00:00Z"
	}`
	spawnPath := filepath.Join(spawnDir, "spawn-spawn-contract-1")
	if err := os.WriteFile(spawnPath, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write conforming per-spawn sidecar record: %v", err)
	}

	spawnCfg := attestation.SidecarConfig{
		Dir:           spawnDir,
		FilePrefix:    "spawn-",
		SessionIDEnv:  spawnEnv,
		IdentityField: "attested_name",
	}
	sessionCfg := attestation.SidecarConfig{
		Dir:          sessionDir,
		FilePrefix:   "lore-agent-name-",
		SessionIDEnv: sessionEnv,
	}

	chain, err := attestation.NewChain(attestation.ChainConfig{
		Sidecars: []attestation.SidecarConfig{spawnCfg, sessionCfg},
	})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}
	spawnProvider, err := attestation.NewSidecarProvider(spawnCfg)
	if err != nil {
		t.Fatalf("NewSidecarProvider (per-spawn): unexpected error: %v", err)
	}
	d := &attestation.DomainResolver{Chain: chain, PerSpawn: attestation.NewResolver(spawnProvider)}

	id, err := d.Resolve(context.Background(), attestation.DomainA2A)
	if err != nil {
		t.Fatalf("Resolve(DomainA2A): unexpected error: %v", err)
	}
	if id.Subject != "producer-agent" || id.Source != "sidecar" {
		t.Errorf("Resolve(DomainA2A) = %+v, want Subject=producer-agent Source=sidecar", id)
	}
	if id.ParentSessionID != "session-contract-1" {
		t.Errorf("ParentSessionID = %q, want %q", id.ParentSessionID, "session-contract-1")
	}
	if id.SpawnID != "spawn-contract-1" {
		t.Errorf("SpawnID = %q, want %q", id.SpawnID, "spawn-contract-1")
	}
	if id.AgentType != "builder" {
		t.Errorf("AgentType = %q, want %q", id.AgentType, "builder")
	}
	if id.SpawnedAt != "2026-07-23T00:00:00Z" {
		t.Errorf("SpawnedAt = %q, want %q", id.SpawnedAt, "2026-07-23T00:00:00Z")
	}
}

// TestDomainResolver_A2A_MissingRequiredField_RefusedWithStructuredError is
// the AC#5 regression test: a per-spawn sidecar record that is PRESENT but
// missing the identity_field-named required field must refuse the
// A2A-domain resolve with a structured error naming the missing field —
// never a soft ErrNoIdentity decline, and never a fallback to
// ErrPerSpawnRequired's "try elsewhere" framing (DomainResolver.Resolve
// returns a hard PerSpawn error as-is).
func TestDomainResolver_A2A_MissingRequiredField_RefusedWithStructuredError(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "ATTESTATION_TEST_CONTRACT_A2A_MISSING_SPAWN_LRA850D0"
	const sessionEnv = "ATTESTATION_TEST_CONTRACT_A2A_MISSING_SESSION_LRA850D0"

	t.Setenv(spawnEnv, "spawn-contract-2")
	// Session sidecar IS present and would resolve under DomainLocal — proves
	// the missing-field refusal does not fall through to it either.
	t.Setenv(sessionEnv, "session-contract-2")
	sessionPath := filepath.Join(sessionDir, "lore-agent-name-session-contract-2")
	if err := os.WriteFile(sessionPath, []byte("holden"), 0o600); err != nil {
		t.Fatalf("setup: write session sidecar file: %v", err)
	}

	// Record is present but omits the required identity field
	// ("attested_name") — only an attribution field is set.
	record := `{"parent_session_id": "session-contract-2"}`
	spawnPath := filepath.Join(spawnDir, "spawn-spawn-contract-2")
	if err := os.WriteFile(spawnPath, []byte(record), 0o600); err != nil {
		t.Fatalf("setup: write non-conforming per-spawn sidecar record: %v", err)
	}

	spawnCfg := attestation.SidecarConfig{
		Dir:           spawnDir,
		FilePrefix:    "spawn-",
		SessionIDEnv:  spawnEnv,
		IdentityField: "attested_name",
	}
	sessionCfg := attestation.SidecarConfig{
		Dir:          sessionDir,
		FilePrefix:   "lore-agent-name-",
		SessionIDEnv: sessionEnv,
	}

	chain, err := attestation.NewChain(attestation.ChainConfig{
		Sidecars: []attestation.SidecarConfig{spawnCfg, sessionCfg},
	})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}
	spawnProvider, err := attestation.NewSidecarProvider(spawnCfg)
	if err != nil {
		t.Fatalf("NewSidecarProvider (per-spawn): unexpected error: %v", err)
	}
	d := &attestation.DomainResolver{Chain: chain, PerSpawn: attestation.NewResolver(spawnProvider)}

	id, err := d.Resolve(context.Background(), attestation.DomainA2A)
	if err == nil {
		t.Fatalf("Resolve(DomainA2A) = %+v, nil; want a fail-closed refusal for a missing required field", id)
	}
	if errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve(DomainA2A) error = %v, want a hard failure, NOT ErrNoIdentity", err)
	}
	if errors.Is(err, attestation.ErrPerSpawnRequired) {
		t.Fatalf("Resolve(DomainA2A) error = %v, want the underlying MalformedSidecarError, NOT the softer ErrPerSpawnRequired (a present-but-broken record is more severe than an absent one)", err)
	}
	var malformed *attestation.MalformedSidecarError
	if !errors.As(err, &malformed) {
		t.Fatalf("Resolve(DomainA2A) error = %v (%T), want *attestation.MalformedSidecarError", err, err)
	}
	if malformed.Field != "attested_name" {
		t.Errorf("MalformedSidecarError.Field = %q, want %q (the missing required field must be named)", malformed.Field, "attested_name")
	}
	if id.Subject == "holden" {
		t.Fatal("Resolve(DomainA2A) resolved to the parent session identity on a missing required field — confused-deputy regression")
	}
}
