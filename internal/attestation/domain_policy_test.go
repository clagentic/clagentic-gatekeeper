package attestation_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// buildSpawnFirstDeployment builds a DomainResolver mirroring the deployed
// shape from lr-86779f seq 9 / lr-2ca216: an ordered chain of [per-spawn
// sidecar, session sidecar] plus the built-in fallback (via Chain), and a
// PerSpawn resolver scoped to ONLY the per-spawn sidecar entry.
func buildSpawnFirstDeployment(t *testing.T, spawnDir, sessionDir, spawnEnv, sessionEnv string) *attestation.DomainResolver {
	t.Helper()

	spawnCfg := attestation.SidecarConfig{
		Dir:          spawnDir,
		FilePrefix:   "spawn-",
		SessionIDEnv: spawnEnv,
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
	perSpawn := attestation.NewResolver(spawnProvider)

	return &attestation.DomainResolver{Chain: chain, PerSpawn: perSpawn}
}

// TestDomainResolver_A2A_PerSpawnMiss_FailsClosed_NeverSessionFallback is
// direction (a) of the mandatory regression test (lr-2ca216 MILLER comment
// #2): an A2A-domain mint with a per-spawn attestation MISS must refuse
// fail-closed and must NEVER resolve to the session identity, even though
// the session sidecar file IS present and would resolve under DomainLocal.
func TestDomainResolver_A2A_PerSpawnMiss_FailsClosed_NeverSessionFallback(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "ATTESTATION_TEST_DOMAIN_A2A_SPAWN_LR2CA216"
	const sessionEnv = "ATTESTATION_TEST_DOMAIN_A2A_SESSION_LR2CA216"

	// Per-spawn sidecar's harness is NOT active for this invocation (the
	// MISS): no per-spawn env var, no per-spawn file.
	os.Unsetenv(spawnEnv)

	// Session sidecar IS present and WOULD resolve under DomainLocal — this
	// is exactly the parent-identity fallback lr-2ca216 says must never
	// happen for an A2A-domain mint.
	t.Setenv(sessionEnv, "session-lead-1")
	sessionPath := filepath.Join(sessionDir, "lore-agent-name-session-lead-1")
	if err := os.WriteFile(sessionPath, []byte("holden"), 0o600); err != nil {
		t.Fatalf("setup: write session sidecar file: %v", err)
	}

	d := buildSpawnFirstDeployment(t, spawnDir, sessionDir, spawnEnv, sessionEnv)

	id, err := d.Resolve(context.Background(), attestation.DomainA2A)
	if err == nil {
		t.Fatalf("Resolve(DomainA2A) = %+v, nil; want a fail-closed refusal on per-spawn MISS", id)
	}
	if !errors.Is(err, attestation.ErrPerSpawnRequired) {
		t.Fatalf("Resolve(DomainA2A) error = %v, want ErrPerSpawnRequired", err)
	}
	if id.Subject == "holden" {
		t.Fatal("Resolve(DomainA2A) resolved to the parent session identity on a per-spawn MISS — confused-deputy regression")
	}
}

// TestDomainResolver_Local_PerSpawnMiss_StillResolvesViaSession is
// direction (b) of the mandatory regression test: the SAME per-spawn MISS,
// under DomainLocal, must still resolve via the session sidecar exactly as
// today (lr-86779f) — the domain-aware policy must not regress the local
// GitHub/reader mint path.
func TestDomainResolver_Local_PerSpawnMiss_StillResolvesViaSession(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "ATTESTATION_TEST_DOMAIN_LOCAL_SPAWN_LR2CA216"
	const sessionEnv = "ATTESTATION_TEST_DOMAIN_LOCAL_SESSION_LR2CA216"

	os.Unsetenv(spawnEnv)
	t.Setenv(sessionEnv, "session-lead-2")
	sessionPath := filepath.Join(sessionDir, "lore-agent-name-session-lead-2")
	if err := os.WriteFile(sessionPath, []byte("holden"), 0o600); err != nil {
		t.Fatalf("setup: write session sidecar file: %v", err)
	}

	d := buildSpawnFirstDeployment(t, spawnDir, sessionDir, spawnEnv, sessionEnv)

	id, err := d.Resolve(context.Background(), attestation.DomainLocal)
	if err != nil {
		t.Fatalf("Resolve(DomainLocal): unexpected error: %v", err)
	}
	if id.Subject != "holden" || id.Source != "sidecar" {
		t.Errorf("Resolve(DomainLocal) = %+v, want Subject=holden Source=sidecar (session-sidecar fallback preserved)", id)
	}
}

// TestDomainResolver_A2A_PerSpawnResolves_Succeeds verifies the A2A-domain
// happy path: when the per-spawn provider DOES resolve, DomainResolver
// returns that identity (not the session identity), matching AC#3 of
// lr-a850d0 (structured record + attribution available for cross-attribution).
func TestDomainResolver_A2A_PerSpawnResolves_Succeeds(t *testing.T) {
	spawnDir := t.TempDir()
	sessionDir := t.TempDir()

	const spawnEnv = "ATTESTATION_TEST_DOMAIN_A2A_HIT_SPAWN_LR2CA216"
	const sessionEnv = "ATTESTATION_TEST_DOMAIN_A2A_HIT_SESSION_LR2CA216"

	t.Setenv(spawnEnv, "spawn-99")
	spawnPath := filepath.Join(spawnDir, "spawn-spawn-99")
	if err := os.WriteFile(spawnPath, []byte("caller-agent"), 0o600); err != nil {
		t.Fatalf("setup: write per-spawn sidecar file: %v", err)
	}
	os.Unsetenv(sessionEnv)

	d := buildSpawnFirstDeployment(t, spawnDir, sessionDir, spawnEnv, sessionEnv)

	id, err := d.Resolve(context.Background(), attestation.DomainA2A)
	if err != nil {
		t.Fatalf("Resolve(DomainA2A): unexpected error: %v", err)
	}
	if id.Subject != "caller-agent" {
		t.Errorf("Resolve(DomainA2A) = %+v, want Subject=caller-agent", id)
	}
}

// TestDomainResolver_A2A_NilPerSpawn_FailsClosed verifies that a
// DomainResolver with no PerSpawn resolver configured at all refuses
// DomainA2A rather than panicking or silently delegating to Chain.
func TestDomainResolver_A2A_NilPerSpawn_FailsClosed(t *testing.T) {
	chain, err := attestation.NewChain(attestation.ChainConfig{})
	if err != nil {
		t.Fatalf("NewChain: unexpected error: %v", err)
	}
	d := &attestation.DomainResolver{Chain: chain}

	_, err = d.Resolve(context.Background(), attestation.DomainA2A)
	if !errors.Is(err, attestation.ErrPerSpawnRequired) {
		t.Fatalf("Resolve(DomainA2A) error = %v, want ErrPerSpawnRequired", err)
	}
}
