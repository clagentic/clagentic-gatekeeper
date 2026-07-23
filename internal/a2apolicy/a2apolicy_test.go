package a2apolicy_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/config"
)

// Roster-agnostic fixture values — invented names, generic role vocabulary
// (AC 5). None of these correspond to any real crew agent.
const (
	fixtureIdentity = "peer-agent-alpha"
	fixtureRole     = "peer-builder"
	fixtureAudience = "peer-project-x"
	otherAudience   = "peer-project-y"
)

func fixturePolicy() *a2apolicy.Policy {
	return a2apolicy.NewPolicy(map[string]a2apolicy.Entitlement{
		fixtureIdentity: {
			Role:      fixtureRole,
			Audiences: []string{fixtureAudience},
		},
	})
}

// TestCheckPermitted covers AC 1: an entitled identity requesting a covered
// audience is permitted and the configured role is returned.
func TestCheckPermitted(t *testing.T) {
	p := fixturePolicy()

	role, err := p.Check(fixtureIdentity, fixtureAudience)
	if err != nil {
		t.Fatalf("Check() unexpected error: %v", err)
	}
	if role != fixtureRole {
		t.Errorf("Check() role = %q, want %q", role, fixtureRole)
	}
}

// TestCheckIdentityAbsent covers AC 2: an attested identity absent from the
// mapping is refused fail-closed with a structured error reporting the
// resolved identity and requested audience. Role must be empty — there is
// no role to name for an identity that was never found.
func TestCheckIdentityAbsent(t *testing.T) {
	p := fixturePolicy()

	const unknownIdentity = "peer-agent-unmapped"
	role, err := p.Check(unknownIdentity, fixtureAudience)
	if err == nil {
		t.Fatal("expected error for identity absent from mapping, got nil")
	}
	if role != "" {
		t.Errorf("Check() role = %q, want empty on denial", role)
	}

	var denied *a2apolicy.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *a2apolicy.DeniedError, got %T: %v", err, err)
	}
	if denied.Identity != unknownIdentity {
		t.Errorf("DeniedError.Identity = %q, want %q (must report RESOLVED identity, never stale/guessed)", denied.Identity, unknownIdentity)
	}
	if denied.Audience != fixtureAudience {
		t.Errorf("DeniedError.Audience = %q, want %q", denied.Audience, fixtureAudience)
	}
	if denied.Role != "" {
		t.Errorf("DeniedError.Role = %q, want empty (identity was never found in the mapping)", denied.Role)
	}
	if !strings.Contains(err.Error(), unknownIdentity) || !strings.Contains(err.Error(), fixtureAudience) {
		t.Errorf("error message %q must name the resolved identity and requested audience", err.Error())
	}
}

// TestCheckAudienceNotCovered covers AC 3: an entitled identity requesting
// an audience its role does not cover is refused, naming the resolved role
// and the denied audience.
func TestCheckAudienceNotCovered(t *testing.T) {
	p := fixturePolicy()

	role, err := p.Check(fixtureIdentity, otherAudience)
	if err == nil {
		t.Fatal("expected error for audience not covered by role, got nil")
	}
	if role != "" {
		t.Errorf("Check() role = %q, want empty on denial", role)
	}

	var denied *a2apolicy.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *a2apolicy.DeniedError, got %T: %v", err, err)
	}
	if denied.Identity != fixtureIdentity {
		t.Errorf("DeniedError.Identity = %q, want %q", denied.Identity, fixtureIdentity)
	}
	if denied.Role != fixtureRole {
		t.Errorf("DeniedError.Role = %q, want %q (must name the RESOLVED role)", denied.Role, fixtureRole)
	}
	if denied.Audience != otherAudience {
		t.Errorf("DeniedError.Audience = %q, want %q (must name the DENIED audience)", denied.Audience, otherAudience)
	}
	if !strings.Contains(err.Error(), fixtureRole) || !strings.Contains(err.Error(), otherAudience) {
		t.Errorf("error message %q must name the resolved role and the denied audience", err.Error())
	}
}

// TestCheckEmptyPolicyFailsClosed covers AC 4's other half: a Policy built
// from a nil/empty map (exactly what a deployment with no A2A mapping
// stanza produces) refuses every request rather than defaulting open.
func TestCheckEmptyPolicyFailsClosed(t *testing.T) {
	p := a2apolicy.NewPolicy(nil)

	_, err := p.Check(fixtureIdentity, fixtureAudience)
	if err == nil {
		t.Fatal("expected error for empty policy, got nil")
	}
	var denied *a2apolicy.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *a2apolicy.DeniedError, got %T: %v", err, err)
	}
}

// TestCheckNilPolicyFailsClosed asserts that a nil *Policy (the zero value
// a deployment gets when a2apolicy is never wired up at all) also fails
// closed rather than panicking or defaulting open.
func TestCheckNilPolicyFailsClosed(t *testing.T) {
	var p *a2apolicy.Policy

	_, err := p.Check(fixtureIdentity, fixtureAudience)
	if err == nil {
		t.Fatal("expected error for nil *Policy, got nil")
	}
}

// TestEntitlementNoAudiencesFailsClosed asserts that an Entitlement with an
// empty Audiences list (an identity mapped to a role but no audiences)
// refuses every audience request — mirrors internal/mint's
// "empty entitled list fails closed" regression guard.
func TestEntitlementNoAudiencesFailsClosed(t *testing.T) {
	p := a2apolicy.NewPolicy(map[string]a2apolicy.Entitlement{
		fixtureIdentity: {Role: fixtureRole, Audiences: nil},
	})

	_, err := p.Check(fixtureIdentity, fixtureAudience)
	if err == nil {
		t.Fatal("expected error for role with no configured audiences, got nil")
	}
}

// TestNewPolicyFromEntries_ConfigWiring is an end-to-end test proving the
// real wiring path: config.Load parses an a2a_mapping stanza into
// config.A2AEntitlementConfig, and NewPolicyFromEntries builds a working
// Policy from it directly — no separate hand-conversion step, and no
// a2apolicy<->config import cycle (config.A2AEntitlementConfig satisfies
// a2apolicy.EntitlementSource structurally).
func TestNewPolicyFromEntries_ConfigWiring(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
github:
  owner: myorg

broker:
  type: env

roles: {}

a2a_mapping:
  peer-agent-alpha:
    role: peer-builder
    audiences:
      - peer-project-x
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load returned error: %v", err)
	}

	p := a2apolicy.NewPolicyFromEntries(cfg.A2AMapping)

	role, err := p.Check(fixtureIdentity, fixtureAudience)
	if err != nil {
		t.Fatalf("Check() unexpected error for config-sourced entry: %v", err)
	}
	if role != fixtureRole {
		t.Errorf("Check() role = %q, want %q", role, fixtureRole)
	}

	if _, err := p.Check(fixtureIdentity, otherAudience); err == nil {
		t.Error("expected denial for audience not covered by the config-sourced entitlement")
	}
}

// TestNewPolicyFromEntries_EmptyMapFailsClosed covers AC 4 via the actual
// wiring helper: a config with no a2a_mapping stanza produces a nil
// cfg.A2AMapping, and NewPolicyFromEntries must turn that into a
// fully-closed Policy, not a nil Policy that panics or an open one.
func TestNewPolicyFromEntries_EmptyMapFailsClosed(t *testing.T) {
	p := a2apolicy.NewPolicyFromEntries(map[string]config.A2AEntitlementConfig(nil))

	_, err := p.Check(fixtureIdentity, fixtureAudience)
	if err == nil {
		t.Fatal("expected error for empty/absent a2a_mapping, got nil")
	}
}
