package mint_test

import (
	"context"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/githubapp"
	"github.com/clagentic/clagentic-gatekeeper/internal/mint"
	"github.com/clagentic/clagentic-gatekeeper/internal/roles"
)

// assertionProvider stands in for the assertion provider: it resolves the
// identity the verified assertion would have produced.
type assertionProvider struct{ id attestation.Identity }

func (p assertionProvider) Resolve(context.Context) (attestation.Identity, error) { return p.id, nil }

func assertionIdentity(grade string, roleNames ...string) attestation.Identity {
	return attestation.Identity{
		Subject: "agent:example-builder", Source: attestation.SourceAssertion,
		Roles: roleNames, Grade: grade, Issuer: "https://issuer.example",
	}
}

func assertionService(id attestation.Identity, bindings map[string]mint.RoleBinding, audit func(mint.AuditEvent)) (*mint.Service, *bool) {
	minted := false
	return &mint.Service{
		Roles: roles.NewRegistry(),
		Broker: &fakeBroker{vals: map[string]string{
			testAppIDPath: testAppID, testInstallIDPath: testInstallID,
			testPrivateKeyPath: testFakeKey, testAppSlugPath: testAppSlug,
		}},
		AttestationResolver: attestation.NewResolver(assertionProvider{id}),
		Bindings:            bindings,
		Audit:               audit,
		MintFunc: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
			minted = true
			return fakeToken, nil
		},
	}, &minted
}

// assertionBinding has no entitled_identities: the assertion's roles are the
// entitlement.
func assertionBinding(minGrade string) mint.RoleBinding {
	b := builderBinding()
	b.EntitledIdentities = nil
	b.MinGrade = minGrade
	return b
}

func TestAssertionRoleInCeilingMintsAndAuditNamesSubjectAndGrade(t *testing.T) {
	var events []mint.AuditEvent
	svc, _ := assertionService(assertionIdentity("harness", "builder"),
		map[string]mint.RoleBinding{"builder": assertionBinding("")},
		func(ev mint.AuditEvent) { events = append(events, ev) })

	res, err := svc.MintAttributed(context.Background(), attestation.DomainLocal, "builder", nil)
	if err != nil {
		t.Fatalf("MintAttributed: %v", err)
	}
	if res.Token.Value != fakeToken.Value || res.Identity.Subject != "agent:example-builder" || res.Identity.Grade != "harness" {
		t.Errorf("result = %+v", res)
	}
	if len(events) != 1 || !events[0].Permitted || events[0].Subject != "agent:example-builder" || events[0].Grade != "harness" || events[0].Role != "builder" {
		t.Errorf("audit events = %+v", events)
	}
}

func TestAssertionRoleOutsideCeilingRefusesNamingBothRoles(t *testing.T) {
	var events []mint.AuditEvent
	svc, minted := assertionService(assertionIdentity("workload", "builder"),
		map[string]mint.RoleBinding{"builder": assertionBinding(""), "merger": assertionBinding("")},
		func(ev mint.AuditEvent) { events = append(events, ev) })

	_, err := svc.Mint(context.Background(), "merger", nil)
	if err == nil {
		t.Fatal("a builder assertion minted the merger role")
	}
	for _, want := range []string{"merger", "builder"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if *minted {
		t.Error("a token was minted for a refused role")
	}
	if len(events) != 1 || events[0].Permitted || events[0].Reason == "" {
		t.Errorf("audit events = %+v, want one refusal with a reason", events)
	}
}

func TestAssertionBelowMinGradeRefusesNamingGradeRequirement(t *testing.T) {
	svc, minted := assertionService(assertionIdentity("harness", "merger"),
		map[string]mint.RoleBinding{"merger": assertionBinding("workload")}, nil)

	_, err := svc.Mint(context.Background(), "merger", nil)
	if err == nil {
		t.Fatal("a harness assertion minted a role that requires workload")
	}
	for _, want := range []string{"workload", "harness", "grade"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if *minted {
		t.Error("a token was minted below the minimum grade")
	}
}

func TestAssertionWorkloadMeetsEitherMinGrade(t *testing.T) {
	for _, min := range []string{"", "harness", "workload"} {
		svc, _ := assertionService(assertionIdentity("workload", "merger"),
			map[string]mint.RoleBinding{"merger": assertionBinding(min)}, nil)
		if _, err := svc.Mint(context.Background(), "merger", nil); err != nil {
			t.Errorf("min_grade %q refused a workload assertion: %v", min, err)
		}
	}
}

func TestAssertionEntitledIdentitiesOnlyNarrows(t *testing.T) {
	b := assertionBinding("")
	b.EntitledIdentities = []string{"agent:someone-else"}
	svc, minted := assertionService(assertionIdentity("workload", "builder"),
		map[string]mint.RoleBinding{"builder": b}, nil)
	_, err := svc.Mint(context.Background(), "builder", nil)
	if err == nil || !strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("got %v, want an entitlement refusal from the extra allowlist", err)
	}
	if *minted {
		t.Error("a token was minted outside the extra allowlist")
	}

	b.EntitledIdentities = []string{"agent:example-builder"}
	svc, _ = assertionService(assertionIdentity("workload", "builder"),
		map[string]mint.RoleBinding{"builder": b}, nil)
	if _, err := svc.Mint(context.Background(), "builder", nil); err != nil {
		t.Fatalf("listed subject refused: %v", err)
	}
}

// A non-assertion identity is entitled exactly as before: min_grade does not
// apply to it and no audit event is produced.
func TestNonAssertionIdentityKeepsEntitledIdentitiesPath(t *testing.T) {
	audited := false
	b := builderBinding()
	b.MinGrade = "workload"
	svc := &mint.Service{
		Roles: roles.NewRegistry(),
		Broker: &fakeBroker{vals: map[string]string{
			testAppIDPath: testAppID, testInstallIDPath: testInstallID,
			testPrivateKeyPath: testFakeKey, testAppSlugPath: testAppSlug,
		}},
		AttestationResolver: testResolver(),
		Bindings:            map[string]mint.RoleBinding{"builder": b},
		Audit:               func(mint.AuditEvent) { audited = true },
		MintFunc: func(context.Context, githubapp.MintRequest) (githubapp.Token, error) {
			return fakeToken, nil
		},
	}
	if _, err := svc.Mint(context.Background(), "builder", nil); err != nil {
		t.Fatalf("configured-provider mint refused: %v", err)
	}
	if audited {
		t.Error("an audit event was produced for a non-assertion identity")
	}

	b.EntitledIdentities = []string{"someone-else"}
	svc.Bindings["builder"] = b
	if _, err := svc.Mint(context.Background(), "builder", nil); err == nil || !strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("got %v, want the unchanged entitlement refusal", err)
	}
}

func TestValidMinGrade(t *testing.T) {
	for _, ok := range []string{"", "workload", "harness"} {
		if !mint.ValidMinGrade(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	if mint.ValidMinGrade("admin") {
		t.Error("admin should be invalid")
	}
}
