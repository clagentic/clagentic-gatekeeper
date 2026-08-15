package a2amint_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2amint"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2atoken"
	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// Roster-agnostic fixture values — invented names, generic role vocabulary.
// None correspond to any real crew agent.
const (
	fixtureIdentity = "peer-agent-alpha"
	fixtureRole     = "peer-builder"
	fixtureAudience = "peer-project-x"
)

// fixedIdentityProvider always resolves to a fixed identity, used to build a
// DomainResolver whose PerSpawn leg succeeds (the A2A domain requires a
// per-spawn-scoped resolver to succeed at all, per attestation.DomainA2A).
type fixedIdentityProvider struct {
	identity attestation.Identity
}

func (p fixedIdentityProvider) Resolve(context.Context) (attestation.Identity, error) {
	return p.identity, nil
}

// decliningProvider always declines, used to exercise the fail-closed
// per-spawn-required refusal path.
type decliningProvider struct{}

func (decliningProvider) Resolve(context.Context) (attestation.Identity, error) {
	return attestation.Identity{}, attestation.ErrNoIdentity
}

func domainResolver(identity attestation.Identity) *attestation.DomainResolver {
	chain := attestation.NewResolver(fixedIdentityProvider{identity: identity})
	perSpawn := attestation.NewResolver(fixedIdentityProvider{identity: identity})
	return &attestation.DomainResolver{Chain: chain, PerSpawn: perSpawn}
}

func fixturePolicy() *a2apolicy.Policy {
	return a2apolicy.NewPolicy(map[string]a2apolicy.Entitlement{
		fixtureIdentity: {Role: fixtureRole, Audiences: []string{fixtureAudience}},
	})
}

// fakeBroker implements broker.Broker for tests.
type fakeBroker struct {
	val string
	err error
}

func (f *fakeBroker) Get(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.val, nil
}

func baseService(t *testing.T) *a2amint.Service {
	t.Helper()
	return &a2amint.Service{
		DomainResolver: domainResolver(attestation.Identity{Subject: fixtureIdentity}),
		Policy:         fixturePolicy(),
		Broker:         &fakeBroker{val: "fake-assertion-key-pem"},

		AssertionPrivateKeyPath: "secret/gatekeeper/a2a/assertion-private-key",
		Issuer:                  "gatekeeper-test-issuer",
		AssertionTTL:            5 * time.Minute,

		Endpoint:  "https://openbao.example.invalid",
		AuthMount: "a2a-jwt",
		AuthRoleForRole: map[string]string{
			fixtureRole: "a2a-role",
		},
		OIDCRoleForRole: map[string]string{
			fixtureRole: "a2a-oidc-role",
		},
	}
}

// TestMintPermitted covers the corrected AC1 (lr-890fae comment #5): an
// entitled, attested caller is permitted and Service.Mint calls through to
// issuance (IssueFunc) with the resolved role wired into the request. The
// returned Token carries the OpenBao-issued value and native subject.
func TestMintPermitted(t *testing.T) {
	svc := baseService(t)

	var gotReq a2atoken.IssueRequest
	svc.IssueFunc = func(_ context.Context, req a2atoken.IssueRequest) (a2atoken.Token, error) {
		gotReq = req
		return a2atoken.Token{Value: "openbao-issued-jwt", Subject: req.Subject}, nil
	}

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	tok, err := svc.Mint(context.Background(), fixtureAudience)
	if err != nil {
		t.Fatalf("Mint() unexpected error: %v", err)
	}
	if tok.Value != "openbao-issued-jwt" {
		t.Errorf("Token.Value = %q, want %q", tok.Value, "openbao-issued-jwt")
	}
	if tok.Subject != fixtureIdentity {
		t.Errorf("Token.Subject = %q, want %q", tok.Subject, fixtureIdentity)
	}

	if gotReq.Subject != fixtureIdentity {
		t.Errorf("IssueRequest.Subject = %q, want %q", gotReq.Subject, fixtureIdentity)
	}
	if gotReq.AuthRole != "a2a-role" {
		t.Errorf("IssueRequest.AuthRole = %q, want %q", gotReq.AuthRole, "a2a-role")
	}
	if gotReq.OIDCRole != "a2a-oidc-role" {
		t.Errorf("IssueRequest.OIDCRole = %q, want %q", gotReq.OIDCRole, "a2a-oidc-role")
	}
	if gotReq.AssertionPrivateKeyPEM != "fake-assertion-key-pem" {
		t.Errorf("IssueRequest.AssertionPrivateKeyPEM = %q, want the broker-sourced value", gotReq.AssertionPrivateKeyPEM)
	}

	if len(events) != 1 || !events[0].Permitted {
		t.Fatalf("expected exactly one permitted audit event, got %+v", events)
	}
	if events[0].Identity != fixtureIdentity || events[0].Role != fixtureRole || events[0].Audience != fixtureAudience {
		t.Errorf("audit event = %+v, want identity/role/audience %q/%q/%q", events[0], fixtureIdentity, fixtureRole, fixtureAudience)
	}
}

// TestMintRefusedUnresolvableAttestation covers the fail-closed refusal path
// when attestation itself cannot resolve (A2A domain's per-spawn-required
// policy declines): no token material is returned, IssueFunc is never
// called, and the refusal is audited.
func TestMintRefusedUnresolvableAttestation(t *testing.T) {
	svc := baseService(t)
	svc.DomainResolver = &attestation.DomainResolver{
		Chain:    attestation.NewResolver(decliningProvider{}),
		PerSpawn: attestation.NewResolver(decliningProvider{}),
	}

	issueCalled := false
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		issueCalled = true
		return a2atoken.Token{Value: "should-never-be-returned"}, nil
	}

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	tok, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error for unresolvable attestation, got nil")
	}
	if !errors.Is(err, attestation.ErrPerSpawnRequired) {
		t.Errorf("expected error to wrap ErrPerSpawnRequired, got: %v", err)
	}
	if tok.Value != "" {
		t.Errorf("expected no token material, got %q", tok.Value)
	}
	if issueCalled {
		t.Error("IssueFunc must never be called when attestation cannot resolve")
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("expected exactly one refused audit event, got %+v", events)
	}
}

// TestMintRefusedNotEntitled covers the fail-closed refusal path when the
// attested identity is not entitled to the requested audience
// (internal/a2apolicy denies): no broker read, no issuance call, refusal
// audited with the resolved identity.
func TestMintRefusedNotEntitled(t *testing.T) {
	svc := baseService(t)
	svc.DomainResolver = domainResolver(attestation.Identity{Subject: "unmapped-caller"})

	brokerCalled := false
	svc.Broker = &fakeBrokerFunc{fn: func(context.Context, string) (string, error) {
		brokerCalled = true
		return "", fmt.Errorf("must never be called")
	}}
	issueCalled := false
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		issueCalled = true
		return a2atoken.Token{}, nil
	}

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	tok, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error for unentitled identity, got nil")
	}
	var denied *a2apolicy.DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected *a2apolicy.DeniedError wrapped in the returned error, got %T: %v", err, err)
	}
	if tok.Value != "" {
		t.Errorf("expected no token material, got %q", tok.Value)
	}
	if brokerCalled {
		t.Error("broker must never be read before entitlement is checked")
	}
	if issueCalled {
		t.Error("IssueFunc must never be called for an unentitled identity")
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("expected exactly one refused audit event, got %+v", events)
	}
	if events[0].Identity != "unmapped-caller" {
		t.Errorf("audit event Identity = %q, want %q", events[0].Identity, "unmapped-caller")
	}
}

// TestMintRefusedMissingRoleMapping covers a config-completeness refusal: a
// resolved A2A role with no configured AuthRole/OIDCRole mapping refuses
// closed rather than silently falling back to some other role's mapping.
func TestMintRefusedMissingRoleMapping(t *testing.T) {
	svc := baseService(t)
	svc.AuthRoleForRole = map[string]string{} // no mapping for fixtureRole

	issueCalled := false
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		issueCalled = true
		return a2atoken.Token{}, nil
	}

	_, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error for missing auth-role mapping, got nil")
	}
	if issueCalled {
		t.Error("IssueFunc must never be called when the role mapping is incomplete")
	}
}

// TestMintRefusedIssuanceError covers propagation of an issuance failure:
// the caller sees an error and no token, and the refusal is still audited.
func TestMintRefusedIssuanceError(t *testing.T) {
	svc := baseService(t)
	wantErr := fmt.Errorf("openbao: simulated issuance failure")
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		return a2atoken.Token{}, wantErr
	}

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	_, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error propagated from issuance, got nil")
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("expected exactly one refused audit event, got %+v", events)
	}
}

// fakeBrokerFunc implements broker.Broker with a caller-supplied function,
// used where the test needs to assert the broker was never called at all.
type fakeBrokerFunc struct {
	fn func(context.Context, string) (string, error)
}

func (f *fakeBrokerFunc) Get(ctx context.Context, path string) (string, error) {
	return f.fn(ctx, path)
}
