package a2amint_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/a2amint"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2apolicy"
	"github.com/clagentic/clagentic-gatekeeper/internal/a2atoken"
	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// Roster-agnostic fixture values — invented names, generic role vocabulary.
// None correspond to any real crew agent.
const (
	fixtureIdentity  = "peer-agent-alpha"
	fixtureRole      = "peer-builder"
	fixtureAudience  = "peer-project-x"
	fixtureAssertion = "eyJhbGciOiJFZERTQSJ9.fixture-payload.fixture-signature"
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

func baseService(t *testing.T) *a2amint.Service {
	t.Helper()
	return &a2amint.Service{
		DomainResolver: domainResolver(attestation.Identity{
			Subject:   fixtureIdentity,
			ActSub:    fixtureIdentity,
			Source:    attestation.SourceAssertion,
			Assertion: fixtureAssertion,
		}),
		Policy: fixturePolicy(),

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
	if gotReq.Assertion != fixtureAssertion {
		t.Errorf("IssueRequest.Assertion = %q, want the caller's verified assertion", gotReq.Assertion)
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
// (internal/a2apolicy denies): no issuance call, refusal audited with the
// resolved identity.
func TestMintRefusedNotEntitled(t *testing.T) {
	svc := baseService(t)
	svc.DomainResolver = domainResolver(attestation.Identity{Subject: "unmapped-caller", Source: attestation.SourceAssertion, Assertion: fixtureAssertion})

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

// TestMintAuditRedactsTransportErrorBody is the cross-boundary regression
// test for the MILLER-adjudicated F1 finding (lr-890fae comment #8): the
// per-package invariants around key material were already covered (neither
// a2atoken nor a2amint ever puts key content in an error), but nothing
// traced an OpenBao HTTP response BODY across the a2atoken -> a2amint
// boundary into AuditEvent.Reason. This test drives Service.Mint with the
// REAL a2atoken.Issue (not a stub IssueFunc) against a stub HTTP server that
// stands in for an intervening proxy returning an oversized, non-OpenBao-
// shaped error body on the jwt-auth-login leg, and asserts the value that
// actually lands in AuditEvent.Reason — what a real deployment's log sink
// would see — is bounded and redacted, not an unbounded echo of the body.
func TestMintAuditRedactsTransportErrorBody(t *testing.T) {
	hugeProxyBody := "<html><body>" + strings.Repeat("leaked-upstream-content-", 20) + "</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxy error page: not JSON, not OpenBao's {"errors":[...]}
		// envelope — exactly the unbounded third-party-content case
		// a2atoken.TransportError's truncation exists for.
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(hugeProxyBody)) //nolint:errcheck
	}))
	defer srv.Close()

	svc := baseService(t)
	svc.Endpoint = srv.URL
	svc.IssueFunc = nil // use the real a2atoken.Issue, the actual boundary.

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	_, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error propagated from issuance, got nil")
	}
	var transportErr *a2atoken.TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected the returned error to wrap *a2atoken.TransportError, got %T: %v", err, err)
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("expected exactly one refused audit event, got %+v", events)
	}

	reason := events[0].Reason
	// The proxy body is ~500 bytes; the load-bearing assertion is that
	// Reason is BOUNDED (truncated) rather than an unbounded, verbatim echo
	// of the full body — not that every substring of the body is absent, a
	// truncated excerpt legitimately still contains a prefix of the source
	// content by design (a2atoken.truncateExcerpt).
	if !strings.Contains(reason, "...(truncated)") {
		t.Errorf("AuditEvent.Reason = %q, want it to carry the truncation marker for an oversized non-OpenBao-shaped body", reason)
	}
	if strings.Contains(reason, hugeProxyBody) {
		t.Fatalf("AuditEvent.Reason contains the full, untruncated proxy body: %q", reason)
	}
	if len(reason) > 400 {
		t.Errorf("AuditEvent.Reason is not bounded: %d bytes: %q", len(reason), reason)
	}
	// The bounded TransportError message itself (op + status + truncated
	// excerpt marker) must still be present — this is redaction, not
	// silence; gatekeeper's own audit record must still show an OpenBao
	// call failed and why, just not an unbounded echo of what a proxy sent.
	if !strings.Contains(reason, "jwt auth login") {
		t.Errorf("AuditEvent.Reason = %q, want it to still name the failing OpenBao operation", reason)
	}
}

// TestMintAuditRedactsOversizedOpenBaoErrorEnvelope is the cross-boundary
// regression test for the F1-class-completeness gap MILLER's adjudication
// (lr-890fae comment #11) identified: TestMintAuditRedactsTransportErrorBody
// above only ever drove a NON-OpenBao-shaped (raw-fallback) body across this
// boundary. This test drives a body that DOES match OpenBao's documented
// {"errors":[...]} envelope shape but whose joined error strings exceed
// a2atoken's maxRawBodyExcerpt, through the REAL a2atoken.Issue, and asserts
// AuditEvent.Reason — what a real deployment's log sink would see — is
// bounded on this branch exactly as it is on the raw-fallback branch.
func TestMintAuditRedactsOversizedOpenBaoErrorEnvelope(t *testing.T) {
	oversizedErrors := []string{
		strings.Repeat("policy-validation-detail-", 12),
		strings.Repeat("secondary-detail-", 12),
	}
	joined := strings.Join(oversizedErrors, "; ")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"errors":[%s]}`, quoteAll(oversizedErrors)) //nolint:errcheck
	}))
	defer srv.Close()

	svc := baseService(t)
	svc.Endpoint = srv.URL
	svc.IssueFunc = nil // use the real a2atoken.Issue, the actual boundary.

	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	_, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil {
		t.Fatal("expected error propagated from issuance, got nil")
	}
	var transportErr *a2atoken.TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected the returned error to wrap *a2atoken.TransportError, got %T: %v", err, err)
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("expected exactly one refused audit event, got %+v", events)
	}

	reason := events[0].Reason
	if len(joined) < 200 {
		t.Fatalf("test setup error: joined envelope strings (%d bytes) must exceed the a2atoken truncation bound to exercise it", len(joined))
	}
	if strings.Contains(reason, joined) {
		t.Fatalf("AuditEvent.Reason contains the full, untruncated joined OpenBao envelope strings: %q", reason)
	}
	if !strings.Contains(reason, "...(truncated)") {
		t.Errorf("AuditEvent.Reason = %q, want it to carry the truncation marker for an oversized OpenBao errors[] envelope", reason)
	}
	if len(reason) > 400 {
		t.Errorf("AuditEvent.Reason is not bounded: %d bytes: %q", len(reason), reason)
	}
	if !strings.Contains(reason, "jwt auth login") {
		t.Errorf("AuditEvent.Reason = %q, want it to still name the failing OpenBao operation", reason)
	}
}

// quoteAll renders each string in ss as a JSON string literal, joined by
// commas, for constructing a raw {"errors":[...]} response body by hand in
// TestMintAuditRedactsOversizedOpenBaoErrorEnvelope — avoids importing
// encoding/json purely to marshal a one-off literal in the test itself.
func quoteAll(ss []string) string {
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ",")
}

// An assertion that carries no act.sub is refused with a named error before any
// OpenBao call, even when its sub is entitled: there is no sub fallback.
func TestMintRefusedAssertionWithoutActSub(t *testing.T) {
	svc := baseService(t)
	svc.DomainResolver = domainResolver(attestation.Identity{
		Subject: fixtureIdentity, Source: attestation.SourceAssertion, Assertion: fixtureAssertion,
	})

	issueCalled := false
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		issueCalled = true
		return a2atoken.Token{}, nil
	}
	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	tok, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil || !strings.Contains(err.Error(), "carries no act.sub") {
		t.Fatalf("Mint() = %v, want a refusal naming the missing act.sub", err)
	}
	if tok.Value != "" || issueCalled {
		t.Errorf("token %q, issueCalled %v: nothing may be issued without act.sub", tok.Value, issueCalled)
	}
	if len(events) != 1 || events[0].Permitted {
		t.Fatalf("audit events = %+v, want one refusal", events)
	}
}

// TestMintRefusedWithoutAssertion: an identity that did not come from an
// identity assertion (a sidecar or configured identity) has nothing to log in
// with at the JWT mount. It is refused before any OpenBao call and the refusal
// is audited with the resolved identity.
func TestMintRefusedWithoutAssertion(t *testing.T) {
	svc := baseService(t)
	svc.DomainResolver = domainResolver(attestation.Identity{Subject: fixtureIdentity, Source: "sidecar"})

	issueCalled := false
	svc.IssueFunc = func(context.Context, a2atoken.IssueRequest) (a2atoken.Token, error) {
		issueCalled = true
		return a2atoken.Token{}, nil
	}
	var events []a2amint.AuditEvent
	svc.Audit = func(ev a2amint.AuditEvent) { events = append(events, ev) }

	tok, err := svc.Mint(context.Background(), fixtureAudience)
	if err == nil || !strings.Contains(err.Error(), "identity assertion") {
		t.Fatalf("Mint() = %v, want a refusal naming the missing identity assertion", err)
	}
	if tok.Value != "" || issueCalled {
		t.Errorf("token %q, issueCalled %v: nothing may be issued without an assertion", tok.Value, issueCalled)
	}
	if len(events) != 1 || events[0].Permitted || events[0].Identity != fixtureIdentity {
		t.Fatalf("audit events = %+v, want one refusal for %q", events, fixtureIdentity)
	}
}
