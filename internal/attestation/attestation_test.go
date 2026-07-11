package attestation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
)

// stubProvider is a minimal Provider for exercising Resolver without I/O.
type stubProvider struct {
	id  attestation.Identity
	err error
}

func (s stubProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	return s.id, s.err
}

func TestResolver_FirstProviderWins(t *testing.T) {
	r := attestation.NewResolver(
		stubProvider{id: attestation.Identity{Subject: "first", Source: "a"}},
		stubProvider{id: attestation.Identity{Subject: "second", Source: "b"}},
	)

	got, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if got.Subject != "first" || got.Source != "a" {
		t.Errorf("Resolve() = %+v, want Subject=first Source=a", got)
	}
}

func TestResolver_FallsThroughOnNoIdentity(t *testing.T) {
	r := attestation.NewResolver(
		stubProvider{err: attestation.ErrNoIdentity},
		stubProvider{id: attestation.Identity{Subject: "second", Source: "b"}},
	)

	got, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if got.Subject != "second" || got.Source != "b" {
		t.Errorf("Resolve() = %+v, want Subject=second Source=b", got)
	}
}

func TestResolver_AllDecline_ReturnsErrNoIdentity(t *testing.T) {
	r := attestation.NewResolver(
		stubProvider{err: attestation.ErrNoIdentity},
		stubProvider{err: attestation.ErrNoIdentity},
	)

	_, err := r.Resolve(context.Background())
	if !errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}

func TestResolver_EmptyChain_ReturnsErrNoIdentity(t *testing.T) {
	r := attestation.NewResolver()

	_, err := r.Resolve(context.Background())
	if !errors.Is(err, attestation.ErrNoIdentity) {
		t.Fatalf("Resolve() error = %v, want ErrNoIdentity", err)
	}
}

func TestResolver_HardErrorStopsChain(t *testing.T) {
	hardErr := errors.New("boom")
	called := false
	r := attestation.NewResolver(
		stubProvider{err: hardErr},
		// This provider must never run: a non-ErrNoIdentity error is a hard
		// failure, not a decline, so the chain must not fall through.
		trackingProvider{&called},
	)

	_, err := r.Resolve(context.Background())
	if !errors.Is(err, hardErr) {
		t.Fatalf("Resolve() error = %v, want %v", err, hardErr)
	}
	if called {
		t.Error("provider after a hard error must not be invoked")
	}
}

type trackingProvider struct {
	called *bool
}

func (t trackingProvider) Resolve(_ context.Context) (attestation.Identity, error) {
	*t.called = true
	return attestation.Identity{Subject: "unused"}, nil
}
