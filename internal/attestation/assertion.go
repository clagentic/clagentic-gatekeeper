package attestation

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// This file owns the Identity Assertion provider: the chain layer that reads
// the assertion delivered through CLAGENTIC_IDENTITY_DIR, verifies it against
// the issuers the deployment trusts (docs/identity-contract.md), and turns the
// verified claims into an Identity. The verification steps live in
// assertion_verify.go, key discovery in assertion_jwks.go and the platform
// file reads in assertion_delivery_*.go.

const (
	// IdentityDirEnv is the delivery variable of the contract's section 6.
	IdentityDirEnv = "CLAGENTIC_IDENTITY_DIR"

	// AssertionFile is the file name inside the delivery directory.
	AssertionFile = "identity.jwt"

	// SourceAssertion is the Identity.Source of an identity the assertion
	// provider resolved. mint keys the role-ceiling and grade checks on it.
	SourceAssertion = "assertion"
)

// AssertionIssuer names one trusted issuer and where its keys are found.
type AssertionIssuer struct {
	// Iss is the exact string compared with the token's iss claim.
	Iss string
	// JWKS is the optional explicit key set locator: an absolute path or a
	// file: URL (the document), an http(s) URL (the document) or a unix: URL
	// (the socket serving /.well-known/jwks.json). Empty derives it from Iss
	// by the contract's section 5.1 rule.
	JWKS string
}

// AssertionConfig configures the assertion provider.
type AssertionConfig struct {
	// Issuers is the trusted issuer list. Trust is exactly this list and
	// nothing the token names.
	Issuers []AssertionIssuer
}

type assertionProvider struct {
	issuers map[string]locator
	fetch   func(ctx context.Context, l locator) ([]byte, error)
	now     func() time.Time
}

// NewAssertionProvider builds the provider, validating every issuer entry up
// front so a bad config fails at startup rather than on the first mint.
func NewAssertionProvider(cfg AssertionConfig) (Provider, error) {
	if len(cfg.Issuers) == 0 {
		return nil, fmt.Errorf("attestation: assertion provider needs at least one trusted issuer")
	}
	issuers := make(map[string]locator, len(cfg.Issuers))
	for _, is := range cfg.Issuers {
		if is.Iss == "" {
			return nil, fmt.Errorf("attestation: assertion issuer entry has an empty iss")
		}
		if _, dup := issuers[is.Iss]; dup {
			return nil, fmt.Errorf("attestation: assertion issuer %q is listed twice", is.Iss)
		}
		l, err := resolveLocator(is.Iss, is.JWKS)
		if err != nil {
			return nil, fmt.Errorf("attestation: assertion issuer %q: %w", is.Iss, err)
		}
		issuers[is.Iss] = l
	}
	return &assertionProvider{issuers: issuers, fetch: fetchJWKS, now: time.Now}, nil
}

// Resolve returns ErrNoIdentity only when the delivery variable is not set (or
// empty): there is then no assertion to judge and the next provider may
// answer. Every other failure is a hard error, so a bad, forged or expired
// assertion is never papered over by a lower-priority identity.
func (p *assertionProvider) Resolve(ctx context.Context) (Identity, error) {
	dir, set := os.LookupEnv(IdentityDirEnv)
	if !set || dir == "" {
		return Identity{}, ErrNoIdentity
	}
	token, aerr := readDelivery(dir)
	if aerr != nil {
		return Identity{}, aerr
	}
	claims, aerr := verifyAssertion(ctx, string(token), p, verifyParams{
		Now:         p.now().Unix(),
		Mode:        modeLocal,
		ObservedDir: dir,
	})
	if aerr != nil {
		return Identity{}, aerr
	}
	return Identity{
		Subject: claims.Actor,
		Source:  SourceAssertion,
		Roles:   claims.Roles,
		Grade:   claims.Grade,
		Issuer:  claims.Iss,

		Assertion: strings.TrimSpace(string(token)),
	}, nil
}

func (p *assertionProvider) trusted(iss string) bool {
	_, ok := p.issuers[iss]
	return ok
}

func (p *assertionProvider) keys(ctx context.Context, iss string) ([]jwk, error) {
	raw, err := p.fetch(ctx, p.issuers[iss])
	if err != nil {
		return nil, err
	}
	return parseJWKS(raw)
}
