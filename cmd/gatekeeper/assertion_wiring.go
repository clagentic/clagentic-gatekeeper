package main

import (
	"fmt"

	"github.com/clagentic/clagentic-gatekeeper/internal/attestation"
	"github.com/clagentic/clagentic-gatekeeper/internal/config"
)

// buildAssertionProvider returns the Identity Assertion provider when the
// config has an attestation.assertion section, else nil. The local serve
// issuer is always trusted: its iss is identity.issuer or unix://<socket>, and
// its key set is identity.jwks_path when set, else discovered from the iss. An
// explicitly listed issuer with the same iss replaces that default entry.
func buildAssertionProvider(cfg *config.Config) (attestation.Provider, error) {
	if cfg.Attestation.Assertion == nil {
		return nil, nil
	}
	var issuers []attestation.AssertionIssuer
	listed := map[string]bool{}
	for i, is := range cfg.Attestation.Assertion.Issuers {
		if is.Iss == "" {
			return nil, fmt.Errorf("attestation.assertion.issuers[%d] has no iss", i)
		}
		listed[is.Iss] = true
		issuers = append(issuers, attestation.AssertionIssuer{Iss: is.Iss, JWKS: is.JWKS})
	}
	localIss := cfg.Identity.Issuer
	if localIss == "" {
		localIss = "unix://" + socketFor("", cfg)
	}
	if !listed[localIss] {
		issuers = append(issuers, attestation.AssertionIssuer{Iss: localIss, JWKS: cfg.Identity.JWKSPath})
	}
	return attestation.NewAssertionProvider(attestation.AssertionConfig{Issuers: issuers})
}
