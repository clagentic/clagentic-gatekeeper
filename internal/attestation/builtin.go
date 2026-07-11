package attestation

import (
	"context"
	"os/user"
)

// currentUser is overridden in tests to avoid depending on the test
// runner's actual OS user/environment.
var currentUser = user.Current

// NewBuiltinProvider returns the layer (c) fallback provider gatekeeper
// ships unconditionally: the OS-reported invoking user. It has no
// deployment-specific configuration and is always available, so a bare
// install always has an attested source rather than failing open.
func NewBuiltinProvider() Provider {
	return &builtinProvider{}
}

// builtinProvider resolves the attested identity to the OS user the
// gatekeeper process is running as. This is the last-resort fallback: it
// carries no crew-role semantics of its own, only whatever the host OS
// attests to.
type builtinProvider struct{}

func (p *builtinProvider) Resolve(_ context.Context) (Identity, error) {
	u, err := currentUser()
	if err != nil || u == nil || u.Username == "" {
		// The built-in fallback must never hard-fail the chain: if even the
		// OS cannot attest to a user, there is nothing left to resolve.
		return Identity{}, ErrNoIdentity
	}
	return Identity{Subject: u.Username, Source: "builtin"}, nil
}
