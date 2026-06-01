// Package githubapp signs the GitHub App JWT and exchanges it for a short-lived,
// permission-narrowed installation access token. It is an I/O leaf: it talks to
// the GitHub API and nothing else. The App private key is used only to sign the
// JWT and is never returned, logged, or persisted.
package githubapp

import (
	"context"
	"time"
)

// Token is a minted installation access token and its expiry.
type Token struct {
	Value     string
	ExpiresAt time.Time
}

// MintRequest narrows an installation token to a role's permissions and repos.
type MintRequest struct {
	APIBase        string            // e.g. https://api.github.com
	AppID          string            // GitHub App numeric ID (from broker)
	InstallationID string            // installation ID on the target org (from broker)
	PrivateKeyPEM  string            // App private key PEM (from broker) — never logged
	Permissions    map[string]string // role-narrowed permissions
	Repositories   []string          // repo names to scope the token to (may be empty = all)
	TTL            time.Duration     // requested lifetime; GitHub caps at 1h
}

// Mint signs the App JWT and calls
// POST {APIBase}/app/installations/{InstallationID}/access_tokens
// with the narrowed permissions and repositories, returning the scoped token.
//
// TODO(build): implement JWT signing (RS256 over the App private key) and the
// access_tokens exchange. Ensure the private key is zeroed/dropped after signing
// and never appears in any error message.
func Mint(ctx context.Context, req MintRequest) (Token, error) {
	panic("not yet implemented")
}
