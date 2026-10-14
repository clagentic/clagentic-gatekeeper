// Package identity issues the Identity Assertion defined in
// docs/identity-contract.md: a signed statement of which actor is acting, on
// whose behalf, under which role ceiling. It owns the signing key, the
// published key set, and the policy that turns kernel-attested peer
// credentials into claims. The issuer relies on SO_PEERCRED and /proc and is
// linux-only; the wire types and Client in this package build everywhere.
package identity

import "errors"

// This file holds what a client of the issuer needs and nothing that touches
// the host: it builds on every platform, while the issuer itself is linux-only.

// Wire paths. JWKS discovery uses the contract's fixed path.
const (
	PathJWKS         = "/.well-known/jwks.json"
	PathIssueSession = "/v1/issue-session"
	PathIssueChild   = "/v1/issue-child"
)

// DefaultSocketPath is used when neither --socket nor identity.socket_path is set.
const DefaultSocketPath = "/run/clagentic-gatekeeper/identity.sock"

// DeliveryFile is the file name the contract's section 6 fixes.
const DeliveryFile = "identity.jwt"

// Public error codes. Each code has exactly one message, fixed in the issuer;
// anything that varies with the request or the host goes to the server log.
const (
	CodeBadRequest        = "bad_request"
	CodePeerUnattested    = "peer_unattested"
	CodePeerUIDRefused    = "peer_uid_refused"
	CodeRuntimeMismatch   = "runtime_mismatch"
	CodeOriginForbidden   = "origin_forbidden"
	CodeDefinitionUnknown = "definition_unknown"
	CodeParentInvalid     = "parent_invalid"
	CodeParentExpired     = "parent_expired"
	CodeParentUnknown     = "parent_unknown"
	CodeUIDMismatch       = "uid_mismatch"
	CodePIDMismatch       = "parent_pid_mismatch"
	CodeLifetimeEmpty     = "lifetime_empty"
	CodeSpawnDir          = "spawn_dir"
	CodeInternal          = "internal"
)

// IssueError is a refusal with a stable code and message a client can act on.
// detail holds the internal cause (paths, keys, parser and host errors, the
// ids that differed); it is logged by the server and never serialised or
// included in Error. It is unexported so no package-level caller can read it;
// Unwrap is the in-process route for errors.Is/As.
type IssueError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"-"`
	detail  error
}

func (e *IssueError) Error() string { return e.Code + ": " + e.Message }

// Unwrap exposes the internal cause to errors.Is/As in-process only.
func (e *IssueError) Unwrap() error { return e.detail }

// IsIssueError extracts an *IssueError from err.
func IsIssueError(err error) (*IssueError, bool) {
	var ie *IssueError
	ok := errors.As(err, &ie)
	return ie, ok
}

// RuntimeDecl is a client's statement that it is a runtime session. The id is
// optional and, when given, must equal the attested one.
type RuntimeDecl struct {
	ID      string `json:"id,omitempty"`
	Version string `json:"version,omitempty"`
}

// SessionRequest is the body of issue-session.
type SessionRequest struct {
	Definition string       `json:"definition,omitempty"`
	Origin     string       `json:"origin,omitempty"`
	Runtime    *RuntimeDecl `json:"runtime,omitempty"`
}

// ChildRequest is the body of issue-child.
type ChildRequest struct {
	ParentToken string `json:"parent_token"`
	AgentType   string `json:"agent_type"`
	AgentID     string `json:"agent_id"`
}

// PolicyStep is the roles one policy removed.
type PolicyStep struct {
	Policy  string   `json:"policy"`
	Dropped []string `json:"dropped"`
}

// Narrowing reports every policy that removed roles from a requested set.
// Policy and Dropped summarise all steps (policy names joined by a comma,
// dropped roles in order); Steps lists each policy with its own drops.
type Narrowing struct {
	Policy  string       `json:"policy"`
	Dropped []string     `json:"dropped"`
	Steps   []PolicyStep `json:"steps"`
}

// Issued is the response of both operations.
type Issued struct {
	Token     string     `json:"token"`
	Dir       string     `json:"dir"`
	ExpiresAt int64      `json:"expires_at"`
	Subject   string     `json:"sub"`
	Actor     string     `json:"actor"`
	Grade     string     `json:"grade"`
	Roles     []string   `json:"roles"`
	Narrowed  *Narrowing `json:"narrowed,omitempty"`
}

// JWK is the public half of a key, in the shape of RFC 7517/7518/8037.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

// JWKS is the published key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}
