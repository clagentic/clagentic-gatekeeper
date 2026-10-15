package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"path"
	"regexp"
	"strings"
)

// AssertionCode is a failure code of docs/identity-contract.md section 4.1,
// plus the gatekeeper-local CodeJWKSUnavailable.
type AssertionCode string

const (
	CodeDirMissing      AssertionCode = "identity_dir_missing"
	CodeDirUnsafe       AssertionCode = "identity_dir_unsafe"
	CodeFileMissing     AssertionCode = "identity_file_missing"
	CodeFileSymlink     AssertionCode = "identity_file_symlink"
	CodeMalformed       AssertionCode = "malformed"
	CodeAlgNotAllowed   AssertionCode = "alg_not_allowed"
	CodeIssuerUntrusted AssertionCode = "issuer_untrusted"
	CodeKeyNotFound     AssertionCode = "key_not_found"
	CodeSignatureBad    AssertionCode = "signature_invalid"
	CodeVersionNew      AssertionCode = "contract_version_unsupported"
	CodeExpired         AssertionCode = "expired"
	CodeNotYetValid     AssertionCode = "not_yet_valid"
	CodeTTLExceeded     AssertionCode = "ttl_exceeded"
	CodeClaimsInvalid   AssertionCode = "claims_invalid"
	CodeAudUnexpected   AssertionCode = "audience_unexpected"
	CodeAudMismatch     AssertionCode = "audience_mismatch"
	CodeDirMismatch     AssertionCode = "dir_mismatch"

	// CodeJWKSUnavailable is not a contract code: the contract has no word for
	// a key set that could not be fetched, and a verifier must still refuse.
	CodeJWKSUnavailable AssertionCode = "jwks_unavailable"
)

// AssertionError is a refusal of the assertion provider. Detail is for the
// operator and never carries token bytes.
type AssertionError struct {
	Code   AssertionCode
	Detail string
}

func (e *AssertionError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("attestation: identity assertion refused: %s", e.Code)
	}
	return fmt.Sprintf("attestation: identity assertion refused: %s: %s", e.Code, e.Detail)
}

func refuseAssertion(code AssertionCode, format string, args ...any) *AssertionError {
	return &AssertionError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

const (
	// supportedContractMajor is the highest contract major this verifier
	// implements; it accepts every major from 1 up to it.
	supportedContractMajor = 2
	// originDrivenMajor is the first major whose origin vocabulary has driven.
	originDrivenMajor = 2

	maxAssertionLifetime = 43200
	maxAssertionFileBytes  = 16384

	// maxNumericDate is 9999-12-31T23:59:59Z, far beyond any real assertion and
	// small enough that no sum or difference of two dates overflows.
	maxNumericDate = 253402300799
)

type audienceMode int

const (
	modeLocal audienceMode = iota
	modePeer
)

// verifyParams is everything a verification depends on besides the token and
// the trusted keys. Now is read once by the caller and applied with zero leeway.
type verifyParams struct {
	Now         int64
	Mode        audienceMode
	PeerID      string
	ObservedDir string
	// MaxMajor is the highest contract major accepted; zero means
	// supportedContractMajor. A run pinned to an older conformance set lowers it.
	MaxMajor int64
}

// keySource answers the two questions of steps 3 and 4: is the issuer trusted,
// and which keys does it publish. Splitting them keeps the contract's order:
// an untrusted issuer is refused before any key set is fetched.
type keySource interface {
	trusted(iss string) bool
	keys(ctx context.Context, iss string) ([]jwk, error)
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// assertionClaims is the verified subset consumers act on.
type assertionClaims struct {
	Iss   string
	Actor string
	Roles []string
	Grade string
}

var (
	reActor    = regexp.MustCompile(`^(human|agent|runtime):[A-Za-z0-9._-]{1,128}$`)
	reActorSub = regexp.MustCompile(`^(agent|runtime):[A-Za-z0-9._-]{1,128}$`)
	reRoleName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

var alwaysRequiredClaims = []string{"iss", "sub", "roles", "grade", "rt", "sid", "origin", "iat", "exp", "jti", "cia"}

func b64url(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// decodeObject decodes a segment that is exactly one JSON object; a second
// value or any trailing junk makes it invalid.
func decodeObject(seg string) (map[string]any, bool) {
	raw, err := b64url(seg)
	if err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return m, true
}

func asInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func nonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func verifySignature(k jwk, alg string, input, sig []byte) bool {
	switch alg {
	case "EdDSA":
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return false
		}
		x, err := b64url(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), input, sig)
	case "ES256":
		if k.Kty != "EC" || k.Crv != "P-256" || len(sig) != 64 {
			return false
		}
		xb, errx := b64url(k.X)
		yb, erry := b64url(k.Y)
		if errx != nil || erry != nil {
			return false
		}
		pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return false
		}
		digest := sha256.Sum256(input)
		return ecdsa.Verify(&pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	return false
}

// signingKeys returns the keys of a key set that may verify a token whose
// header names kid and alg: the kid matches, the key is for signatures (use
// absent or sig) and any alg the key declares is the header alg. The key type
// and curve are checked by verifySignature against the same alg, so a kid
// alone never selects a key.
func signingKeys(keys []jwk, kid, alg string) []jwk {
	if kid == "" {
		return nil
	}
	var out []jwk
	for _, k := range keys {
		if k.Kid != kid || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != alg) {
			continue
		}
		out = append(out, k)
	}
	return out
}

func validActorChain(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if s, ok := m["sub"].(string); !ok || !reActorSub.MatchString(s) {
		return false
	}
	if inner, has := m["act"]; has && !validActorChain(inner) {
		return false
	}
	return true
}

// claimsShapeValid is section 3.1: required claims, name patterns, and the
// per-grade and per-audience required and forbidden sets.
func claimsShapeValid(c map[string]any, cia int64) bool {
	for _, name := range alwaysRequiredClaims {
		if _, ok := c[name]; !ok {
			return false
		}
	}
	if !nonEmptyString(c["iss"]) || !nonEmptyString(c["sid"]) || !nonEmptyString(c["jti"]) {
		return false
	}
	if s, ok := c["sub"].(string); !ok || !reActor.MatchString(s) {
		return false
	}
	roles, ok := c["roles"].([]any)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, r := range roles {
		s, ok := r.(string)
		if !ok || !reRoleName.MatchString(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	if g, _ := c["grade"].(string); g != "workload" && g != "harness" {
		return false
	}
	switch o, _ := c["origin"].(string); o {
	case "human", "scheduled", "loop", "trigger", "agent":
	case "driven":
		// driven exists from major 2. It is a workload statement about a launched
		// session and never names a human, whatever else the token claims.
		sub, _ := c["sub"].(string)
		if cia < originDrivenMajor || c["grade"] != "workload" || strings.HasPrefix(sub, "human:") {
			return false
		}
	default:
		return false
	}
	rt, ok := c["rt"].(map[string]any)
	if !ok || !nonEmptyString(rt["id"]) || !nonEmptyString(rt["version"]) {
		return false
	}
	if a, has := c["act"]; has && !validActorChain(a) {
		return false
	}
	if sp, has := c["spawn"]; has && !nonEmptyString(sp) {
		return false
	}
	if au, has := c["aud"]; has && !nonEmptyString(au) {
		return false
	}
	if d, has := c["dir"]; has {
		if s, ok := d.(string); !ok || !strings.HasPrefix(s, "/") {
			return false
		}
	}
	_, hasAud := c["aud"]
	_, hasDir := c["dir"]
	if hasAud == hasDir {
		// aud present forbids dir; aud absent requires dir.
		return false
	}
	if c["grade"] == "harness" {
		if _, ok := c["act"]; !ok {
			return false
		}
		if _, ok := c["spawn"]; !ok {
			return false
		}
	}
	return true
}

// verifyAssertion runs section 4 of the contract in its normative order and
// reports the first failure.
func verifyAssertion(ctx context.Context, token string, src keySource, p verifyParams) (*assertionClaims, *AssertionError) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, refuseAssertion(CodeMalformed, "not a three-segment compact JWS")
	}
	header, okh := decodeObject(parts[0])
	claims, okp := decodeObject(parts[1])
	sig, sigErr := b64url(parts[2])
	if !okh || !okp {
		return nil, refuseAssertion(CodeMalformed, "header or payload is not exactly one JSON object")
	}
	if _, crit := header["crit"]; crit {
		return nil, refuseAssertion(CodeMalformed, "header carries crit")
	}
	alg, _ := header["alg"].(string)
	if alg != "EdDSA" && alg != "ES256" {
		return nil, refuseAssertion(CodeAlgNotAllowed, "alg %q", alg)
	}
	iss, _ := claims["iss"].(string)
	if iss == "" || !src.trusted(iss) {
		return nil, refuseAssertion(CodeIssuerUntrusted, "iss %q is not a trusted issuer", iss)
	}
	keys, err := src.keys(ctx, iss)
	if err != nil {
		return nil, refuseAssertion(CodeJWKSUnavailable, "key set of %q: %v", iss, err)
	}
	kid, _ := header["kid"].(string)
	candidates := signingKeys(keys, kid, alg)
	if len(candidates) == 0 {
		return nil, refuseAssertion(CodeKeyNotFound, "no signing key %q for %s in the key set of %q", kid, alg, iss)
	}
	verified := false
	if sigErr == nil {
		for _, k := range candidates {
			if verifySignature(k, alg, []byte(parts[0]+"."+parts[1]), sig) {
				verified = true
				break
			}
		}
	}
	if !verified {
		return nil, refuseAssertion(CodeSignatureBad, "signature does not verify")
	}
	maxMajor := p.MaxMajor
	if maxMajor == 0 {
		maxMajor = supportedContractMajor
	}
	cia, ok := asInt(claims["cia"])
	if !ok || cia < 1 || cia > maxMajor {
		return nil, refuseAssertion(CodeVersionNew, "cia is not a supported major (1 to %d)", maxMajor)
	}
	iat, okIat := asInt(claims["iat"])
	exp, okExp := asInt(claims["exp"])
	var nbf int64
	hasNbf := false
	if raw, has := claims["nbf"]; has {
		var okNbf bool
		if nbf, okNbf = asInt(raw); !okNbf {
			return nil, refuseAssertion(CodeClaimsInvalid, "nbf is not an integer NumericDate")
		}
		hasNbf = true
	}
	if !okIat || !okExp {
		return nil, refuseAssertion(CodeClaimsInvalid, "iat or exp is missing or not an integer NumericDate")
	}
	// Bounding both dates keeps exp-iat below from overflowing int64, where a
	// wrapped difference would pass the lifetime cap.
	if iat < 0 || iat > maxNumericDate || exp < 0 || exp > maxNumericDate {
		return nil, refuseAssertion(CodeClaimsInvalid, "iat or exp is outside the supported NumericDate range")
	}
	if exp <= p.Now {
		return nil, refuseAssertion(CodeExpired, "exp %d, now %d", exp, p.Now)
	}
	if (hasNbf && p.Now < nbf) || iat > p.Now {
		return nil, refuseAssertion(CodeNotYetValid, "nbf/iat is in the future (now %d)", p.Now)
	}
	if exp-iat > maxAssertionLifetime {
		return nil, refuseAssertion(CodeTTLExceeded, "lifetime %ds exceeds %ds", exp-iat, maxAssertionLifetime)
	}
	if !claimsShapeValid(claims, cia) {
		return nil, refuseAssertion(CodeClaimsInvalid, "claim shape does not meet section 3.1")
	}
	aud, hasAud := claims["aud"].(string)
	switch p.Mode {
	case modeLocal:
		if hasAud {
			return nil, refuseAssertion(CodeAudUnexpected, "a local assertion must not carry aud")
		}
		if path.Clean(claims["dir"].(string)) != path.Clean(p.ObservedDir) {
			return nil, refuseAssertion(CodeDirMismatch, "assertion is bound to a different directory")
		}
	case modePeer:
		if !hasAud || aud != p.PeerID {
			return nil, refuseAssertion(CodeAudMismatch, "aud is not this peer")
		}
	}

	out := &assertionClaims{
		Iss:   iss,
		Actor: claims["sub"].(string),
		Grade: claims["grade"].(string),
	}
	if act, ok := claims["act"].(map[string]any); ok {
		out.Actor = act["sub"].(string)
	}
	for _, r := range claims["roles"].([]any) {
		out.Roles = append(out.Roles, r.(string))
	}
	return out, nil
}
