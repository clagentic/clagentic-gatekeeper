//go:build unix

package vectors

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
)

// This file is a deliberately small reference verifier written from
// docs/identity-contract.md using only the standard library. It exists to
// prove the vector set is consistent; it is not a supported implementation.

const (
	supportedCia    = 1
	maxLifetimeSecs = 43200
	maxIdentityFile = 16384
	audienceLocal   = "local"
	audiencePeer    = "peer"
)

var alwaysRequired = []string{"iss", "sub", "roles", "grade", "rt", "sid", "origin", "iat", "exp", "jti", "cia"}

var (
	reActor    = regexp.MustCompile(`^(human|agent|runtime):[A-Za-z0-9._-]{1,128}$`)
	reActorSub = regexp.MustCompile(`^(agent|runtime):[A-Za-z0-9._-]{1,128}$`)
	reRole     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

var allCodes = []string{
	"identity_dir_missing", "identity_dir_unsafe", "identity_file_missing", "identity_file_symlink",
	"malformed", "alg_not_allowed", "issuer_untrusted", "key_not_found", "signature_invalid",
	"contract_version_unsupported", "expired", "not_yet_valid", "ttl_exceeded", "claims_invalid",
	"audience_unexpected", "audience_mismatch", "dir_mismatch",
}

type layout struct {
	Dir     string `json:"dir"`
	DirMode string `json:"dir_mode,omitempty"`
	File    string `json:"file,omitempty"`
	Content string `json:"content,omitempty"`
}

type expectation struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Actor string `json:"actor,omitempty"`
	Grade string `json:"grade,omitempty"`
}

type vector struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Kind        string      `json:"kind"`
	Mode        string      `json:"mode,omitempty"`
	PeerID      string      `json:"peer_id,omitempty"`
	Now         int64       `json:"now,omitempty"`
	ObservedDir string      `json:"observed_dir,omitempty"`
	Token       string      `json:"token,omitempty"`
	Layout      *layout     `json:"layout,omitempty"`
	Expect      expectation `json:"expect"`
}

type trustedIssuer struct {
	Iss string `json:"iss"`
}

type manifest struct {
	ContractVersion string `json:"contract_version"`
	Cia             int    `json:"cia"`
	Trust           struct {
		Issuers []trustedIssuer `json:"issuers"`
	} `json:"trust"`
	JWKSFiles map[string]string `json:"jwks_files"`
	Vectors   []vector          `json:"vectors"`
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// trust maps a trusted issuer to its key set.
type trust map[string]jwksDoc

type outcome struct {
	Actor string
	Grade string
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func decodeObject(seg string) (map[string]any, bool) {
	raw, err := b64(seg)
	if err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
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
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(x), input, sig)
	case "ES256":
		if k.Kty != "EC" || k.Crv != "P-256" || len(sig) != 64 {
			return false
		}
		xb, errx := b64(k.X)
		yb, erry := b64(k.Y)
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

func validActor(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if s, ok := m["sub"].(string); !ok || !reActorSub.MatchString(s) {
		return false
	}
	if inner, has := m["act"]; has && !validActor(inner) {
		return false
	}
	return true
}

func claimsShapeValid(c map[string]any) bool {
	for _, name := range alwaysRequired {
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
		if !ok || !reRole.MatchString(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	if g, _ := c["grade"].(string); g != "workload" && g != "harness" {
		return false
	}
	switch o, _ := c["origin"].(string); o {
	case "human", "scheduled", "loop", "trigger", "agent":
	default:
		return false
	}
	rt, ok := c["rt"].(map[string]any)
	if !ok || !nonEmptyString(rt["id"]) || !nonEmptyString(rt["version"]) {
		return false
	}
	if a, has := c["act"]; has && !validActor(a) {
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

// verifyToken implements section 4 of the contract.
func verifyToken(tr trust, v vector) (outcome, string) {
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 {
		return outcome{}, "malformed"
	}
	header, okh := decodeObject(parts[0])
	claims, okp := decodeObject(parts[1])
	sig, errs := b64(parts[2])
	if !okh || !okp {
		return outcome{}, "malformed"
	}
	if _, crit := header["crit"]; crit {
		return outcome{}, "malformed"
	}
	alg, _ := header["alg"].(string)
	if alg != "EdDSA" && alg != "ES256" {
		return outcome{}, "alg_not_allowed"
	}
	iss, _ := claims["iss"].(string)
	doc, trusted := tr[iss]
	if !trusted {
		return outcome{}, "issuer_untrusted"
	}
	kid, _ := header["kid"].(string)
	var key *jwk
	for i := range doc.Keys {
		if kid != "" && doc.Keys[i].Kid == kid {
			key = &doc.Keys[i]
			break
		}
	}
	if key == nil {
		return outcome{}, "key_not_found"
	}
	if errs != nil || !verifySignature(*key, alg, []byte(parts[0]+"."+parts[1]), sig) {
		return outcome{}, "signature_invalid"
	}
	if cia, ok := asInt(claims["cia"]); !ok || cia != supportedCia {
		return outcome{}, "contract_version_unsupported"
	}
	iat, okIat := asInt(claims["iat"])
	exp, okExp := asInt(claims["exp"])
	if !okIat || !okExp {
		return outcome{}, "claims_invalid"
	}
	if exp <= v.Now {
		return outcome{}, "expired"
	}
	if nbfRaw, has := claims["nbf"]; has {
		nbf, ok := asInt(nbfRaw)
		if !ok {
			return outcome{}, "claims_invalid"
		}
		if v.Now < nbf {
			return outcome{}, "not_yet_valid"
		}
	}
	if iat > v.Now {
		return outcome{}, "not_yet_valid"
	}
	if exp-iat > maxLifetimeSecs {
		return outcome{}, "ttl_exceeded"
	}
	if !claimsShapeValid(claims) {
		return outcome{}, "claims_invalid"
	}
	aud, hasAud := claims["aud"].(string)
	switch v.Mode {
	case audienceLocal:
		if hasAud {
			return outcome{}, "audience_unexpected"
		}
	case audiencePeer:
		if !hasAud || aud != v.PeerID {
			return outcome{}, "audience_mismatch"
		}
	}
	if v.Mode == audienceLocal {
		if path.Clean(claims["dir"].(string)) != path.Clean(v.ObservedDir) {
			return outcome{}, "dir_mismatch"
		}
	}
	out := outcome{Grade: claims["grade"].(string), Actor: claims["sub"].(string)}
	if act, ok := claims["act"].(map[string]any); ok {
		out.Actor = act["sub"].(string)
	}
	return out, ""
}

// deliver implements section 6: it returns the file contents or a failure code.
func deliver(envSet bool, dir string) ([]byte, string) {
	if !envSet || dir == "" || !path.IsAbs(dir) {
		return nil, "identity_dir_missing"
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "identity_dir_missing"
	}
	if err != nil {
		return nil, "identity_dir_unsafe"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, "identity_dir_unsafe"
	}
	if !info.IsDir() {
		return nil, "identity_dir_missing"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
		return nil, "identity_dir_unsafe"
	}
	fd, err := syscall.Open(path.Join(dir, "identity.jwt"), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, "identity_file_missing"
	}
	if errors.Is(err, syscall.ELOOP) {
		// ELOOP is what O_NOFOLLOW reports for a symlink.
		return nil, "identity_file_symlink"
	}
	if err != nil {
		return nil, "identity_file_missing"
	}
	f := os.NewFile(uintptr(fd), "identity.jwt")
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, "identity_file_symlink"
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIdentityFile+1))
	if err != nil || len(data) > maxIdentityFile {
		return nil, "malformed"
	}
	return bytes.TrimSuffix(data, []byte("\n")), ""
}
