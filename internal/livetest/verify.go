package livetest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// Claims is the part of an assertion the shapes assert on.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Act   *Actor   `json:"act"`
	Roles []string `json:"roles"`
	Grade string   `json:"grade"`
	RT    struct {
		ID string `json:"id"`
	} `json:"rt"`
	Sid   string `json:"sid"`
	Spawn string `json:"spawn"`
	Dir   string `json:"dir"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Cia   int    `json:"cia"`
}

// Actor is one level of the act chain.
type Actor struct {
	Sub string `json:"sub"`
}

// VerifyAssertion checks a compact JWS against a published key set using only
// the standard library, independently of the issuer's own code: a relying party
// has nothing else. It checks the signature, the algorithm the key declares and
// the lifetime, and returns the claims.
func VerifyAssertion(token string, set identity.JWKS, now time.Time) (Claims, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("not a three-segment compact JWS")
	}
	var hdr struct{ Alg, Kid string }
	if err := decodePart(parts[0], &hdr); err != nil {
		return Claims{}, fmt.Errorf("header: %w", err)
	}
	var key *identity.JWK
	for i := range set.Keys {
		if set.Keys[i].Kid == hdr.Kid {
			key = &set.Keys[i]
		}
	}
	if key == nil {
		return Claims{}, fmt.Errorf("kid %q is not in the published key set", hdr.Kid)
	}
	if key.Alg != hdr.Alg {
		return Claims{}, fmt.Errorf("header alg %q differs from the key's %q", hdr.Alg, key.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("signature is not base64url")
	}
	if err := verifySignature(*key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := decodePart(parts[1], &c); err != nil {
		return Claims{}, fmt.Errorf("claims: %w", err)
	}
	if c.Cia != 1 {
		return Claims{}, fmt.Errorf("cia is %d, want 1", c.Cia)
	}
	if c.Exp <= now.Unix() {
		return Claims{}, errors.New("assertion is expired")
	}
	if c.Iat > now.Add(time.Minute).Unix() {
		return Claims{}, errors.New("assertion is issued in the future")
	}
	return c, nil
}

// flipFirst changes the first character of a base64url segment to another valid
// one, which changes the decoded bytes without breaking the encoding. Shapes use
// it to build a token whose payload was altered after signing.
func flipFirst(seg string) string {
	if seg[0] == 'e' {
		return "f" + seg[1:]
	}
	return "e" + seg[1:]
}

func decodePart(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return errors.New("not base64url")
	}
	return json.NewDecoder(bytes.NewReader(raw)).Decode(into)
}

func verifySignature(k identity.JWK, input, sig []byte) error {
	switch k.Alg {
	case "EdDSA":
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return errors.New("malformed Ed25519 key in the published set")
		}
		if !ed25519.Verify(ed25519.PublicKey(x), input, sig) {
			return errors.New("signature does not verify")
		}
	case "ES256":
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(sig) != 64 {
			return errors.New("malformed P-256 key or signature")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		digest := sha256.Sum256(input)
		if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("signature does not verify")
		}
	default:
		return fmt.Errorf("unsupported alg %q", k.Alg)
	}
	return nil
}
