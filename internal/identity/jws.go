//go:build linux

package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ContractVersion is the `cia` claim value this issuer emits.
const ContractVersion = 1

// MaxLifetimeSeconds is the contract's cap on exp - iat.
const MaxLifetimeSeconds = 43200

// Actor is one level of the RFC 8693 act chain.
type Actor struct {
	Sub string `json:"sub"`
	Act *Actor `json:"act,omitempty"`
}

// Runtime is the rt claim.
type Runtime struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Claims is the assertion payload of the contract's section 3.
type Claims struct {
	Iss   string   `json:"iss"`
	Sub   string   `json:"sub"`
	Act   *Actor   `json:"act,omitempty"`
	Roles []string `json:"roles"`
	Grade string   `json:"grade"`
	RT    Runtime  `json:"rt"`
	Sid   string   `json:"sid"`
	Spawn string   `json:"spawn,omitempty"`
	Orig  string   `json:"origin"`
	Dir   string   `json:"dir"`
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	Jti   string   `json:"jti"`
	Cia   int      `json:"cia"`
}

// SignClaims returns the compact JWS for c.
func (k *Keyring) SignClaims(c Claims) (string, error) {
	if c.Roles == nil {
		c.Roles = []string{}
	}
	hdr, err := json.Marshal(map[string]string{"alg": k.Alg(), "kid": k.Kid()})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := b64(hdr) + "." + b64(payload)
	sig, err := k.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// ErrTokenInvalid marks a token this issuer did not sign or that is not
// well-formed. The wrapped detail is safe to show the caller.
var ErrTokenInvalid = errors.New("token invalid")

// ParseOwn verifies a compact JWS against the keyring and returns its claims.
// It checks authenticity and shape only; lifetime is the caller's decision.
func (k *Keyring) ParseOwn(token string) (Claims, error) {
	invalid := func(detail string) error { return fmt.Errorf("%w: %s", ErrTokenInvalid, detail) }
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return Claims{}, invalid("not a three-segment compact JWS")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return Claims{}, invalid(err.Error())
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, invalid("signature is not base64url")
	}
	if !k.verify(hdr.Kid, hdr.Alg, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, invalid("signature does not verify against a key this issuer publishes")
	}
	var c Claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return Claims{}, invalid(err.Error())
	}
	return c, nil
}

// decodeSegment decodes one base64url segment holding exactly one JSON object.
func decodeSegment(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return errors.New("segment is not base64url")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(into); err != nil {
		return errors.New("segment is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing content after the JSON object")
	}
	return nil
}
