//go:build linux

package identity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// retiredPublicKey turns one retired_keys entry into a published key. The
// entry is only a public JWK, so nothing here can sign; the published form is
// rebuilt from the decoded point, never copied from the entry, so what is
// served is what was checked. The kid must be the RFC 7638 thumbprint of that
// point, which is what makes two keys unable to share one.
func retiredPublicKey(j JWK) (publicKey, error) {
	if j.Use != "" && j.Use != "sig" {
		return publicKey{}, fmt.Errorf("use %q is not sig", j.Use)
	}
	var pk publicKey
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519" && j.Alg == AlgEdDSA:
		x, err := decodeCoordinate("x", j.X, ed25519.PublicKeySize)
		if err != nil {
			return publicKey{}, err
		}
		if j.Y != "" {
			return publicKey{}, errors.New("an OKP key has no y member")
		}
		pk = edPublic(ed25519.PublicKey(x))
	case j.Kty == "EC" && j.Crv == "P-256" && j.Alg == AlgES256:
		x, err := decodeCoordinate("x", j.X, 32)
		if err != nil {
			return publicKey{}, err
		}
		y, err := decodeCoordinate("y", j.Y, 32)
		if err != nil {
			return publicKey{}, err
		}
		// NewPublicKey refuses a point that is not on the curve.
		uncompressed := append(append([]byte{4}, x...), y...)
		if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
			return publicKey{}, fmt.Errorf("the point is not on P-256: %w", err)
		}
		pk = ecPublic(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)})
	default:
		return publicKey{}, fmt.Errorf("kty %q, crv %q and alg %q are not one of OKP/Ed25519/EdDSA or EC/P-256/ES256", j.Kty, j.Crv, j.Alg)
	}
	if j.Kid != pk.jwk.Kid {
		return publicKey{}, fmt.Errorf("kid is not the RFC 7638 thumbprint of the key; it must be %q", pk.jwk.Kid)
	}
	return pk, nil
}

// decodeCoordinate reads one base64url member of exactly size bytes.
func decodeCoordinate(name, value string, size int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s is not unpadded base64url", name)
	}
	if len(raw) != size {
		return nil, fmt.Errorf("%s is %d bytes, want %d", name, len(raw), size)
	}
	return raw, nil
}
