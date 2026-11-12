package livetest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

func TestMutateOneByteChangesExactlyOne(t *testing.T) {
	for _, in := range [][]byte{[]byte(`{"keys":[]}`), []byte("A"), []byte("ABA")} {
		out := mutateOneByte(in)
		diff := 0
		for i := range in {
			if in[i] != out[i] {
				diff++
			}
		}
		if len(out) != len(in) || diff != 1 || bytes.Equal(in, out) {
			t.Errorf("%q -> %q: %d bytes differ", in, out, diff)
		}
	}
}

func TestRetiredKeysYAMLCarriesOnlyPublicMembers(t *testing.T) {
	ed := retiredKeysYAML(identity.JWK{Kty: "OKP", Crv: "Ed25519", Kid: "k", Alg: "EdDSA", Use: "sig", X: "xx"})
	if strings.Contains(ed, "\n      y:") || strings.Contains(ed, "use") || !strings.Contains(ed, `kid: "k"`) || !strings.HasPrefix(ed, "  retired_keys:\n") {
		t.Errorf("%s", ed)
	}
	ec := retiredKeysYAML(identity.JWK{Kty: "EC", Crv: "P-256", Kid: "k", Alg: "ES256", X: "xx", Y: "yy"})
	if !strings.Contains(ec, "\n      y: \"yy\"") {
		t.Errorf("%s", ec)
	}
}

func TestWithKidRefusedByVerifier(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := identity.JWKS{Keys: []identity.JWK{{Kty: "OKP", Crv: "Ed25519", Kid: "k1", Alg: "EdDSA", X: base64.RawURLEncoding.EncodeToString(pub)}}}
	now := time.Now()
	tok := signedToken(t, priv, "k1", map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "cia": 1})
	if _, err := VerifyAssertion(tok, set, now); err != nil {
		t.Fatal(err)
	}
	forged, err := withKid(tok, "unknown")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAssertion(forged, set, now); err == nil || !strings.Contains(err.Error(), "not in the published key set") {
		t.Errorf("forged kid: %v", err)
	}
	if _, err := withKid("abc", "x"); err == nil {
		t.Error("a non-JWS was accepted")
	}
	if _, ok := keyByKid(set, "k1"); !ok {
		t.Error("keyByKid missed k1")
	}
}
