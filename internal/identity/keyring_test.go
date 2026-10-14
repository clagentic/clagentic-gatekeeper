package identity

import (
	"os"
	"strings"
	"testing"
)

func TestKeyFilePermissionsAreEnforced(t *testing.T) {
	dir := t.TempDir()
	p := writeKey(t, dir, "k.pem", false)
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(p, ""); err == nil {
		t.Fatal("group-readable signing key accepted")
	}
}

func TestAlgMustMatchKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKeyring(writeKey(t, dir, "k.pem", false), "ES256"); err == nil {
		t.Fatal("ES256 accepted for an Ed25519 key")
	}
}

func TestPublishedKeySetHoldsOnlyTheCurrentKeyAndNoPrivateMembers(t *testing.T) {
	ring, err := LoadKeyring(writeKey(t, t.TempDir(), "k.pem", true), "")
	if err != nil {
		t.Fatal(err)
	}
	if keys := ring.JWKS().Keys; len(keys) != 1 || keys[0].Kid != ring.Kid() {
		t.Fatalf("published keys %+v", keys)
	}
	raw, err := ring.MarshalJWKS()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{`"d"`, `"p"`, `"q"`, `"k"`} {
		if strings.Contains(string(raw), m) {
			t.Fatalf("jwks contains %s", m)
		}
	}
}
