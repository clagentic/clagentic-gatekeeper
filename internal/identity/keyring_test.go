package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotationKeepsOldKidVerifiable(t *testing.T) {
	dir := t.TempDir()
	oldPath := writeKey(t, dir, "old.pem", false)
	oldRing, err := LoadKeyring(oldPath, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, err := oldRing.SignClaims(Claims{Iss: "x", Sub: "runtime:a"})
	if err != nil {
		t.Fatal(err)
	}
	oldKid := oldRing.Kid()

	// Rotation: a new current key, the old one listed as retired.
	newRing, err := LoadKeyring(writeKey(t, dir, "new.pem", true), "ES256", []string{oldPath})
	if err != nil {
		t.Fatal(err)
	}
	if newRing.Kid() == oldKid {
		t.Fatal("rotation kept the same kid")
	}
	published := map[string]bool{}
	for _, k := range newRing.JWKS().Keys {
		published[k.Kid] = true
	}
	if !published[oldKid] || !published[newRing.Kid()] {
		t.Fatalf("published kids %v", published)
	}
	if _, err := newRing.ParseOwn(token); err != nil {
		t.Fatalf("token signed by the previous kid no longer verifies: %v", err)
	}

	// Once the old key is dropped from configuration it stops verifying.
	bare, err := LoadKeyring(writeKey(t, dir, "third.pem", false), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bare.ParseOwn(token); err == nil {
		t.Fatal("a key that was never published verified the token")
	}
}

func TestMissingRetiredKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKeyring(writeKey(t, dir, "k.pem", false), "", []string{filepath.Join(dir, "missing.pem")}); err == nil {
		t.Fatal("missing retired key accepted")
	}
}

func TestKeyFilePermissionsAreEnforced(t *testing.T) {
	dir := t.TempDir()
	p := writeKey(t, dir, "k.pem", false)
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(p, "", nil); err == nil {
		t.Fatal("group-readable signing key accepted")
	}
}

func TestAlgMustMatchKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadKeyring(writeKey(t, dir, "k.pem", false), "ES256", nil); err == nil {
		t.Fatal("ES256 accepted for an Ed25519 key")
	}
}

func TestPublishedKeySetHasNoPrivateMembers(t *testing.T) {
	ring, err := LoadKeyring(writeKey(t, t.TempDir(), "k.pem", true), "", nil)
	if err != nil {
		t.Fatal(err)
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
