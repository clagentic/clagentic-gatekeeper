//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The signing key's directory is a trust root: a uid that can write it can
// replace the key with its own, so serve refuses to start and names it.
func TestKeyInADirectoryWritableByOthersIsRefusedNamingIt(t *testing.T) {
	dir := t.TempDir()
	p := writeKey(t, dir, "k.pem", false)
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(p, ""); err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatalf("got %v, want a refusal naming %s", err, dir)
	}
}

func TestKeyBehindASymlinkedDirectoryIsRefused(t *testing.T) {
	real := t.TempDir()
	p := writeKey(t, real, "k.pem", false)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyring(filepath.Join(link, filepath.Base(p)), ""); err == nil {
		t.Fatal("a key reached through a symlinked directory was loaded")
	}
}

func TestWriteJWKSLeavesNoTemporaryFileAndIsWorldReadable(t *testing.T) {
	dir := t.TempDir()
	ring, err := LoadKeyring(writeKey(t, dir, "k.pem", false), "")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "jwks.json")
	if err := ring.WriteJWKS(out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", fi, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("directory after publish: %v %v", entries, err)
	}
}

func TestWriteJWKSRefusesADirectoryWritableByOthers(t *testing.T) {
	dir := t.TempDir()
	ring, err := LoadKeyring(writeKey(t, dir, "k.pem", false), "")
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "pub")
	if err := os.Mkdir(pub, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pub, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ring.WriteJWKS(filepath.Join(pub, "jwks.json")); err == nil || !strings.Contains(err.Error(), pub) {
		t.Fatalf("got %v, want a refusal naming %s", err, pub)
	}
}

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
