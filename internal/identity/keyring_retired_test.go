//go:build linux

package identity

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// newKeyring loads a keyring from a freshly generated key.
func newKeyring(t *testing.T, ec bool) *Keyring {
	t.Helper()
	ring, err := LoadKeyring(writeKey(t, t.TempDir(), "k.pem", ec), "")
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func testClaims(exp time.Time) Claims {
	return Claims{Iss: "unix:///example", Sub: "runtime:example", Grade: "workload", Orig: "trigger",
		Iat: testNow.Unix(), Exp: exp.Unix(), Jti: "j", Cia: 1}
}

// headerOf returns the decoded protected header of a compact JWS.
func headerOf(t *testing.T, token string) string {
	t.Helper()
	seg, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A rotation moves the previous key to retired_keys: its token still parses
// against the new keyring, the published set lists the new key first and the old
// one after it, and only the new key signs.
func TestRotatedKeyringVerifiesAPreviousKeysToken(t *testing.T) {
	for _, c := range []struct {
		name         string
		oldEC, newEC bool
	}{
		{"ed25519 to ed25519", false, false},
		{"p-256 to ed25519", true, false},
		{"ed25519 to p-256", false, true},
		{"p-256 to p-256", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			oldRing := newKeyring(t, c.oldEC)
			oldJWK := oldRing.JWKS().Keys[0]
			token, err := oldRing.SignClaims(testClaims(testNow.Add(time.Hour)))
			if err != nil {
				t.Fatal(err)
			}
			newRing, err := LoadKeyringRetired(writeKey(t, t.TempDir(), "k.pem", c.newEC), "", []JWK{oldJWK})
			if err != nil {
				t.Fatal(err)
			}
			claims, err := newRing.ParseOwn(token)
			if err != nil || claims.Exp != testNow.Add(time.Hour).Unix() {
				t.Fatalf("the previous key's token does not verify: %+v %v", claims, err)
			}
			keys := newRing.JWKS().Keys
			if len(keys) != 2 || keys[0].Kid != newRing.Kid() || keys[1] != oldJWK {
				t.Fatalf("published keys %+v, want the new key then the retired one", keys)
			}
			fresh, err := newRing.SignClaims(testClaims(testNow.Add(time.Hour)))
			if err != nil {
				t.Fatal(err)
			}
			if hdr := headerOf(t, fresh); !strings.Contains(hdr, newRing.Kid()) || strings.Contains(hdr, oldJWK.Kid) {
				t.Fatalf("a token signed after the rotation is not signed by the new key: %s", hdr)
			}
			// The verification above came from the retired entry and nothing
			// else: a keyring without it rejects the same token.
			if _, err := newKeyring(t, c.newEC).ParseOwn(token); err == nil {
				t.Fatal("a keyring without the retired entry verified the previous key's token")
			}
		})
	}
}

// A retired entry that is not what a retired key must be is refused, naming its
// index and kid, when the keyring loads.
func TestRetiredKeyEntriesAreRefusedNamingTheEntry(t *testing.T) {
	edJWK := newKeyring(t, false).JWKS().Keys[0]
	ecJWK := newKeyring(t, true).JWKS().Keys[0]
	with := func(j JWK, edit func(*JWK)) JWK { edit(&j); return j }
	for _, c := range []struct {
		name    string
		retired []JWK
		want    string
	}{
		{"a kid that is not the thumbprint", []JWK{with(edJWK, func(j *JWK) { j.Kid = "not-the-thumbprint" })}, "thumbprint"},
		{"an ec kid that is not the thumbprint", []JWK{with(ecJWK, func(j *JWK) { j.Kid = edJWK.Kid })}, "thumbprint"},
		{"a kty, crv and alg that disagree", []JWK{with(edJWK, func(j *JWK) { j.Alg = AlgES256 })}, "not one of"},
		{"a short x", []JWK{with(edJWK, func(j *JWK) { j.X = j.X[:8] })}, "bytes"},
		{"an x that is not base64url", []JWK{with(edJWK, func(j *JWK) { j.X = "!!!" })}, "base64url"},
		{"a y on an OKP key", []JWK{with(edJWK, func(j *JWK) { j.Y = j.X })}, "no y member"},
		{"a point off the curve", []JWK{with(ecJWK, func(j *JWK) { j.Y = strings.Repeat("A", 43) })}, "not on P-256"},
		{"a use that is not sig", []JWK{with(edJWK, func(j *JWK) { j.Use = "enc" })}, "use"},
		{"a repeated kid", []JWK{edJWK, ecJWK, edJWK}, "repeats the kid of identity.retired_keys[0]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadKeyringRetired(writeKey(t, t.TempDir(), "k.pem", false), "", c.retired)
			if err == nil || !strings.Contains(err.Error(), "identity.retired_keys[") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal naming the entry and %q", err, c.want)
			}
		})
	}
}

// The current key's own kid is refused as a retired key, which only the keyring
// can know: the config does not hold the current key.
func TestCurrentKeyAsARetiredKeyIsRefused(t *testing.T) {
	path := writeKey(t, t.TempDir(), "k.pem", false)
	current, err := LoadKeyring(path, "")
	if err != nil {
		t.Fatal(err)
	}
	other := newKeyring(t, false).JWKS().Keys[0]
	_, err = LoadKeyringRetired(path, "", []JWK{other, current.JWKS().Keys[0]})
	if err == nil || !strings.Contains(err.Error(), "identity.retired_keys[1]") || !strings.Contains(err.Error(), "current signing key") {
		t.Fatalf("the current key as a retired key: %v", err)
	}
}

// The served and the written key set are one document, so a reader can compare
// them byte for byte.
func TestPublishedKeySetBytesAreRenderedOnce(t *testing.T) {
	old := newKeyring(t, false).JWKS().Keys[0]
	ring, err := LoadKeyringRetired(writeKey(t, t.TempDir(), "k.pem", false), "", []JWK{old})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := ring.MarshalJWKS()
	b, _ := ring.MarshalJWKS()
	if string(a) != string(b) || strings.HasSuffix(string(a), "\n") {
		t.Fatalf("the document is not stable or carries a trailing newline: %q", a)
	}
	a[0] = 'X'
	if c, _ := ring.MarshalJWKS(); c[0] == 'X' {
		t.Fatal("a caller changed the keyring's published bytes")
	}
	// Equal bytes do not show a single rendering: a keyring that rendered on
	// every call would agree with itself. The bytes must be the ones made at load,
	// so drop a key from the set they were rendered from and they must not change.
	want, _ := ring.MarshalJWKS()
	ring.public = ring.public[:1]
	if got, _ := ring.MarshalJWKS(); string(got) != string(want) {
		t.Fatalf("the published bytes follow the key set instead of the one rendering made at load:\n got %s\nwant %s", got, want)
	}
}
