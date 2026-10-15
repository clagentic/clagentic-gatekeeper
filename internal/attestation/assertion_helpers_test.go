//go:build unix

package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// signer signs test assertions with a throwaway Ed25519 key.
type signer struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigner(t *testing.T, kid string) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{kid: kid, priv: priv, pub: pub}
}

func (s signer) jwksJSON() []byte {
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": s.kid, "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(s.pub),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

func (s signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "EdDSA", "kid": s.kid}) + "." + enc(claims)
	sig := ed25519.Sign(s.priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// localClaims is a valid local workload assertion bound to dir, acting as
// agent:<actor> for the given roles.
func localClaims(iss, dir, actor, grade string, now time.Time, roles ...string) map[string]any {
	if roles == nil {
		roles = []string{}
	}
	c := map[string]any{
		"iss": iss, "sub": "human:example-user", "act": map[string]any{"sub": "agent:" + actor},
		"roles": roles, "grade": grade, "rt": map[string]any{"id": "example-runtime", "version": "1.0.0"},
		"sid": "sess-1", "origin": "agent", "dir": dir,
		"iat": now.Unix() - 60, "exp": now.Unix() + 3600, "jti": "jti-1", "cia": 1,
	}
	if grade == "harness" {
		c["spawn"] = "spawn-1"
	}
	return c
}

// deliverTo writes token into a fresh 0700 delivery directory, points the
// delivery variable at it and returns the directory.
func deliverTo(t *testing.T, token string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(IdentityDirEnv, dir)
	return dir
}

// jwksFile writes the signer's key set to a file and returns its path.
func jwksFile(t *testing.T, s signer) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(p, s.jwksJSON(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
