package livetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

func signedToken(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "EdDSA", "kid": kid}) + "." + enc(claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
}

func TestVerifyAssertionAcceptsAndRefuses(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := identity.JWKS{Keys: []identity.JWK{{Kty: "OKP", Crv: "Ed25519", Kid: "k1", Alg: "EdDSA", Use: "sig", X: base64.RawURLEncoding.EncodeToString(pub)}}}
	now := time.Now()
	claims := map[string]any{"iss": "i", "grade": "workload", "roles": []string{"r"}, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "cia": 1}
	tok := signedToken(t, priv, "k1", claims)

	c, err := VerifyAssertion(tok, set, now)
	if err != nil || c.Grade != "workload" {
		t.Fatalf("%+v %v", c, err)
	}

	parts := strings.Split(tok, ".")
	cases := map[string]struct {
		token string
		set   identity.JWKS
	}{
		"changed payload": {parts[0] + "." + flipFirst(parts[1]) + "." + parts[2], set},
		"unknown kid":     {signedToken(t, priv, "other", claims), set},
		"empty key set":   {tok, identity.JWKS{}},
		"expired":         {signedToken(t, priv, "k1", map[string]any{"iat": now.Unix(), "exp": now.Add(-time.Minute).Unix(), "cia": 1}), set},
		"wrong contract":  {signedToken(t, priv, "k1", map[string]any{"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "cia": 2}), set},
		"not a JWS":       {"abc", set},
	}
	for name, tc := range cases {
		if _, err := VerifyAssertion(tc.token, tc.set, now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestReporterCountsAndKeepsWriteErrors(t *testing.T) {
	var sb strings.Builder
	r := NewReporter(&sb)
	r.Add(Result{Shape: "a", Status: Pass})
	r.Add(Result{Shape: "b", Status: Skip, Reason: "why"})
	if r.Failed() {
		t.Fatal("no shape failed")
	}
	r.Add(Result{Shape: "c", Status: Fail, Reason: "x"})
	r.Summary()
	if !r.Failed() || r.Count(Pass) != 1 || r.Count(Skip) != 1 {
		t.Fatal("tallies")
	}
	if !strings.Contains(sb.String(), `{"shape":"b","status":"skip","reason":"why"}`) || !strings.Contains(sb.String(), `"summary":{"fail":1,"pass":1,"skip":1}`) {
		t.Fatalf("%s", sb.String())
	}
	if r.Err() != nil {
		t.Fatal(r.Err())
	}
}
