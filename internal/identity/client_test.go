package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSameKeysComparesKeyMaterialNotJustKid(t *testing.T) {
	base := JWK{Kty: "OKP", Crv: "Ed25519", Kid: "k1", Alg: AlgEdDSA, Use: "sig", X: "AAAA"}
	same := JWKS{Keys: []JWK{base}}
	if !sameKeys(same, JWKS{Keys: []JWK{base}}) {
		t.Fatal("identical sets reported different")
	}
	for name, mutate := range map[string]func(*JWK){
		"x":   func(k *JWK) { k.X = "BBBB" },
		"y":   func(k *JWK) { k.Y = "BBBB" },
		"crv": func(k *JWK) { k.Crv = "P-256" },
		"kty": func(k *JWK) { k.Kty = "EC" },
	} {
		other := base
		mutate(&other)
		if sameKeys(same, JWKS{Keys: []JWK{other}}) {
			t.Errorf("same kid with different %s reported as matching", name)
		}
	}
	if sameKeys(JWKS{Keys: []JWK{base, base}}, JWKS{Keys: []JWK{base, base}}) {
		t.Error("a set with a repeated kid was accepted")
	}
}

func TestSelfCheckDetectsSameKidWithDifferentMaterial(t *testing.T) {
	c, f := startServer(t, nil)
	live := f.issuer.Keys.JWKS()
	live.Keys[0].X = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	raw, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwks, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	checks := SelfCheck(c, jwks, 0, time.Now())
	if last := checks[len(checks)-1]; last.Name != "jwks_fresh" || last.OK {
		t.Fatalf("tampered key material reported fresh: %+v", checks)
	}
}
