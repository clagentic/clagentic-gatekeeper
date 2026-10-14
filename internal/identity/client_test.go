package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSameJWKSDocumentComparesEveryMember(t *testing.T) {
	const base = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"AAAA"}]}`
	same := func(a, b string) bool {
		t.Helper()
		ok, err := sameJWKSDocument([]byte(a), []byte(b))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return ok
	}
	if !same(base, base) {
		t.Fatal("identical documents reported different")
	}
	reordered := `{"keys":[{"x":"AAAA","use":"sig","alg":"EdDSA","kid":"k1","crv":"Ed25519","kty":"OKP"}]}`
	if !same(base, reordered) {
		t.Fatal("member order changed the verdict")
	}
	two := `{"keys":[{"kid":"k1","kty":"OKP"},{"kid":"k2","kty":"OKP"}]}`
	twoSwapped := `{"keys":[{"kty":"OKP","kid":"k2"},{"kid":"k1","kty":"OKP"}]}`
	if !same(two, twoSwapped) {
		t.Fatal("key order changed the verdict")
	}
	for name, other := range map[string]string{
		"x":       `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"BBBB"}]}`,
		"alg":     `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"ES256","use":"sig","x":"AAAA"}]}`,
		"use":     `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"enc","x":"AAAA"}]}`,
		"unknown": `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"AAAA","key_ops":["verify"]}]}`,
		"missing": `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","x":"AAAA"}]}`,
		"extra":   `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"AAAA"},{"kid":"k2"}]}`,
	} {
		if same(base, other) {
			t.Errorf("a difference in %s was reported as matching", name)
		}
	}
	dup := `{"keys":[{"kid":"k1","x":"A"},{"kid":"k1","x":"A"}]}`
	if _, err := sameJWKSDocument([]byte(dup), []byte(dup)); err == nil {
		t.Error("a document with a repeated kid was accepted")
	}
}

// selfCheckAgainstFile runs SelfCheck with the on-disk JWKS set to mutate(live)
// and returns the jwks_fresh line.
func selfCheckAgainstFile(t *testing.T, mutate func(live []byte) []byte) Check {
	t.Helper()
	c, _ := startServer(t, nil)
	live, err := c.fetchJWKSRaw()
	if err != nil {
		t.Fatal(err)
	}
	jwks := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwks, mutate(live), 0o644); err != nil {
		t.Fatal(err)
	}
	checks := SelfCheck(c, jwks, 0, time.Now())
	last := checks[len(checks)-1]
	if last.Name != "jwks_fresh" {
		t.Fatalf("unexpected last check %+v", last)
	}
	return last
}

func editFirstKey(t *testing.T, live []byte, fn func(key map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(live, &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc["keys"].([]any)[0].(map[string]any))
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSelfCheckReportsNotFreshWhenOnlyOneMemberDiffers(t *testing.T) {
	for name, fn := range map[string]func(map[string]any){
		"x":       func(k map[string]any) { k["x"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		"alg":     func(k map[string]any) { k["alg"] = "ES256" },
		"use":     func(k map[string]any) { k["use"] = "enc" },
		"unknown": func(k map[string]any) { k["key_ops"] = []string{"verify"} },
	} {
		last := selfCheckAgainstFile(t, func(live []byte) []byte { return editFirstKey(t, live, fn) })
		if last.OK {
			t.Errorf("%s: reported fresh: %+v", name, last)
		}
	}
}

func TestSelfCheckReportsNotFreshOnDuplicateKid(t *testing.T) {
	last := selfCheckAgainstFile(t, func(live []byte) []byte {
		var doc map[string]any
		if err := json.Unmarshal(live, &doc); err != nil {
			t.Fatal(err)
		}
		keys := doc["keys"].([]any)
		doc["keys"] = append(keys, keys[0])
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	if last.OK {
		t.Fatalf("duplicate kid reported fresh: %+v", last)
	}
}

func TestSelfCheckReportsFreshForReorderedIdenticalDocument(t *testing.T) {
	last := selfCheckAgainstFile(t, func(live []byte) []byte {
		var doc struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(live, &doc); err != nil {
			t.Fatal(err)
		}
		for i, j := 0, len(doc.Keys)-1; i < j; i, j = i+1, j-1 {
			doc.Keys[i], doc.Keys[j] = doc.Keys[j], doc.Keys[i]
		}
		out, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	if !last.OK {
		t.Fatalf("identical document in a different order reported not fresh: %+v", last)
	}
}
