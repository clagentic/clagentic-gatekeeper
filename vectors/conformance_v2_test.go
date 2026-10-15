//go:build unix

package vectors

import (
	"strings"
	"testing"
)

func TestV2VectorsMatchReferenceVerifier(t *testing.T) {
	m, tr := loadManifestFrom(t, vectorDirV2)
	if m.ContractVersion != "2.0.0" || m.Cia != 2 {
		t.Fatalf("manifest is contract %s cia %d, want 2.0.0 cia 2", m.ContractVersion, m.Cia)
	}
	for _, v := range m.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			got, code := verifyTokenUpTo(tr, v, int64(m.Cia))
			if v.Expect.OK {
				if code != "" {
					t.Fatalf("expected success, got %s", code)
				}
				if got.Actor != v.Expect.Actor || got.Grade != v.Expect.Grade {
					t.Fatalf("got actor=%s grade=%s, want actor=%s grade=%s", got.Actor, got.Grade, v.Expect.Actor, v.Expect.Grade)
				}
				return
			}
			if code != v.Expect.Error {
				t.Fatalf("got %q, want %q", code, v.Expect.Error)
			}
		})
	}
}

// A driven assertion is never human-graded and never names a human, and a
// verifier tells it from the automated origins by the value alone.
func TestV2DrivenInvariants(t *testing.T) {
	m, _ := loadManifestFrom(t, vectorDirV2)
	driven := 0
	for _, v := range m.Vectors {
		if !v.Expect.OK {
			continue
		}
		parts := strings.Split(v.Token, ".")
		claims, ok := decodeObject(parts[1])
		if !ok {
			t.Fatalf("%s: bad payload", v.ID)
		}
		if claims["origin"] != "driven" {
			continue
		}
		driven++
		if sub, _ := claims["sub"].(string); strings.HasPrefix(sub, "human:") {
			t.Errorf("%s: a passing driven vector names a human sub %q", v.ID, sub)
		}
		if v.Expect.Grade != "workload" || strings.HasPrefix(v.Expect.Actor, "human:") {
			t.Errorf("%s: a passing driven vector is graded %q for %q", v.ID, v.Expect.Grade, v.Expect.Actor)
		}
	}
	if driven == 0 {
		t.Fatal("no passing driven vector")
	}
}

// The v1 set stays the test of a major 1 verifier: its cia 2 vector is
// unsupported there, and a major 2 verifier reads the same token as valid.
func TestV1UnsupportedVectorIsMajor1Only(t *testing.T) {
	m, tr := loadManifest(t)
	for _, v := range m.Vectors {
		if v.ID != "contract-version-unsupported" {
			continue
		}
		if _, code := verifyTokenUpTo(tr, v, 1); code != "contract_version_unsupported" {
			t.Fatalf("major 1 verifier got %q", code)
		}
		got, code := verifyTokenUpTo(tr, v, 2)
		if code != "" || got.Grade != "workload" {
			t.Fatalf("major 2 verifier got %q (%+v), want the token accepted", code, got)
		}
		return
	}
	t.Fatal("v1 set lost its contract-version-unsupported vector")
}
