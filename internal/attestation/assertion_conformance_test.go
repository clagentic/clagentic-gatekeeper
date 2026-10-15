//go:build unix

package attestation

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsDir is the conformance set the provider is pinned to: contract
// version 1.0.0, cia 1.
const vectorsDir = "../../vectors/v1"

type vectorLayout struct {
	Dir     string `json:"dir"`
	DirMode string `json:"dir_mode"`
	File    string `json:"file"`
	Content string `json:"content"`
}

type vectorExpect struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Actor string `json:"actor"`
	Grade string `json:"grade"`
}

type vectorCase struct {
	ID          string        `json:"id"`
	Kind        string        `json:"kind"`
	Mode        string        `json:"mode"`
	PeerID      string        `json:"peer_id"`
	Now         int64         `json:"now"`
	ObservedDir string        `json:"observed_dir"`
	Token       string        `json:"token"`
	Layout      *vectorLayout `json:"layout"`
	Expect      vectorExpect  `json:"expect"`
}

type vectorManifest struct {
	ContractVersion string            `json:"contract_version"`
	Cia             int               `json:"cia"`
	JWKSFiles       map[string]string `json:"jwks_files"`
	Vectors         []vectorCase      `json:"vectors"`
}

// vectorKeys serves the key sets named by the manifest to the verifier.
type vectorKeys map[string][]jwk

func (v vectorKeys) trusted(iss string) bool { _, ok := v[iss]; return ok }
func (v vectorKeys) keys(_ context.Context, iss string) ([]jwk, error) {
	return v[iss], nil
}

func loadVectors(t *testing.T) (vectorManifest, vectorKeys) {
	t.Helper()
	return loadVectorsFrom(t, vectorsDir)
}

func loadVectorsFrom(t *testing.T, vectorsDir string) (vectorManifest, vectorKeys) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m vectorManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := vectorKeys{}
	for iss, file := range m.JWKSFiles {
		doc, err := os.ReadFile(filepath.Join(vectorsDir, file))
		if err != nil {
			t.Fatal(err)
		}
		ks, err := parseJWKS(doc)
		if err != nil {
			t.Fatal(err)
		}
		keys[iss] = ks
	}
	return m, keys
}

func materializeLayout(t *testing.T, l vectorLayout) (envSet bool, dir string) {
	t.Helper()
	switch l.Dir {
	case "unset":
		return false, ""
	case "absent":
		return true, filepath.Join(t.TempDir(), "does-not-exist")
	}
	d := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o700)
	if l.DirMode == "0755" {
		mode = 0o755
	}
	if err := os.Chmod(d, mode); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(d, AssertionFile)
	switch l.File {
	case "regular":
		if err := os.WriteFile(f, []byte(l.Content), 0o600); err != nil {
			t.Fatal(err)
		}
	case "symlink":
		target := filepath.Join(t.TempDir(), "elsewhere.jwt")
		if err := os.WriteFile(target, []byte(l.Content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, f); err != nil {
			t.Fatal(err)
		}
	}
	return true, d
}

// TestVendoredVectorsMatchProvider runs every vector of the pinned conformance
// set through the provider's own verification and delivery code and requires
// the expected outcome for each.
func TestVendoredVectorsMatchProvider(t *testing.T) {
	m, keys := loadVectors(t)
	if m.ContractVersion != "1.0.0" || m.Cia != 1 {
		t.Fatalf("vectors are contract %s cia %d; this set is the pinned 1.0.0 set", m.ContractVersion, m.Cia)
	}
	// The v1 set is the test of a verifier that implements major 1 only.
	runVectors(t, m, keys, 1)
}

// TestVendoredV2VectorsMatchProvider runs the contract 2.0.0 supplement through
// the provider as configured in production, accepting majors 1 and 2.
func TestVendoredV2VectorsMatchProvider(t *testing.T) {
	m, keys := loadVectorsFrom(t, "../../vectors/v2")
	if m.ContractVersion != "2.0.0" || m.Cia != supportedContractMajor {
		t.Fatalf("vectors are contract %s cia %d; this verifier supports up to cia %d", m.ContractVersion, m.Cia, supportedContractMajor)
	}
	runVectors(t, m, keys, 0)
}

func runVectors(t *testing.T, m vectorManifest, keys vectorKeys, maxMajor int64) {
	t.Helper()
	for _, v := range m.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			var code AssertionCode
			var claims *assertionClaims
			switch v.Kind {
			case "delivery":
				envSet, dir := materializeLayout(t, *v.Layout)
				if !envSet {
					// The provider treats an unset variable as "no assertion", which
					// the contract reports as identity_dir_missing.
					code = CodeDirMissing
					break
				}
				data, aerr := readDelivery(dir)
				if aerr != nil {
					code = aerr.Code
				} else if string(data) != v.Layout.Content {
					t.Fatalf("delivered %q, want %q", data, v.Layout.Content)
				}
			case "token":
				p := verifyParams{Now: v.Now, ObservedDir: v.ObservedDir, PeerID: v.PeerID, MaxMajor: maxMajor}
				if v.Mode == "peer" {
					p.Mode = modePeer
				}
				var aerr *AssertionError
				claims, aerr = verifyAssertion(context.Background(), v.Token, keys, p)
				if aerr != nil {
					code = aerr.Code
				}
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
			if v.Expect.OK {
				if code != "" {
					t.Fatalf("expected success, got %s", code)
				}
				if v.Kind == "token" && (claims.Actor != v.Expect.Actor || claims.Grade != v.Expect.Grade) {
					t.Fatalf("got actor=%s grade=%s, want actor=%s grade=%s", claims.Actor, claims.Grade, v.Expect.Actor, v.Expect.Grade)
				}
				return
			}
			if string(code) != v.Expect.Error {
				t.Fatalf("got %q, want %q", code, v.Expect.Error)
			}
		})
	}
}
