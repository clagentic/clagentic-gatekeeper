//go:build unix

package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const vectorDir = "v1"

func readJSON(t *testing.T, p string, into any) {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", p, err)
	}
}

func loadManifest(t *testing.T) (manifest, trust) {
	t.Helper()
	return loadManifestFrom(t, vectorDir)
}

func loadManifestFrom(t *testing.T, dirName string) (manifest, trust) {
	t.Helper()
	var m manifest
	readJSON(t, filepath.Join(dirName, "manifest.json"), &m)
	tr := trust{}
	for _, iss := range m.Trust.Issuers {
		file, ok := m.JWKSFiles[iss.Iss]
		if !ok {
			t.Fatalf("no jwks file for trusted issuer %q", iss.Iss)
		}
		var doc jwksDoc
		readJSON(t, filepath.Join(dirName, file), &doc)
		tr[iss.Iss] = doc
	}
	return m, tr
}

func materialize(t *testing.T, l layout) (envSet bool, dir string) {
	t.Helper()
	switch l.Dir {
	case "unset":
		return false, ""
	case "absent":
		return true, filepath.Join(t.TempDir(), "does-not-exist")
	case "present":
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
		f := filepath.Join(d, "identity.jwt")
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
		case "absent":
		default:
			t.Fatalf("unknown file layout %q", l.File)
		}
		return true, d
	}
	t.Fatalf("unknown dir layout %q", l.Dir)
	return false, ""
}

func TestVectorsMatchReferenceVerifier(t *testing.T) {
	m, tr := loadManifest(t)
	if m.Cia != 1 {
		t.Fatalf("manifest cia %d, this set is the pinned major 1 set", m.Cia)
	}
	for _, v := range m.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			var code string
			var got outcome
			switch v.Kind {
			case "delivery":
				envSet, dir := materialize(t, *v.Layout)
				data, c := deliver(envSet, dir)
				code = c
				if code == "" && string(data) != v.Layout.Content {
					t.Fatalf("delivered %q, want %q", data, v.Layout.Content)
				}
			case "token":
				got, code = verifyTokenUpTo(tr, v, int64(m.Cia))
			default:
				t.Fatalf("unknown kind %q", v.Kind)
			}
			if v.Expect.OK {
				if code != "" {
					t.Fatalf("expected success, got %s", code)
				}
				if v.Kind == "token" && (got.Actor != v.Expect.Actor || got.Grade != v.Expect.Grade) {
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

func TestEveryFailureCodeHasAVector(t *testing.T) {
	m, _ := loadManifest(t)
	covered := map[string]bool{}
	ids := map[string]bool{}
	for _, v := range m.Vectors {
		if ids[v.ID] {
			t.Errorf("duplicate vector id %q", v.ID)
		}
		ids[v.ID] = true
		if !v.Expect.OK {
			covered[v.Expect.Error] = true
		}
	}
	for _, c := range allCodes {
		if !covered[c] {
			t.Errorf("no vector for failure code %q", c)
		}
	}
	for c := range covered {
		known := false
		for _, a := range allCodes {
			known = known || a == c
		}
		if !known {
			t.Errorf("vector expects undocumented code %q", c)
		}
	}
}

func TestSpecDocumentsEveryFailureCode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "identity-contract.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range allCodes {
		if !strings.Contains(string(raw), "| `"+c+"` |") {
			t.Errorf("spec table does not list %q", c)
		}
	}
}

func TestBothAlgorithmsAndGradesAreCovered(t *testing.T) {
	m, _ := loadManifest(t)
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		if v.Kind != "token" || !v.Expect.OK {
			continue
		}
		hdr, ok := decodeObject(strings.Split(v.Token, ".")[0])
		if !ok {
			t.Fatalf("%s: bad header", v.ID)
		}
		seen[hdr["alg"].(string)] = true
		seen["grade:"+v.Expect.Grade] = true
		seen["mode:"+v.Mode] = true
	}
	for _, want := range []string{"EdDSA", "ES256", "grade:workload", "grade:harness", "mode:local", "mode:peer"} {
		if !seen[want] {
			t.Errorf("no passing vector for %s", want)
		}
	}
}

func TestPublishedKeysArePublicOnly(t *testing.T) {
	_, tr := loadManifest(t)
	for iss, doc := range tr {
		if len(doc.Keys) == 0 {
			t.Errorf("%s: empty key set", iss)
		}
		for _, k := range doc.Keys {
			if k.D != "" {
				t.Errorf("%s: key %s carries private material", iss, k.Kid)
			}
			if k.Use != "sig" || k.Kid == "" || k.Alg == "" {
				t.Errorf("%s: key %q missing kid/alg/use", iss, k.Kid)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(vectorDir, "jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, `"k"`} {
		if strings.Contains(string(raw), member) {
			t.Errorf("jwks.json contains private member %s", member)
		}
	}
}

// The schema's x-contract summary is what a schema-driven implementation reads;
// it must agree with the rules the reference verifier enforces.
func TestSchemaAgreesWithVerifier(t *testing.T) {
	var schema struct {
		Contract struct {
			RequiredAlways []string            `json:"requiredAlways"`
			ByGrade        map[string][]string `json:"requiredByGrade"`
			LocalOnly      []string            `json:"requiredLocalAssertion"`
			Exchanged      []string            `json:"requiredExchanged"`
			Forbidden      []string            `json:"forbiddenExchanged"`
			MaxLifetime    int                 `json:"maxLifetimeSeconds"`
		} `json:"x-contract"`
	}
	readJSON(t, filepath.Join("..", "schemas", "identity-assertion.json"), &schema)
	c := schema.Contract
	a, b := append([]string(nil), c.RequiredAlways...), append([]string(nil), alwaysRequired...)
	sort.Strings(a)
	sort.Strings(b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("schema requiredAlways %v, verifier %v", a, b)
	}
	if !reflect.DeepEqual(c.ByGrade["harness"], []string{"act", "spawn"}) || len(c.ByGrade["workload"]) != 0 {
		t.Errorf("schema requiredByGrade %v disagrees with verifier", c.ByGrade)
	}
	if !reflect.DeepEqual(c.LocalOnly, []string{"dir"}) || !reflect.DeepEqual(c.Forbidden, []string{"dir"}) || !reflect.DeepEqual(c.Exchanged, []string{"aud"}) {
		t.Errorf("schema local/exchanged sets disagree with verifier")
	}
	if c.MaxLifetime != maxLifetimeSecs {
		t.Errorf("schema max lifetime %d, verifier %d", c.MaxLifetime, maxLifetimeSecs)
	}
	var disc map[string]any
	readJSON(t, filepath.Join("..", "schemas", "jwks-discovery.json"), &disc)
}
