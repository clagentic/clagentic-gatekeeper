//go:build unix

package vectors

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The operator approval of contract section 13 has its own vector set, in its
// own directory, with its own keys: the identity vectors under v1/ and v2/ are
// not touched by it. This file holds the reference verifier written from the
// section with the standard library, and the tests that hold the set to it.

const (
	approvalDir     = "approval"
	approvalTyp     = "clagentic-approval+jwt"
	approvalMaxLife = 300
)

var approvalRequired = []string{"iss", "rid", "op", "pd", "sid", "acked_by", "iat", "exp", "cap"}

var approvalCodes = []string{
	"approval_malformed", "approval_alg_not_allowed", "approval_typ_invalid", "approval_issuer_untrusted",
	"approval_key_not_found", "approval_signature_invalid", "approval_expired", "approval_not_yet_valid",
	"approval_ttl_exceeded", "approval_claims_invalid", "approval_op_mismatch", "approval_digest_mismatch",
}

var (
	reApprovalRid    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reApprovalOp     = regexp.MustCompile(`^[A-Za-z0-9._:/@+-]{1,128}$`)
	reApprovalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reApprover       = regexp.MustCompile(`^[A-Za-z0-9._:@+-]{1,128}$`)
)

type approvalExpect struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Op       string `json:"op,omitempty"`
	Sid      string `json:"sid,omitempty"`
	AckedBy  string `json:"acked_by,omitempty"`
	Rid      string `json:"rid,omitempty"`
	ParamsPD string `json:"pd,omitempty"`
}

// approvalVector is one token and what the consumer expects to be approved. The
// consumer states the operation and the digest of the parameters it is about to
// run; the verifier compares them with what the approval binds.
type approvalVector struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Token       string         `json:"token"`
	Now         int64          `json:"now"`
	ExpectedOp  string         `json:"expected_op"`
	ExpectedPD  string         `json:"expected_pd"`
	Expect      approvalExpect `json:"expect"`
}

type approvalManifest struct {
	ContractVersion string `json:"contract_version"`
	Typ             string `json:"typ"`
	Trust           struct {
		Issuers []trustedIssuer `json:"issuers"`
	} `json:"trust"`
	JWKSFiles map[string]string `json:"jwks_files"`
	Vectors   []approvalVector  `json:"vectors"`
}

func loadApprovalManifest(t *testing.T) (approvalManifest, trust) {
	t.Helper()
	var m approvalManifest
	readJSON(t, filepath.Join(approvalDir, "manifest.json"), &m)
	tr := trust{}
	for _, iss := range m.Trust.Issuers {
		file, ok := m.JWKSFiles[iss.Iss]
		if !ok {
			t.Fatalf("no jwks file for trusted issuer %q", iss.Iss)
		}
		var doc jwksDoc
		readJSON(t, filepath.Join(approvalDir, file), &doc)
		tr[iss.Iss] = doc
	}
	return m, tr
}

// approvalClaimsValid is section 13.3's shape check.
func approvalClaimsValid(c map[string]any) bool {
	for _, name := range approvalRequired {
		if _, ok := c[name]; !ok {
			return false
		}
	}
	str := func(name string, re *regexp.Regexp) bool {
		s, ok := c[name].(string)
		return ok && re.MatchString(s)
	}
	uses, ok := asInt(c["cap"])
	return nonEmptyString(c["iss"]) && nonEmptyString(c["sid"]) && str("rid", reApprovalRid) && str("op", reApprovalOp) &&
		str("pd", reApprovalDigest) && str("acked_by", reApprover) && ok && uses == 1
}

// verifyApproval implements section 13.3 and returns the claims or the first
// failure code, in the normative order.
func verifyApproval(tr trust, v approvalVector) (map[string]any, string) {
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 {
		return nil, "approval_malformed"
	}
	header, okh := decodeObject(parts[0])
	claims, okp := decodeObject(parts[1])
	sig, errs := b64(parts[2])
	if !okh || !okp {
		return nil, "approval_malformed"
	}
	if _, crit := header["crit"]; crit {
		return nil, "approval_malformed"
	}
	alg, _ := header["alg"].(string)
	if alg != "EdDSA" && alg != "ES256" {
		return nil, "approval_alg_not_allowed"
	}
	if typ, _ := header["typ"].(string); typ != approvalTyp {
		return nil, "approval_typ_invalid"
	}
	iss, _ := claims["iss"].(string)
	doc, trusted := tr[iss]
	if !trusted {
		return nil, "approval_issuer_untrusted"
	}
	kid, _ := header["kid"].(string)
	var key *jwk
	for i := range doc.Keys {
		if kid != "" && doc.Keys[i].Kid == kid {
			key = &doc.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, "approval_key_not_found"
	}
	if errs != nil || !verifySignature(*key, alg, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, "approval_signature_invalid"
	}
	iat, okIat := asInt(claims["iat"])
	exp, okExp := asInt(claims["exp"])
	if !okIat || !okExp {
		return nil, "approval_claims_invalid"
	}
	switch {
	case exp <= v.Now:
		return nil, "approval_expired"
	case iat > v.Now:
		return nil, "approval_not_yet_valid"
	case exp-iat > approvalMaxLife:
		return nil, "approval_ttl_exceeded"
	}
	if !approvalClaimsValid(claims) {
		return nil, "approval_claims_invalid"
	}
	if claims["op"] != v.ExpectedOp {
		return nil, "approval_op_mismatch"
	}
	if claims["pd"] != v.ExpectedPD {
		return nil, "approval_digest_mismatch"
	}
	return claims, ""
}

func TestApprovalVectorsMatchReferenceVerifier(t *testing.T) {
	m, tr := loadApprovalManifest(t)
	if m.ContractVersion != "2.2.0" || m.Typ != approvalTyp {
		t.Fatalf("manifest is contract %s typ %s, want 2.2.0 %s", m.ContractVersion, m.Typ, approvalTyp)
	}
	for _, v := range m.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			claims, code := verifyApproval(tr, v)
			if !v.Expect.OK {
				if code != v.Expect.Error {
					t.Fatalf("got %q, want %q", code, v.Expect.Error)
				}
				return
			}
			if code != "" {
				t.Fatalf("expected success, got %s", code)
			}
			if claims["op"] != v.Expect.Op || claims["sid"] != v.Expect.Sid || claims["acked_by"] != v.Expect.AckedBy ||
				claims["rid"] != v.Expect.Rid || claims["pd"] != v.Expect.ParamsPD {
				t.Fatalf("claims %v, want %+v", claims, v.Expect)
			}
		})
	}
}

func TestEveryApprovalCodeHasAVector(t *testing.T) {
	m, _ := loadApprovalManifest(t)
	covered, ids := map[string]bool{}, map[string]bool{}
	for _, v := range m.Vectors {
		if ids[v.ID] {
			t.Errorf("duplicate vector id %q", v.ID)
		}
		ids[v.ID] = true
		if !v.Expect.OK {
			covered[v.Expect.Error] = true
		}
	}
	for _, c := range approvalCodes {
		if !covered[c] {
			t.Errorf("no vector for failure code %q", c)
		}
	}
	for c := range covered {
		if !slices.Contains(approvalCodes, c) {
			t.Errorf("vector expects undocumented code %q", c)
		}
	}
}

func TestSpecDocumentsEveryApprovalCode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "identity-contract.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range approvalCodes {
		if !strings.Contains(string(raw), "| `"+c+"` |") {
			t.Errorf("spec table does not list %q", c)
		}
	}
}

// Both algorithms verify, and the vector keys are public only.
func TestApprovalVectorsCoverBothAlgorithmsAndPublishNoPrivateKey(t *testing.T) {
	m, tr := loadApprovalManifest(t)
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		if !v.Expect.OK {
			continue
		}
		hdr, ok := decodeObject(strings.Split(v.Token, ".")[0])
		if !ok {
			t.Fatalf("%s: bad header", v.ID)
		}
		seen[hdr["alg"].(string)] = true
	}
	for _, alg := range []string{"EdDSA", "ES256"} {
		if !seen[alg] {
			t.Errorf("no passing vector for %s", alg)
		}
	}
	for iss, doc := range tr {
		for _, k := range doc.Keys {
			if k.D != "" {
				t.Errorf("%s: key %s carries private material", iss, k.Kid)
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(approvalDir, "jwks.json"))
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
func TestApprovalSchemaAgreesWithVerifier(t *testing.T) {
	var schema struct {
		ID       string `json:"$id"`
		Required []string
		Contract struct {
			Version        string   `json:"version"`
			Typ            string   `json:"typ"`
			RequiredAlways []string `json:"requiredAlways"`
			MaxLifetime    int      `json:"maxLifetimeSeconds"`
		} `json:"x-contract"`
		Properties map[string]map[string]any `json:"properties"`
	}
	readJSON(t, filepath.Join("..", "schemas", "approval.json"), &schema)
	if schema.ID != "https://schemas.clagentic.ai/approval/1.json" || schema.Contract.Version != "2.2.0" || schema.Contract.Typ != approvalTyp {
		t.Errorf("schema $id %q version %q typ %q", schema.ID, schema.Contract.Version, schema.Contract.Typ)
	}
	a, b, c := append([]string(nil), schema.Contract.RequiredAlways...), append([]string(nil), approvalRequired...), append([]string(nil), schema.Required...)
	sort.Strings(a)
	sort.Strings(b)
	sort.Strings(c)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(c, b) {
		t.Errorf("schema requiredAlways %v, required %v, verifier %v", a, c, b)
	}
	if schema.Contract.MaxLifetime != approvalMaxLife {
		t.Errorf("schema max lifetime %d, verifier %d", schema.Contract.MaxLifetime, approvalMaxLife)
	}
	for name, re := range map[string]*regexp.Regexp{"rid": reApprovalRid, "op": reApprovalOp, "pd": reApprovalDigest, "acked_by": reApprover} {
		if got, _ := schema.Properties[name]["pattern"].(string); got != re.String() {
			t.Errorf("schema pattern of %s is %q, verifier %q", name, got, re.String())
		}
	}
}

// The identity vector sets are read, never rewritten, by this release: their
// contract_version stays the one they were generated for.
func TestIdentityVectorSetsKeepTheirContractVersion(t *testing.T) {
	for dir, want := range map[string]string{vectorDir: "1.0.0", vectorDirV2: "2.1.0"} {
		var m struct {
			ContractVersion string `json:"contract_version"`
		}
		readJSON(t, filepath.Join(dir, "manifest.json"), &m)
		if m.ContractVersion != want {
			t.Errorf("%s: contract_version %q, want %q", dir, m.ContractVersion, want)
		}
	}
}
