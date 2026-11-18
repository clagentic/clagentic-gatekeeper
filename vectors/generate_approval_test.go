//go:build unix

package vectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The approval set has keys of its own. Regenerating it touches neither v1 nor
// v2, whose tokens and keys consumers pin.
var regenerateApproval = flag.Bool("regenerate-approval", false, "rewrite the approval vector set with fresh throwaway keys")

const (
	approvalOp  = "example.run-command"
	approvalPD  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	approvalRid = "0123456789abcdef0123456789abcdef"
)

// approvalClaims is a valid approval payload at genNow: issued a minute ago for
// the full 300 seconds.
func approvalClaims() map[string]any {
	return map[string]any{
		"iss": genIssuer, "rid": approvalRid, "op": approvalOp, "pd": approvalPD,
		"sid": "sess-0001", "acked_by": "example-operator",
		"iat": genNow - 60, "exp": genNow - 60 + approvalMaxLife, "cap": 1,
	}
}

// approvalToken signs claims under a protected header that carries typ.
func approvalToken(s signer, typ string, claims map[string]any) string {
	hdr := map[string]any{"alg": s.alg, "kid": s.kid}
	if typ != "" {
		hdr["typ"] = typ
	}
	return s.rawToken(mustJSON(hdr), mustJSON(claims))
}

func TestRegenerateApprovalVectors(t *testing.T) {
	if !*regenerateApproval {
		t.Skipf("run with -args -regenerate-approval to rewrite %s", approvalDir)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed, es := edSigner("ed-1", edPriv), esSigner("es-1", esPriv)
	rogue := edSigner("ed-1", roguePriv)
	unknownKid := edSigner("ed-9", edPriv)

	good := func(s signer, claims map[string]any) string { return approvalToken(s, approvalTyp, claims) }
	ok := func(id, desc, token string) approvalVector {
		return approvalVector{ID: id, Description: desc, Token: token, Now: genNow, ExpectedOp: approvalOp, ExpectedPD: approvalPD,
			Expect: approvalExpect{OK: true, Op: approvalOp, Sid: "sess-0001", AckedBy: "example-operator", Rid: approvalRid, ParamsPD: approvalPD}}
	}
	bad := func(id, desc, token, code string) approvalVector {
		return approvalVector{ID: id, Description: desc, Token: token, Now: genNow, ExpectedOp: approvalOp, ExpectedPD: approvalPD,
			Expect: approvalExpect{Error: code}}
	}
	with := func(kv ...any) map[string]any { return withClaims(approvalClaims(), kv...) }

	valid := good(ed, approvalClaims())
	tampered := func(key string, value any) string {
		parts := strings.Split(valid, ".")
		return parts[0] + "." + enc(mustJSON(withClaims(approvalClaims(), key, value))) + "." + parts[2]
	}
	hdrJSON := mustJSON(map[string]any{"alg": "EdDSA", "kid": "ed-1", "typ": approvalTyp})
	payloadJSON := mustJSON(approvalClaims())
	hsToken := func() string {
		h := enc(mustJSON(map[string]any{"alg": "HS256", "kid": "ed-1", "typ": approvalTyp}))
		p := enc(payloadJSON)
		mac := hmac.New(sha256.New, []byte("not-a-real-secret-for-algorithm-confusion"))
		mac.Write([]byte(h + "." + p))
		return h + "." + p + "." + enc(mac.Sum(nil))
	}()
	noneToken := enc(mustJSON(map[string]any{"alg": "none", "kid": "ed-1", "typ": approvalTyp})) + "." + enc(payloadJSON) + "."

	mismatchOp, mismatchPD := ok("approval-op-mismatch", "A valid approval for another operation than the one the consumer is about to run.", valid), ok("approval-digest-mismatch", "A valid approval for other parameters than the ones the consumer is about to run.", valid)
	mismatchOp.ExpectedOp, mismatchOp.Expect = "example.other-command", approvalExpect{Error: "approval_op_mismatch"}
	mismatchPD.ExpectedPD, mismatchPD.Expect = "00"+approvalPD[2:], approvalExpect{Error: "approval_digest_mismatch"}

	vs := []approvalVector{
		ok("approval-valid-eddsa", "An approval, EdDSA, issued a minute ago for 300 seconds.", valid),
		ok("approval-valid-es256", "An approval, ES256.", good(es, approvalClaims())),
		withExpect(ok("approval-valid-rid-differs", "Another request id; the claims read back as signed.", good(ed, with("rid", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),

		bad("approval-expired", "exp is ten seconds before now.", good(ed, with("iat", genNow-310, "exp", genNow-10)), "approval_expired"),
		bad("approval-expired-at-boundary", "exp equal to now is expired.", good(ed, with("exp", genNow)), "approval_expired"),
		bad("approval-not-yet-valid", "iat is after now.", good(ed, with("iat", genNow+10, "exp", genNow+100)), "approval_not_yet_valid"),
		bad("approval-ttl-exceeded", "exp minus iat is 301 seconds.", good(ed, with("iat", genNow-60, "exp", genNow-60+approvalMaxLife+1)), "approval_ttl_exceeded"),

		bad("approval-tampered-op", "The op changed after signing.", tampered("op", "example.other-command"), "approval_signature_invalid"),
		bad("approval-tampered-digest", "The pd changed after signing.", tampered("pd", "00"+approvalPD[2:]), "approval_signature_invalid"),
		bad("approval-wrong-key", "Names the trusted issuer and its kid but is signed by a different key.", good(rogue, approvalClaims()), "approval_signature_invalid"),
		bad("approval-key-not-found", "kid is not in the issuer's key set.", good(unknownKid, approvalClaims()), "approval_key_not_found"),
		bad("approval-issuer-untrusted", "Validly signed, iss is not a trusted issuer.", good(ed, with("iss", "https://other-issuer.example")), "approval_issuer_untrusted"),

		bad("approval-wrong-typ", "Validly signed, typ is JWT.", approvalToken(ed, "JWT", approvalClaims()), "approval_typ_invalid"),
		bad("approval-missing-typ", "Validly signed with no typ: an identity assertion is not an approval.", approvalToken(ed, "", approvalClaims()), "approval_typ_invalid"),
		bad("approval-alg-none", "Unsigned token with alg none.", noneToken, "approval_alg_not_allowed"),
		bad("approval-alg-hs256", "HMAC token, algorithm confusion attempt.", hsToken, "approval_alg_not_allowed"),
		bad("approval-malformed-segments", "Two segments only.", "abc.def", "approval_malformed"),
		bad("approval-malformed-payload-trailing-junk", "Payload segment holds a valid object followed by junk; validly signed.", ed.rawToken(hdrJSON, cat(payloadJSON, ` junk`)), "approval_malformed"),

		bad("approval-claims-missing-rid", "rid is absent.", good(ed, with("rid", nil)), "approval_claims_invalid"),
		bad("approval-claims-bad-rid", "rid is not 32 lower-case hex characters.", good(ed, with("rid", "short")), "approval_claims_invalid"),
		bad("approval-claims-upper-case-digest", "pd is upper case: the digest is 64 lower-case hex characters.", good(ed, with("pd", "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210")), "approval_claims_invalid"),
		bad("approval-claims-cap-2", "cap is 2: an approval is for one use.", good(ed, with("cap", 2)), "approval_claims_invalid"),
		bad("approval-claims-empty-sid", "sid is empty.", good(ed, with("sid", "")), "approval_claims_invalid"),
		bad("approval-claims-exp-string", "exp is a string; the type is checked before any comparison.", good(ed, with("exp", "1792000240")), "approval_claims_invalid"),
		mismatchOp,
		mismatchPD,
	}

	var m approvalManifest
	m.ContractVersion, m.Typ = "2.2.0", approvalTyp
	m.Trust.Issuers = []trustedIssuer{{Iss: genIssuer}}
	m.JWKSFiles = map[string]string{genIssuer: "jwks.json"}
	m.Vectors = vs

	write := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(approvalDir, name), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(approvalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write("jwks.json", map[string]any{"keys": []any{ed25519JWK("ed-1", edPub), p256JWK("es-1", &esPriv.PublicKey)}})
	write("manifest.json", m)
}

// withClaims is with from generate_test.go under a name that says what it
// edits; a nil value removes the claim.
func withClaims(c map[string]any, kv ...any) map[string]any { return with(c, kv...) }

// withExpect sets the rid a passing vector is expected to read back.
func withExpect(v approvalVector, rid string) approvalVector {
	v.Expect.Rid = rid
	return v
}

