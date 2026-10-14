//go:build unix

package vectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regenerating rotates every key: the signing keys are created in memory,
// used once, and discarded. Only the public halves are written.
var regenerate = flag.Bool("regenerate", false, "rewrite the vector set with fresh throwaway keys")

const (
	genNow    = int64(1792000000)
	genIssuer = "https://issuer.example"
	genPeer   = "peer.example"
	genDirA   = "/run/example/identity/spawn/a1"
	genDirB   = "/run/example/identity/spawn/b2"
)

type signer struct {
	alg  string
	kid  string
	sign func(input []byte) []byte
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (s signer) token(claims map[string]any) string {
	h := enc(mustJSON(map[string]any{"alg": s.alg, "kid": s.kid}))
	p := enc(mustJSON(claims))
	return h + "." + p + "." + enc(s.sign([]byte(h+"."+p)))
}

// rawToken signs caller-supplied segment bytes, so a vector can carry content
// that json.Marshal would never produce (trailing values, junk).
func (s signer) rawToken(header, payload []byte) string {
	h, p := enc(header), enc(payload)
	return h + "." + p + "." + enc(s.sign([]byte(h+"."+p)))
}

// cat returns a fresh slice so vectors built from one base never share storage.
func cat(base []byte, tail string) []byte {
	return append(append([]byte(nil), base...), tail...)
}

func edSigner(kid string, priv ed25519.PrivateKey) signer {
	return signer{alg: "EdDSA", kid: kid, sign: func(in []byte) []byte { return ed25519.Sign(priv, in) }}
}

func esSigner(kid string, priv *ecdsa.PrivateKey) signer {
	return signer{alg: "ES256", kid: kid, sign: func(in []byte) []byte {
		d := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, priv, d[:])
		if err != nil {
			panic(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}}
}

func session() map[string]any {
	return map[string]any{
		"iss": genIssuer, "sub": "human:example-user", "roles": []string{"builder"},
		"grade": "workload", "rt": map[string]any{"id": "example-runtime", "version": "1.0.0"},
		"sid": "sess-0001", "origin": "human", "dir": genDirA,
		"iat": genNow - 60, "exp": genNow - 60 + 39600, "jti": "jti-0001", "cia": 1,
	}
}

func child() map[string]any {
	c := session()
	c["grade"] = "harness"
	c["roles"] = []string{"reviewer"}
	c["act"] = map[string]any{"sub": "agent:example-reviewer", "act": map[string]any{"sub": "runtime:example-runtime"}}
	c["spawn"] = "spawn-0001"
	c["origin"] = "agent"
	c["dir"] = genDirB
	c["jti"] = "jti-0002"
	return c
}

func exchanged(base map[string]any) map[string]any {
	c := base
	delete(c, "dir")
	c["aud"] = genPeer
	c["jti"] = "jti-x-" + c["jti"].(string)
	c["exp"] = genNow - 60 + 900
	return c
}

func with(c map[string]any, kv ...any) map[string]any {
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(c, kv[i].(string))
		} else {
			c[kv[i].(string)] = kv[i+1]
		}
	}
	return c
}

func ed25519JWK(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig", "x": enc(pub)}
}

func p256JWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig", "x": enc(x), "y": enc(y)}
}

func TestRegenerateVectors(t *testing.T) {
	if !*regenerate {
		t.Skipf("run with -args -regenerate to rewrite %s", vectorDir)
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
	ed := edSigner("ed-1", edPriv)
	es := esSigner("es-1", esPriv)
	rogueSameKid := edSigner("ed-1", roguePriv)
	unknownKid := edSigner("ed-9", edPriv)

	tok := func(s signer, c map[string]any) string { return s.token(c) }
	tokV := func(id, desc, mode, observed string, token string, e expectation) vector {
		v := vector{ID: id, Description: desc, Kind: "token", Mode: mode, Now: genNow, Token: token, Expect: e}
		if mode == audienceLocal {
			v.ObservedDir = observed
		} else {
			v.PeerID = genPeer
		}
		return v
	}
	okE := func(actor, grade string) expectation { return expectation{OK: true, Actor: actor, Grade: grade} }
	errE := func(code string) expectation { return expectation{Error: code} }

	validEd := tok(ed, session())
	tamperedPayload := func() string {
		parts := strings.Split(validEd, ".")
		forged := with(session(), "roles", []string{"builder", "merger"})
		return parts[0] + "." + enc(mustJSON(forged)) + "." + parts[2]
	}()
	hsKey := []byte("not-a-real-secret-for-algorithm-confusion")
	hsToken := func() string {
		h := enc(mustJSON(map[string]any{"alg": "HS256", "kid": "ed-1"}))
		p := enc(mustJSON(session()))
		mac := hmac.New(sha256.New, hsKey)
		mac.Write([]byte(h + "." + p))
		return h + "." + p + "." + enc(mac.Sum(nil))
	}()
	noneToken := enc(mustJSON(map[string]any{"alg": "none", "kid": "ed-1"})) + "." + enc(mustJSON(session())) + "."

	hdrJSON := mustJSON(map[string]any{"alg": "EdDSA", "kid": "ed-1"})
	payloadJSON := mustJSON(session())

	L := audienceLocal
	P := audiencePeer
	vs := []vector{
		tokV("valid-session-eddsa", "Session assertion, EdDSA, human acting directly with no act chain.", L, genDirA, validEd, okE("human:example-user", "workload")),
		tokV("valid-session-es256", "Session assertion, ES256, agent acting for a human.", L, genDirA,
			tok(es, with(session(), "act", map[string]any{"sub": "agent:example-builder"}, "jti", "jti-0003")), okE("agent:example-builder", "workload")),
		tokV("valid-child-eddsa", "Child assertion, grade harness, two-level act chain, own delivery directory.", L, genDirB, tok(ed, child()), okE("agent:example-reviewer", "harness")),
		tokV("valid-unknown-claims-ignored", "Unknown claims, including inside rt, are ignored.", L, genDirA,
			tok(ed, with(session(), "ext_note", "ignored", "rt", map[string]any{"id": "example-runtime", "version": "1.0.0", "ext": 1})), okE("human:example-user", "workload")),
		tokV("valid-peer-es256", "Exchanged token for a peer, ES256, aud equals the peer identifier, no dir.", P, "",
			tok(es, exchanged(with(session(), "act", map[string]any{"sub": "agent:example-builder"}))), okE("agent:example-builder", "workload")),
		tokV("valid-peer-child-eddsa", "Exchanged child token for a peer, EdDSA.", P, "", tok(ed, exchanged(child())), okE("agent:example-reviewer", "harness")),

		tokV("expired", "exp is one hour before now.", L, genDirA, tok(ed, with(session(), "iat", genNow-7200, "exp", genNow-3600)), errE("expired")),
		tokV("expired-at-boundary", "exp equal to now is expired.", L, genDirA, tok(ed, with(session(), "exp", genNow)), errE("expired")),
		tokV("not-yet-valid-nbf", "nbf is one hour after now.", L, genDirA, tok(ed, with(session(), "nbf", genNow+3600)), errE("not_yet_valid")),
		tokV("not-yet-valid-iat", "iat is after now.", L, genDirA, tok(ed, with(session(), "iat", genNow+10, "exp", genNow+3600)), errE("not_yet_valid")),
		tokV("ttl-exceeded", "exp minus iat is 43201 seconds.", L, genDirA, tok(ed, with(session(), "exp", genNow-60+43201)), errE("ttl_exceeded")),

		tokV("issuer-untrusted", "Valid signature from an issuer that is not in the trust list.", L, genDirA, tok(rogueSameKid, with(session(), "iss", "https://other-issuer.example")), errE("issuer_untrusted")),
		tokV("signature-forged", "Names the trusted issuer and its kid but is signed by a different key.", L, genDirA, tok(rogueSameKid, session()), errE("signature_invalid")),
		tokV("tampered-payload", "Payload changed after signing (merger added to roles).", L, genDirA, tamperedPayload, errE("signature_invalid")),
		tokV("key-not-found", "kid is not in the issuer's key set.", L, genDirA, tok(unknownKid, session()), errE("key_not_found")),
		tokV("alg-none", "Unsigned token with alg none.", L, genDirA, noneToken, errE("alg_not_allowed")),
		tokV("alg-hs256", "HMAC token, algorithm confusion attempt.", L, genDirA, hsToken, errE("alg_not_allowed")),
		tokV("malformed-segments", "Two segments only.", L, genDirA, "abc.def", errE("malformed")),
		tokV("malformed-payload", "Payload is not a JSON object.", L, genDirA, enc(mustJSON(map[string]any{"alg": "EdDSA", "kid": "ed-1"}))+"."+enc([]byte("not-json"))+"."+enc([]byte("sig")), errE("malformed")),

		tokV("malformed-header-trailing-value", "Header segment holds a valid object followed by a second JSON object; validly signed.", L, genDirA,
			ed.rawToken(cat(hdrJSON, `{}`), payloadJSON), errE("malformed")),
		tokV("malformed-header-trailing-junk", "Header segment holds a valid object followed by junk; validly signed.", L, genDirA,
			ed.rawToken(cat(hdrJSON, ` junk`), payloadJSON), errE("malformed")),
		tokV("malformed-payload-trailing-value", "Payload segment holds a valid object followed by a second JSON object; validly signed.", L, genDirA,
			ed.rawToken(hdrJSON, cat(payloadJSON, `{}`)), errE("malformed")),
		tokV("malformed-payload-trailing-junk", "Payload segment holds a valid object followed by junk; validly signed.", L, genDirA,
			ed.rawToken(hdrJSON, cat(payloadJSON, ` junk`)), errE("malformed")),

		tokV("time-nbf-string", "nbf is a string; type is checked before any time comparison.", L, genDirA, tok(ed, with(session(), "nbf", "0")), errE("claims_invalid")),
		tokV("time-nbf-string-expired", "nbf is a string and exp is already past; the type fault wins over expired.", L, genDirA, tok(ed, with(session(), "iat", genNow-7200, "exp", genNow-3600, "nbf", "0")), errE("claims_invalid")),
		tokV("time-iat-string-expired", "iat is a string and exp is already past; the type fault wins over expired.", L, genDirA, tok(ed, with(session(), "iat", "1791992800", "exp", genNow-3600)), errE("claims_invalid")),
		tokV("time-exp-string", "exp is a string.", L, genDirA, tok(ed, with(session(), "exp", "1792000900")), errE("claims_invalid")),
		tokV("time-exp-fractional", "exp is a fractional number.", L, genDirA, tok(ed, with(session(), "exp", float64(genNow)+0.5)), errE("claims_invalid")),
		tokV("time-exp-fractional-expired", "exp is fractional and also in the past; the type fault wins over expired.", L, genDirA, tok(ed, with(session(), "exp", float64(genNow-3600)+0.5)), errE("claims_invalid")),

		tokV("contract-version-unsupported", "Validly signed, cia is 2.", L, genDirA, tok(ed, with(session(), "cia", 2)), errE("contract_version_unsupported")),

		tokV("workload-missing-dir", "Workload local assertion without dir.", L, genDirA, tok(ed, with(session(), "dir", nil)), errE("claims_invalid")),
		tokV("workload-missing-sid", "Workload assertion without sid.", L, genDirA, tok(ed, with(session(), "sid", nil)), errE("claims_invalid")),
		tokV("harness-missing-spawn", "Harness assertion without spawn.", L, genDirB, tok(ed, with(child(), "spawn", nil)), errE("claims_invalid")),
		tokV("harness-missing-act", "Harness assertion without act.", L, genDirB, tok(ed, with(child(), "act", nil)), errE("claims_invalid")),
		tokV("grade-unknown", "grade is not workload or harness.", L, genDirA, tok(ed, with(session(), "grade", "service")), errE("claims_invalid")),
		tokV("origin-unknown", "origin is not in the vocabulary.", L, genDirA, tok(ed, with(session(), "origin", "cron")), errE("claims_invalid")),
		tokV("sub-bad-pattern", "sub lacks the actor type prefix.", L, genDirA, tok(ed, with(session(), "sub", "someone")), errE("claims_invalid")),
		tokV("peer-dir-present", "Exchanged token that still carries dir.", P, "", tok(ed, with(exchanged(session()), "dir", genDirA)), errE("claims_invalid")),

		tokV("audience-unexpected-local", "A token minted for a peer presented to a local consumer.", L, genDirA, tok(ed, exchanged(session())), errE("audience_unexpected")),
		tokV("audience-mismatch-peer", "aud names a different peer.", P, "", tok(ed, with(exchanged(session()), "aud", "other-peer.example")), errE("audience_mismatch")),
		tokV("audience-missing-peer", "A local assertion presented to a peer.", P, "", validEd, errE("audience_mismatch")),
		tokV("dir-mismatch", "dir claim differs from the directory the token was read from.", L, genDirB, validEd, errE("dir_mismatch")),
	}

	d := func(id, desc string, l layout, e expectation) vector {
		return vector{ID: id, Description: desc, Kind: "delivery", Layout: &l, Expect: e}
	}
	vs = append(vs,
		d("delivery-ok", "0700 directory holding a regular identity.jwt.", layout{Dir: "present", DirMode: "0700", File: "regular", Content: "header.payload.signature"}, expectation{OK: true}),
		d("delivery-dir-unset", "CLAGENTIC_IDENTITY_DIR is not set.", layout{Dir: "unset"}, errE("identity_dir_missing")),
		d("delivery-dir-absent", "The variable names a directory that does not exist.", layout{Dir: "absent"}, errE("identity_dir_missing")),
		d("delivery-dir-unsafe-mode", "Directory mode 0755.", layout{Dir: "present", DirMode: "0755", File: "regular", Content: "header.payload.signature"}, errE("identity_dir_unsafe")),
		d("delivery-file-missing", "Directory without identity.jwt.", layout{Dir: "present", DirMode: "0700", File: "absent"}, errE("identity_file_missing")),
		d("delivery-file-symlink", "identity.jwt is a symlink.", layout{Dir: "present", DirMode: "0700", File: "symlink", Content: "header.payload.signature"}, errE("identity_file_symlink")),
	)

	var m manifest
	m.ContractVersion = "1.0.0"
	m.Cia = supportedCia
	m.Trust.Issuers = []trustedIssuer{{Iss: genIssuer}}
	m.JWKSFiles = map[string]string{genIssuer: "jwks.json"}
	m.Vectors = vs

	write := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vectorDir, name), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(vectorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write("jwks.json", map[string]any{"keys": []any{ed25519JWK("ed-1", edPub), p256JWK("es-1", &esPriv.PublicKey)}})
	write("manifest.json", m)
}
