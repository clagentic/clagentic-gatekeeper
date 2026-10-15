//go:build unix

package vectors

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The v2 set is a supplement to v1 with keys of its own. Regenerating it never
// touches v1, whose tokens and keys consumers pin.
var regenerateV2 = flag.Bool("regenerate-v2", false, "rewrite the v2 vector set with fresh throwaway keys")

const vectorDirV2 = "v2"

// sessionV2 is a driven session of contract major 2: a workload assertion for
// a launched runtime, acting as an agent definition, naming no human.
func sessionV2() map[string]any {
	c := session()
	c["sub"] = "runtime:example-runtime"
	c["act"] = map[string]any{"sub": "agent:example-builder"}
	c["origin"] = "driven"
	c["cia"] = 2
	c["jti"] = "jti-v2-0001"
	return c
}

func TestRegenerateVectorsV2(t *testing.T) {
	if !*regenerateV2 {
		t.Skipf("run with -args -regenerate-v2 to rewrite %s", vectorDirV2)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := edSigner("ed-1", edPriv)
	es := esSigner("es-1", esPriv)

	tokV := func(id, desc, mode, observed, token string, e expectation) vector {
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
	L, P := audienceLocal, audiencePeer

	vs := []vector{
		tokV("v2-valid-driven-eddsa", "Driven session, EdDSA, cia 2: workload grade, runtime sub, acting as an agent definition.", L, genDirA,
			ed.token(sessionV2()), okE("agent:example-builder", "workload")),
		tokV("v2-valid-driven-es256-no-act", "Driven session, ES256, no act: the actor is the runtime itself.", L, genDirA,
			es.token(with(sessionV2(), "act", nil, "jti", "jti-v2-0002")), okE("runtime:example-runtime", "workload")),
		tokV("v2-valid-driven-peer-eddsa", "Exchanged driven token for a peer; origin and cia are carried over unchanged.", P, "",
			ed.token(exchanged(sessionV2())), okE("agent:example-builder", "workload")),
		tokV("v2-valid-v1-origin-under-cia2", "A major 1 origin is also valid in a cia 2 assertion.", L, genDirA,
			ed.token(with(sessionV2(), "origin", "trigger", "jti", "jti-v2-0003")), okE("agent:example-builder", "workload")),
		tokV("v2-valid-v1-assertion-still-valid", "A cia 1 assertion, human origin and human sub, verifies unchanged in a major 2 verifier.", L, genDirA,
			ed.token(session()), okE("human:example-user", "workload")),

		tokV("v2-driven-under-cia1", "origin driven in a cia 1 assertion: the value does not exist in major 1.", L, genDirA,
			ed.token(with(sessionV2(), "cia", 1)), errE("claims_invalid")),
		tokV("v2-driven-human-sub", "origin driven with a human: sub is refused: a driven assertion never names a human.", L, genDirA,
			ed.token(with(sessionV2(), "sub", "human:example-user", "act", nil)), errE("claims_invalid")),
		tokV("v2-driven-harness-grade", "origin driven with grade harness is refused: driven is a workload statement.", L, genDirB,
			ed.token(with(sessionV2(), "grade", "harness", "spawn", "spawn-v2-0001", "dir", genDirB)), errE("claims_invalid")),
		tokV("v2-origin-unknown", "An origin outside the major 2 vocabulary.", L, genDirA,
			ed.token(with(sessionV2(), "origin", "cron")), errE("claims_invalid")),
		tokV("v2-contract-version-unsupported", "Validly signed, cia is 3.", L, genDirA,
			ed.token(with(sessionV2(), "cia", 3)), errE("contract_version_unsupported")),
	}

	var m manifest
	m.ContractVersion = "2.0.0"
	m.Cia = 2
	m.Trust.Issuers = []trustedIssuer{{Iss: genIssuer}}
	m.JWKSFiles = map[string]string{genIssuer: "jwks.json"}
	m.Vectors = vs

	write := func(name string, v any) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vectorDirV2, name), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(vectorDirV2, 0o755); err != nil {
		t.Fatal(err)
	}
	write("jwks.json", map[string]any{"keys": []any{ed25519JWK("ed-1", edPub), p256JWK("es-1", &esPriv.PublicKey)}})
	write("manifest.json", m)
}
