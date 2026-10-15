//go:build unix

package attestation

import (
	"context"
	"testing"
	"time"
)

func TestDrivenOriginVerification(t *testing.T) {
	s := newSigner(t, "k1")
	keys, err := parseJWKS(s.jwksJSON())
	if err != nil {
		t.Fatal(err)
	}
	src := vectorKeys{testIss: keys}
	now := time.Now()
	const dir = "/run/example/identity/spawn/a1"

	driven := func() map[string]any {
		c := localClaims(testIss, dir, "example-builder", "workload", now, "builder")
		c["sub"], c["origin"], c["cia"] = "runtime:example-runtime", "driven", 2
		return c
	}
	cases := []struct {
		name   string
		mutate func(map[string]any)
		max    int64
		code   AssertionCode
	}{
		{"accepted under major 2", func(map[string]any) {}, 0, ""},
		{"cia 1 cannot carry it", func(c map[string]any) { c["cia"] = 1 }, 0, CodeClaimsInvalid},
		{"a major 1 verifier refuses the whole token by version", func(map[string]any) {}, 1, CodeVersionNew},
		{"a human sub is refused", func(c map[string]any) { c["sub"] = "human:example-user" }, 0, CodeClaimsInvalid},
		{"a human act.sub is refused", func(c map[string]any) { c["act"] = map[string]any{"sub": "human:example-user"} }, 0, CodeClaimsInvalid},
		{"a human act.act.sub is refused", func(c map[string]any) {
			c["act"] = map[string]any{"sub": "agent:example-builder", "act": map[string]any{"sub": "human:example-user"}}
		}, 0, CodeClaimsInvalid},
		{"a human act.act.act.sub is refused", func(c map[string]any) {
			c["act"] = map[string]any{"sub": "agent:example-builder", "act": map[string]any{"sub": "runtime:example-runtime", "act": map[string]any{"sub": "human:example-user"}}}
		}, 0, CodeClaimsInvalid},
		{"an agent act chain is accepted", func(c map[string]any) {
			c["act"] = map[string]any{"sub": "agent:example-builder", "act": map[string]any{"sub": "runtime:example-runtime"}}
		}, 0, ""},
		{"harness grade is refused", func(c map[string]any) { c["grade"], c["spawn"] = "harness", "spawn-1" }, 0, CodeClaimsInvalid},
		{"an unknown origin is still refused", func(c map[string]any) { c["origin"] = "cron" }, 0, CodeClaimsInvalid},
		{"cia 3 is unsupported", func(c map[string]any) { c["cia"] = 3 }, 0, CodeVersionNew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := driven()
			tc.mutate(c)
			p := verifyParams{Now: now.Unix(), ObservedDir: dir, MaxMajor: tc.max}
			got, aerr := verifyAssertion(context.Background(), s.sign(t, c), src, p)
			switch {
			case tc.code == "" && aerr != nil:
				t.Fatalf("refused: %v", aerr)
			case tc.code == "" && got.Grade != "workload":
				t.Fatalf("grade %q", got.Grade)
			case tc.code != "" && (aerr == nil || aerr.Code != tc.code):
				t.Fatalf("got %v, want %s", aerr, tc.code)
			}
		})
	}
}
