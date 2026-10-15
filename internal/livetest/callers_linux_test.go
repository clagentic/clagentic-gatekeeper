//go:build linux

package livetest

import (
	"slices"
	"strings"
	"testing"
)

func TestCallerArgvKeepsEachCallersOwnForm(t *testing.T) {
	cases := []struct {
		form callerForm
		want string
	}{
		{callerForm{role: "builder"}, "mint --role builder --config C"},
		{callerForm{role: "builder", json: true}, "mint --role builder --config C --json"},
		{callerForm{role: "reader", noConfig: true}, "mint --role reader"},
		{callerForm{role: "security", repo: callerRepo}, "mint --role security --repo example/example-repo --config C"},
	}
	for _, c := range cases {
		if got := strings.Join(c.form.argv("C"), " "); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

func TestEveryCallerFormNamesAKnownRoleAndDefinition(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range callerForms() {
		if seen[f.id] {
			t.Errorf("duplicate form id %q", f.id)
		}
		seen[f.id] = true
		if f.refused {
			continue
		}
		if !slices.Contains(mintRoles, f.role) {
			t.Errorf("%s: role %q is not bound by the fixture", f.id, f.role)
		}
	}
	for _, role := range mintRoles {
		if def := definitionFor(role); def != defBuilder && def != defLead && def != defOps {
			t.Errorf("role %q maps to unknown definition %q", role, def)
		}
	}
}

func TestMintedChecksRefuseDriftedOutput(t *testing.T) {
	bare := callerForm{role: "builder"}
	structured := callerForm{role: "builder", json: true}
	audit := `mint audit: subject="agent:` + defBuilder + `" source="assertion" grade="workload" issuer="i" role="builder" permitted=true reason=""` + "\n"
	okJSON := `{"token":"` + mintToken + `","expires_at":"2099-01-01T00:00:00Z","app_slug":"example-app"}` + "\n"
	withID := `{"token":"` + mintToken + `","expires_at":"2099-01-01T00:00:00Z","app_slug":"example-app","identity":{"subject":"agent:` + defBuilder + `","source":"assertion","grade":"workload"}}` + "\n"

	good := []struct {
		name      string
		form      callerForm
		res       procResult
		assertion bool
	}{
		{"bare", bare, procResult{Stdout: mintToken + "\n"}, false},
		{"bare with assertion", bare, procResult{Stdout: mintToken + "\n", Stderr: audit}, true},
		{"json", structured, procResult{Stdout: okJSON}, false},
		{"json with assertion", structured, procResult{Stdout: withID, Stderr: audit}, true},
	}
	for _, c := range good {
		if err := checkMinted(c.form, c.res, c.assertion, defBuilder); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}

	bad := []struct {
		name      string
		form      callerForm
		res       procResult
		assertion bool
	}{
		{"bare output with extra line", bare, procResult{Stdout: mintToken + "\nextra\n"}, false},
		{"stderr noise with no assertion configured", bare, procResult{Stdout: mintToken + "\n", Stderr: "warning\n"}, false},
		{"identity printed with no assertion configured", structured, procResult{Stdout: withID}, false},
		{"assertion configured but not audited", bare, procResult{Stdout: mintToken + "\n"}, true},
		{"assertion configured, identity missing from json", structured, procResult{Stdout: okJSON, Stderr: audit}, true},
		{"non-zero exit", bare, procResult{Code: 1, Stderr: "boom"}, false},
	}
	for _, c := range bad {
		if err := checkMinted(c.form, c.res, c.assertion, defBuilder); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestRefusedChecksRequireARefusalThatReachedNothing(t *testing.T) {
	stub := newTokenStub(nil)
	defer stub.srv.Close()
	fx := &callerFixture{stub: stub}
	if err := checkRefused(procResult{Code: 1, Stderr: "no such role"}, fx, ""); err != nil {
		t.Fatalf("a refusal was rejected: %v", err)
	}
	for name, res := range map[string]procResult{
		"exit zero":     {Stderr: "x"},
		"token printed": {Code: 1, Stdout: "t", Stderr: "x"},
		"no reason":     {Code: 1},
	} {
		if checkRefused(res, fx, "") == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if checkRefused(procResult{Code: 1, Stderr: "other"}, fx, "attested identity") == nil {
		t.Error("a refusal for another reason was accepted")
	}
	stub.mu.Lock()
	stub.exchanges = append(stub.exchanges, "{}")
	stub.mu.Unlock()
	if checkRefused(procResult{Code: 1, Stderr: "x"}, fx, "") == nil {
		t.Error("a refusal after a token exchange was accepted")
	}
	stub.mu.Lock()
	stub.exchanges = nil
	stub.reads++
	stub.mu.Unlock()
	if checkRefused(procResult{Code: 1, Stderr: "x"}, fx, "") == nil {
		t.Error("a refusal after a credential read was accepted")
	}
}
