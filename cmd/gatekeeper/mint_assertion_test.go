//go:build unix

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const assertionTestIss = "https://issuer.example"

// assertionFixture is a stub GitHub API, an env broker holding App credentials
// for the builder and merger roles, and a signing key whose public half is the
// configured issuer's key set.
type assertionFixture struct {
	t    *testing.T
	priv ed25519.PrivateKey
	jwks string
	srv  *httptest.Server
}

func newAssertionFixture(t *testing.T) *assertionFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(jwksPath, jwks, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(jwksPath, 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"token": "ghs_assertion_test", "expires_at": "2099-01-01T00:00:00Z"}) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)

	pem := generateTestPEM(t)
	for _, role := range []string{"BUILDER", "MERGER"} {
		t.Setenv("GK_ASSERT_"+role+"_APPID", "12345")
		t.Setenv("GK_ASSERT_"+role+"_INSTALLID", "67890")
		t.Setenv("GK_ASSERT_"+role+"_KEY", pem)
		t.Setenv("GK_ASSERT_"+role+"_SLUG", "slug-"+strings.ToLower(role))
	}
	return &assertionFixture{t: t, priv: priv, jwks: jwksPath, srv: srv}
}

func (f *assertionFixture) roleBlock(role, extra string) string {
	up := strings.ToUpper(role)
	return "  " + role + ":\n" +
		"    app_id_path: GK_ASSERT_" + up + "_APPID\n" +
		"    installation_id_path: GK_ASSERT_" + up + "_INSTALLID\n" +
		"    private_key_path: GK_ASSERT_" + up + "_KEY\n" +
		"    app_slug: slug-" + role + "\n" +
		"    app_slug_path: GK_ASSERT_" + up + "_SLUG\n" + extra
}

// config returns a config trusting the fixture's issuer; attestationBlock is
// the full attestation section.
func (f *assertionFixture) config(attestationBlock, builderExtra, mergerExtra string) string {
	return "github:\n  owner: testorg\n  api_base: " + f.srv.URL + "\nbroker:\n  type: env\n" +
		"roles:\n" + f.roleBlock("builder", builderExtra) + f.roleBlock("merger", mergerExtra) + attestationBlock
}

func (f *assertionFixture) assertionBlock() string {
	return "attestation:\n  allow_os_user: false\n  assertion:\n    issuers:\n      - iss: " + assertionTestIss + "\n        jwks: " + f.jwks + "\n"
}

// deliver writes a signed assertion into a fresh delivery directory and points
// CLAGENTIC_IDENTITY_DIR at it.
func (f *assertionFixture) deliver(grade string, roleNames ...string) {
	f.t.Helper()
	f.deliverAs("agent:example-builder", grade, roleNames...)
}

// deliverAs is deliver for a chosen act.sub, and returns the delivered token.
func (f *assertionFixture) deliverAs(actor, grade string, roleNames ...string) string {
	f.t.Helper()
	return f.deliverSigned(grade, roleNames, func(c map[string]any) { c["act"] = map[string]any{"sub": actor} })
}

// deliverWithoutAct delivers a workload assertion that has no act claim and
// whose sub is the given runtime identity, the shape the plain mint resolves
// from sub.
func (f *assertionFixture) deliverWithoutAct(sub string, roleNames ...string) string {
	f.t.Helper()
	return f.deliverSigned("workload", roleNames, func(c map[string]any) {
		delete(c, "act")
		c["sub"] = sub
	})
}

// deliverSigned signs a valid assertion, lets shape adjust its claims, writes
// it into a fresh delivery directory and returns the token.
func (f *assertionFixture) deliverSigned(grade string, roleNames []string, shape func(map[string]any)) string {
	f.t.Helper()
	dir := filepath.Join(f.t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": assertionTestIss, "sub": "human:example-user",
		"roles": roleNames, "grade": grade, "rt": map[string]any{"id": "example-runtime", "version": "1.0.0"},
		"sid": "sess-1", "origin": "agent", "dir": dir,
		"iat": now - 60, "exp": now + 3600, "jti": "jti-1", "cia": 1,
	}
	if grade == "harness" {
		claims["spawn"] = "spawn-1"
	}
	shape(claims)
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "EdDSA", "kid": "k1"}) + "." + enc(claims)
	token := input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.priv, []byte(input)))
	if err := os.WriteFile(filepath.Join(dir, "identity.jwt"), []byte(token+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.t.Setenv("CLAGENTIC_IDENTITY_DIR", dir)
	return token
}

func currentOSUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || u.Username == "" {
		t.Skipf("no OS user to resolve: %v", err)
	}
	return u.Username
}

// Acceptance: an assertion carrying the builder role from a trusted issuer
// mints builder, the audit line names subject and grade, and --json returns the
// identity.
func TestRunMintAssertionBuilderMintsAndAuditsSubjectAndGrade(t *testing.T) {
	f := newAssertionFixture(t)
	path := writeTempConfig(t, f.config(f.assertionBlock(), "", ""))
	f.deliver("harness", "builder")

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runMint([]string{"--role", "builder", "--config", path, "--json"}); err != nil {
				t.Fatalf("runMint: %v", err)
			}
		})
	})

	var got struct {
		Token    string `json:"token"`
		AppSlug  string `json:"app_slug"`
		Identity struct {
			Subject string `json:"subject"`
			Source  string `json:"source"`
			Grade   string `json:"grade"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v: %q", err, stdout)
	}
	if got.Token != "ghs_assertion_test" || got.AppSlug != "slug-builder" {
		t.Errorf("token/app_slug = %q/%q", got.Token, got.AppSlug)
	}
	if got.Identity.Subject != "agent:example-builder" || got.Identity.Source != "assertion" || got.Identity.Grade != "harness" {
		t.Errorf("identity = %+v", got.Identity)
	}
	if !strings.Contains(stderr, "mint audit:") || !strings.Contains(stderr, `subject="agent:example-builder"`) || !strings.Contains(stderr, `grade="harness"`) {
		t.Errorf("audit line missing subject and grade: %q", stderr)
	}
}

// Acceptance: the same assertion asked for merger refuses, naming merger and builder.
func TestRunMintAssertionOtherRoleRefusesNamingBoth(t *testing.T) {
	f := newAssertionFixture(t)
	path := writeTempConfig(t, f.config(f.assertionBlock(), "", ""))
	f.deliver("workload", "builder")

	var err error
	captureStderr(t, func() { err = runMint([]string{"--role", "merger", "--config", path}) })
	if err == nil || !strings.Contains(err.Error(), "merger") || !strings.Contains(err.Error(), "builder") {
		t.Fatalf("got %v, want a refusal naming merger and builder", err)
	}
}

// Acceptance: roles.merger.min_grade workload refuses a harness assertion.
func TestRunMintAssertionMinGradeRefuses(t *testing.T) {
	f := newAssertionFixture(t)
	path := writeTempConfig(t, f.config(f.assertionBlock(), "", "    min_grade: workload\n"))
	f.deliver("harness", "merger")

	var err error
	captureStderr(t, func() { err = runMint([]string{"--role", "merger", "--config", path}) })
	if err == nil || !strings.Contains(err.Error(), "workload") || !strings.Contains(err.Error(), "grade") {
		t.Fatalf("got %v, want a refusal naming the grade requirement", err)
	}
}

func TestRunMintRejectsUnknownMinGrade(t *testing.T) {
	f := newAssertionFixture(t)
	path := writeTempConfig(t, f.config(f.assertionBlock(), "    min_grade: admin\n", ""))
	err := runMint([]string{"--role", "builder", "--config", path})
	if err == nil || !strings.Contains(err.Error(), "min_grade") {
		t.Fatalf("got %v, want a min_grade config error", err)
	}
}

// Acceptance: an assertion signed by a key absent from every configured key set
// refuses, and the configured provider is never consulted even though it would
// have been entitled.
func TestRunMintAssertionUnknownKeyIsHardErrorNotFallback(t *testing.T) {
	f := newAssertionFixture(t)
	t.Setenv("GK_ASSERT_FALLBACK_IDENTITY", "fallback-caller")
	att := f.assertionBlock() + "  configured:\n    type: env\n    source: GK_ASSERT_FALLBACK_IDENTITY\n"
	path := writeTempConfig(t, f.config(att, "    entitled_identities:\n      - fallback-caller\n", ""))
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.priv = other // signs with a key the configured key set does not hold
	f.deliver("workload", "builder")

	var runErr error
	var stdout string
	captureStderr(t, func() {
		stdout = captureStdout(t, func() { runErr = runMint([]string{"--role", "builder", "--config", path}) })
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "signature_invalid") {
		t.Fatalf("got %v, want a signature_invalid refusal", runErr)
	}
	if stdout != "" {
		t.Errorf("a token was printed: %q", stdout)
	}
}

// Acceptance: with no assertion configured, the configured provider and
// entitled_identities mint exactly as before, even when the delivery variable
// happens to be set, and --json carries no identity member.
func TestRunMintWithoutAssertionConfigIsUnchanged(t *testing.T) {
	f := newAssertionFixture(t)
	t.Setenv("GK_ASSERT_CONFIGURED_IDENTITY", "configured-caller")
	att := "attestation:\n  configured:\n    type: env\n    source: GK_ASSERT_CONFIGURED_IDENTITY\n"
	path := writeTempConfig(t, f.config(att, "    entitled_identities:\n      - configured-caller\n", ""))
	f.deliver("workload", "merger") // present but not configured as a source

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runMint([]string{"--role", "builder", "--config", path, "--json"}); err != nil {
				t.Fatalf("runMint: %v", err)
			}
		})
	})
	var raw map[string]any
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil {
		t.Fatal(err)
	}
	if _, has := raw["identity"]; has {
		t.Errorf("--json gained an identity member without an assertion config: %s", stdout)
	}
	if len(raw) != 3 {
		t.Errorf("--json members = %v, want token, expires_at, app_slug", raw)
	}
	if stderr != "" {
		t.Errorf("stderr is not empty for a configured-provider mint: %q", stderr)
	}

	plain := captureStdout(t, func() {
		if err := runMint([]string{"--role", "builder", "--config", path}); err != nil {
			t.Fatal(err)
		}
	})
	if plain != "ghs_assertion_test\n" {
		t.Errorf("plain output = %q, want the bare token and a newline", plain)
	}
}

// With an assertion configured but none delivered, the configured provider
// still answers: an existing caller that has no assertion keeps working.
func TestRunMintAssertionConfiguredButNotDeliveredFallsToConfigured(t *testing.T) {
	f := newAssertionFixture(t)
	t.Setenv("GK_ASSERT_CONFIGURED_IDENTITY", "configured-caller")
	os.Unsetenv("CLAGENTIC_IDENTITY_DIR")
	att := f.assertionBlock() + "  configured:\n    type: env\n    source: GK_ASSERT_CONFIGURED_IDENTITY\n"
	path := writeTempConfig(t, f.config(att, "    entitled_identities:\n      - configured-caller\n", ""))

	var stdout string
	captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runMint([]string{"--role", "builder", "--config", path}); err != nil {
				t.Fatalf("runMint: %v", err)
			}
		})
	})
	if stdout != "ghs_assertion_test\n" {
		t.Errorf("output = %q", stdout)
	}
}

// The OS-user provider is off by default; only the deprecated opt-in
// allow_os_user: true appends it, and it says so on stderr when it answers.
func TestRunMintOSUserProviderOffByDefaultAndWarnsUnderOptIn(t *testing.T) {
	f := newAssertionFixture(t)
	os.Unsetenv("CLAGENTIC_IDENTITY_DIR")

	// Entitle whoever the OS says is running, so only the provider differs.
	who := currentOSUser(t)
	entitled := "    entitled_identities:\n      - " + who + "\n"

	for name, block := range map[string]string{
		"unset": "",
		"false": "attestation:\n  allow_os_user: false\n",
	} {
		path := writeTempConfig(t, f.config(block, entitled, ""))
		var err error
		captureStderr(t, func() { err = runMint([]string{"--role", "builder", "--config", path}) })
		if err == nil || !strings.Contains(err.Error(), "no identity available") {
			t.Fatalf("allow_os_user %s: got %v, want no identity", name, err)
		}
	}

	on := writeTempConfig(t, f.config("attestation:\n  allow_os_user: true\n", entitled, ""))
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if err := runMint([]string{"--role", "builder", "--config", on}); err != nil {
				t.Fatalf("runMint with allow_os_user true: %v", err)
			}
		})
	})
	if stdout != "ghs_assertion_test\n" || !strings.Contains(stderr, "deprecated OS-user provider") {
		t.Errorf("stdout %q stderr %q", stdout, stderr)
	}
}
