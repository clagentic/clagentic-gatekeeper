//go:build unix

package attestation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testIss = "https://issuer.example"

func newTestProvider(t *testing.T, jwks string) *assertionProvider {
	t.Helper()
	p, err := NewAssertionProvider(AssertionConfig{Issuers: []AssertionIssuer{{Iss: testIss, JWKS: jwks}}})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*assertionProvider)
}

func TestAssertionResolvesRolesGradeAndActor(t *testing.T) {
	s := newSigner(t, "k1")
	p := newTestProvider(t, jwksFile(t, s))
	dir := deliverTo(t, "")
	token := s.sign(t, localClaims(testIss, dir, "example-builder", "workload", time.Now(), "builder", "reviewer"))
	if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := p.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Subject != "agent:example-builder" || id.Source != SourceAssertion || id.Grade != "workload" || id.Issuer != testIss {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "builder" || id.Roles[1] != "reviewer" {
		t.Errorf("roles = %v", id.Roles)
	}
}

func TestAssertionUnsetDeliveryDeclinesSoNextProviderMayAnswer(t *testing.T) {
	s := newSigner(t, "k1")
	p := newTestProvider(t, jwksFile(t, s))
	os.Unsetenv(IdentityDirEnv)
	if _, err := p.Resolve(context.Background()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("unset variable: got %v, want ErrNoIdentity", err)
	}
	t.Setenv(IdentityDirEnv, "")
	if _, err := p.Resolve(context.Background()); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("empty variable: got %v, want ErrNoIdentity", err)
	}
}

func TestAssertionFailuresAreHardErrorsAndNeverFallThrough(t *testing.T) {
	s := newSigner(t, "k1")
	other := newSigner(t, "k1")
	jwks := jwksFile(t, s)
	now := time.Now()

	cases := map[string]struct {
		token func(dir string) string
		code  AssertionCode
	}{
		"signed by a key absent from every configured key set": {
			token: func(dir string) string {
				return other.sign(t, localClaims(testIss, dir, "example-builder", "workload", now, "builder"))
			},
			code: CodeSignatureBad,
		},
		"unknown kid": {
			token: func(dir string) string {
				return newSigner(t, "rotated").sign(t, localClaims(testIss, dir, "example-builder", "workload", now, "builder"))
			},
			code: CodeKeyNotFound,
		},
		"untrusted issuer": {
			token: func(dir string) string {
				return s.sign(t, localClaims("https://elsewhere.example", dir, "example-builder", "workload", now, "builder"))
			},
			code: CodeIssuerUntrusted,
		},
		"expired": {
			token: func(dir string) string {
				c := localClaims(testIss, dir, "example-builder", "workload", now, "builder")
				c["iat"], c["exp"] = now.Unix()-7200, now.Unix()-3600
				return s.sign(t, c)
			},
			code: CodeExpired,
		},
		"not yet valid": {
			token: func(dir string) string {
				c := localClaims(testIss, dir, "example-builder", "workload", now, "builder")
				c["nbf"] = now.Unix() + 600
				return s.sign(t, c)
			},
			code: CodeNotYetValid,
		},
		"unsupported contract version": {
			token: func(dir string) string {
				c := localClaims(testIss, dir, "example-builder", "workload", now, "builder")
				c["cia"] = supportedContractMajor + 1
				return s.sign(t, c)
			},
			code: CodeVersionNew,
		},
		"bound to another directory": {
			token: func(string) string {
				return s.sign(t, localClaims(testIss, "/somewhere/else", "example-builder", "workload", now, "builder"))
			},
			code: CodeDirMismatch,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := deliverTo(t, "")
			if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(tc.token(dir)), 0o600); err != nil {
				t.Fatal(err)
			}
			// A configured provider that would happily answer sits behind the
			// assertion provider: it must never be consulted.
			t.Setenv("ASSERTION_TEST_FALLBACK", "would-be-fallback")
			fallback, err := NewConfiguredProvider(ConfiguredConfig{Type: ConfiguredEnv, Source: "ASSERTION_TEST_FALLBACK"})
			if err != nil {
				t.Fatal(err)
			}
			r := NewResolver(newTestProvider(t, jwks), fallback)

			_, err = r.Resolve(context.Background())
			var aerr *AssertionError
			if !errors.As(err, &aerr) || aerr.Code != tc.code {
				t.Fatalf("got %v, want assertion refusal %s", err, tc.code)
			}
		})
	}
}

func TestAssertionDeliveryRefusals(t *testing.T) {
	s := newSigner(t, "k1")
	p := newTestProvider(t, jwksFile(t, s))
	t.Run("directory missing", func(t *testing.T) {
		t.Setenv(IdentityDirEnv, filepath.Join(t.TempDir(), "absent"))
		_, err := p.Resolve(context.Background())
		var aerr *AssertionError
		if !errors.As(err, &aerr) || aerr.Code != CodeDirMissing {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("directory too open", func(t *testing.T) {
		dir := deliverTo(t, "x")
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := p.Resolve(context.Background())
		var aerr *AssertionError
		if !errors.As(err, &aerr) || aerr.Code != CodeDirUnsafe {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAssertionKeySetFromSocketAndHTTP(t *testing.T) {
	s := newSigner(t, "k1")
	mux := http.NewServeMux()
	mux.HandleFunc(wellKnownJWKS, func(w http.ResponseWriter, _ *http.Request) { w.Write(s.jwksJSON()) })

	t.Run("unix socket", func(t *testing.T) {
		// A socket path is limited to about 100 bytes, which t.TempDir often
		// exceeds, so the socket lives in a short-named directory.
		short, err := os.MkdirTemp("/tmp", "gk")
		if err != nil {
			t.Skipf("no short temporary directory for a unix socket: %v", err)
		}
		t.Cleanup(func() { os.RemoveAll(short) })
		sock := filepath.Join(short, "s.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: mux}
		go srv.Serve(l)
		defer srv.Close()

		iss := "unix://" + sock
		p, err := NewAssertionProvider(AssertionConfig{Issuers: []AssertionIssuer{{Iss: iss}}})
		if err != nil {
			t.Fatal(err)
		}
		dir := deliverTo(t, "")
		token := s.sign(t, localClaims(iss, dir, "example-builder", "workload", time.Now(), "builder"))
		if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		id, err := p.Resolve(context.Background())
		if err != nil || id.Subject != "agent:example-builder" {
			t.Fatalf("got %+v, %v", id, err)
		}
	})

	t.Run("loopback http with explicit locator", func(t *testing.T) {
		srv := httptest.NewServer(mux)
		defer srv.Close()
		p, err := NewAssertionProvider(AssertionConfig{Issuers: []AssertionIssuer{{Iss: testIss, JWKS: srv.URL + wellKnownJWKS}}})
		if err != nil {
			t.Fatal(err)
		}
		dir := deliverTo(t, "")
		token := s.sign(t, localClaims(testIss, dir, "example-builder", "workload", time.Now(), "builder"))
		if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Resolve(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unreachable key set refuses", func(t *testing.T) {
		p, err := NewAssertionProvider(AssertionConfig{Issuers: []AssertionIssuer{{Iss: testIss, JWKS: filepath.Join(t.TempDir(), "nope.json")}}})
		if err != nil {
			t.Fatal(err)
		}
		dir := deliverTo(t, "")
		token := s.sign(t, localClaims(testIss, dir, "example-builder", "workload", time.Now(), "builder"))
		if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = p.Resolve(context.Background())
		var aerr *AssertionError
		if !errors.As(err, &aerr) || aerr.Code != CodeJWKSUnavailable {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAssertionLocatorRules(t *testing.T) {
	good := map[string]string{
		"https://issuer.example":        "https://issuer.example/.well-known/jwks.json",
		"https://issuer.example/base/":  "https://issuer.example/base/.well-known/jwks.json",
		"http://127.0.0.1:8080":         "http://127.0.0.1:8080/.well-known/jwks.json",
		"file:///etc/clagentic/jwks.js": "/etc/clagentic/jwks.js",
		"unix:///run/x/identity.sock":   "/run/x/identity.sock",
	}
	for iss, want := range good {
		l, err := resolveLocator(iss, "")
		if err != nil || l.target != want {
			t.Errorf("resolveLocator(%q) = %+v, %v; want target %q", iss, l, err, want)
		}
	}
	for _, iss := range []string{"http://issuer.example", "urn:example:issuer", "https://"} {
		if _, err := resolveLocator(iss, ""); err == nil {
			t.Errorf("resolveLocator(%q) succeeded, want an error", iss)
		}
	}
	if _, err := resolveLocator("urn:example:issuer", "/etc/jwks.json"); err != nil {
		t.Errorf("explicit locator for a non-derivable iss: %v", err)
	}
}

func TestJWKSFileWritableByOthersIsRefused(t *testing.T) {
	s := newSigner(t, "k1")
	p := jwksFile(t, s)
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := readJWKSFile(p); err == nil {
		t.Fatal("a world-writable key set file was accepted")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(jwksFile(t, s), link); err != nil {
		t.Fatal(err)
	}
	if _, err := readJWKSFile(link); err == nil {
		t.Fatal("a symlinked key set file was accepted")
	}
}

func TestChainOrderAssertionFirstAndOSUserOptional(t *testing.T) {
	s := newSigner(t, "k1")
	asr, err := NewAssertionProvider(AssertionConfig{Issuers: []AssertionIssuer{{Iss: testIss, JWKS: jwksFile(t, s)}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHAIN_TEST_CONFIGURED", "configured-caller")
	cc := ConfiguredConfig{Type: ConfiguredEnv, Source: "CHAIN_TEST_CONFIGURED"}

	t.Run("no assertion delivered: configured answers", func(t *testing.T) {
		os.Unsetenv(IdentityDirEnv)
		r, err := NewChain(ChainConfig{Assertion: asr, Configured: cc})
		if err != nil {
			t.Fatal(err)
		}
		id, err := r.Resolve(context.Background())
		if err != nil || id.Subject != "configured-caller" || id.Source != "configured" {
			t.Fatalf("got %+v, %v", id, err)
		}
	})
	t.Run("assertion delivered: assertion answers", func(t *testing.T) {
		dir := deliverTo(t, "")
		token := s.sign(t, localClaims(testIss, dir, "example-builder", "workload", time.Now(), "builder"))
		if err := os.WriteFile(filepath.Join(dir, AssertionFile), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		r, _ := NewChain(ChainConfig{Assertion: asr, Configured: cc})
		id, err := r.Resolve(context.Background())
		if err != nil || id.Source != SourceAssertion {
			t.Fatalf("got %+v, %v", id, err)
		}
	})
	t.Run("OS user omitted", func(t *testing.T) {
		os.Unsetenv(IdentityDirEnv)
		r, _ := NewChain(ChainConfig{OmitOSUser: true})
		if _, err := r.Resolve(context.Background()); !errors.Is(err, ErrNoIdentity) {
			t.Fatalf("got %v, want ErrNoIdentity", err)
		}
	})
	t.Run("OS user kept by default and reported", func(t *testing.T) {
		os.Unsetenv(IdentityDirEnv)
		var warned []Identity
		r, _ := NewChain(ChainConfig{OSUserWarn: func(id Identity) { warned = append(warned, id) }})
		id, err := r.Resolve(context.Background())
		if err != nil || id.Source != "builtin" || len(warned) != 1 {
			t.Fatalf("got %+v, %v, warned %d", id, err, len(warned))
		}
	})
}
