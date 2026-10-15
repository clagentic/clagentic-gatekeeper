//go:build unix

package attestation

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func signerJWK(s signer, mutate func(*jwk)) jwk {
	k := jwk{Kty: "OKP", Crv: "Ed25519", Kid: s.kid, Alg: "EdDSA", Use: "sig", X: base64.RawURLEncoding.EncodeToString(s.pub)}
	if mutate != nil {
		mutate(&k)
	}
	return k
}

func refusal(t *testing.T, err *AssertionError, want AssertionCode) {
	t.Helper()
	if err == nil || err.Code != want {
		t.Fatalf("got %v, want refusal %s", err, want)
	}
}

func TestRedirectPolicyKeepsSchemeHostAndLocatorRules(t *testing.T) {
	req := func(raw string) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Request{URL: u}
	}
	cases := []struct {
		name    string
		first   string
		target  string
		allowed bool
	}{
		{"https same host", "https://issuer.example/jwks", "https://issuer.example/other", true},
		{"https downgraded to http", "https://issuer.example/jwks", "http://issuer.example/jwks", false},
		{"https to another host", "https://issuer.example/jwks", "https://elsewhere.example/jwks", false},
		{"loopback http stays http", "http://127.0.0.1:8080/jwks", "http://127.0.0.1:8080/next", true},
		{"loopback http upgraded is still a scheme change", "http://127.0.0.1:8080/jwks", "https://127.0.0.1:8080/jwks", false},
		{"loopback http to a non-loopback host", "http://127.0.0.1:8080/jwks", "http://issuer.example/jwks", false},
		{"other scheme", "https://issuer.example/jwks", "file:///etc/jwks.json", false},
	}
	for _, c := range cases {
		err := jwksRedirectPolicy(req(c.target), []*http.Request{req(c.first)})
		if (err == nil) != c.allowed {
			t.Errorf("%s: got %v, allowed want %v", c.name, err, c.allowed)
		}
	}
	via := []*http.Request{req("https://a.example/"), req("https://a.example/"), req("https://a.example/")}
	if jwksRedirectPolicy(req("https://a.example/"), via) == nil {
		t.Error("a fourth hop was followed")
	}
}

func TestFetchJWKSFollowsSameHostRedirectAndRefusesOtherHost(t *testing.T) {
	s := newSigner(t, "k1")
	mux := http.NewServeMux()
	mux.HandleFunc("/doc", func(w http.ResponseWriter, _ *http.Request) { w.Write(s.jwksJSON()) })
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/doc", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	otherHost := "http://localhost:" + u.Port() + "/doc"
	mux.HandleFunc("/away", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, otherHost, http.StatusFound) })

	if _, err := fetchJWKS(context.Background(), locator{kind: locHTTP, target: srv.URL + "/same"}); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	if _, err := fetchJWKS(context.Background(), locator{kind: locHTTP, target: srv.URL + "/away"}); err == nil {
		t.Fatal("a redirect to another host was followed")
	}
}

func TestLifetimeCheckIsOverflowSafe(t *testing.T) {
	s := newSigner(t, "k1")
	keys := vectorKeys{testIss: {signerJWK(s, nil)}}
	now := time.Now()
	const half = int64(1) << 62
	cases := map[string]struct {
		iat, exp int64
		want     AssertionCode
	}{
		"difference wraps negative":   {-half, half, CodeClaimsInvalid},
		"exp at the top of int64":     {now.Unix() - 60, 1<<63 - 1, CodeClaimsInvalid},
		"negative iat":                {-1, now.Unix() + 60, CodeClaimsInvalid},
		"iat at the bottom of int64":  {-1 << 63, now.Unix() + 60, CodeClaimsInvalid},
		"real lifetime above the cap": {now.Unix() - 60, now.Unix() + maxAssertionLifetime, CodeTTLExceeded},
		"in range at exactly the cap": {now.Unix() - 60, now.Unix() - 60 + maxAssertionLifetime, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			claims := localClaims(testIss, "/d", "example-builder", "workload", now, "builder")
			claims["iat"], claims["exp"] = c.iat, c.exp
			_, aerr := verifyAssertion(context.Background(), s.sign(t, claims), keys, verifyParams{Now: now.Unix(), ObservedDir: "/d"})
			if c.want == "" {
				if aerr != nil {
					t.Fatalf("refused: %v", aerr)
				}
				return
			}
			refusal(t, aerr, c.want)
		})
	}
}

func TestKeySelectionNeedsASigningKeyOfTheHeaderAlg(t *testing.T) {
	s := newSigner(t, "k1")
	now := time.Now()
	token := s.sign(t, localClaims(testIss, "/d", "example-builder", "workload", now, "builder"))
	verify := func(keys ...jwk) *AssertionError {
		_, aerr := verifyAssertion(context.Background(), token, vectorKeys{testIss: keys}, verifyParams{Now: now.Unix(), ObservedDir: "/d"})
		return aerr
	}

	if aerr := verify(signerJWK(s, nil)); aerr != nil {
		t.Fatalf("a valid signing key was refused: %v", aerr)
	}
	if aerr := verify(signerJWK(s, func(k *jwk) { k.Use, k.Alg = "", "" })); aerr != nil {
		t.Fatalf("a key without use and alg was refused: %v", aerr)
	}
	refusal(t, verify(signerJWK(s, func(k *jwk) { k.Use = "enc" })), CodeKeyNotFound)
	refusal(t, verify(signerJWK(s, func(k *jwk) { k.Alg = "ES256" })), CodeKeyNotFound)
	refusal(t, verify(signerJWK(s, func(k *jwk) { k.Kty, k.Crv = "EC", "P-256" })), CodeSignatureBad)
	refusal(t, verify(signerJWK(s, func(k *jwk) { k.Crv = "Ed448" })), CodeSignatureBad)

	// A rotation can publish two keys under one kid; an ineligible one never
	// shadows the signing key.
	wrong := signerJWK(s, func(k *jwk) { k.Use = "enc" })
	if aerr := verify(wrong, signerJWK(s, nil)); aerr != nil {
		t.Fatalf("an encryption key shadowed the signing key: %v", aerr)
	}
}

func TestDeliveryReadsTheValidatedDirectoryEvenIfItsPathIsReplaced(t *testing.T) {
	good := deliverTo(t, "")
	if err := os.WriteFile(filepath.Join(good, AssertionFile), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := good + ".moved"
	afterDirValidated = func() {
		if err := os.Rename(good, moved); err != nil {
			t.Error(err)
			return
		}
		if err := os.Mkdir(good, 0o700); err != nil {
			t.Error(err)
			return
		}
		if err := os.WriteFile(filepath.Join(good, AssertionFile), []byte("planted"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterDirValidated = nil })

	data, aerr := readDelivery(good)
	if string(data) == "planted" {
		t.Fatal("the file was read from the replacement directory")
	}
	if runtime.GOOS == "linux" && (aerr != nil || string(data) != "original") {
		t.Fatalf("got %q, %v; want the validated directory's file", data, aerr)
	}
}

func TestDeliveryDirectoryModeIsExactly0700(t *testing.T) {
	for _, mode := range []os.FileMode{0o500, 0o600, 0o750, 0o701, 0o755} {
		dir := deliverTo(t, "x")
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		_, aerr := readDelivery(dir)
		refusal(t, aerr, CodeDirUnsafe)
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dir := deliverTo(t, "x")
	if data, aerr := readDelivery(dir); aerr != nil || string(data) != "x" {
		t.Fatalf("a 0700 directory: %q, %v", data, aerr)
	}
}

func TestDeliveryRefusesSymlinkedDirectoryAndFile(t *testing.T) {
	real := deliverTo(t, "x")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	_, aerr := readDelivery(link)
	refusal(t, aerr, CodeDirUnsafe)

	if err := os.Remove(filepath.Join(real, AssertionFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(real, "elsewhere"), filepath.Join(real, AssertionFile)); err != nil {
		t.Fatal(err)
	}
	_, aerr = readDelivery(real)
	refusal(t, aerr, CodeFileSymlink)
}
