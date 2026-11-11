package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	recAppIDEnv   = "GATEKEEPER_TEST_REC_APPID"
	recInstallEnv = "GATEKEEPER_TEST_REC_INSTALLID"
	recKeyEnv     = "GATEKEEPER_TEST_REC_KEY"
	recSlugEnv    = "GATEKEEPER_TEST_REC_SLUG"
	recIdentEnv   = "GATEKEEPER_TEST_REC_IDENTITY"
	recToken      = "ghs_planted_record_token"
	recIdentity   = "record-test-caller"
)

// fakeGitHub answers access_tokens with the configured status and records the
// bearer JWT it was sent.
type fakeGitHub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	body   string
	jwts   []string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{status: http.StatusCreated, body: `{"token":"` + recToken + `","expires_at":"2099-01-01T00:00:00Z",` +
		`"permissions":{"contents":"write","metadata":"read"},"repository_selection":"selected"}`}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.jwts = append(g.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		w.Header().Set("X-GitHub-Request-Id", "REQ-FAKE-1")
		w.WriteHeader(g.status)
		io.WriteString(w, g.body) //nolint:errcheck
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitHub) set(status int, body string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.status, g.body = status, body
}

// recordConfig sets the env broker values and returns a config naming sinkLine
// (empty for no sink key) and the fake GitHub; it returns the PEM planted as
// the broker's private key.
func recordConfig(t *testing.T, g *fakeGitHub, sinkLine string) (cfgPath, pemKey string) {
	t.Helper()
	pemKey = generateTestPEM(t)
	t.Setenv(recAppIDEnv, "12345")
	t.Setenv(recInstallEnv, "67890")
	t.Setenv(recKeyEnv, pemKey)
	t.Setenv(recSlugEnv, "record-app")
	t.Setenv(recIdentEnv, recIdentity)
	return writeTempConfig(t, sinkLine+`
github:
  owner: testorg
  api_base: `+g.srv.URL+`
broker:
  type: env
attestation:
  configured:
    type: env
    source: `+recIdentEnv+`
roles:
  builder:
    app_id_path: `+recAppIDEnv+`
    installation_id_path: `+recInstallEnv+`
    private_key_path: `+recKeyEnv+`
    entitled_identities:
      - `+recIdentity+`
    app_slug: record-app
    app_slug_path: `+recSlugEnv+`
`), pemKey
}

type mintRun struct {
	stdout, stderr string
	err            error
}

func runMintCaptured(t *testing.T, args ...string) mintRun {
	t.Helper()
	var res mintRun
	res.stderr = captureStderr(t, func() {
		res.stdout = captureStdout(t, func() { res.err = runMint(args) })
	})
	return res
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A mint with the sink on writes one record per mint, success and refusal, and
// nothing in the file carries the token, a JWT, the PEM or the broker secret.
func TestRunMint_RecordHoldsNoSecretMaterial(t *testing.T) {
	g := newFakeGitHub(t)
	sink := filepath.Join(t.TempDir(), "mints.jsonl")
	cfg, pemKey := recordConfig(t, g, "mint_record_path: "+sink+"\n")

	if res := runMintCaptured(t, "--role", "builder", "--repo", "testorg/widgets", "--config", cfg); res.err != nil {
		t.Fatalf("success mint: %v", res.err)
	}
	g.set(http.StatusUnprocessableEntity, `{"message":"The repository widgets does not exist or is not accessible to the parent installation"}`)
	if res := runMintCaptured(t, "--role", "builder", "--repo", "testorg/widgets", "--config", cfg); res.err == nil {
		t.Fatal("want the 422 mint to fail")
	}

	data, err := os.ReadFile(sink)
	if err != nil {
		t.Fatalf("read sink: %v", err)
	}
	file := string(data)
	lines := strings.Split(strings.TrimSuffix(file, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 records, got %d: %q", len(lines), file)
	}
	for _, want := range []string{
		`"outcome":"ok"`, `"installation_id":"67890"`, `"permissions":{"contents":"write","metadata":"read"}`,
		`"repository_selection":"selected"`, `"request_id":"REQ-FAKE-1"`, `"status":201`, `"token_fingerprint":"`,
		`"app_slug":"record-app"`, `"requested_repositories":["widgets"]`,
	} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("ok record lacks %s: %s", want, lines[0])
		}
	}
	for _, want := range []string{`"outcome":"error"`, `"failure_category":"repo_not_in_installation"`, `"status":422`, `"request_id":"REQ-FAKE-1"`} {
		if !strings.Contains(lines[1], want) {
			t.Errorf("error record lacks %s: %s", want, lines[1])
		}
	}

	secrets := []string{recToken, "BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY"}
	for _, l := range strings.Split(pemKey, "\n") {
		if len(l) > 20 {
			secrets = append(secrets, l)
		}
	}
	g.mu.Lock()
	for _, j := range g.jwts {
		if j == "" {
			t.Fatal("the fake GitHub saw no JWT; the scan below would be vacuous")
		}
		secrets = append(secrets, j)
	}
	g.mu.Unlock()
	for _, s := range secrets {
		if strings.Contains(file, s) {
			t.Errorf("record file contains secret material %q", s)
		}
	}
	if info, err := os.Stat(sink); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("sink mode = %v (%v), want 0600", info.Mode().Perm(), err)
	}
}

// With no sink key nothing is written, and the sink being on changes neither
// stdout, stderr nor the result of the mint.
func TestRunMint_SinkOffIsByteIdentical(t *testing.T) {
	g := newFakeGitHub(t)
	offCfg, _ := recordConfig(t, g, "")
	sink := filepath.Join(t.TempDir(), "mints.jsonl")
	onCfg, _ := recordConfig(t, g, "mint_record_path: "+sink+"\n")

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "success", status: http.StatusCreated, body: g.body},
		{name: "refusal", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.set(tc.status, tc.body)
			off := runMintCaptured(t, "--role", "builder", "--config", offCfg)
			if _, err := os.Stat(sink); err == nil {
				t.Fatal("sink file exists before any sink-on run")
			}
			on := runMintCaptured(t, "--role", "builder", "--config", onCfg)
			if off.stdout != on.stdout || off.stderr != on.stderr || errText(off.err) != errText(on.err) {
				t.Errorf("sink changed the mint: off=%+v on=%+v", off, on)
			}
			if err := os.Remove(sink); err != nil {
				t.Fatalf("sink-on run wrote no record: %v", err)
			}
		})
	}
}

// A sink that cannot be written leaves the mint's result and exit status alone
// and names the failure on stderr.
func TestRunMint_UnwritableSinkDoesNotChangeTheMint(t *testing.T) {
	g := newFakeGitHub(t)
	offCfg, _ := recordConfig(t, g, "")
	badSink := filepath.Join(t.TempDir(), "no-such-dir", "mints.jsonl")
	badCfg, _ := recordConfig(t, g, "mint_record_path: "+badSink+"\n")

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "success", status: http.StatusCreated, body: g.body},
		{name: "refusal", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.set(tc.status, tc.body)
			off := runMintCaptured(t, "--role", "builder", "--config", offCfg)
			bad := runMintCaptured(t, "--role", "builder", "--config", badCfg)
			if off.stdout != bad.stdout || errText(off.err) != errText(bad.err) {
				t.Errorf("unwritable sink changed the mint: off=%+v bad=%+v", off, bad)
			}
			if !strings.Contains(bad.stderr, "mint record not written") || !strings.Contains(bad.stderr, badSink) {
				t.Errorf("stderr = %q, want the sink failure naming %s", bad.stderr, badSink)
			}
			if !strings.HasPrefix(bad.stderr, off.stderr) {
				t.Errorf("stderr before the sink line differs: off=%q bad=%q", off.stderr, bad.stderr)
			}
		})
	}
}
