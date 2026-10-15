//go:build linux

package livetest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
)

// This file builds the deployments the mint caller shapes run against: a config
// the real binary loads, a broker it reads the App credentials from, and a stub
// of the two network services a mint talks to. Everything decided before the
// token exchange (identity, entitlement, grade, refusal) runs for real; only the
// git host's token endpoint and, for the OpenBao broker, the secret store are
// stood in for, because they need real credentials.

const (
	stubRoleID      = "example-role-id"
	stubSecretID    = "example-secret-id"
	stubClientToken = "example-client-token"

	// callerIdentity is the subject the sidecar file names.
	callerIdentity = "example-caller"
	sidecarSession = "s1"
	sidecarEnvVar  = "LIVETEST_SESSION"
)

// mintRoles are the roles every fixture binds, so one config serves every caller.
var mintRoles = []string{"builder", "reviewer", "merger", "security", "reader"}

// tokenStub answers the git host's installation-token endpoint and a minimal
// OpenBao: AppRole login and a KV v1 read.
type tokenStub struct {
	srv     *httptest.Server
	secrets map[string]string

	mu        sync.Mutex
	exchanges []string
	logins    int
	reads     int
}

func newTokenStub(secrets map[string]string) *tokenStub {
	s := &tokenStub{secrets: secrets}
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/", s.exchange)
	mux.HandleFunc("/v1/auth/approle/login", s.login)
	mux.HandleFunc("/v1/", s.read)
	s.srv = httptest.NewServer(mux)
	return s
}

func (s *tokenStub) exchange(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.exchanges = append(s.exchanges, string(body))
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"token": mintToken, "expires_at": "2099-01-01T00:00:00Z"})
}

func (s *tokenStub) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.RoleID != stubRoleID || in.SecretID != stubSecretID {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]string{"client_token": stubClientToken}})
}

func (s *tokenStub) read(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reads++
	s.mu.Unlock()
	if r.Header.Get("X-Vault-Token") != stubClientToken {
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	v, ok := s.secrets[strings.TrimPrefix(r.URL.Path, "/v1/")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"value": v}})
}

// exchangeBodies is every request body the token endpoint received.
func (s *tokenStub) exchangeBodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.exchanges...)
}

func (s *tokenStub) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// readCount is the number of secret reads attempted, whether or not they
// carried a valid login.
func (s *tokenStub) readCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

// appKeyPEM is the App private key every fixture of this run signs with.
func (e *Env) appKeyPEM() (string, error) {
	e.appKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			e.appKeyErr = err
			return
		}
		e.appKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	})
	return e.appKey, e.appKeyErr
}

type brokerKind string

const (
	brokerEnv     brokerKind = "env"
	brokerFile    brokerKind = "file"
	brokerOpenBao brokerKind = "openbao"
)

// fixtureSpec says what deployment to build.
type fixtureSpec struct {
	// assertion trusts this run's issuer for identity assertions.
	assertion bool
	// sidecar adds a session sidecar naming callerIdentity, with the variable
	// that selects it set in the fixture's environment.
	sidecar bool
	// osUser leaves the OS-user provider on (the default) and entitles the user
	// running the harness; otherwise it is switched off.
	osUser bool
	broker brokerKind
	// cwdConfig writes the config as config.yaml in a working directory of its
	// own, for a caller that passes no --config.
	cwdConfig bool
}

// callerFixture is a built deployment.
type callerFixture struct {
	cfgPath string
	// cwd is the working directory to run in, empty for the default.
	cwd  string
	env  []string
	stub *tokenStub
}

func (f *callerFixture) close() { f.stub.srv.Close() }

// currentUserName is the OS user the mint process will resolve to: it runs as
// the same user as the harness.
func currentUserName() (string, error) {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return "", skipf("the harness cannot tell which OS user it runs as")
	}
	return u.Username, nil
}

func (e *Env) newCallerFixture(spec fixtureSpec) (*callerFixture, error) {
	dir, err := os.MkdirTemp(e.Dir, "caller-")
	if err != nil {
		return nil, err
	}
	key, err := e.appKeyPEM()
	if err != nil {
		return nil, err
	}

	secrets := map[string]string{}
	// paths names where one role's App id, installation id, private key and slug
	// are read from, in the namespace of the chosen broker.
	var paths func(role string) (id, install, privateKey, slug string)
	var env []string
	switch spec.broker {
	case brokerFile:
		files := map[string]string{"app_id": "12345", "installation_id": "67890", "app_key": key, "app_slug": "example-app"}
		for name, v := range files {
			if err := writeOwnerOnly(filepath.Join(dir, name), []byte(v)); err != nil {
				return nil, err
			}
		}
		paths = func(string) (string, string, string, string) {
			return filepath.Join(dir, "app_id"), filepath.Join(dir, "installation_id"), filepath.Join(dir, "app_key"), filepath.Join(dir, "app_slug")
		}
	case brokerOpenBao:
		for _, role := range mintRoles {
			base := "secret/example/" + role + "/"
			secrets[base+"app_id"], secrets[base+"installation_id"], secrets[base+"app_key"], secrets[base+"app_slug"] = "12345", "67890", key, "example-app"
		}
		paths = func(role string) (string, string, string, string) {
			base := "secret/example/" + role + "/"
			return base + "app_id", base + "installation_id", base + "app_key", base + "app_slug"
		}
		env = append(env, "BROKER_ROLE_ID="+stubRoleID, "BROKER_SECRET_ID="+stubSecretID)
	default:
		env = append(env, "LIVETEST_APP_ID=12345", "LIVETEST_INSTALL_ID=67890", "LIVETEST_APP_KEY="+key, "LIVETEST_APP_SLUG=example-app")
		paths = func(string) (string, string, string, string) {
			return "LIVETEST_APP_ID", "LIVETEST_INSTALL_ID", "LIVETEST_APP_KEY", "LIVETEST_APP_SLUG"
		}
	}
	stub := newTokenStub(secrets)

	var entitled []string
	if spec.sidecar {
		entitled = append(entitled, callerIdentity)
	}
	if spec.osUser {
		name, err := currentUserName()
		if err != nil {
			stub.srv.Close()
			return nil, err
		}
		entitled = append(entitled, name)
	}

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "github:\n  owner: example\n  api_base: %s\nbroker:\n  type: %s\n", stub.srv.URL, brokerTypeName(spec.broker))
	if spec.broker == brokerOpenBao {
		fmt.Fprintf(&cfg, "  endpoint: %s\n  auth: approle\n", stub.srv.URL)
	}
	cfg.WriteString("roles:\n")
	for _, role := range mintRoles {
		id, install, privateKey, slug := paths(role)
		fmt.Fprintf(&cfg, "  %s:\n    app_id_path: %q\n    installation_id_path: %q\n    private_key_path: %q\n    app_slug: example-app\n    app_slug_path: %q\n", role, id, install, privateKey, slug)
		if len(entitled) > 0 {
			cfg.WriteString("    entitled_identities:\n")
			for _, id := range entitled {
				fmt.Fprintf(&cfg, "      - %q\n", id)
			}
		}
	}
	fmt.Fprintf(&cfg, "attestation:\n  allow_os_user: %v\n", spec.osUser)
	if spec.assertion {
		fmt.Fprintf(&cfg, "  assertion:\n    issuers:\n      - iss: unix://%s\n        jwks: %s\n", e.Sock, e.JWKSFile)
	}
	if spec.sidecar {
		sidecar := filepath.Join(dir, "sidecar")
		if err := os.Mkdir(sidecar, 0o700); err != nil {
			stub.srv.Close()
			return nil, err
		}
		if err := writeOwnerOnly(filepath.Join(sidecar, "id-"+sidecarSession), []byte(callerIdentity+"\n")); err != nil {
			stub.srv.Close()
			return nil, err
		}
		fmt.Fprintf(&cfg, "  sidecar:\n    dir: %q\n    file_prefix: id-\n    session_id_env: %s\n", sidecar, sidecarEnvVar)
		env = append(env, sidecarEnvVar+"="+sidecarSession)
	}

	f := &callerFixture{env: env, stub: stub}
	if spec.cwdConfig {
		f.cwd = filepath.Join(dir, "cwd")
		if err := os.Mkdir(f.cwd, 0o700); err != nil {
			stub.srv.Close()
			return nil, err
		}
		f.cfgPath = filepath.Join(f.cwd, "config.yaml")
	} else {
		f.cfgPath = filepath.Join(dir, "mint.yaml")
	}
	if err := writeOwnerOnly(f.cfgPath, []byte(cfg.String())); err != nil {
		stub.srv.Close()
		return nil, err
	}
	return f, nil
}

func brokerTypeName(k brokerKind) string {
	if k == "" {
		return string(brokerEnv)
	}
	return string(k)
}
