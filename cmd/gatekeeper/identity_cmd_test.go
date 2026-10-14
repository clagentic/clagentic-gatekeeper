//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// identityDeployment lays out a key, a definitions directory and a socket
// directory short enough for a unix socket path.
func identityDeployment(t *testing.T) (dir, key, defs string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "gkcmd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	// The socket lives here and a unix socket path is limited to 108 bytes.
	if sock := filepath.Join(dir, "id.sock"); len(sock) >= 108 {
		t.Fatalf("socket path %q is %d bytes, over the 108-byte sun_path limit; point TMPDIR at a shorter directory", sock, len(sock))
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	defs = filepath.Join(dir, "defs")
	if err := os.Mkdir(defs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(defs, "example-builder.md"), []byte("---\nname: example-builder\nroles: [builder]\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, key, defs
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startServe(t *testing.T, cfgPath, sock string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- runServe([]string{"--config", cfgPath, "--socket", sock}) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("serve did not open its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		// runServe handles SIGTERM itself; the signal never reaches the test runner.
		if self, err := os.FindProcess(os.Getpid()); err == nil {
			_ = self.Signal(syscall.SIGTERM)
		}
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
}

func TestIdentityOnlyConfigServesAndMintReportsNotConfigured(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	jwks := filepath.Join(dir, "jwks.json")
	cfg := writeConfig(t, dir, "identity:\n  key_path: "+key+"\n  jwks_path: "+jwks+"\n  definitions_dir: "+defs+"\n  spawn_root: "+filepath.Join(dir, "spawn")+"\n")
	startServe(t, cfg, sock)

	c := identity.Client{Socket: sock}
	out, err := c.IssueSession(identity.SessionRequest{Definition: "example-builder"})
	if err != nil || len(out.Roles) != 1 || out.Roles[0] != "builder" {
		t.Fatalf("%+v %v", out, err)
	}
	if _, err := os.Stat(jwks); err != nil {
		t.Fatalf("jwks_path not written: %v", err)
	}

	err = runMint([]string{"--role", "builder", "--config", cfg})
	if err == nil || !strings.Contains(err.Error(), "minting is not configured") {
		t.Fatalf("mint on an identity-only config: %v", err)
	}
	err = runMintA2A([]string{"--audience", "peer", "--config", cfg})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("mint-a2a on an identity-only config: %v", err)
	}
}

// A config that names a GitHub API and a broker but no roles must stop mint
// before either is contacted. The doubles fail the test on any request.
func TestIdentityOnlyMintNeverContactsBrokerOrGitHub(t *testing.T) {
	var calls atomic.Int32
	double := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("unexpected request to the broker or GitHub double: %s %s", r.Method, r.URL.Path)
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer double.Close()

	dir, key, defs := identityDeployment(t)
	cfg := writeConfig(t, dir, `github:
  owner: example-org
  api_base: `+double.URL+`
broker:
  type: vault
  endpoint: `+double.URL+`
identity:
  key_path: `+key+`
  definitions_dir: `+defs+`
  spawn_root: `+filepath.Join(dir, "spawn")+`
`)
	err := runMint([]string{"--role", "builder", "--config", cfg})
	if err == nil || !strings.Contains(err.Error(), "minting is not configured") {
		t.Fatalf("mint on a config with no roles section: %v", err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("mint contacted the broker or GitHub %d time(s)", n)
	}
}

func TestCombinedConfigServesAndKeepsMintSections(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	cfg := writeConfig(t, dir, `github:
  owner: example-org
broker:
  type: env
roles:
  builder:
    app_id_path: a
    installation_id_path: b
    private_key_path: c
identity:
  key_path: `+key+`
  definitions_dir: `+defs+`
  spawn_root: `+filepath.Join(dir, "spawn")+`
`)
	startServe(t, cfg, sock)
	if _, err := (identity.Client{Socket: sock}).IssueSession(identity.SessionRequest{}); err != nil {
		t.Fatal(err)
	}
	// With roles present mint proceeds past the new guard and fails later, at
	// the broker, exactly as it did before the identity section existed.
	err := runMint([]string{"--role", "builder", "--config", cfg})
	if err != nil && strings.Contains(err.Error(), "minting is not configured") {
		t.Fatalf("combined config wrongly reported as not configured: %v", err)
	}
}

// serve publishes nothing until it owns the socket: a second serve that Listen
// refuses leaves the live server's key set byte-identical, or absent if absent.
func TestServeRefusedAtOccupiedSocketPublishesNoJWKS(t *testing.T) {
	for name, existing := range map[string][]byte{
		"existing key set is untouched": []byte(`{"keys":["live"]}`),
		"absent key set stays absent":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			dir, key, defs := identityDeployment(t)
			sock := filepath.Join(dir, "id.sock")
			jwks := filepath.Join(dir, "jwks.json")
			if existing != nil {
				if err := os.WriteFile(jwks, existing, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(sock, []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := writeConfig(t, dir, "identity:\n  key_path: "+key+"\n  jwks_path: "+jwks+"\n  definitions_dir: "+defs+"\n  spawn_root: "+filepath.Join(dir, "spawn")+"\n")
			err := runServe([]string{"--config", cfg, "--socket", sock})
			if err == nil || !strings.Contains(err.Error(), "already exists") {
				t.Fatalf("serve at an occupied socket: %v", err)
			}
			got, readErr := os.ReadFile(jwks)
			if existing == nil {
				if !os.IsNotExist(readErr) {
					t.Fatalf("jwks_path was created by a refused serve: %v", readErr)
				}
				return
			}
			if readErr != nil || string(got) != string(existing) {
				t.Fatalf("jwks_path changed by a refused serve: %q %v", got, readErr)
			}
		})
	}
}

// Serve verifies every trust root before it creates or publishes anything, and
// names the path it refused. Each case makes exactly one root writable by group.
func TestServeRefusesAtStartWhenATrustRootIsWritableByOthers(t *testing.T) {
	for _, root := range []string{"definitions_dir", "spawn_root", "socket directory", "jwks_path directory", "key_path directory"} {
		t.Run(root, func(t *testing.T) {
			dir, key, defs := identityDeployment(t)
			sock := filepath.Join(dir, "id.sock")
			jwks := filepath.Join(dir, "pub", "jwks.json")
			spawn := filepath.Join(dir, "spawn")
			keyDir := filepath.Join(dir, "keys")
			for _, d := range []string{filepath.Dir(jwks), spawn, keyDir} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(key, filepath.Join(keyDir, "key.pem")); err != nil {
				t.Fatal(err)
			}
			key = filepath.Join(keyDir, "key.pem")
			loose := map[string]string{
				"definitions_dir": defs, "spawn_root": spawn, "socket directory": dir,
				"jwks_path directory": filepath.Dir(jwks), "key_path directory": keyDir,
			}[root]
			if err := os.Chmod(loose, 0o775); err != nil {
				t.Fatal(err)
			}
			cfg := writeConfig(t, t.TempDir(), "identity:\n  key_path: "+key+"\n  jwks_path: "+jwks+"\n  definitions_dir: "+defs+"\n  spawn_root: "+spawn+"\n")
			err := runServe([]string{"--config", cfg, "--socket", sock})
			if err == nil || !strings.Contains(err.Error(), loose) {
				t.Fatalf("got %v, want a refusal naming %s", err, loose)
			}
			if _, statErr := os.Lstat(sock); statErr == nil {
				t.Fatalf("a refused start left a socket behind")
			}
			if _, statErr := os.Lstat(jwks); statErr == nil {
				t.Fatalf("a refused start published a key set")
			}
		})
	}
}

// Only the serving uid is served, so an operator uid that is not the serving uid
// leaves every peer, which is the serving uid, a workload and never a human.
func TestServeWithAnotherOperatorUidNeverIssuesHuman(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	other := os.Getuid() + 1
	cfg := writeConfig(t, dir, fmt.Sprintf("identity:\n  key_path: %s\n  definitions_dir: %s\n  spawn_root: %s\n  operator_uid: %d\n  operator_name: example-operator\n", key, defs, filepath.Join(dir, "spawn"), other))
	startServe(t, cfg, sock)
	out, err := identity.Client{Socket: sock}.IssueSession(identity.SessionRequest{})
	if err != nil || strings.HasPrefix(out.Subject, "human:") {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestServeRefusesAnIdentitySectionWithoutKeyPath(t *testing.T) {
	dir, _, defs := identityDeployment(t)
	cfg := writeConfig(t, dir, "identity:\n  definitions_dir: "+defs+"\n")
	err := runServe([]string{"--config", cfg, "--socket", filepath.Join(dir, "id.sock")})
	if err == nil || !strings.Contains(err.Error(), "identity.key_path") {
		t.Fatalf("got %v", err)
	}
}

func TestServeRefusesConfigWithoutIdentitySection(t *testing.T) {
	dir, _, _ := identityDeployment(t)
	cfg := writeConfig(t, dir, "github:\n  owner: example-org\n")
	err := runServe([]string{"--config", cfg, "--socket", filepath.Join(dir, "x.sock")})
	if err == nil || !strings.Contains(err.Error(), "identity section is not configured") {
		t.Fatalf("got %v", err)
	}
}
