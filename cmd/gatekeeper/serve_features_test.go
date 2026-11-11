//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
	"github.com/clagentic/clagentic-gatekeeper/internal/livetest"
)

// deploymentConfig is an identity-only config for a deployment laid out by
// identityDeployment, with extra identity lines appended.
func deploymentConfig(key, defs, spawn, extra string) string {
	return "identity:\n  key_path: " + key + "\n  definitions_dir: " + defs + "\n  spawn_root: " + spawn + "\n" + extra
}

// Every client command resolves the socket by one order: the flag, then
// identity.socket_path through --config, then the built-in default.
func TestSocketResolutionOrderIsOneForEveryClient(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	spawn := filepath.Join(dir, "spawn")
	cfg := writeConfig(t, dir, deploymentConfig(key, defs, spawn, "  socket_path: "+sock+"\n"))
	// serve takes its socket from the config alone: no --socket.
	startServeWith(t, []string{"--config", cfg}, sock, io.Discard)

	dead := filepath.Join(dir, "nobody.sock")
	deadCfg := writeConfig(t, t.TempDir(), deploymentConfig(key, defs, spawn, "  socket_path: "+dead+"\n"))

	t.Run("config names the socket, no flag", func(t *testing.T) {
		var out bytes.Buffer
		if err := issueSession([]string{"--config", cfg, "--definition", "example-builder", "--json"}, &out); err != nil {
			t.Fatal(err)
		}
		var issued identity.Issued
		if err := json.Unmarshal(out.Bytes(), &issued); err != nil || issued.Actor != "agent:example-builder" {
			t.Fatalf("%q %v", out.String(), err)
		}
	})
	t.Run("the flag wins over the config", func(t *testing.T) {
		var out bytes.Buffer
		if err := issueSession([]string{"--config", deadCfg, "--socket", sock, "--definition", "example-builder", "--json"}, &out); err != nil {
			t.Fatalf("the flag did not win over a config naming %s: %v", dead, err)
		}
	})
	t.Run("the config socket is the one used, not another", func(t *testing.T) {
		err := issueSession([]string{"--config", deadCfg, "--definition", "example-builder"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), dead) {
			t.Fatalf("got %v, want a failure to reach %s", err, dead)
		}
	})
	t.Run("issue-child reads the config too", func(t *testing.T) {
		parent := filepath.Join(dir, "parent.jwt")
		if err := os.WriteFile(parent, []byte("not-a-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args := func(cfgPath string) []string {
			return []string{"--config", cfgPath, "--parent-token-file", parent, "--agent-type", "example-builder", "--agent-id", "a1"}
		}
		if err := issueChild(args(deadCfg), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), dead) {
			t.Fatalf("got %v, want a failure to reach %s", err, dead)
		}
		// Against the live socket the server answers, which shows the config's
		// socket was the one dialled.
		if err := issueChild(args(cfg), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), identity.CodeParentInvalid) {
			t.Fatalf("got %v, want the server's parent_invalid refusal", err)
		}
	})
	t.Run("neither names it: the documented default", func(t *testing.T) {
		got, err := resolveSocket("", "", identity.DefaultSocketPath)
		if err != nil || got != identity.DefaultSocketPath {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("a client that must not guess has no default", func(t *testing.T) {
		if _, err := explicitSocket("", ""); err == nil {
			t.Fatal("explicitSocket named a socket nobody gave it")
		}
	})
}

// A socket path that is not absolute, or is too long for a unix socket, is
// refused by every command that takes one, naming the input, by the same check
// identity.socket_path gets at config load.
func TestEverySocketInputRefusesARelativeOrOverlongPath(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	cfg := writeConfig(t, dir, deploymentConfig(key, defs, filepath.Join(dir, "spawn"), ""))
	settings := filepath.Join(dir, "settings.json")
	long := "/" + strings.Repeat("l", config.MaxSocketPathBytes)
	for _, bad := range []struct{ name, path, want string }{
		{"relative", "rel.sock", "absolute"},
		{"overlong", long, "limit"},
	} {
		for name, run := range map[string]func() error{
			"serve --socket":         func() error { return serve([]string{"--config", cfg, "--socket", bad.path}, io.Discard) },
			"issue-session --socket": func() error { return issueSession([]string{"--socket", bad.path}, io.Discard) },
			"issue-child --socket": func() error {
				return issueChild([]string{"--socket", bad.path, "--parent-token-file", cfg, "--agent-type", "a", "--agent-id", "b"}, io.Discard, io.Discard)
			},
			"hook socket flag":       func() error { _, err := explicitSocket(bad.path, ""); return err },
			"hook process --socket":  func() error { return runHookProcess([]string{"--socket", bad.path}, io.Discard) },
			"hooks-install --socket": func() error { return runHooksInstall([]string{"--runtime", "claude-code", "--settings", settings, "--socket", bad.path}, io.Discard) },
			"self-check --socket":    func() error { return runSelfCheck([]string{"--socket", bad.path}, io.Discard) },
		} {
			t.Run(bad.name+" "+name, func(t *testing.T) {
				err := run()
				if err == nil || !strings.Contains(err.Error(), bad.path) || !strings.Contains(err.Error(), bad.want) {
					t.Fatalf("got %v, want a refusal naming %q that says %q", err, bad.path, bad.want)
				}
			})
		}
	}
}

// self-check reports the socket reachable and the key set fresh only while the
// served bytes equal the file's bytes exactly; one differing byte, or a byte
// that changes no meaning, is stale and names where.
func TestSelfCheckComparesServedAndFileBytesExactly(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	jwks := filepath.Join(dir, "jwks.json")
	cfg := writeConfig(t, dir, deploymentConfig(key, defs, filepath.Join(dir, "spawn"), "  jwks_path: "+jwks+"\n"))
	startServe(t, cfg, sock)
	args := []string{"--config", cfg, "--socket", sock}

	served, err := identity.Client{Socket: sock}.FetchJWKSBytes()
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(served, onDisk) {
		t.Fatalf("serve published bytes that differ from what it serves:\nserved %q\nfile   %q", served, onDisk)
	}

	var out bytes.Buffer
	if err := runSelfCheck(args, &out); err != nil {
		t.Fatalf("fresh: %v\n%s", err, out.String())
	}
	for _, want := range []string{"socket: reachable (" + sock + ")", "jwks: fresh (" + strconv.Itoa(len(served)) + " bytes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("fresh output %q lacks %q", out.String(), want)
		}
	}

	// One byte of the file differs, at a known offset, with the length unchanged.
	at := bytes.Index(onDisk, []byte(`"x"`)) + len(`"x": "`)
	flipped := append([]byte(nil), onDisk...)
	if flipped[at] == 'A' {
		flipped[at] = 'B'
	} else {
		flipped[at] = 'A'
	}
	if err := os.WriteFile(jwks, flipped, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSelfCheck(args, &out); err == nil {
		t.Fatalf("a key set differing in one byte was reported fresh:\n%s", out.String())
	}
	if want := "jwks: stale"; !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "differ at byte "+strconv.Itoa(at)) {
		t.Errorf("stale output %q must say %q and the offset %d", out.String(), want, at)
	}
	if strings.Contains(out.String(), "jwks: fresh") {
		t.Errorf("both verdicts printed: %q", out.String())
	}

	// A trailing newline changes no JSON meaning; there is no semantic comparison.
	if err := os.WriteFile(jwks, append(append([]byte(nil), onDisk...), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSelfCheck(args, &out); err == nil || !strings.Contains(out.String(), "jwks: stale") {
		t.Fatalf("a semantically equal file was reported fresh: %v %q", err, out.String())
	}

	// Restored, it is fresh again, which shows the stale verdicts were the bytes.
	if err := os.WriteFile(jwks, onDisk, 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSelfCheck(args, &out); err != nil {
		t.Fatalf("restored file: %v %q", err, out.String())
	}

	// A missing file is stale, not a pass.
	if err := os.Remove(jwks); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runSelfCheck(args, &out); err == nil || !strings.Contains(out.String(), "jwks: stale: cannot read") {
		t.Fatalf("a missing key set file: %v %q", err, out.String())
	}
}

func TestSelfCheckReportsAnUnreachableSocketAndANamelessKeySet(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	var out bytes.Buffer
	err := runSelfCheck([]string{"--socket", filepath.Join(dir, "nobody.sock")}, &out)
	if err == nil || !strings.Contains(out.String(), "socket: unreachable") {
		t.Fatalf("%v %q", err, out.String())
	}

	sock := filepath.Join(dir, "id.sock")
	cfg := writeConfig(t, dir, deploymentConfig(key, defs, filepath.Join(dir, "spawn"), ""))
	startServe(t, cfg, sock)
	out.Reset()
	if err := runSelfCheck([]string{"--config", cfg, "--socket", sock}, &out); err != nil {
		t.Fatalf("%v %q", err, out.String())
	}
	if !strings.Contains(out.String(), "socket: reachable") || !strings.Contains(out.String(), "jwks: not checked") {
		t.Fatalf("with no key set file named: %q", out.String())
	}
}

// After a rotation, with the previous key moved to retired_keys, a token the
// previous key signed verifies against the published key set until its exp and
// not after, checked by a relying party that shares no code with the issuer.
func TestRotationKeepsThePreviousKeyVerifyingUntilItsExp(t *testing.T) {
	dir, keyA, defs := identityDeployment(t)
	spawn := filepath.Join(dir, "spawn")
	jwksA := filepath.Join(dir, "jwks-a.json")
	var token string
	var previous identity.JWK

	t.Run("before the rotation", func(t *testing.T) {
		sock := filepath.Join(dir, "a.sock")
		startServe(t, writeConfig(t, t.TempDir(), deploymentConfig(keyA, defs, spawn, "  jwks_path: "+jwksA+"\n")), sock)
		out, err := identity.Client{Socket: sock}.IssueSession(identity.SessionRequest{Definition: "example-builder"})
		if err != nil {
			t.Fatal(err)
		}
		token = out.Token
		raw, err := os.ReadFile(jwksA)
		if err != nil {
			t.Fatal(err)
		}
		var set identity.JWKS
		if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 {
			t.Fatalf("%q %v", raw, err)
		}
		previous = set.Keys[0]
	})
	if token == "" {
		t.Fatal("no token was issued before the rotation")
	}

	t.Run("after the rotation", func(t *testing.T) {
		keyB := filepath.Join(dir, "key-b.pem")
		writeSigningKey(t, keyB)
		jwksB := filepath.Join(dir, "jwks-b.json")
		retired := "  retired_keys:\n    - kty: " + previous.Kty + "\n      crv: " + previous.Crv + "\n      alg: " + previous.Alg +
			"\n      kid: " + previous.Kid + "\n      x: " + previous.X + "\n"
		sock := filepath.Join(dir, "b.sock")
		startServe(t, writeConfig(t, t.TempDir(), deploymentConfig(keyB, defs, spawn, "  jwks_path: "+jwksB+"\n"+retired)), sock)

		raw, err := os.ReadFile(jwksB)
		if err != nil {
			t.Fatal(err)
		}
		var set identity.JWKS
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatal(err)
		}
		if len(set.Keys) != 2 || set.Keys[1].Kid != previous.Kid || set.Keys[0].Kid == previous.Kid {
			t.Fatalf("the published set must list the new key then the retired one: %q", raw)
		}
		claims, err := livetest.VerifyAssertion(token, set, time.Now())
		if err != nil {
			t.Fatalf("the previous key's token does not verify against the rotated key set: %v", err)
		}
		if _, err := livetest.VerifyAssertion(token, set, time.Unix(claims.Exp, 0)); err == nil {
			t.Fatal("the previous key's token verified at its exp")
		}

		// The new key signs, and the retired one never does.
		fresh, err := identity.Client{Socket: sock}.IssueSession(identity.SessionRequest{Definition: "example-builder"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := livetest.VerifyAssertion(fresh.Token, identity.JWKS{Keys: set.Keys[1:]}, time.Now()); err == nil {
			t.Fatal("a token issued after the rotation verified against the retired key alone")
		}
		if _, err := livetest.VerifyAssertion(fresh.Token, identity.JWKS{Keys: set.Keys[:1]}, time.Now()); err != nil {
			t.Fatalf("a token issued after the rotation does not verify against the new key: %v", err)
		}
	})
}

// A retired_keys entry that is wrong stops the start, naming the entry, and
// publishes nothing.
func TestServeRefusesABadRetiredKeyNamingTheEntry(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	jwks := filepath.Join(dir, "jwks.json")
	for name, c := range map[string]struct{ entry, want string }{
		"a private member": {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: k1, x: AAAA, d: AAAA}\n", "private member d"},
		"a kid that is not the thumbprint": {"    - {kty: OKP, crv: Ed25519, alg: EdDSA, kid: not-the-thumbprint, x: " +
			strings.Repeat("A", 43) + "}\n", "thumbprint"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := writeConfig(t, t.TempDir(), deploymentConfig(key, defs, filepath.Join(dir, "spawn"), "  jwks_path: "+jwks+"\n  retired_keys:\n"+c.entry))
			err := serve([]string{"--config", cfg, "--socket", filepath.Join(dir, "id.sock")}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), "identity.retired_keys[0]") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want a refusal naming identity.retired_keys[0] and %q", err, c.want)
			}
			if _, statErr := os.Lstat(jwks); statErr == nil {
				t.Fatal("a refused start published a key set")
			}
		})
	}
}

// A unix socket in definitions_dir is skipped as a non-regular entry, and an
// identity section that reaches the document through a YAML merge key is the
// one serve runs with.
func TestServeStartsWithASocketInDefinitionsAndAMergedIdentitySection(t *testing.T) {
	dir, key, defs := identityDeployment(t)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(defs, "example-sock.md"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	body := "shared: &shared\n  identity:\n    key_path: " + key + "\n    definitions_dir: " + defs +
		"\n    spawn_root: " + filepath.Join(dir, "spawn") + "\n<<: *shared\n"
	sock := filepath.Join(dir, "id.sock")
	startServe(t, writeConfig(t, dir, body), sock)

	out, err := identity.Client{Socket: sock}.IssueSession(identity.SessionRequest{Definition: "example-builder"})
	if err != nil || out.Actor != "agent:example-builder" {
		t.Fatalf("%+v %v", out, err)
	}
}
