//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/hook"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

const (
	e2eOp     = "example.run-command"
	e2eDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// runWith runs the real binary with the given extra environment, and with the
// host variable removed unless env sets it.
func runWith(t *testing.T, env []string, stdin, bin string, args ...string) hookRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, hook.EnvHostScheduledRun+"=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return hookRun{out.String(), errb.String(), code}
}

// fakeOrigin writes an executable standing in for a turn-origin provider: it
// drains the hook payload from stdin and then prints, or fails with, what the
// test put in the answer file.
func fakeOrigin(t *testing.T, dir string) (program, answer string) {
	t.Helper()
	program, answer = filepath.Join(dir, "origin.sh"), filepath.Join(dir, "answer")
	script := "#!/bin/sh\ncat >/dev/null\ncat '" + answer + "' || exit 1\n"
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, answer
}

// verifyApprovalAgainstJWKS checks the approval the way a consumer with a JWS
// library would: header typ, then the signature against the key set the issuer
// publishes, then the claims.
func verifyApprovalAgainstJWKS(t *testing.T, jwks identity.JWKS, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", token)
	}
	seg := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(seg(parts[0]), &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Typ != identity.ApprovalTyp || hdr.Alg != "EdDSA" {
		t.Fatalf("header %+v", hdr)
	}
	for _, k := range jwks.Keys {
		if k.Kid == hdr.Kid && k.Alg == hdr.Alg {
			if !ed25519.Verify(ed25519.PublicKey(seg(k.X)), []byte(parts[0]+"."+parts[1]), seg(parts[2])) {
				t.Fatal("the approval does not verify against the published key")
			}
			var claims map[string]any
			if err := json.Unmarshal(seg(parts[1]), &claims); err != nil {
				t.Fatal(err)
			}
			return claims
		}
	}
	t.Fatalf("no published key has kid %q", hdr.Kid)
	return nil
}

// The coordinator shape against a real serve and real processes. A lane's op and
// digest are relayed to a coordinator session, which runs the request; the
// operator's phrase arrives in that session on a host that declares injected
// turns; a different process fetches. What decides whether anything is granted
// is the turn-origin provider, here a fake.
func TestApprovalEndToEnd(t *testing.T) {
	bin := buildGatekeeper(t)
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	program, answer := fakeOrigin(t, dir)
	base := "identity:\n  key_path: " + key + "\n  definitions_dir: " + defs + "\n  spawn_root: " + filepath.Join(dir, "spawn") + "\n  approval:\n    approver: example-operator\n    ttl_seconds: 120\n"
	withProvider := filepath.Join(dir, "with-provider.yaml")
	withoutProvider := filepath.Join(dir, "without-provider.yaml")
	if err := os.WriteFile(withProvider, []byte(base+"    turn_origin:\n      command: ["+program+"]\n      timeout_seconds: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(withoutProvider, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real serve process, so that the built binary is the helper it recognises.
	startServeProcess(t, bin, withProvider, sock)

	state := filepath.Join(t.TempDir(), "state")
	hookArgs := func(event, cfg string) []string {
		return []string{"hook", "claude-code", event, "--socket", sock, "--state-dir", state, "--mode", "enforce", "--config", cfg}
	}
	const session = "coordinator-1"
	r := runWith(t, nil, `{"hook_event_name":"SessionStart","session_id":"`+session+`","source":"startup"}`, bin, hookArgs("session-start", withProvider)...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("session-start: %+v", r)
	}
	rawRec, err := os.ReadFile(filepath.Join(state, session, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(rawRec, &rec); err != nil {
		t.Fatal(err)
	}
	sessionClaims := claimsOf(t, rec.Dir)

	for _, tc := range []struct {
		name     string
		config   string
		answer   string // the fake provider's output; "-" removes the file so it fails
		source   string // JSON member added to the prompt payload
		hostSet  bool
		granted  bool
		wantInfo string // what the hook log says
	}{
		{"provider path: host injects turns, provider says human", withProvider, `{"origin":{"kind":"human"}}`, "", true, true, "granted"},
		{"scheduled or sent turn: provider says task-notification", withProvider, `{"origin":{"kind":"task-notification","subkind":"scheduled-trigger"}}`, "", true, false, "turn-origin rung 3"},
		{"provider fails", withProvider, "-", "", true, false, "turn-origin rung 3"},
		{"provider prints garbage", withProvider, "human", "", true, false, "turn-origin rung 3"},
		{"no provider configured, host injects turns", withoutProvider, "", "", true, false, "no origin was available"},
		{"cli path: source user", withoutProvider, "", `,"source":"user"`, true, true, "granted"},
		{"source sdk", withProvider, `{"origin":{"kind":"human"}}`, `,"source":"sdk"`, true, false, "turn-origin rung 2"},
		{"plain terminal baseline: no source, no provider, host declares none", withoutProvider, "", "", false, true, "granted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.answer == "-" {
				_ = os.Remove(answer)
			} else if err := os.WriteFile(answer, []byte(tc.answer), 0o600); err != nil {
				t.Fatal(err)
			}
			// The coordinator runs the request the lane relayed.
			r := runWith(t, []string{identityEnvDir + "=" + rec.Dir}, "", bin, "approval", "request", "--socket", sock, "--op", e2eOp, "--params-digest", e2eDigest, "--summary", "relayed by a lane")
			if r.code != 0 {
				t.Fatalf("approval request: %+v", r)
			}
			var pending identity.ApprovalPending
			if err := json.Unmarshal([]byte(r.stdout), &pending); err != nil || pending.Phrase != "approve "+pending.Rid || pending.ExpiresAt <= time.Now().Unix() {
				t.Fatalf("request output %q: %v", r.stdout, err)
			}
			// The operator's phrase arrives in the coordinator session.
			var env []string
			if tc.hostSet {
				env = []string{hook.EnvHostScheduledRun + "=1"}
			}
			payload := `{"hook_event_name":"UserPromptSubmit","session_id":"` + session + `","prompt":"` + pending.Phrase + `"` + tc.source + `}`
			before, _ := os.ReadFile(filepath.Join(state, "hook.log"))
			r = runWith(t, env, payload, bin, hookArgs("user-prompt-submit", tc.config)...)
			if r.code != 0 || r.stdout != "" {
				t.Fatalf("the hook answered the prompt: %+v", r)
			}
			after, _ := os.ReadFile(filepath.Join(state, "hook.log"))
			if added := strings.TrimPrefix(string(after), string(before)); !strings.Contains(added, tc.wantInfo) {
				t.Fatalf("the hook log lacks %q:\n%s", tc.wantInfo, added)
			}
			// A different process fetches by rid.
			r = runWith(t, nil, "", bin, "approval", "fetch", "--socket", sock, "--rid", pending.Rid)
			if !tc.granted {
				if r.code == 0 || !strings.Contains(r.stderr, identity.CodeApprovalNotGranted) {
					t.Fatalf("something was granted: %+v", r)
				}
				return
			}
			if r.code != 0 {
				t.Fatalf("approval fetch: %+v", r)
			}
			var fetched identity.ApprovalFetched
			if err := json.Unmarshal([]byte(r.stdout), &fetched); err != nil || fetched.Rid != pending.Rid {
				t.Fatalf("fetch output %q: %v", r.stdout, err)
			}
			jwks, err := identity.Client{Socket: sock}.FetchJWKS()
			if err != nil {
				t.Fatal(err)
			}
			claims := verifyApprovalAgainstJWKS(t, jwks, fetched.Approval)
			if claims["op"] != e2eOp || claims["pd"] != e2eDigest || claims["sid"] != sessionClaims["sid"] || claims["rid"] != pending.Rid ||
				claims["acked_by"] != "example-operator" || claims["cap"] != float64(1) {
				t.Fatalf("claims %v, session %v", claims, sessionClaims["sid"])
			}
			if exp, iat := claims["exp"].(float64), claims["iat"].(float64); exp-iat != 120 {
				t.Fatalf("approval lifetime %v, want the configured 120", exp-iat)
			}
			// Once only.
			r = runWith(t, nil, "", bin, "approval", "fetch", "--socket", sock, "--rid", pending.Rid)
			if r.code == 0 || !strings.Contains(r.stderr, identity.CodeApprovalAlreadyFetched) {
				t.Fatalf("second fetch: %+v", r)
			}
		})
	}
}

// The commands refuse a call that cannot work, with a non-zero exit and nothing
// on stdout.
func TestApprovalCommandsRefuse(t *testing.T) {
	var out bytes.Buffer
	for name, args := range map[string][]string{
		"no command":          nil,
		"unknown command":     {"approve"},
		"request without op":  {"request", "--socket", "/x", "--params-digest", e2eDigest},
		"request no digest":   {"request", "--socket", "/x", "--op", e2eOp},
		"request no token":    {"request", "--socket", "/x", "--op", e2eOp, "--params-digest", e2eDigest},
		"fetch without a rid": {"fetch", "--socket", "/x"},
		"fetch no socket":     {"fetch", "--socket", "relative.sock", "--rid", "a"},
	} {
		t.Setenv(identityEnvDir, "")
		out.Reset()
		if err := runApproval(args, &out); err == nil || out.Len() != 0 {
			t.Errorf("%s: err %v stdout %q", name, err, out.String())
		}
	}
}

// config's cap on a provider's run is what the hook's registration timeout and
// deadline are built from; the two constants must agree.
func TestProviderTimeoutCapsAgree(t *testing.T) {
	if hook.MaxProviderTimeout != time.Duration(config.MaxTurnOriginTimeoutSeconds)*time.Second {
		t.Fatalf("hook allows a provider %s, config allows %d seconds", hook.MaxProviderTimeout, config.MaxTurnOriginTimeoutSeconds)
	}
}
