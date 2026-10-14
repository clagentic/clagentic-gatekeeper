//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// buildGatekeeper compiles the real binary: the hooks are separate processes,
// and the issuer attests them by their executable and parent chain, so only a
// built binary exercises the binding that matters.
func buildGatekeeper(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain to build the binary under test")
	}
	bin := filepath.Join(t.TempDir(), "gatekeeper")
	cmd := exec.Command(goBin, "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// startServeProcess runs the real `gatekeeper serve` and waits for its socket.
func startServeProcess(t *testing.T, bin, cfg, sock string) {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", cfg, "--socket", sock)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited: %v\n%s", err, stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve did not open its socket\n%s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type hookRun struct {
	stdout, stderr string
	code           int
}

func runBinary(t *testing.T, stdin string, name string, args ...string) hookRun {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
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

func claimsOf(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "identity.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", raw)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func dirFromRewrite(t *testing.T, stdout string) (dir, command string) {
	t.Helper()
	var reply struct {
		Specific struct {
			Decision string `json:"permissionDecision"`
			Updated  struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &reply); err != nil {
		t.Fatalf("reply %q: %v", stdout, err)
	}
	if reply.Specific.Decision != "allow" {
		t.Fatalf("decision %q", reply.Specific.Decision)
	}
	command = reply.Specific.Updated.Command
	rest, ok := strings.CutPrefix(command, "export CLAGENTIC_IDENTITY_DIR=")
	if !ok {
		t.Fatalf("command %q", command)
	}
	dir, _, _ = strings.Cut(rest, "; ")
	return dir, command
}

// The whole path against a real serve: separate hook processes under one
// runtime (the test process), one of them behind a `sh -c` wrapper.
func TestHooksAgainstARealServe(t *testing.T) {
	bin := buildGatekeeper(t)
	dir, key, defs := identityDeployment(t)
	sock := filepath.Join(dir, "id.sock")
	cfg := writeConfig(t, dir, "identity:\n  key_path: "+key+"\n  definitions_dir: "+defs+"\n  spawn_root: "+filepath.Join(dir, "spawn")+"\n")
	startServeProcess(t, bin, cfg, sock)
	state := filepath.Join(t.TempDir(), "state")
	common := []string{"--socket", sock, "--state-dir", state, "--mode", "enforce"}
	hookArgs := func(event string) []string {
		return append([]string{"hook", "claude-code", event}, common...)
	}

	r := runBinary(t, `{"hook_event_name":"SessionStart","session_id":"s1","source":"startup"}`, bin, hookArgs("session-start")...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("session-start: %+v", r)
	}
	r = runBinary(t, `{"hook_event_name":"SubagentStart","session_id":"s1","agent_id":"a1","agent_type":"example-builder"}`, bin, hookArgs("subagent-start")...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("subagent-start: %+v", r)
	}
	// A second subagent's start, through a command wrapper as a runtime that runs
	// hooks with `sh -c` would.
	wrapped := append([]string{"-c", `"$0" "$@"; echo wrapped >&2`, bin}, hookArgs("subagent-start")...)
	r = runBinary(t, `{"hook_event_name":"SubagentStart","session_id":"s1","agent_id":"a2","agent_type":"example-builder"}`, "sh", wrapped...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("wrapped subagent-start: %+v", r)
	}

	call := func(agent string) (string, string) {
		payload := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"echo one; rm -f x && echo {0,600}"}}`
		if agent != "" {
			payload = `{"hook_event_name":"PreToolUse","session_id":"s1","agent_id":"` + agent + `","agent_type":"example-builder","tool_name":"Bash","tool_input":{"command":"echo one; rm -f x && echo {0,600}"}}`
		}
		r := runBinary(t, payload, bin, hookArgs("pre-tool-use-bash")...)
		if r.code != 0 {
			t.Fatalf("pre-tool-use-bash: %+v", r)
		}
		return dirFromRewrite(t, r.stdout)
	}
	mainDir, command := call("")
	if !strings.HasSuffix(command, "; echo one; rm -f x && echo {0,600}") {
		t.Fatalf("the original command was altered: %q", command)
	}
	a1, _ := call("a1")
	a2, _ := call("a2")
	if mainDir == a1 || a1 == a2 || mainDir == a2 {
		t.Fatalf("directories are shared: %s %s %s", mainDir, a1, a2)
	}
	mc, ac := claimsOf(t, mainDir), claimsOf(t, a1)
	if mc["grade"] != "workload" || ac["grade"] != "harness" || ac["spawn"] != "a1" || mc["sid"] != ac["sid"] {
		t.Fatalf("claims main=%v child=%v", mc, ac)
	}
	act := ac["act"].(map[string]any)
	if act["sub"] != "agent:example-builder" {
		t.Fatalf("child actor %v", act)
	}
	// The runtime id is the process that owns the session (this test binary), not
	// the short-lived hook process.
	rt := mc["rt"].(map[string]any)["id"].(string)
	if rt == "gatekeeper" || rt == "" {
		t.Fatalf("the assertion names the hook as its runtime: %v", mc["rt"])
	}

	r = runBinary(t, `{"hook_event_name":"SubagentStop","session_id":"s1","agent_id":"a1"}`, bin, hookArgs("subagent-stop")...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("subagent-stop: %+v", r)
	}
	if _, err := os.Stat(a1); !os.IsNotExist(err) {
		t.Fatalf("the stopped agent's directory remains: %v", err)
	}
	if _, err := os.Stat(a2); err != nil {
		t.Fatalf("a sibling's directory was removed: %v", err)
	}

	// The process adapter: a launcher gets its child's assignment before exec.
	r = runBinary(t, "", bin, "hook", "process", "--socket", sock, "--definition", "example-builder")
	line := strings.TrimSpace(r.stdout)
	procDir, ok := strings.CutPrefix(line, "CLAGENTIC_IDENTITY_DIR=")
	if r.code != 0 || !ok {
		t.Fatalf("hook process: %+v", r)
	}
	if c := claimsOf(t, procDir); c["grade"] != "workload" {
		t.Fatalf("process claims %v", c)
	}
	act = claimsOf(t, procDir)["act"].(map[string]any)
	if act["sub"] != "agent:example-builder" {
		t.Fatalf("launcher-declared definition: %v", act)
	}
}

func TestHookFailsOpenWithoutAnIssuer(t *testing.T) {
	bin := buildGatekeeper(t)
	state := filepath.Join(t.TempDir(), "state")
	sock := filepath.Join(t.TempDir(), "absent.sock")
	args := []string{"hook", "claude-code", "pre-tool-use-bash", "--socket", sock, "--state-dir", state, "--mode", "enforce"}
	payload := `{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}`
	r := runBinary(t, payload, bin, args...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("%+v", r)
	}
	r = runBinary(t, `{"hook_event_name":"SessionStart","session_id":"s1"}`, bin, append([]string{"hook", "claude-code", "session-start", "--socket", sock, "--state-dir", state}, "--mode", "enforce")...)
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("session-start without an issuer: %+v", r)
	}
	raw, err := os.ReadFile(filepath.Join(state, "hook.log"))
	if err != nil || !strings.Contains(string(raw), "absent.sock") {
		t.Fatalf("the failure was not logged: %q %v", raw, err)
	}
	// A launcher is told: the process adapter fails loudly and prints nothing.
	r = runBinary(t, "", bin, "hook", "process", "--socket", sock)
	if r.code == 0 || r.stdout != "" {
		t.Fatalf("hook process without an issuer: %+v", r)
	}
}

func TestHookRefusesNoSocketAndHumanOrigin(t *testing.T) {
	var out, errb bytes.Buffer
	state := t.TempDir()
	if code := runHook([]string{"claude-code", "session-start", "--state-dir", state}, strings.NewReader(`{"session_id":"s1"}`), &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("no socket: code %d out %q", code, out.String())
	}
	raw, _ := os.ReadFile(filepath.Join(state, "hook.log"))
	if !strings.Contains(string(raw), "no socket") {
		t.Fatalf("log %q", raw)
	}
	for _, args := range [][]string{
		{"claude-code", "session-start", "--state-dir", state, "--socket", "/x", "--origin", "human"},
		{"process", "--socket", "/x", "--origin", "human"},
	} {
		out.Reset()
		errb.Reset()
		if code := runHook(args, strings.NewReader("{}"), &out, &errb); code == 0 || !strings.Contains(errb.String(), "human") {
			t.Errorf("%v: code %d stderr %q", args, code, errb.String())
		}
	}
	if code := runHook([]string{"claude-code", "session-start", "--socket", "/x", "--state-dir", "relative"}, strings.NewReader("{}"), &out, &errb); code == 0 {
		t.Error("a relative state dir was accepted")
	}
}

func TestHooksInstallTwiceChangesNothingTheSecondTime(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(settings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/other/guard.py"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--runtime", "claude-code", "--settings", settings, "--socket", "/run/gk/id.sock", "--state-dir", "/var/cache/gk", "--binary", "/opt/gk/gatekeeper"}
	var out bytes.Buffer
	if err := runHooksInstall(args, &out); err != nil || !strings.Contains(out.String(), "registered (mode warn)") {
		t.Fatalf("%v %q", err, out.String())
	}
	first, _ := os.ReadFile(settings)
	out.Reset()
	if err := runHooksInstall(args, &out); err != nil || !strings.Contains(out.String(), "no change") {
		t.Fatalf("%v %q", err, out.String())
	}
	second, _ := os.ReadFile(settings)
	if !bytes.Equal(first, second) {
		t.Fatal("the second run changed the file")
	}
	out.Reset()
	if err := runHooksInstall([]string{"--runtime", "claude-code", "--settings", settings, "--remove"}, &out); err != nil || !strings.Contains(out.String(), "unregistered") {
		t.Fatalf("%v %q", err, out.String())
	}
	raw, _ := os.ReadFile(settings)
	if strings.Contains(string(raw), "gatekeeper") || !strings.Contains(string(raw), "/opt/other/guard.py") {
		t.Fatalf("after remove: %s", raw)
	}
}

func TestHooksInstallNeedsAnExplicitSocketAndKnownRuntime(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "settings.json")
	var out bytes.Buffer
	if err := runHooksInstall([]string{"--runtime", "claude-code", "--settings", settings, "--state-dir", "/var/cache/gk", "--binary", "/opt/gk/gatekeeper"}, &out); err == nil || !strings.Contains(err.Error(), "no socket") {
		t.Fatalf("got %v", err)
	}
	if err := runHooksInstall([]string{"--runtime", "codex", "--settings", settings, "--socket", "/x"}, &out); err == nil || !strings.Contains(err.Error(), "claude-code") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatal("a refused install created the settings file")
	}
}

func TestRenderAgentCommand(t *testing.T) {
	dir := t.TempDir()
	def := "---\nname: example-builder\ndescription: Builds.\ntools: [Read]\nroles: [builder]\n---\nbody\n"
	if err := os.WriteFile(filepath.Join(dir, "example-builder.md"), []byte(def), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runRenderAgent([]string{"--runtime", "claude-code", "--definitions-dir", dir, "example-builder"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "---\nname: example-builder\ndescription: Builds.\ntools: Read\n---\nbody\n" {
		t.Fatalf("%q", out.String())
	}
	if err := runRenderAgent([]string{"--runtime", "claude-code"}, &out); err == nil {
		t.Fatal("no definition accepted")
	}
	if err := runRenderAgent([]string{"--runtime", "codex", "x"}, &out); err == nil {
		t.Fatal("codex accepted: it is not in this release")
	}
}
