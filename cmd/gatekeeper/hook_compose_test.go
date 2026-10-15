//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/hook"
)

const bashCall = `{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"make build"}}`

// upstreamScript writes an executable that discards its stdin and runs body.
func upstreamScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "up.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ncat >/dev/null\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func runComposed(t *testing.T, stdin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	code = runHook(append([]string{"claude-code", "pre-tool-use-bash"}, args...), strings.NewReader(stdin), &out, &errb)
	return out.String(), errb.String(), code
}

// The composed hook sits at the fixed position hooks-install writes, so a flag
// that does not parse, anywhere after it, still leaves the upstream's result as
// the process result, its blocking exit code included.
func TestUpstreamRunsAndSpeaksWhateverElseOnTheCommandLineIsWrong(t *testing.T) {
	deny := upstreamScript(t, "echo blocked; echo why >&2; exit 2")
	cases := map[string][]string{
		"unknown flag after":     {"--compose", deny, "--bogus"},
		"bad value after":        {"--compose", deny, "--upstream-timeout", "5s", "--timeout", "forever"},
		"bad budget and a flag":  {"--compose", deny, "--upstream-timeout", "never", "--bogus"},
		"non-positive budget":    {"--compose", deny, "--upstream-timeout", "0s", "--socket", "/x"},
		"negative budget":        {"--compose", deny, "--upstream-timeout", "-3s", "--socket", "/x"},
		"relative state dir":     {"--compose", deny, "--upstream-timeout", "5s", "--state-dir", "rel", "--socket", "/x", "--mode", "enforce"},
		"mode unreadable":        {"--compose", deny, "--upstream-timeout", "5s", "--socket", "/x", "--mode", "loud"},
		"help":                   {"--compose", deny, "-h"},
		"non-positive call time": {"--compose", deny, "--upstream-timeout", "5s", "--socket", "/x", "--timeout", "0s"},
	}
	for name, args := range cases {
		stdout, stderr, code := runComposed(t, bashCall, args...)
		if stdout != "blocked\n" || stderr != "why\n" || code != 2 {
			t.Errorf("%s: stdout %q stderr %q exit %d", name, stdout, stderr, code)
		}
	}
}

// The upstream is given the stdin as it arrived: not JSON, empty, or over the cap.
func TestUpstreamGetsTheRawStdinBeforeAnyCapOrParse(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "bytes")
	up := filepath.Join(t.TempDir(), "up.sh")
	if err := os.WriteFile(up, []byte("#!/bin/sh\nwc -c > "+seen+"\nprintf 'verdict'\nexit 2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", 5<<20)
	for name, stdin := range map[string]string{
		"unparseable": "not json at all",
		"empty":       "",
		"oversized":   huge,
		"not bash":    `{"session_id":"s1","tool_name":"Read","tool_input":{"file_path":"/x"}}`,
	} {
		stdout, _, code := runComposed(t, stdin, "--compose", up, "--socket", "/x", "--state-dir", t.TempDir(), "--mode", "enforce")
		if stdout != "verdict" || code != 2 {
			t.Errorf("%s: stdout %q exit %d", name, stdout, code)
		}
		raw, err := os.ReadFile(seen)
		if err != nil || strings.TrimSpace(string(raw)) != strconv.Itoa(len(stdin)) {
			t.Errorf("%s: the upstream read %q (%v), want %d bytes", name, raw, err, len(stdin))
		}
	}
}

// Gatekeeper's diagnostics never touch the stderr of a composed hook: it is the
// upstream's bytes alone.
func TestComposedStderrIsTheUpstreamsAlone(t *testing.T) {
	up := upstreamScript(t, "echo note >&2; printf '{}'")
	_, stderr, code := runComposed(t, bashCall, "--compose", up, "--bogus-flag")
	if stderr != "note\n" || code != 0 {
		t.Fatalf("stderr %q exit %d", stderr, code)
	}
}

// An upstream that cannot run yields nothing and never an allow.
func TestUpstreamWithoutAVerdictYieldsNothingAtTheCommand(t *testing.T) {
	stdout, stderr, code := runComposed(t, bashCall, "--compose", filepath.Join(t.TempDir(), "absent"), "--socket", "/x", "--mode", "enforce")
	if stdout != "" || stderr != "" || code != 0 {
		t.Fatalf("stdout %q stderr %q exit %d", stdout, stderr, code)
	}
}

func TestFixedComposeReadsOnlyTheFixedPosition(t *testing.T) {
	exe, budget, ok := fixedCompose(hook.EventPreToolUseBash, []string{"--compose", "/up", "--upstream-timeout", "7s", "--socket", "/s"})
	if !ok || exe != "/up" || budget != 7*time.Second {
		t.Fatalf("%q %s %v", exe, budget, ok)
	}
	for name, rest := range map[string][]string{
		"not first":   {"--socket", "/s", "--compose", "/up"},
		"no value":    {"--compose"},
		"empty value": {"--compose", ""},
		"none":        nil,
		"other event": {"--compose", "/up"},
	} {
		event := hook.EventPreToolUseBash
		if name == "other event" {
			event = hook.EventSessionStart
		}
		if _, _, ok := fixedCompose(event, rest); ok {
			t.Errorf("%s: found", name)
		}
	}
	for _, bad := range []string{"", "x", "0s", "-1s"} {
		if _, b, _ := fixedCompose(hook.EventPreToolUseBash, []string{"--compose", "/up", "--upstream-timeout", bad}); b != hook.DefaultUpstreamTimeout {
			t.Errorf("budget %q -> %s, want the default", bad, b)
		}
	}
}

func TestRunBoundedFallsBackOnAPanicAndOnAMissedDeadline(t *testing.T) {
	fallback := hook.Result{Stdout: []byte("upstream"), ExitCode: 2}
	got := runBounded(time.Second, fallback, hook.Log{}, "e", func() hook.Result { panic("boom") })
	if string(got.Stdout) != "upstream" || got.ExitCode != 2 {
		t.Fatalf("panic: %+v", got)
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	start := time.Now()
	got = runBounded(100*time.Millisecond, fallback, hook.Log{}, "e", func() hook.Result {
		<-release
		return hook.Result{Stdout: []byte("late")}
	})
	if string(got.Stdout) != "upstream" || got.ExitCode != 2 || time.Since(start) > 3*time.Second {
		t.Fatalf("deadline: %+v after %s", got, time.Since(start))
	}
	got = runBounded(time.Second, fallback, hook.Log{}, "e", func() hook.Result { return hook.Result{Stdout: []byte("own")} })
	if string(got.Stdout) != "own" || got.ExitCode != 0 {
		t.Fatalf("normal: %+v", got)
	}
}

// The exit code belongs to the result: a reply that cannot be written is logged
// and the process still exits with the upstream's code.
func TestExitCodeSurvivesAFailedWrite(t *testing.T) {
	state := t.TempDir()
	log := hook.Log{Path: filepath.Join(state, "hook.log")}
	res := hook.Result{Stdout: []byte("blocked"), Stderr: []byte("why"), ExitCode: 2}
	if code := writeResult(res, failingWriter{}, failingWriter{}, log, "pre-tool-use-bash"); code != 2 {
		t.Fatalf("exit %d", code)
	}
	raw, _ := os.ReadFile(log.Path)
	if !strings.Contains(string(raw), "write reply") {
		t.Fatalf("the failed write was not logged: %q", raw)
	}
}

// A missing or relative state directory disables state entirely: nothing is
// created under the working directory.
func TestRelativeStateDirCreatesNothingInTheWorkingDirectory(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	for _, args := range [][]string{
		{"claude-code", "session-start", "--state-dir", "rel", "--socket", "/x"},
		{"claude-code", "session-start", "--socket", "/x"},
		{"claude-code", "user-prompt-submit", "--state-dir", "./rel", "--socket", "/x", "--refresh-below", "1h"},
		{"claude-code", "subagent-stop", "--state-dir", "../rel", "--socket", "/x"},
	} {
		var out, errb bytes.Buffer
		payload := `{"session_id":"s1","agent_id":"a1","agent_type":"x"}`
		if code := runHook(args, strings.NewReader(payload), &out, &errb); code != 0 || out.Len() != 0 {
			t.Errorf("%v: exit %d out %q", args, code, out.String())
		}
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatalf("files appeared in the working directory: %v %v", entries, err)
	}
}
