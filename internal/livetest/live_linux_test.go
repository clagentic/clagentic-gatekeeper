//go:build linux

package livetest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	builtGK   string
	buildErr  error
	buildDir  string
)

// gatekeeperBinary builds the binary under test once for the package.
func gatekeeperBinary(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain to build the binary under test")
	}
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "gkltest")
		if buildErr != nil {
			return
		}
		builtGK = filepath.Join(buildDir, "gatekeeper")
		cmd := exec.Command("go", "build", "-o", builtGK, "../../cmd/gatekeeper")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = &buildFailure{err, string(out)}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtGK
}

type buildFailure struct {
	err error
	out string
}

func (b *buildFailure) Error() string { return b.err.Error() + "\n" + b.out }

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

func parseReport(t *testing.T, raw string) (map[string]Result, map[string]int) {
	t.Helper()
	results := map[string]Result{}
	var summary map[string]int
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		var line struct {
			Result
			Summary map[string]int `json:"summary"`
		}
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("output line %q is not JSON: %v", sc.Text(), err)
		}
		if line.Summary != nil {
			summary = line.Summary
			continue
		}
		results[line.Shape] = line.Result
	}
	return results, summary
}

// shortParent is a parent directory for a run, short because the socket inside
// it is limited to 108 bytes and t.TempDir includes the test name.
func shortParent(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "p")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func leftovers(t *testing.T, parent string) []string {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// A host with no runtime: the issuer and adapter shapes pass, the runtime shapes
// skip with a reason, and nothing is left behind.
func TestHostWithoutRuntimeSkipsRuntimeShapesAndPassesTheRest(t *testing.T) {
	bin := gatekeeperBinary(t)
	parent := shortParent(t)
	var out bytes.Buffer
	code := Run(context.Background(), Options{Binary: bin, TempParent: parent, RuntimeCLI: "no-such-runtime-cli-for-the-harness"}, &out)
	results, summary := parseReport(t, out.String())
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	var runtimeShapes int
	for name, r := range results {
		if strings.HasPrefix(name, runtimePrefix) {
			runtimeShapes++
			if r.Status != Skip || r.Reason == "" {
				t.Errorf("%s: %+v, want a skip with a reason", name, r)
			}
			continue
		}
		if r.Status != Pass {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if runtimeShapes != 6 || summary["fail"] != 0 || summary["skip"] != 6 || summary["pass"] < 10 {
		t.Fatalf("runtime shapes %d, summary %v\n%s", runtimeShapes, summary, out.String())
	}
	if left := leftovers(t, parent); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
}

var (
	liveRun        = flag.Bool("live", false, "run the whole harness with runtime detection as on a developer host, and log its output")
	liveRuntimeCLI = flag.String("live-runtime-cli", "", "runtime CLI for -live (default: the usual command name on PATH)")
)

// TestRunOnThisHost is the harness exactly as a gate runs it, for a developer
// who wants its per-shape record: go test ./internal/livetest -run RunOnThisHost -live -v
func TestRunOnThisHost(t *testing.T) {
	if !*liveRun {
		t.Skip("pass -live to run the harness against this host's runtime")
	}
	bin := gatekeeperBinary(t)
	var out bytes.Buffer
	code := Run(context.Background(), Options{Binary: bin, TempParent: shortParent(t), RuntimeCLI: *liveRuntimeCLI}, &out)
	t.Logf("exit %d\n%s", code, out.String())
	if code != ExitOK {
		t.Fail()
	}
}

func TestRuntimeThatCannotRunATurnSkips(t *testing.T) {
	bin := gatekeeperBinary(t)
	parent := shortParent(t)
	fake := filepath.Join(t.TempDir(), "fake-runtime")
	script := "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"type\":\"result\",\"is_error\":true,\"subtype\":\"error_during_execution\"}'\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := Run(context.Background(), Options{Binary: bin, TempParent: parent, RuntimeCLI: fake}, &out)
	results, _ := parseReport(t, out.String())
	if code != ExitOK {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	r := results["runtime-claude-code/main-headless-session"]
	if r.Status != Skip || !strings.Contains(r.Reason, "error_during_execution") {
		t.Fatalf("%+v", r)
	}
	// The same host under a gate that requires the runtime fails instead.
	res := execute(context.Background(), shape{name: "runtime-x", run: func(context.Context) error { return skipf("no runtime") }}, Options{RequireRuntime: true})
	if res.Status != Fail || !strings.Contains(res.Reason, "no runtime") {
		t.Fatalf("require-runtime: %+v", res)
	}
}

// Interrupting the harness mid-run leaves no serve process, socket, runtime
// process or directory behind.
func TestInterruptLeavesNothingBehind(t *testing.T) {
	bin := gatekeeperBinary(t)
	tools := t.TempDir()
	harness := filepath.Join(tools, "livetest")
	if out, err := exec.Command("go", "build", "-o", harness, "../../cmd/livetest").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// A stand-in runtime that records its pid and then hangs, so the harness is
	// still running when it is interrupted.
	fake := filepath.Join(tools, "hang-runtime")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho $$ > \"$HANG_DIR/pid\"\nexec sleep 300\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent := shortParent(t)
	cmd := exec.Command(harness, "--binary", bin, "--temp-dir", parent, "--runtime-cli", fake, "--runtime-env", "HANG_DIR="+tools)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	pidFile := filepath.Join(tools, "pid")
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the runtime shapes were never reached\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("pid file %q", raw)
	}
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-waited:
	case <-time.After(30 * time.Second):
		t.Fatal("the harness did not stop after the interrupt")
	}
	if code := cmd.ProcessState.ExitCode(); code != ExitInterrupted {
		t.Fatalf("exit %d\n%s", code, out.String())
	}
	if left := leftovers(t, parent); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatal("the runtime process is still alive")
	}
}

func TestDeliveredDirsAndDenials(t *testing.T) {
	e := &Env{Spawn: "/x/spawn"}
	stream := `{"a":"/x/spawn/abc-1 and /x/spawn/def_2"} {"b":"/x/spawn/abc-1"} /elsewhere/spawn/zzz`
	if got := e.deliveredDirs(stream); len(got) != 2 || got[0] != "/x/spawn/abc-1" || got[1] != "/x/spawn/def_2" {
		t.Fatalf("%v", got)
	}
	final := map[string]any{"permission_denials": []any{map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "touch m"}}}}
	if got := denialsOf(final); len(got) != 1 || got[0] != "Bash: touch m" {
		t.Fatalf("%v", got)
	}
	if err := e.expectDirs(&runtimeRun{dirs: []string{"/x/spawn/a"}}, 2); err == nil {
		t.Fatal("one directory satisfied a want of two")
	} else if _, ok := err.(retryable); !ok {
		t.Fatalf("a missing delivery must be retryable, got %T", err)
	}
}
