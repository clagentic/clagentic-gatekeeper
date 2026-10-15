//go:build linux

package livetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// defaultRuntimeCLI is the usual command name of the one supported runtime. The
// caller overrides it with Options.RuntimeCLI.
const defaultRuntimeCLI = "claude"

// retryable marks a run that completed but did not do what the prompt asked of
// the model: another attempt may, a denial or a wrong delivery may not.
type retryable struct{ error }

// runtimeSetup is the isolated runtime configuration shared by the runtime
// shapes: one settings file, written by the real registration command, with no
// user or project settings sources behind it.
type runtimeSetup struct {
	cli      string
	settings string
	work     string
	agents   string
}

// runtimeShape is one runtime shape: a prompt, and a check of what the run
// delivered.
type runtimeShape struct {
	name   string
	prompt func(e *Env) string
	check  func(e *Env, r *runtimeRun) error
}

// runtimeRun is what one invocation of the runtime produced.
type runtimeRun struct {
	dirs    []string
	denials []string
}

const printenvCommand = "printenv CLAGENTIC_IDENTITY_DIR"

// The model never expands a variable itself: the runtime refuses a command whose
// variable it cannot check before running it, which would test the runtime and
// not the hook.
const driverPreamble = "You are a test driver. Do exactly the steps below and nothing else. Use the Bash tool for shell commands and run each command exactly as written. Never use a shell variable, a substitution or any other command. "

func (e *Env) runtimeShapes() []shape {
	delegate := "Use the example-builder subagent with this prompt: Run this exact command with the Bash tool and reply with its output only: " + printenvCommand + ". "
	specs := []runtimeShape{
		{"runtime-claude-code/main-headless-session",
			func(*Env) string {
				return driverPreamble + "Run this exact command: " + printenvCommand + ". Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error { return e.expectDirs(r, 1) }},
		{"runtime-claude-code/foreground-subagent",
			func(*Env) string {
				return driverPreamble + "Step 1: run this exact command: " + printenvCommand + ". Step 2: " + delegate + "Wait for it in the foreground. Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error { return e.expectDirs(r, 2) }},
		{"runtime-claude-code/background-subagent",
			func(*Env) string {
				return driverPreamble + "Step 1: run this exact command: " + printenvCommand + ". Step 2: " + delegate + "Start it in the background (run_in_background true). Step 3: run the command sleep 20, up to five times, until the subagent's result has arrived. Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error { return e.expectDirs(r, 2) }},
		{"runtime-claude-code/two-concurrent-subagents",
			func(*Env) string {
				return driverPreamble + "Step 1: run this exact command: " + printenvCommand + ". Step 2: start two example-builder subagents in the same turn so they run concurrently, each with this prompt: Run this exact command with the Bash tool and reply with its output only: " + printenvCommand + ". Wait for both. Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error { return e.expectDirs(r, 3) }},
		{"runtime-claude-code/compound-command",
			func(*Env) string {
				return driverPreamble + "Run this exact command: echo first; " + printenvCommand + " && echo last. Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error { return e.expectDirs(r, 1) }},
		{"runtime-claude-code/unruled-command-still-prompts",
			func(e *Env) string {
				return driverPreamble + "Run this exact command: touch " + e.unruledMarker() + ". Then reply with the word done."
			},
			func(e *Env, r *runtimeRun) error {
				if len(r.denials) == 0 {
					return errors.New("a command no rule covers did not prompt (no denial was recorded)")
				}
				for _, d := range r.denials {
					if !strings.Contains(d, "touch") {
						return fmt.Errorf("a ruled command was denied: %.200s", d)
					}
				}
				if _, err := os.Stat(e.unruledMarker()); err == nil {
					return errors.New("the unruled command ran")
				}
				return nil
			}},
	}
	out := make([]shape, 0, len(specs))
	for _, s := range specs {
		out = append(out, shape{name: s.name, run: func(ctx context.Context) error { return e.runtimeShape(ctx, s) }})
	}
	return out
}

func (e *Env) unruledMarker() string { return filepath.Join(e.Dir, "rt", "work", "unruled-marker") }

// runtimeShape runs one spec, retrying while the model did not do what it was
// asked, and turns a runtime that cannot run a turn at all into a skip.
func (e *Env) runtimeShape(ctx context.Context, s runtimeShape) error {
	setup, err := e.runtimeSetup(ctx)
	if err != nil {
		return err
	}
	var last error
	for attempt := 1; attempt <= e.opts.RuntimeAttempts; attempt++ {
		run, err := e.invokeRuntime(ctx, setup, s.prompt(e))
		if err != nil {
			return err
		}
		// The unruled shape expects a denial; every other shape expects none.
		if s.name != "runtime-claude-code/unruled-command-still-prompts" && len(run.denials) > 0 {
			return fmt.Errorf("a permission denial occurred: %.300s", strings.Join(run.denials, " | "))
		}
		last = s.check(e, run)
		var again retryable
		if last == nil || !errors.As(last, &again) {
			return last
		}
	}
	return last
}

// runtimeSetup prepares the isolated runtime configuration once.
func (e *Env) runtimeSetup(ctx context.Context) (*runtimeSetup, error) {
	if e.rt != nil || e.rtErr != nil {
		return e.rt, e.rtErr
	}
	e.rt, e.rtErr = e.prepareRuntime(ctx)
	return e.rt, e.rtErr
}

func (e *Env) prepareRuntime(ctx context.Context) (*runtimeSetup, error) {
	if e.opts.NoRuntime {
		return nil, skipf("runtime shapes were turned off by the caller")
	}
	name := e.opts.RuntimeCLI
	if name == "" {
		name = defaultRuntimeCLI
	}
	cli, err := exec.LookPath(name)
	if err != nil {
		return nil, skipf("the runtime CLI was not found; pass --runtime-cli or set GATEKEEPER_LIVETEST_RUNTIME_CLI")
	}
	rtDir := filepath.Join(e.Dir, "rt")
	work := filepath.Join(rtDir, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	settings := filepath.Join(rtDir, "settings.json")
	res, err := e.gk(ctx, runOpts{}, "hooks-install", "--runtime", "claude-code", "--settings", settings,
		"--socket", e.Sock, "--state-dir", filepath.Join(rtDir, "state"), "--mode", "enforce", "--binary", e.Bin)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, fmt.Errorf("hooks-install: exit %d: %.300s", res.Code, res.Stderr)
	}
	// The commands the shapes run are ruled; the one the unruled shape runs is not.
	if err := addAllowRules(settings, "Bash("+printenvCommand+")", "Bash(echo *)", "Bash(sleep *)"); err != nil {
		return nil, err
	}
	agents, err := json.Marshal(map[string]any{defBuilder: map[string]any{
		"description": "Runs the one shell command it is given and reports its output.",
		"prompt":      "Run exactly the shell command you are given with the Bash tool and reply with its output only.",
		"tools":       []string{"Bash"},
	}})
	if err != nil {
		return nil, err
	}
	return &runtimeSetup{cli: cli, settings: settings, work: work, agents: string(agents)}, nil
}

// addAllowRules appends to permissions.allow in a settings file, keeping every
// other key.
func addAllowRules(path string, rules ...string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	perms, _ := doc["permissions"].(map[string]any)
	if perms == nil {
		perms = map[string]any{}
	}
	allow, _ := perms["allow"].([]any)
	for _, r := range rules {
		allow = append(allow, r)
	}
	perms["allow"], doc["permissions"] = allow, perms
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// invokeRuntime runs one headless session with the isolated settings and reads
// the stream it prints.
func (e *Env) invokeRuntime(ctx context.Context, s *runtimeSetup, prompt string) (*runtimeRun, error) {
	ctx, cancel := context.WithTimeout(ctx, e.opts.RuntimeTimeout)
	defer cancel()
	res, err := e.run(ctx, runOpts{Stdin: prompt, Full: true, Env: e.opts.RuntimeEnv, Dir: s.work}, s.cli,
		"-p", "--settings", s.settings, "--setting-sources", "", "--output-format", "stream-json", "--verbose",
		"--permission-mode", "default", "--no-session-persistence", "--agents", s.agents)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("the runtime did not finish within %s", e.opts.RuntimeTimeout)
		}
		return nil, err
	}
	var final map[string]any
	for _, line := range strings.Split(res.Stdout, "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["type"] == "result" {
			final = rec
		}
	}
	if final == nil {
		return nil, skipf("the runtime produced no result record (exit %d); it cannot run a model turn here", res.Code)
	}
	if bad, _ := final["is_error"].(bool); bad {
		sub, _ := final["subtype"].(string)
		return nil, skipf("the runtime could not complete a model turn (%s)", sub)
	}
	return &runtimeRun{dirs: e.deliveredDirs(res.Stdout), denials: denialsOf(final)}, nil
}

// denialsOf lists the commands of the permission denials of a finished run.
func denialsOf(final map[string]any) []string {
	var out []string
	list, _ := final["permission_denials"].([]any)
	for _, item := range list {
		m, _ := item.(map[string]any)
		in, _ := m["tool_input"].(map[string]any)
		cmd, _ := in["command"].(string)
		tool, _ := m["tool_name"].(string)
		out = append(out, tool+": "+cmd)
	}
	return out
}

// deliveredDirs finds the distinct delivery directories a run printed, in order
// of appearance. The pattern is anchored on the spawn root of this deployment,
// so only a directory this issuer made can match.
func (e *Env) deliveredDirs(stream string) []string {
	re := regexp.MustCompile(regexp.QuoteMeta(e.Spawn) + `/[A-Za-z0-9._+-]+`)
	var out []string
	seen := map[string]bool{}
	for _, d := range re.FindAllString(stream, -1) {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// expectDirs requires at least want distinct delivery directories, which proves
// each agent got a variable of its own, and verifies every one still on disk (a
// stopped subagent's is removed by design). The main session's, which lives for
// the run, must be a verifiable workload assertion.
func (e *Env) expectDirs(r *runtimeRun, want int) error {
	if len(r.dirs) < want {
		return retryable{fmt.Errorf("%d distinct delivery directories were printed, want at least %d", len(r.dirs), want)}
	}
	workload := 0
	for _, d := range r.dirs {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		c, err := e.claimsIn(d)
		if err != nil {
			return fmt.Errorf("a delivered assertion does not verify: %w", err)
		}
		if c.Grade == "workload" {
			workload++
		}
	}
	if workload == 0 {
		return errors.New("no delivered session assertion is left to verify")
	}
	return nil
}
