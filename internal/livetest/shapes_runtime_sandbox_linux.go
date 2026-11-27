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

// passNote is returned by a shape that passed and has evidence worth recording;
// the harness reports it as the reason of the pass line.
type passNote struct{ note string }

func (p passNote) Error() string { return p.note }

// Runtime shapes for a session under the runtime's sandbox, registered with the
// allow-rewritten setting and with no export-prefix allow rule. They prove the
// setting through the real runtime: no prompt on a rewritten call, the sandbox
// still bounding writes and reads, and a native deny rule still winning. A shape
// whose sandbox cannot start skips with the reason (a failure under
// --require-runtime); it never passes unsandboxed.

const (
	sandboxPrefix = "runtime-claude-code/sandbox-"
	// credMarker is planted in a dummy credential file the sandbox must keep
	// unreadable; it is not a secret.
	credMarker = "gatekeeper-dummy-credential-4c19d2"
	// deniedCommand is matched by the native deny rule the deny shape registers.
	deniedCommand = "mkdir ./denied-dir"
)

// sandboxKinds are the ways a command reaches the hook: the main session, a
// foreground subagent, a background subagent and a subagent in its own worktree.
var sandboxKinds = []string{"main", "foreground", "background", "worktree"}

func (e *Env) sandboxShapes() []shape {
	var out []shape
	for _, kind := range sandboxKinds {
		out = append(out, shape{name: sandboxPrefix + kind, run: func(ctx context.Context) error { return e.shapeSandbox(ctx, kind) }})
	}
	out = append(out, shape{name: sandboxPrefix + "native-deny-still-wins", run: e.shapeSandboxDeny})
	return out
}

// sandboxSetup writes an isolated settings file for one shape: hooks-install with
// the setting on (and so no export-prefix rule), a sandbox block, a dummy
// credential the sandbox denies reading, and a sibling directory outside the
// sandbox write roots.
func (e *Env) sandboxSetup(ctx context.Context, name string, deny ...string) (*runtimeSetup, string, error) {
	if e.opts.NoRuntime {
		return nil, "", skipf("runtime shapes were turned off by the caller")
	}
	cliName := e.opts.RuntimeCLI
	if cliName == "" {
		cliName = defaultRuntimeCLI
	}
	cli, err := exec.LookPath(cliName)
	if err != nil {
		return nil, "", skipf("the runtime CLI was not found; pass --runtime-cli or set GATEKEEPER_LIVETEST_RUNTIME_CLI")
	}
	root := filepath.Join(e.Dir, "rt-sandbox-"+name)
	work, outside := filepath.Join(root, "work"), filepath.Join(root, "outside")
	creds := filepath.Join(work, "creds")
	for _, d := range []string{creds, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, "", err
		}
	}
	if err := os.WriteFile(filepath.Join(creds, ".env.dummy"), []byte(credMarker+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	// Only a worktree-isolated subagent needs a repository to branch from; on a
	// host without git, just that shape skips.
	if name == "worktree" {
		for _, args := range [][]string{{"init", "-q"}, {"-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "base"}} {
			res, err := e.run(ctx, runOpts{Dir: work}, "git", args...)
			if err != nil || res.Code != 0 {
				return nil, "", skipf("git could not prepare a repository for the worktree shape: %v %.200s", err, res.Stderr)
			}
		}
	}
	settings := filepath.Join(root, "settings.json")
	res, err := e.gk(ctx, runOpts{}, "hooks-install", "--runtime", "claude-code", "--settings", settings,
		"--socket", e.Sock, "--state-dir", filepath.Join(root, "state"), "--mode", "enforce", "--binary", e.Bin, "--allow-rewritten")
	if err != nil {
		return nil, "", err
	}
	if res.Code != 0 {
		return nil, "", fmt.Errorf("hooks-install --allow-rewritten: exit %d: %.300s", res.Code, res.Stderr)
	}
	raw, err := os.ReadFile(settings)
	if err != nil {
		return nil, "", err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", err
	}
	if strings.Contains(string(raw), "export CLAGENTIC_IDENTITY_DIR=*") {
		return nil, "", errors.New("hooks-install --allow-rewritten registered the export-prefix allow rule")
	}
	sandbox := map[string]any{
		"enabled": true, "failIfUnavailable": true, "autoAllowBashIfSandboxed": true,
		"filesystem": map[string]any{"denyRead": []string{creds}},
	}
	if e.opts.NestedSandbox {
		sandbox["enableWeakerNestedSandbox"] = true
	}
	doc["sandbox"] = sandbox
	if len(deny) > 0 {
		doc["permissions"] = map[string]any{"deny": deny}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(settings, out, 0o600); err != nil {
		return nil, "", err
	}
	agents, err := json.Marshal(map[string]any{defBuilder: map[string]any{
		"description": "Runs the shell commands it is given and reports their output.",
		"prompt":      "Run exactly the shell commands you are given with the Bash tool, one at a time, and reply with their output only.",
		"tools":       []string{"Bash"},
	}})
	if err != nil {
		return nil, "", err
	}
	return &runtimeSetup{cli: cli, settings: settings, work: work, agents: string(agents)}, outside, nil
}

// sandboxSteps are the commands each actor runs, in this order. A read-only
// command is never rewritten (so the hook gives it no allow), and the denied
// credential reads must be calls the hook did rewrite and allow, so each is joined
// to a command that is not read-only. Every non-read-only step is a rewritten
// call: without the allow it would prompt, which a headless run records as a
// denial, so a run with no denial shows the allow was given.
func sandboxSteps(kind, outside string) []string {
	return []string{
		"find . -maxdepth 1",
		"find . -name x | wc -l",
		"date && find . -maxdepth 1",
		"touch ./made-" + kind,
		printenvCommand,
		"touch " + filepath.Join(outside, kind+"-marker"),
		"touch ./made-" + kind + "-b && cat ./creds/.env.dummy",
		printenvCommand + " && cat ./creds/.env.dummy",
	}
}

func (e *Env) sandboxPrompt(kind string, steps []string) string {
	list := strings.Join(steps, " ;; ")
	if kind == "main" {
		return driverPreamble + "Run these commands one at a time, each exactly as written (they are separated by ' ;; ', which is not part of any command), even if one fails: " + list + ". Then reply with the word done."
	}
	// The session prints its own directory first, so the subagent's is shown to
	// differ from it.
	sub := "Step 1: run this exact command: " + printenvCommand + ". Step 2: use the example-builder subagent with this prompt: Run these commands one at a time, each exactly as written (separated by ' ;; ', which is not part of any command), even if one fails, and reply with all their output: " + list + ". "
	switch kind {
	case "background":
		sub += "Start it in the background (run_in_background true). Then run the command sleep 20, up to five times, until its result has arrived. "
	case "worktree":
		sub += "Start it with isolation worktree. Wait for it in the foreground. "
	default:
		sub += "Wait for it in the foreground. "
	}
	return driverPreamble + sub + "Then reply with the word done."
}

// shapeSandbox runs the read-only, piped, compound, in-directory write, delivery,
// outside write and denied read commands for one way of reaching the hook, and
// checks what the runtime and the issuer produced rather than what the model said.
func (e *Env) shapeSandbox(ctx context.Context, kind string) error {
	setup, outside, err := e.sandboxSetup(ctx, kind)
	if err != nil {
		return err
	}
	steps := sandboxSteps(kind, outside)
	wantDirs := 2
	if kind == "main" {
		wantDirs = 1
	}
	var last error
	for attempt := 1; attempt <= e.opts.RuntimeAttempts; attempt++ {
		run, err := e.invokeRuntime(ctx, setup, e.sandboxPrompt(kind, steps), nil)
		if err != nil {
			return err
		}
		texts := toolResults(run.stream)
		seen := resultExcerpt(texts)
		if len(run.denials) > 0 {
			return fmt.Errorf("a permission prompt was raised under the setting: %.300s; tool results: %s", strings.Join(run.denials, " | "), seen)
		}
		if strings.Contains(run.stream, credMarker) {
			return errors.New("the dummy credential was read: the hook allow opened a path the sandbox denyRead closes")
		}
		if _, err := os.Stat(filepath.Join(outside, kind+"-marker")); err == nil {
			return errors.New("a write outside the sandbox write roots succeeded")
		}
		// The count rests on directories a printenv result printed, not on the
		// rewrite prefix a tool call carries. The session printed its own first, so
		// a subagent's directory must differ from it to count.
		if err := e.expectDirs(&runtimeRun{dirs: e.printedDirs(texts)}, wantDirs); err != nil {
			last = fmt.Errorf("%v; tool results: %s", err, seen)
			var again retryable
			if errors.As(err, &again) {
				continue
			}
			return last
		}
		// A worktree agent writes in its own checkout, so only the others leave
		// the file in the work directory.
		if kind != "worktree" {
			if _, err := os.Stat(filepath.Join(setup.work, "made-"+kind)); err != nil {
				last = retryable{fmt.Errorf("the in-directory write did not happen: %v; tool results: %s", err, seen)}
				continue
			}
		}
		writeErr := outsideWriteFailure(texts, kind+"-marker")
		if writeErr == "" {
			last = retryable{fmt.Errorf("the outside write did not fail with a sandbox error in a tool result; tool results: %s", seen)}
			continue
		}
		// The denied read must show the cat ran and failed; the marker being absent
		// alone would pass for a model that never ran the read.
		readErr := credReadFailure(texts)
		if readErr == "" {
			last = retryable{fmt.Errorf("no tool result shows the denied credential read failing with an OS error; tool results: %s", seen)}
			continue
		}
		return passNote{"outside write failed with: " + writeErr + "; credential read failed with: " + readErr}
	}
	return last
}

var credReadError = regexp.MustCompile(`cat: \./creds/\.env\.dummy: (Permission denied|No such file or directory|Operation not permitted)`)

// credReadFailure returns the OS error text of the failed credential read, or ""
// when no tool result shows one.
func credReadFailure(texts []string) string {
	if m := credReadError.FindStringSubmatch(strings.Join(texts, "\n")); m != nil {
		return m[1]
	}
	return ""
}

// outsideWriteFailure returns the OS error text of the failed write to the file
// named name outside the sandbox write roots, or "" when none is shown.
func outsideWriteFailure(texts []string, name string) string {
	for _, t := range texts {
		if !strings.Contains(t, name) {
			continue
		}
		for _, phrase := range []string{"Read-only file system", "Operation not permitted", "Permission denied"} {
			if strings.Contains(t, phrase) {
				return phrase
			}
		}
	}
	return ""
}

// toolResults returns the text of every tool result in a stream-json record.
func toolResults(stream string) []string {
	var out []string
	for _, line := range strings.Split(stream, "\n") {
		var rec struct {
			Message struct {
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || len(rec.Message.Content) == 0 {
			continue
		}
		var blocks []struct {
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
			Text    string          `json:"text"`
		}
		if json.Unmarshal(rec.Message.Content, &blocks) != nil {
			continue
		}
		for _, b := range blocks {
			if b.Type != "tool_result" {
				continue
			}
			var s string
			if json.Unmarshal(b.Content, &s) == nil {
				out = append(out, s)
				continue
			}
			var parts []struct {
				Text string `json:"text"`
			}
			if json.Unmarshal(b.Content, &parts) == nil {
				for _, p := range parts {
					out = append(out, p.Text)
				}
			}
		}
	}
	return out
}

// printedDirs lists the distinct delivery directories that tool results printed.
func (e *Env) printedDirs(texts []string) []string {
	return e.deliveredDirs(strings.Join(texts, "\n"))
}

// resultExcerpt is a bounded excerpt of the tool results that bear on a failure,
// so a failing run can be diagnosed after its directory is gone. The credential
// marker is never included.
func resultExcerpt(texts []string) string {
	const limit = 600
	var keep []string
	for _, t := range texts {
		if strings.Contains(t, "cat:") || strings.Contains(t, "touch:") || strings.Contains(t, "denied") ||
			strings.Contains(t, "Read-only") || strings.Contains(t, "not permitted") || strings.Contains(t, "No such file") {
			keep = append(keep, strings.TrimSpace(strings.ReplaceAll(t, credMarker, "[marker]")))
		}
	}
	s := strings.Join(keep, " | ")
	if len(s) > limit {
		s = strings.ToValidUTF8(s[:limit], "") + "..."
	}
	return s
}

// shapeSandboxDeny proves a native deny rule still holds over the hook's allow.
func (e *Env) shapeSandboxDeny(ctx context.Context) error {
	setup, _, err := e.sandboxSetup(ctx, "deny", "Bash(mkdir *)")
	if err != nil {
		return err
	}
	prompt := driverPreamble + "Run this exact command: " + deniedCommand + ". Then reply with the word done."
	run, err := e.invokeRuntime(ctx, setup, prompt, nil)
	if err != nil {
		return err
	}
	if len(run.denials) == 0 {
		return errors.New("a command matched by a deny rule was not denied under the hook allow")
	}
	// The deny must hold over a call that carried the hook's allow: the denied
	// command text is the rewritten one, the delivery statement in front of the
	// mkdir. A denial of the bare command would pass without any allow given.
	rewritten := false
	for _, d := range run.denials {
		if !strings.Contains(d, "mkdir") {
			return fmt.Errorf("an unexpected denial: %.200s", d)
		}
		if strings.Contains(d, deliveryPrefix) && strings.Contains(d, "; "+deniedCommand) {
			rewritten = true
		}
	}
	if !rewritten {
		return fmt.Errorf("the denied call did not carry the hook's rewrite, so the deny was not shown holding over an allow: %.300s", strings.Join(run.denials, " | "))
	}
	if _, err := os.Stat(filepath.Join(setup.work, "denied-dir")); err == nil {
		return errors.New("the denied command ran")
	}
	return nil
}
