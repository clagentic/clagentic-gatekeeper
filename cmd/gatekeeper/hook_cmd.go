package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/config"
	"github.com/clagentic/clagentic-gatekeeper/internal/hook"
	"github.com/clagentic/clagentic-gatekeeper/internal/identity"
)

// hookEnvName is the delivery variable, named here once for the usage text.
const hookEnvName = hook.EnvDir

const (
	// hookCallTimeout bounds each call to the issuer socket.
	hookCallTimeout = 3 * time.Second
	// hookOwnSlack is how long past the issuer call timeout gatekeeper's own part
	// of a hook may take before the hook gives up on it and answers with what it
	// already has.
	hookOwnSlack = 2 * time.Second
	// defaultHookTimeoutSeconds is the runtime-side timeout a registration sets.
	defaultHookTimeoutSeconds = 5
	defaultRefreshBelow       = 30 * time.Minute
)

// explicitSocket resolves the issuer socket for a client that must not guess:
// the flag, else identity.socket_path from the config, else an error. Unlike
// socketFor it has no built-in default, so a hook or a registration can never
// quietly talk to a socket nobody named.
func explicitSocket(flagValue, cfgPath string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if cfgPath != "" {
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return "", fmt.Errorf("load config: %w", err)
		}
		if cfg.Identity.SocketPath != "" {
			return cfg.Identity.SocketPath, nil
		}
	}
	return "", errors.New("no socket: pass --socket, or --config with identity.socket_path set")
}

// runHook dispatches `gatekeeper hook <adapter> ...`. It returns the process
// exit code. No path here exits 2 on its own: in a runtime's hook protocol 2 is a
// blocking verdict, and a verdict is not gatekeeper's to give. A command that is
// not a usable hook invocation exits 1, which a runtime reports without blocking.
func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gatekeeper hook claude-code <event> [flags] | gatekeeper hook process [flags]")
		return 1
	}
	switch args[0] {
	case "claude-code":
		return runHookClaudeCode(args[1:], stdin, stdout, stderr)
	case "process":
		if err := runHookProcess(args[1:], stdout); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "unknown hook adapter %q\n", args[0])
	return 1
}

// failOpen records why a hook is doing nothing. The reason goes to the hook log
// when the state directory is usable and to diag, which is the process stderr
// except when a composed upstream owns it.
func failOpen(diag io.Writer, log hook.Log, event, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s: %s", event, msg)
	fmt.Fprintf(diag, "gatekeeper hook %s: %s\n", event, msg)
}

// writeResult is the one place a hook process writes its reply. The exit code is
// the result's whether or not the writes succeed: a failed write is logged and
// never turns an upstream's blocking exit into 0.
func writeResult(res hook.Result, stdout, stderr io.Writer, log hook.Log, event string) int {
	if len(res.Stderr) > 0 {
		if _, err := stderr.Write(res.Stderr); err != nil {
			log.Printf("%s: write stderr: %v", event, err)
		}
	}
	if len(res.Stdout) > 0 {
		if _, err := stdout.Write(res.Stdout); err != nil {
			log.Printf("%s: write reply: %v", event, err)
		}
	}
	return res.ExitCode
}

// runBounded runs gatekeeper's own part of a hook under one deadline. It is the
// only place a hook recovers a panic: a panic, like a missed deadline, yields
// fallback, which is the composed upstream's result when there is one and empty
// otherwise. Without the recover a panic would exit 2, a blocking verdict.
func runBounded(deadline time.Duration, fallback hook.Result, log hook.Log, event string, work func() hook.Result) hook.Result {
	done := make(chan hook.Result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("%s: panic: %v", event, r)
				done <- fallback
			}
		}()
		done <- work()
	}()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case res := <-done:
		return res
	case <-timer.C:
		log.Printf("%s: gatekeeper's part exceeded %s; answering with the upstream result", event, deadline)
		return fallback
	}
}

// parseBudget reads an --upstream-timeout value. A value that is not a positive
// duration is the registered default: a bad budget never costs the upstream its
// verdict.
func parseBudget(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return hook.DefaultUpstreamTimeout
	}
	return hook.UpstreamBudget(d)
}

// fixedCompose finds the composed hook at the one argv position hooks-install
// writes it: directly after the event, as `--compose <path>` optionally followed
// by `--upstream-timeout <duration>`. It is read before any flag is parsed, so
// nothing later on the command line, a flag that does not parse included, can
// keep the upstream from running. A hand-written registration that puts these
// flags elsewhere is found only if the whole command line parses.
func fixedCompose(event string, rest []string) (exe string, budget time.Duration, ok bool) {
	if event != hook.EventPreToolUseBash || len(rest) < 2 || rest[0] != "--compose" || rest[1] == "" {
		return "", 0, false
	}
	budget = hook.DefaultUpstreamTimeout
	if len(rest) >= 4 && rest[2] == "--upstream-timeout" {
		budget = parseBudget(rest[3])
	}
	return rest[1], budget, true
}

// runHookClaudeCode serves one Claude Code event and writes its one reply.
func runHookClaudeCode(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	res, log, event := serveClaudeCode(args, stdin, stderr)
	return writeResult(res, stdout, stderr, log, event)
}

// serveClaudeCode computes the reply to one Claude Code event. It never blocks
// the runtime: whatever goes wrong inside gatekeeper, including a bad flag, an
// unknown event or a panic, the result carries no decision and exit 0, and the
// reason is logged.
//
// In compose mode the composed upstream hook runs first, on the raw stdin, and
// its result is the process result unless gatekeeper's own bounded part adds its
// one statement to an upstream allow or no-decision. Every other path, including
// every gatekeeper failure, yields the upstream's bytes and exit code exactly,
// so a registration that composes loses nothing of the hook it replaced.
func serveClaudeCode(args []string, stdin io.Reader, stderr io.Writer) (hook.Result, hook.Log, string) {
	if len(args) == 0 {
		failOpen(stderr, hook.Log{}, "claude-code", "no event named")
		return hook.Result{}, hook.Log{}, "claude-code"
	}
	event := args[0]

	var (
		composing bool
		raw       []byte
		up        hook.Result
		upErr     error
		readErr   error
	)
	// diag is where gatekeeper's own diagnostics go. With an upstream composed the
	// stderr belongs to the upstream's reply and carries only its bytes.
	var diag io.Writer = stderr
	runUpstream := func(exe string, budget time.Duration) {
		composing, diag = true, io.Discard
		// The upstream gets the stdin as it was read, whatever it holds and however
		// much of it there is.
		raw, readErr = io.ReadAll(stdin)
		up, upErr = hook.RunUpstream(exe, raw, budget)
	}
	if exe, budget, ok := fixedCompose(event, args[1:]); ok {
		runUpstream(exe, budget)
	}
	fallback := func() hook.Result {
		if composing && upErr == nil {
			return up
		}
		return hook.Result{}
	}

	fs := flag.NewFlagSet("hook claude-code "+event, flag.ContinueOnError)
	fs.SetOutput(diag)
	socket := fs.String("socket", "", "issuer unix socket (required unless --config names one)")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	stateDir := fs.String("state-dir", "", "absolute directory for hook state, logs and captures (required)")
	modeName := fs.String("mode", string(hook.ModeWarn), "warn (issue and capture, rewrite nothing) or enforce")
	origin := fs.String("origin", "", "origin sent with issue-session: scheduled, loop, trigger or agent")
	refresh := fs.Duration("refresh-below", 0, "user-prompt-submit: ask for a new session assertion below this remaining lifetime (0 disables)")
	compose := fs.String("compose", "", "pre-tool-use-bash: absolute path of another Bash-rewriting hook to run first (hooks-install writes it directly after the event)")
	upstreamTimeout := fs.String("upstream-timeout", "", "pre-tool-use-bash with --compose: the budget of the composed hook, equal to the timeout it has when registered alone; a value that is not a positive duration means the default")
	timeout := fs.Duration("timeout", hookCallTimeout, "bound on each call to the issuer")
	if err := fs.Parse(args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			failOpen(diag, hook.Log{}, event, "flags: %v", err)
		}
		return fallback(), hook.Log{}, event
	}
	if !composing && event == hook.EventPreToolUseBash && *compose != "" {
		runUpstream(*compose, parseBudget(*upstreamTimeout))
	}

	// Paths derived from the state directory exist only when it is absolute; a
	// missing or relative one disables the store, the log and the capture
	// entirely, so a bad value reads and writes nothing relative to wherever the
	// runtime happened to run.
	log, capture, root := hook.Log{}, hook.Capture{}, ""
	if filepath.IsAbs(*stateDir) {
		root = *stateDir
		log = hook.Log{Path: filepath.Join(root, "hook.log")}
		capture = hook.Capture{Path: filepath.Join(root, "shapes.jsonl")}
	}
	if readErr != nil {
		log.Printf("%s: reading the payload: %v", event, readErr)
	}
	if upErr != nil {
		log.Printf("%s: %v", event, upErr)
	}
	if !knownEvent(event) {
		failOpen(diag, log, event, "unknown claude-code event")
		return fallback(), log, event
	}
	callTimeout := *timeout
	if callTimeout <= 0 {
		failOpen(diag, log, event, "--timeout must be positive; using %s", hookCallTimeout)
		callTimeout = hookCallTimeout
	}
	// A mode that cannot be read becomes warn, which rewrites nothing.
	mode, err := hook.ParseMode(*modeName)
	if err != nil {
		failOpen(diag, log, event, "%v; running as warn", err)
		mode = hook.ModeWarn
	}
	if root == "" {
		failOpen(diag, log, event, "--state-dir must be an absolute path; keeping no state")
	}

	h := &hook.ClaudeCode{
		Store: hook.Store{Root: root},
		Mode:  mode, Origin: *origin, RefreshBelow: *refresh,
		Log: log, Capture: capture,
		HookPID: os.Getpid(),
	}
	// An issuer that cannot be named is an issuer that always refuses: the event
	// still runs, so a composed upstream still speaks, and the reason is logged
	// with every failed issue.
	sock, err := explicitSocket(*socket, *cfgPath)
	if err != nil {
		h.Issuer = hook.UnavailableIssuer{Err: err}
	} else {
		h.Issuer = identity.Client{Socket: sock, Timeout: callTimeout}
	}

	res := runBounded(callTimeout+hookOwnSlack, fallback(), log, event, func() hook.Result {
		if composing {
			return h.HandleComposed(raw, up, upErr)
		}
		return h.Handle(event, stdin)
	})
	return res, log, event
}

func knownEvent(event string) bool {
	for _, e := range hook.Events {
		if e == event {
			return true
		}
	}
	return false
}

// runHookProcess is the process adapter for a launcher that starts a runtime as
// a subprocess: it issues a session before exec and prints the assignment the
// child's environment needs. Unlike the event hooks it fails loudly, with a
// non-zero exit and nothing on stdout, because the launcher is the one to
// decide what a runtime without an identity may do.
func runHookProcess(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("hook process", flag.ContinueOnError)
	socket := fs.String("socket", "", "issuer unix socket (required unless --config names one)")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	definition := fs.String("definition", "", "definition the child runs as")
	origin := fs.String("origin", "", "origin: scheduled, loop, trigger or agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *origin == "human" {
		return hook.ErrOriginHuman
	}
	sock, err := explicitSocket(*socket, *cfgPath)
	if err != nil {
		return err
	}
	line, err := hook.ProcessAssignment(identity.Client{Socket: sock, Timeout: hookCallTimeout}, *definition, *origin)
	if err != nil {
		return fmt.Errorf("hook process: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("hook process: write assignment: %w", err)
	}
	return nil
}

// defaultStateDir is where hooks keep state when hooks-install is not told: a
// per-user cache directory. The result is written into the registered command,
// so a hook itself never defaults.
func defaultStateDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no --state-dir given and no user cache directory: %w", err)
	}
	return filepath.Join(base, "clagentic-gatekeeper", "hooks"), nil
}

// runHooksInstall registers (or with --remove unregisters) the hooks of a
// runtime in its settings file, idempotently.
func runHooksInstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("hooks-install", flag.ContinueOnError)
	runtimeName := fs.String("runtime", "", "runtime to register hooks for: claude-code (required)")
	settings := fs.String("settings", "", "settings file to edit (required)")
	socket := fs.String("socket", "", "issuer unix socket written into each hook (required unless --config names one)")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	stateDir := fs.String("state-dir", "", "absolute hook state directory (default: a per-user cache directory)")
	modeName := fs.String("mode", string(hook.ModeWarn), "warn (default: issue and capture, rewrite nothing) or enforce")
	origin := fs.String("origin", "", "origin for issue-session: scheduled, loop, trigger or agent")
	refresh := fs.Duration("refresh-below", defaultRefreshBelow, "refresh the session assertion below this remaining lifetime (0 disables)")
	compose := fs.String("compose", "", "absolute path of another Bash-rewriting hook to compose on pre-tool-use-bash")
	binary := fs.String("binary", "", "absolute path of the gatekeeper binary (default: this binary)")
	timeoutSeconds := fs.Int("timeout", defaultHookTimeoutSeconds, "runtime-side timeout in seconds for each hook; with --compose it is the budget of the composed hook (the timeout it has registered alone), and the composed entry's own timeout is that plus allowance for gatekeeper's part")
	remove := fs.Bool("remove", false, "unregister the hooks (the rollback); other settings are untouched")
	dryRun := fs.Bool("dry-run", false, "print the resulting settings instead of writing them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runtimeName != "claude-code" {
		return fmt.Errorf("--runtime %q is not supported; the supported runtime is claude-code", *runtimeName)
	}
	if *settings == "" {
		return errors.New("--settings is required")
	}
	var in *hook.Install
	if !*remove {
		sock, err := explicitSocket(*socket, *cfgPath)
		if err != nil {
			return err
		}
		mode, err := hook.ParseMode(*modeName)
		if err != nil {
			return err
		}
		bin := *binary
		if bin == "" {
			if bin, err = os.Executable(); err != nil {
				return fmt.Errorf("resolve this binary: %w", err)
			}
		}
		state := *stateDir
		if state == "" {
			if state, err = defaultStateDir(); err != nil {
				return err
			}
		}
		in = &hook.Install{
			Binary: bin, Socket: sock, StateDir: state, Mode: mode, Origin: *origin,
			RefreshBelow: *refresh, Compose: *compose, TimeoutSeconds: *timeoutSeconds,
		}
		if err := in.Validate(); err != nil {
			return err
		}
		if in.Compose != "" {
			if err := hook.CheckUpstream(in.Compose); err != nil {
				return err
			}
		}
	}
	changed, content, err := hook.ApplySettingsFile(*settings, in, *remove, *dryRun)
	if err != nil {
		return fmt.Errorf("hooks-install: %w", err)
	}
	switch {
	case !changed:
		_, err = fmt.Fprintf(stdout, "%s: no change\n", *settings)
	case *dryRun:
		_, err = stdout.Write(content)
	case *remove:
		_, err = fmt.Fprintf(stdout, "%s: hooks unregistered\n", *settings)
	default:
		_, err = fmt.Fprintf(stdout, "%s: hooks registered (mode %s)\n", *settings, in.Mode)
	}
	return err
}

// runRenderAgent writes a definition in a runtime's native agent format.
func runRenderAgent(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("render-agent", flag.ContinueOnError)
	runtimeName := fs.String("runtime", "", "runtime whose native format to write: claude-code (required)")
	defsDir := fs.String("definitions-dir", "", "resolve the argument as a definition name in this directory instead of a file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runtimeName != "claude-code" {
		return fmt.Errorf("--runtime %q is not supported; the supported runtime is claude-code", *runtimeName)
	}
	if fs.NArg() != 1 {
		return errors.New("render-agent takes exactly one definition (a file path, or a name with --definitions-dir)")
	}
	raw, err := hook.ReadDefinition(*defsDir, fs.Arg(0))
	if err != nil {
		return fmt.Errorf("render-agent: %w", err)
	}
	out, err := hook.RenderClaudeCode(raw)
	if err != nil {
		return fmt.Errorf("render-agent: %w", err)
	}
	_, err = stdout.Write(out)
	return err
}
