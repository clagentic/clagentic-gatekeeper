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
	// hookWatchdogSlack is how long past the call timeout a hook process may live
	// before it exits on its own, whatever it is waiting for.
	hookWatchdogSlack = 2 * time.Second
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
// exit code.
func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gatekeeper hook claude-code <event> [flags] | gatekeeper hook process [flags]")
		return 2
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
	return 2
}

// runHookClaudeCode serves one Claude Code event. Past flag parsing it never
// fails the runtime: whatever goes wrong, the exit code is 0 and the tool call
// proceeds unchanged. The one exception is a composed upstream hook whose own
// verdict is passed through.
func runHookClaudeCode(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gatekeeper hook claude-code <event> [flags]")
		return 2
	}
	event := args[0]
	fs := flag.NewFlagSet("hook claude-code "+event, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "issuer unix socket (required unless --config names one)")
	cfgPath := fs.String("config", "", "config file whose identity.socket_path names the socket")
	stateDir := fs.String("state-dir", "", "absolute directory for hook state, logs and captures (required)")
	modeName := fs.String("mode", string(hook.ModeWarn), "warn (issue and capture, rewrite nothing) or enforce")
	origin := fs.String("origin", "", "origin sent with issue-session: scheduled, loop, trigger or agent")
	refresh := fs.Duration("refresh-below", 0, "user-prompt-submit: ask for a new session assertion below this remaining lifetime (0 disables)")
	compose := fs.String("compose", "", "pre-tool-use-bash: absolute path of another Bash-rewriting hook to run first")
	timeout := fs.Duration("timeout", hookCallTimeout, "bound on each call to the issuer")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if !knownEvent(event) {
		fmt.Fprintf(stderr, "unknown claude-code event %q\n", event)
		return 2
	}
	mode, err := hook.ParseMode(*modeName)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *origin == "human" {
		fmt.Fprintln(stderr, "origin human is never requested by the adapter")
		return 2
	}
	if !filepath.IsAbs(*stateDir) {
		fmt.Fprintln(stderr, "--state-dir must be an absolute path")
		return 2
	}
	log := hook.Log{Path: filepath.Join(*stateDir, "hook.log")}

	// Everything below fails open.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-time.After(*timeout + hookWatchdogSlack):
			log.Printf("%s: exceeded %s; exiting without a rewrite", event, *timeout+hookWatchdogSlack)
			os.Exit(0)
		}
	}()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s: panic: %v", event, r)
			code = 0
		}
	}()

	sock, err := explicitSocket(*socket, *cfgPath)
	if err != nil {
		log.Printf("%s: %v", event, err)
		return 0
	}
	h := &hook.ClaudeCode{
		Issuer: identity.Client{Socket: sock, Timeout: *timeout},
		Store:  hook.Store{Root: *stateDir},
		Mode:   mode, Origin: *origin, RefreshBelow: *refresh, Compose: *compose,
		Log: log, Capture: hook.Capture{Path: filepath.Join(*stateDir, "shapes.jsonl")},
		HookPID: os.Getpid(),
	}
	res := h.Handle(event, stdin)
	if len(res.Stderr) > 0 {
		_, _ = stderr.Write(res.Stderr)
	}
	if len(res.Stdout) > 0 {
		if _, err := stdout.Write(res.Stdout); err != nil {
			log.Printf("%s: write reply: %v", event, err)
			return 0
		}
	}
	return res.ExitCode
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
		return errors.New("origin human is never requested by the adapter")
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
	timeoutSeconds := fs.Int("timeout", defaultHookTimeoutSeconds, "runtime-side timeout in seconds for each hook")
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
