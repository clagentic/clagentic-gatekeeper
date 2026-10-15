// Command livetest runs the real gatekeeper binary through its caller shapes in
// a private temporary directory and prints one JSON line per shape:
//
//	{"shape":"...","status":"pass|fail|skip","reason":"..."}
//
// followed by a {"summary":{...}} line. It exits non-zero when any shape fails.
// It touches nothing outside its temporary directory except the build cache of
// the Go toolchain and whatever state an agent runtime keeps for itself.
//
// Each agent runtime is optional: when its CLI is absent the runtime shapes skip
// with a reason. See docs/LIVE-TEST.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/clagentic/clagentic-gatekeeper/internal/livetest"
)

// envRuntimeCLI names the runtime CLI when --runtime-cli is not given.
const envRuntimeCLI = "GATEKEEPER_LIVETEST_RUNTIME_CLI"

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var opts livetest.Options
	var runtimeEnv listFlag
	fs := flag.NewFlagSet("livetest", flag.ContinueOnError)
	fs.StringVar(&opts.Source, "source", ".", "module root to build the binary from")
	fs.StringVar(&opts.Binary, "binary", "", "use this prebuilt gatekeeper binary instead of building")
	fs.StringVar(&opts.TempParent, "temp-dir", "", "directory to create the private working directory in (default: the system temporary directory)")
	fs.StringVar(&opts.RuntimeCLI, "runtime-cli", os.Getenv(envRuntimeCLI), "agent runtime CLI to drive, a name on PATH or a path (default: the runtime's usual command name; env "+envRuntimeCLI+")")
	fs.Var(&runtimeEnv, "runtime-env", "KEY=VALUE added to the runtime's environment (repeatable)")
	fs.BoolVar(&opts.NoRuntime, "no-runtime", false, "skip every runtime shape without looking for the CLI")
	fs.BoolVar(&opts.RequireRuntime, "require-runtime", false, "fail, instead of skip, a runtime shape that cannot run")
	fs.IntVar(&opts.RuntimeAttempts, "runtime-attempts", 2, "attempts for a runtime shape whose model did not follow the prompt")
	fs.DurationVar(&opts.RuntimeTimeout, "runtime-timeout", 4*time.Minute, "bound on one runtime invocation")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	opts.RuntimeEnv = runtimeEnv
	for _, kv := range opts.RuntimeEnv {
		if !strings.Contains(kv, "=") {
			fmt.Fprintf(os.Stderr, "--runtime-env wants KEY=VALUE\n")
			os.Exit(2)
		}
	}

	// Interrupt and termination cancel the context; Run then stops what it
	// started and removes its directory before it returns.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	code := livetest.Run(ctx, opts, os.Stdout)
	stop()
	os.Exit(code)
}
