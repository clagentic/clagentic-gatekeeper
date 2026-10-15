# Live test: the real caller shapes against an isolated issuer

`make live-test` builds the current tree, starts a private issuer, and runs the
shapes in which the issuer and its runtime adapters are actually called: real
processes over the real socket, with the kernel's `SO_PEERCRED` and `/proc`
deciding who the caller is. Unit tests cannot cover that, and a change to
anything that decides, refuses or rewrites at runtime (the binding, an adapter,
a hook) is only proven by a run like this.

It is self-contained. It needs no operator, no shared service and no installed
gatekeeper, so a merge gate can run it as a pre-check on its own.

## Run it

```
make live-test
make live-test LIVETEST_ARGS="--runtime-cli /path/to/runtime"
```

The make target runs `go run ./cmd/livetest`. The command is a separate program
rather than a `gatekeeper` subcommand so that test-only code is not part of the
shipped binary; it drives the binary as an external process, which is also what
the runtime binding needs (the harness and the binary under test must be
different executables).

Requirements: a Go toolchain (the tree is built) and linux. On any other
platform it reports one skip and exits 0.

| Flag | Meaning |
|------|---------|
| `--source <dir>` | Module root to build. Default `.`. |
| `--binary <path>` | Test this prebuilt binary and build nothing. |
| `--temp-dir <dir>` | Where the private directory is created. Default: the system temporary directory. The socket path inside it must stay under 108 bytes. |
| `--runtime-cli <name-or-path>` | The agent runtime CLI to drive. Default: the runtime's usual command name on `PATH`. Also read from `GATEKEEPER_LIVETEST_RUNTIME_CLI`. |
| `--runtime-env KEY=VALUE` | Extra environment for the runtime process (repeatable), for example a state directory or a credential. |
| `--no-runtime` | Skip every runtime shape without looking for the CLI. |
| `--require-runtime` | Turn a runtime shape that would skip into a failure, for a gate that must have the runtime evidence. |
| `--runtime-attempts N` | Attempts for a runtime shape whose model did not do what the prompt asked. Default 2. |
| `--runtime-timeout D` | Bound on one runtime invocation. Default 4m. |

## Output

One JSON object per line on stdout, as each shape finishes, then a summary:

```
{"shape":"issuer/session-direct-client","status":"pass"}
{"shape":"runtime-claude-code/main-headless-session","status":"skip","reason":"the runtime CLI was not found; ..."}
{"summary":{"fail":0,"pass":11,"skip":6}}
```

`status` is `pass`, `fail` or `skip`; `reason` explains a fail or a skip. The
exit status is 0 when nothing failed, 1 when any shape failed, and 130 when the
run was interrupted. Diagnostics go to stderr.

## What it does

1. Creates a private directory (mode 0700). Everything below lives in it.
2. Builds `./cmd/gatekeeper` into it (or adopts `--binary`).
3. Writes a signing key, created owner-only (0600) from its first byte, and two
   definitions with invented names (`example-lead`, `example-builder`).
4. Starts `gatekeeper serve` on a socket in the directory, in its own process
   group.
5. Runs the shapes below.
6. Stops serve and everything started in its group, removes the directory, and
   reports a `teardown` result. This happens on success, on failure, and on
   `SIGINT`, `SIGTERM` or `SIGHUP`. `SIGKILL` cannot be intercepted by any
   process.

It touches nothing outside that directory, with two exceptions it cannot avoid:
the Go toolchain's own build cache, and any state an agent runtime keeps for
itself when its shapes run (`--runtime-env` can point that elsewhere).

## Shapes

Issuer, always run:

| Shape | What it proves |
|-------|----------------|
| `issuer/session-direct-client` | A process that connects to the socket itself is its own runtime; the assertion verifies and names it. |
| `issuer/assertion-verifies-against-published-keys` | The assertion verifies, with the standard library alone, against the key set both from the published file and from the socket; a changed payload, an unknown key and an empty key set are refused. |
| `issuer/session-cli-direct` | `issue-session` run directly is bound to the process above it, not to itself. |
| `issuer/session-cli-under-command-wrapper` | The same through a `sh -c` wrapper, as a runtime that starts hooks through a shell would. |
| `issuer/child-under-command-wrapper-same-runtime` | `issue-child` under the same runtime succeeds and carries the child's claims. |
| `issuer/child-under-different-runtime-refused` | `issue-child` under a different runtime is refused as `parent_pid_mismatch`. |
| `issuer/unknown-definition-refused` | An unknown definition is refused as `definition_unknown`. |
| `adapter-process/child-holds-assertion` | The process adapter's assignment, placed in a child's environment, gives that child a valid assertion with no per-command step. |

Hook adapter, always run, no runtime needed. These feed the hook the payload
shapes of the runtime to the real binary, as separate processes:

| Shape | What it proves |
|-------|----------------|
| `adapter-claude-code/event-sequence-payload-driven` | session start, subagent start (one through a wrapper), per-agent rewrite with no permission decision and the original command byte for byte, a non-Bash tool left alone, subagent stop removing only its own directory. |
| `adapter-claude-code/compose-synthetic-upstream` | Composed after an upstream hook the harness writes itself: an allowing upstream gets the statement in front of its command; a denying one passes through byte for byte. |

Runtime, run when the runtime CLI is found. Each is one headless session with
an isolated settings file registered by `hooks-install` (no user or project
settings sources), in enforce mode, with the allow rules the shape needs and
nothing else:

| Shape | What it proves |
|-------|----------------|
| `runtime-claude-code/main-headless-session` | The main session's command sees the variable; no permission denial. |
| `runtime-claude-code/foreground-subagent` | A foreground subagent gets a variable of its own. |
| `runtime-claude-code/background-subagent` | So does a background one. |
| `runtime-claude-code/two-concurrent-subagents` | Two concurrent subagents and the main session each get a different one. |
| `runtime-claude-code/compound-command` | A compound command is delivered the variable and not denied. |
| `runtime-claude-code/unruled-command-still-prompts` | A command no rule covers is still denied, so the single allow rule opened nothing else. |

The model is asked to run fixed commands and never to expand a shell variable
itself (a runtime refuses a command whose variable it cannot check before it
runs, which would test the runtime and not the hook). Each shape checks what
the issuer made, not what the model said: the delivery directories it printed
must be under this run's spawn root, be distinct per agent, and the session's
must verify against the published key set. A shape whose model did not follow
the prompt is retried (`--runtime-attempts`); a denial is never retried.

A runtime shape skips, with the reason, when the CLI is not found, or when the
runtime cannot complete a model turn (no credential, no network). Under
`--require-runtime` those become failures.

## Running it from a merge gate

Configure the gate's pre-check to run the command and read its exit status:

```
make live-test LIVETEST_ARGS="--require-runtime --runtime-cli <runtime>"
```

Leave `--require-runtime` off for a gate on a host without the runtime: the
issuer and hook-adapter shapes still decide the verdict and the runtime shapes
are reported as skips with their reason. The run creates and removes its own
private directory and starts nothing that outlives it, so it needs no operator
acknowledgement of its own. A step that does touch live shared state (the
installed binary, user-level settings, a real git host) is not part of it and
still needs one.

A developer who wants the per-shape record from a normal test run:

```
go test ./internal/livetest -run RunOnThisHost -live -v
```
