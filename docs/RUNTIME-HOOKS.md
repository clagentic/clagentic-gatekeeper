# Runtime adapters and the runtime binding

The issuer (`gatekeeper serve`) hands an assertion to a process. This page
describes who that process is, and the client commands that deliver the
assertion into a runtime: `hook claude-code`, `hook process`, `hooks-install`
and `render-agent`.

## The binding invariant

An assertion issued by `issue-session` or `issue-child` is bound to the
**runtime process that owns the session** (for Claude Code, the long-lived
Claude Code process). It is never bound to the transient process that made the
request, and never to anything the request says.

The binding is derived from the kernel's view of the requester: the
`SO_PEERCRED` pid, then the parent chain `/proc` reports, read from `/proc` and
bracketed by start time. A pid, start time and executable file identity triple
(device and inode of `/proc/<pid>/exe`) is recorded for the runtime and checked
again on every `issue-child`. A `/proc` read failure, or an ancestry that breaks
a rule below, refuses the request. Nothing falls back to binding the requester.

`rt.id` of an assertion comes from the bound runtime process (its executable,
or for an interpreter its script), not from the hook.

### Which process is the requester

The issuer knows its own client: `serve` records the path of the `gatekeeper`
binary it runs from. A peer whose executable is that file is a **client
process** (a hook, or the `issue-session` / `issue-child` CLI) and is bound to
the runtime above it. Any other peer is a direct client of the socket and is its
own runtime, as before.

The comparison is by device and inode, resolved on each request, so replacing
the binary in place (a rename, as a package upgrade does) does not strand hooks
started from the new file.

### The ancestry rule

For a client process:

1. Start at the peer's parent (the ppid `/proc` reports for the `SO_PEERCRED`
   pid).
2. If that parent is a shell running a command string (`sh -c ...`, `bash -lc
   ...`: an executable named sh, bash, dash, ash, zsh, ksh, mksh or busybox with
   a leading short option cluster containing `c`), it is a wrapper the runtime
   used to start the hook. Climb to its parent. At most three wrappers are
   climbed; more refuses.
3. The first ancestor that is not such a wrapper is the runtime.
4. A shell running a script file (`sh launcher.sh`), an interactive shell, and
   every non-shell are never skipped. A launcher written as a shell script is
   therefore the runtime for the clients it starts.

Conditions that refuse (`runtime_unbound`):

- the parent is pid 0 or 1 (an orphan or init: no runtime above);
- an ancestor runs as a different uid than the peer, or its uid cannot be read;
- an ancestor started after the process below it (a parent cannot);
- the chain is read twice, each process bracketed by start time and parent pid,
  and any difference between the two reads (a process replaced mid-walk);
- more than three command wrappers.

A `/proc` read failure anywhere in the walk refuses with `peer_unattested`.

### Why request content cannot steer it

The walk starts from the kernel-reported pid and follows only the ppid values
`/proc` reports. The request body is never consulted. A request can still carry
a runtime id, and it must equal the one derived from the bound runtime or the
request is refused (`runtime_mismatch`); it cannot select a different runtime.
There is no request field that names a pid, a process, or a binding.

The trust boundary is the one the issuer already has: the serving uid. A process
of the same uid can start a child of any process it can see, so the binding
attributes a session to a runtime process of that uid; it does not defend one
same-uid process against another. Grants never follow `/proc` data: roles,
grade and delivery directory ownership follow the `SO_PEERCRED` uid and the
definition, exactly as before.

### What a child must satisfy

`issue-child` recomputes the binding for the requester and requires that the
parent token's recorded runtime has the same pid, start time and executable
identity. Hooks of one runtime therefore agree, a hook under a different
runtime is refused (`parent_pid_mismatch`), and a runtime that restarted does
not inherit the sessions of the one it replaced.

### Process adapter

`gatekeeper hook process --socket <path> [--definition <name>]` is for a
launcher that starts a runtime as a subprocess. Run it before exec; it issues a
session and prints `CLAGENTIC_IDENTITY_DIR=<dir>` on stdout. The launcher puts
that in the child's environment and the child holds its assertion for its whole
life with no per-command step. The binding is to the launcher process (the
parent of the `hook process` invocation), so run it as a direct child of the
launcher, not through `sh -c` from a script that is itself a wrapper of
something else.

It exits non-zero and prints nothing when it cannot issue. Unlike the event
hooks it is not fail-open: the launcher decides what a child with no identity
may do.

## Claude Code hooks

```
gatekeeper hook claude-code <event> --socket <path> --state-dir <dir> [--mode warn|enforce]
```

The hook JSON arrives on stdin. The socket and state directory are always
explicit: there is no default socket (`--config` with `identity.socket_path` is
accepted in place of `--socket`).

| Event | Action |
|-------|--------|
| `session-start` | `issue-session`. The definition is the payload's `agent_type` when the session runs under a harness agent; `--origin` comes from configuration. Records the delivery directory. Prints nothing (stdout of this event becomes model context). |
| `subagent-start` | `issue-child` with the payload's `agent_type` and `agent_id`, parented on the session assertion. Prints nothing. |
| `pre-tool-use-bash` | In enforce mode prefixes exactly one statement, `export CLAGENTIC_IDENTITY_DIR=<dir>; `, to the original command for the current `agent_id` (or the session when the payload has none). The original text follows byte for byte. No shell wrapper, no other variable, and `TMPDIR` is never touched. A command that already starts with the statement is left alone. If the agent has no directory yet (its start event never arrived), the first Bash call issues the child. |
| `subagent-stop` | Removes the agent's delivery directory and record. The directory is removed only if it is named like an issuer-created directory, is a real directory owned by the user, and holds an assertion. |
| `user-prompt-submit` | When `--refresh-below` is set and the session assertion has less than that left, asks for a new session under the same definition and records the new directory. The old directory is left for the issuer's reaper because a running command may still use it. |

### No new permission prompts

The reply of `pre-tool-use-bash` carries `permissionDecision: "allow"` **only**
when it rewrites the command: the harness re-checks a rewritten command, so
without it every rewritten call would fall into the operator's permission flow.
Every other event, and every Bash call that is not rewritten (no session, a
non-Bash tool, expired assertion, warn mode), exits 0 with empty output and
leaves the runtime's own permission flow untouched. The hook never wraps the
command in `sh -c` or `bash -c`.

### Failure behaviour

A failed, erroring or slow hook never blocks a tool call and never hangs a
session start. Every error is appended to `<state-dir>/hook.log` (ids and causes
only, never a token or payload value) and the hook exits 0 with no output, so
the command runs without the export. Each call to the issuer is bounded by
`--timeout` (default 3s) and the process exits on its own shortly after,
whatever it is waiting for. The registration gives the runtime a 5s timeout.

Consumers must fail closed on an absent or invalid `CLAGENTIC_IDENTITY_DIR`; the
hook's delivery is best effort by design.

### Warn mode first

A registration ships in `warn` mode (the default of `hooks-install`): hooks
issue, record and log, but rewrite nothing, and each event appends one line to
`<state-dir>/shapes.jsonl`: the event name, which payload members arrived and of
which JSON type (never a value), the decision, and the hook process's ancestry
(pid, ppid, comm, executable name and option flags, never an argument value).
That file is how the real payload shapes and the real hook process tree are
captured before `--mode enforce` is registered.

### Coexisting with another Bash-rewriting hook

Runtime hooks that match the same tool run in parallel, and when several return
`updatedInput` the last to finish wins, nondeterministically. Two registered
Bash rewriters therefore drop each other's output. A deployment that already
registers one (for example a per-spawn environment stamp) registers this hook
**instead of** it, with `--compose <absolute path>`: the other hook is run first
on the same payload, and this hook prefixes its one statement to whatever command
that hook produced.

- the other hook exits non-zero: its stdout, stderr and exit code pass through
  and nothing is added, so a deny stays a deny;
- it cannot be run, or exceeds 3s: the call is handled as if not composed;
- it returns no rewrite: its reply passes through unchanged;
- it rewrites: the statement goes in front of its command and the rest of its
  reply, its permission decision included, is kept.

In warn mode the composed hook's reply is returned unchanged.

### Registration

```
gatekeeper hooks-install --runtime claude-code --settings <path> --socket <path> \
    [--state-dir <dir>] [--mode warn|enforce] [--origin <o>] [--refresh-below 30m] \
    [--compose <path>] [--binary <path>] [--dry-run]
gatekeeper hooks-install --runtime claude-code --settings <path> --remove
```

Registers `SessionStart`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`
and `PreToolUse` (matcher `Bash`), each in a group of its own so removal edits
nothing it did not create. It is idempotent: a second run with the same options
does not touch the file; a changed option (the mode, say) updates the adapter's
own entries in place; duplicates collapse to one. Foreign hooks and settings are
never edited. The settings file is parsed and rewritten as JSON, so object keys
come out sorted and formatting is normalized on the first write.

`--remove` is the rollback: it deletes exactly the adapter's entries and the
groups that held only them.

### Limitations

- The codex adapter is not part of this release. A runtime without a
  per-command hook cannot refresh or scope the variable per command; the
  process adapter is the supported shape for it (one session per launched
  process, fixed for its life).
- A hook command must run `gatekeeper` directly (as `hooks-install` writes it).
  A hook that runs a wrapper script makes the script's shell the runtime.
- Windows and macOS build the client commands; `serve` and the binding are
  linux-only.

## `render-agent`

```
gatekeeper render-agent --runtime claude-code [--definitions-dir <dir>] <definition>
```

Reads a canonical definition (a path, or a name with `--definitions-dir`) and
writes the Claude Code native agent: frontmatter with `name`, `description`,
`tools` (a list becomes one comma separated string) and `model`, then the body
unchanged. `roles` and `trust_boundary` are the issuer's members and are not
carried. The native format requires a description, so a definition without one is
refused.
