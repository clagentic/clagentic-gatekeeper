# Setup — attested identity and the trust model

This doc is for a consumer setting up Gatekeeper for the first time. It covers
one specific piece of the setup: how Gatekeeper decides *who is asking* before
it decides *what they're allowed to mint*. Get this wrong and you either fail
closed with no obvious reason, or you run on the built-in fallback thinking
you configured something stronger.

Authoritative source for everything below: [`internal/attestation/attestation.go`](../internal/attestation/attestation.go)
(package doc + `Resolver.Resolve`), [`internal/attestation/chain.go`](../internal/attestation/chain.go)
(`NewChain`), and [`internal/config/config.go`](../internal/config/config.go)
(`AttestationConfig`). If this doc and the code ever disagree, the code wins —
file an issue.

## The three-layer trust model (tome #700)

Gatekeeper's authorization decision is three layers, and this doc is about
layer 1 only:

1. **Attested invoking identity** — who is actually asking, per whatever your
   deployment's identity source vouches for. This is `internal/attestation`,
   covered below. It is *resolved*, never self-declared by the caller.
2. **Crew role / `--caller`** — which role the attested identity is entitled
   to mint (`roles.<name>.entitled_identities` in `config.yaml`; see
   [`docs/ROLES.md`](ROLES.md) for the full entitlement + App-slug
   verification gate).
3. **Credential grantor** — the secret broker that actually holds the GitHub
   App credentials for the role once entitlement is verified.

Layer 1 only answers "who is this." It carries no policy of its own — mint
decides what an identity may do (layer 1 -> 2), and the broker decides what
credentials that role gets (layer 2 -> 3).

## Attested identity: how it's resolved

`internal/attestation.Resolver` tries a **fixed order** of providers and
returns the first identity found:

1. **Configured provider** — your own identity source, pointed at via
   `config.yaml`. Takes precedence when set. See below.
2. **Sidecar adapter** — reads a per-spawn or per-session identity file
   written by an external harness, when configured and present. Gatekeeper
   does not assume any specific harness exists.
3. **Built-in fallback** — the OS-reported invoking user. Always available,
   no configuration required. See "The built-in fallback" below.

The order is fixed by `NewChain` and is not configurable. What *is*
configurable is whether layers 1 and 2 exist at all — an unconfigured layer
is omitted from the chain, not stubbed in.

## Binding is fail-closed

If a provider has nothing to offer for the current invocation, it declines
(`ErrNoIdentity`) and `Resolver.Resolve` falls through to the next provider in
the chain. That is the *only* case that falls through.

Any other error — a configured provider that is set up but broken (for
example, `configured.type: file` pointing at a file that exists but can't be
read for a permissions reason other than "not found") — is returned
immediately as a hard failure. Resolution stops. It does **not** silently
fall through to the sidecar or built-in layers.

In practice this means: a misconfigured attestation source fails closed. You
will see an error, not a silent downgrade to a weaker identity source. This
is intentional — a deployment that believes it configured real attestation
must never unknowingly end up running the built-in fallback because its real
config was broken.

## Configuring your own attestation source (layer 1a)

This is the `attestation.configured` block in your `config.yaml` (see
[`config.example.yaml`](../config.example.yaml) for the full annotated
reference):

```yaml
attestation:
  configured:
    type: ""      # "env" | "file" — empty disables this layer
    source: ""    # env var name (type: env) or file path (type: file)
```

- `type: env` — Gatekeeper reads the attested identity from the environment
  variable named by `source`. Suitable when your harness already exports the
  invoking identity into the process environment.
- `type: file` — Gatekeeper reads the attested identity from the file at
  `source` (trimmed of whitespace). Suitable when your harness writes the
  invoking identity to a known file outside the process environment.
- `type: ""` (empty/omitted) — layer 1a is disabled entirely; resolution
  falls through to the sidecar layer, then the built-in fallback.

There is also a sidecar layer (`attestation.sidecars`: a list of `dir`,
`file_prefix`, `session_id_env` entries), for a harness that writes a
per-spawn or per-session identity file. All three fields are required
together within an entry — a partially configured entry is treated as
disabled, not guessed at. This is documented in `config.example.yaml`; most
consumers configuring their *own* attestation source will use `configured`,
not `sidecars` (the sidecar path exists for a harness that writes a
per-spawn identity file external to Gatekeeper — see "Wiring your agents"
below if you are building that harness yourself).

**Config location:** this is Gatekeeper's own `config.yaml` (copied from
`config.example.yaml` per the main [README](../README.md#configuration)).
Gatekeeper itself does not read a `.clagentic/loadout/` path — that path is
the *per-repo* loadout config consumed by `clagentic-loadout` (operator-
ratified, tome #701), and is a separate setting in that consumer repo's own
`.clagentic/loadout/config.yaml`, documented there. If you are also running
`clagentic-loadout`, do not confuse its per-repo loadout config with
Gatekeeper's own `config.yaml` described here — this doc covers only what
Gatekeeper itself consumes.

## The built-in fallback — and the risk of doing nothing

If you configure nothing under `attestation:` at all, layers 1a and 1b are
both omitted from the chain, and every mint resolves through the **built-in
fallback**: the OS-reported invoking user (`os/user.Current()`), i.e. whatever
Unix/Windows account the `gatekeeper` process happens to be running as.

This exists so a bare install always has *an* attested source rather than
failing open — there's no path where Gatekeeper mints with no identity at
all. But it means the fallback's "identity" is only as strong as whatever
account runs the process. On a shared host, or a container image where every
agent runs as the same user, the built-in fallback cannot distinguish one
caller from another.

**The risk this doc exists to head off:** a consumer who does not set
`attestation.configured` (or `attestation.sidecar`) is running the built-in
fallback, not real attestation — even though nothing errors and mint appears
to work normally. If your entitlement model (`roles.<name>.entitled_identities`
in [`docs/ROLES.md`](ROLES.md)) depends on distinguishing individual agents or
callers, you need `attestation.configured` (or a working sidecar) pointed at a
real per-caller identity source. The built-in fallback alone will not give you
that.

## Wiring your agents

The sections above describe how Gatekeeper *resolves* an attested identity.
They do not describe how that identity gets there in the first place —
that's a harness you build, external to Gatekeeper. This section is the
generic contract for that harness: write your own agent orchestration
against it and the sidecar layer above will resolve correctly for every
mint your agents perform, without reading any Gatekeeper source.

### 1. The per-spawn sidecar write pattern

Each time your harness spawns an agent, have the spawn-start step write one
identity file, named and located so that concurrent spawns of different
agents never collide:

```
<dir>/<file_prefix><spawn_id>
```

- `<dir>` and `<file_prefix>` are whatever you configure in the matching
  `attestation.sidecars` entry (see `config.example.yaml`).
- `<spawn_id>` must be unique **per spawn**, not per session. If two agents
  run concurrently under the same session (for example, a lead dispatching
  two subagents at once), a session-keyed filename would have the second
  spawn overwrite the first agent's identity file mid-flight. A spawn-keyed
  filename does not have this problem — each spawn gets its own file.
- The file's contents are the attested agent name/identity string —
  whatever value you want `internal/attestation` to return as the
  `Identity.Subject` for that spawn, and whatever you list under
  `roles.<name>.entitled_identities` to entitle it.

Write this file once, at spawn start, before the spawn runs anything that
might mint. Nothing later in the spawn's lifetime should need to touch it
again.

### 2. Spawn-scoped identity env — set once, not per command

The sidecar file alone is not enough — the sidecar provider also needs to
know *which* identity file belongs to *this* invocation. It does that by
reading an identity env var (the `session_id_env` field of the matching
`attestation.sidecars` entry, e.g. `<IDENTITY_ENV>`) and using its value as
the `<spawn_id>` suffix to look up.

**The requirement, stated precisely:** at spawn start, export `<IDENTITY_ENV>`
once into the whole subagent process's environment — not into any single
command's environment, and not re-injected per tool call. Because child
processes inherit their parent's environment by default, every subprocess
and every command the spawn ever runs — a push, a review comment, a merge,
or any future verb you haven't written yet — inherits the same env var
automatically and resolves the same attested identity, with zero
per-command wiring.

**The failure mode this avoids:** it is tempting to instead inject the
identity var only into the specific commands you know mint something today
(for example, just the push command). This looks like it works, because
those specific commands succeed. But you cannot enumerate every command
that will ever mint over the life of a harness — new verbs get added, and
each one you didn't explicitly wire silently falls through the resolver to
the built-in OS-user fallback (see "The built-in fallback" above) instead
of erroring. The mint then either succeeds as the wrong identity, or fails
entitlement with a "not entitled" error that looks like a permissions bug
rather than what it actually is: a missing identity var on that one
command. Debugging this after the fact, command by command, is exactly the
trap spawn-scoped env avoids — set the var once, for the whole spawn, and
there is no command left to forget.

### 3. Multiple sidecar namespaces in one deployment

A single deployment commonly needs to attest more than one kind of caller
at once — for example, short-lived per-spawn subagents (section 1-2 above)
*and* a longer-lived session process, such as an interactive lead agent
that mints directly without going through a per-spawn harness. Both need
their own namespace: a different `<dir>`/`<file_prefix>` pair, keyed on a
different id (a per-spawn id for one, a per-session id for the other).

`attestation.sidecars` is a list for exactly this reason — configure one
entry per namespace. Entries are tried in the order listed, and the first
entry whose identity file is present for the current invocation wins:

```yaml
attestation:
  sidecars:
    # Per-spawn namespace — checked first. Short-lived subagents, keyed on
    # a per-spawn id so concurrent spawns never collide.
    - dir: <dir>
      file_prefix: <file_prefix>
      session_id_env: <IDENTITY_ENV>
    # Session namespace — checked second. A long-lived lead/interactive
    # agent, keyed on a per-session id.
    - dir: <dir>
      file_prefix: <file_prefix>
      session_id_env: <IDENTITY_ENV>
```

Put the per-spawn entry first if both files could plausibly be present in
the same invocation — a spawned subagent's identity should win over an
inherited session identity it happens to also see in its environment.
Every field in every entry is still required together per entry (see
"Configuring your own attestation source" above); an entry with any field
missing is disabled, not partially applied.

## Summary

| Layer | What it answers | Config | Fails closed? |
|-------|------------------|--------|----------------|
| 1. Attested identity | Who is asking | `attestation.configured` / `attestation.sidecar` in `config.yaml` | Yes — a broken configured/sidecar provider is a hard error, not a silent fallthrough |
| 2. Role entitlement | What that identity may mint | `roles.<name>.entitled_identities` in `config.yaml` | Yes — empty/absent list refuses to mint (see [`docs/ROLES.md`](ROLES.md)) |
| 3. Credential grantor | What credentials the role gets | Secret broker (`broker.*` in `config.yaml`) | N/A — reached only after 1 and 2 pass |

If you set up nothing beyond the defaults, you get layer 1 via the built-in
OS-user fallback and layer 2 fully closed (no role has default entitlements).
Both are deliberate: a bare install can run, but it cannot mint anything
until you configure real entitlements — and if you configure real
attestation, a misconfiguration there will tell you loudly rather than
quietly degrading to the fallback.
