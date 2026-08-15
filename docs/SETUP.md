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
2. **Caller role / `--caller`** — which role the attested identity is entitled
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

The generalized read contract this layer implements — spawn-scoped vs.
session-scoped sidecar classes, spawn-first resolution order, fail-closed
handling of a miss, and symlink-safe reads — is specified independently of
Gatekeeper's own naming in
[`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md). That doc treats
Gatekeeper's deployed `attestation.sidecars` config and
`internal/attestation/sidecar.go` as one worked example, not as required
naming for any other consumer implementing the same contract.

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
`attestation.configured` (or `attestation.sidecars`) is running the built-in
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

### 4. Structured sidecar records (`identity_field`) — lr-f1bfe8

Each `attestation.sidecars` entry may optionally set `identity_field`
instead of writing a bare identity string to the sidecar file:

```yaml
attestation:
  sidecars:
    - dir: <dir>
      file_prefix: <file_prefix>
      session_id_env: <IDENTITY_ENV>
      identity_field: attested_name   # optional, per-entry
```

- **Unset** (the default): unchanged whole-file behavior — the file's
  entire contents, trimmed of whitespace, are `Identity.Subject`.
- **Set**: the sidecar file is parsed as a structured object (JSON or
  YAML) and the named field's value becomes `Identity.Subject`. The
  remaining recognized fields — `parent_session_id`, `spawn_id`,
  `agent_type`, `spawned_at` — are captured onto the resolved `Identity`
  whenever present, for cross-attribution/audit (which parent session
  spawned which unit of work). None of the four attribution fields is
  required; their absence never fails the read. Only `identity_field`
  itself is required once you opt in.

This lets a harness write ONE sidecar file per spawn instead of splitting a
bare identity file and a separate structured metadata file.

**Fail-closed on a malformed structured record.** If the file is present
but does not satisfy the structured-sidecar contract — not parseable as
JSON or YAML, `identity_field` absent from the parsed object, or the named
field present but empty or not a string — resolution returns a hard,
named-field error. This is deliberately distinct from the file simply not
existing (which stays the normal `ErrNoIdentity` miss, per section 3 of
`docs/SIDECAR-READ-CONTRACT.md`): a structured sidecar that IS present but
broken is a configuration or harness bug, not an absent attester, and must
never be silently treated as "this layer declines."

### 5. Domain-aware fail-closed MISS — lr-2ca216

This section documents a **resolution-policy** distinction, not a config
setting: which MISS behavior applies depends on the trust boundary the
resolved identity is used for, not on anything in `config.yaml`.

- **Local mint domain** (GitHub App installation tokens, today's only mint
  path): unchanged. A per-spawn sidecar MISS falls through to the next
  configured provider — typically the session sidecar — exactly as
  described in "Multiple sidecar namespaces" above. This is intentional: a
  long-lived lead/interactive session legitimately has no per-spawn sidecar
  of its own and must resolve via its session sidecar (lr-86779f).

- **A2A / remote-facing mint domain**: a per-spawn sidecar MISS must
  **never** fall through to the session sidecar. The token in this domain
  crosses a trust boundary to a remote peer; a wrong-identity mint here is
  a confused-deputy privilege-attribution failure, not a local
  over-grant — the peer would authorize the parent lead's (higher-trust)
  role for a spawn that never earned it, with nothing at the boundary able
  to detect the substitution.

`internal/attestation.DomainResolver` (`domain_policy.go`) implements this
as a policy layered on top of the same shared provider chain every mint
domain uses — it does not reorder or duplicate that chain. `DomainA2A`
requires a per-spawn-scoped resolver to succeed; a MISS there is a
definite refusal (`ErrPerSpawnRequired`), never a softened fallback.

A third domain, `DomainLocalSubagent` (lr-2a8653), applies the identical
PerSpawn-required policy to the *local* GitHub-domain mint (the one
`gatekeeper mint` performs today) when the invocation is itself a spawned
subagent expecting its own per-spawn sidecar — closing the confused-deputy
gap where a subagent's per-spawn MISS silently fell through to the session
sidecar and minted its PARENT session's identity. `DomainLocal` remains the
default for an invocation with no per-spawn source by design (a
lead/director session, lr-86779f); it is unaffected.

**Status in this repository:** `gatekeeper mint` (`cmd/gatekeeper/main.go`)
now constructs a `DomainResolver` for every invocation. It selects
`DomainLocalSubagent` when the configured per-spawn sidecar namespace's own
`session_id_env` is set in the process environment (a per-spawn harness is
active for this invocation) and `DomainLocal` otherwise. No A2A mint command
exists yet in `cmd/gatekeeper` — `DomainA2A` is available for the A2A mint
path (lr-a850d0, gated on a separate substrate-ratification decision) to
consume once it lands, and remains otherwise unused today.

## The A2A caller-attestation contract (required fields)

The normative, standalone required-fields contract — what a structured
sidecar record must carry so gatekeeper can resolve an A2A caller's
attestation with no crew-specific knowledge in gatekeeper source, which
sidecar source is authoritative for that domain, and how a missing required
field is refused — is published in
[`docs/A2A-ATTESTATION-CONTRACT.md`](A2A-ATTESTATION-CONTRACT.md) (lr-a850d0).
A producer (e.g. the crew-manifest harness that writes the sidecar file for
an A2A-caller spawn) implements that doc's contract by writing a file that
satisfies it; this repository never needs code that knows the producer's
identity.

## A2A caller entitlement mapping (`a2a_mapping`) — lr-0ae541

Once an A2A caller's identity is attested (the sections above), a separate
policy decision governs what that identity may actually *do*: which A2A
caller role it holds, and which peer audience(s)/scope(s) that role may
request a mint for. This is `internal/a2apolicy` — config-driven, and a
distinct mapping from `roles.<name>.entitled_identities`
([`docs/ROLES.md`](ROLES.md)), which governs the existing GitHub-domain
mint (`internal/mint`, role -> App-slug). `a2a_mapping` maps identity ->
A2A role -> permitted peer audiences instead of identity -> GitHub role.

This mapping runs strictly **after** attestation and **before** issuance:
it consumes the already-attested identity string plus a requested audience,
and either returns the role to pass to issuance or refuses. It does not
itself mint or issue any credential — the token-provider that consumes an
approved role/audience is a separate, downstream piece of work (lr-890fae).

### Config shape

```yaml
a2a_mapping:
  peer-agent-alpha:      # attested identity (Identity.Subject value)
    role: peer-builder   # A2A caller role name, generic vocabulary
    audiences:           # peer audience(s)/scope(s) this role may mint for
      - peer-project-x
      - peer-project-y
```

See `config.example.yaml` for the full annotated (and, by default,
commented-out) reference stanza.

### Fail-closed semantics

- **No `a2a_mapping` stanza configured at all**: `internal/a2apolicy.Policy`
  is fully closed — every identity/audience request is refused. This has
  **zero effect** on the existing GitHub-domain mint gate
  (`roles.<name>.entitled_identities`) — the two mappings are independent,
  and an absent `a2a_mapping` stanza cannot widen or narrow anything
  `internal/mint` already governs. Existing deployments upgrading to a
  gatekeeper version with this mapping see byte-identical GitHub-domain
  mint behavior.
- **Attested identity absent from the mapping**: refused with a structured
  `*a2apolicy.DeniedError` naming the *resolved* identity and the requested
  audience — never a stale or guessed value. The error's `Role` field is
  empty in this case, since no role was ever resolved for an unmapped
  identity.
- **Identity present, but its role does not cover the requested audience**:
  refused with a `*a2apolicy.DeniedError` naming the resolved role and the
  denied audience.
- **Identity present, requested audience covered**: the mapped role is
  returned for issuance to consume.

### Roster-agnostic by design

Both the identity keys and the `role`/`audiences` values in `a2a_mapping`
are ordinary deployment-supplied strings — gatekeeper source contains no
agent names, org names, or other deployment-specific identities anywhere in
`internal/a2apolicy` or this mapping's config schema. The example above
(`peer-agent-alpha`, `peer-builder`, `peer-project-x`) uses invented names
precisely so a released clone of this repository never ships anyone's real
crew roster.

## A2A token flow: from attested spawn to a peer-validated wire JWT

Once an A2A caller's identity is attested (layer 1, above) and its role/
audience entitlement is checked (`a2a_mapping`, above), `gatekeeper mint-a2a`
brokers issuance of the actual peer-facing credential. This section is the
end-to-end walkthrough: sidecar attestation -> gatekeeper's policy decision
(PDP) -> OpenBao issuance -> the wire JWT -> peer validation.

### The mechanism (B3 — attest-and-route, not mint-on-behalf-of)

An earlier design considered having gatekeeper mint directly through its own
OpenBao credential on behalf of an arbitrary attested caller. That does not
work: OpenBao rejects a template-supplied `sub` override on an
`identity/oidc/role` (a reserved key) and always stamps the *authenticated*
entity's own id. The mechanism gatekeeper actually implements is different,
and is *stronger*, not a workaround:

1. **Sidecar attestation** (layer 1 above) resolves the caller's identity
   from a structured sidecar record — the same substrate
   [`docs/A2A-ATTESTATION-CONTRACT.md`](A2A-ATTESTATION-CONTRACT.md)
   documents. For `mint-a2a` specifically, this MUST resolve through the
   **per-spawn** sidecar entry: `attestation.DomainA2A`'s fail-closed MISS
   policy (section 5, above) means a per-spawn miss refuses outright and
   never falls through to a session-scoped identity.
2. **Gatekeeper PDP**: `internal/a2apolicy.Policy.Check(identity, audience)`
   resolves the attested identity's A2A caller role and verifies that role
   covers the requested audience (`a2a_mapping` in `config.yaml`, documented
   above). An identity absent from the mapping, or a role that does not
   cover the requested audience, refuses here — **before any OpenBao call
   at all**.
3. **Gatekeeper signs a short-lived JWT ASSERTION** with its **own** key
   (`a2a_provider.assertion_private_key_path`, read from the broker like any
   other secret): `sub` = the already-attested, already-entitled caller
   identity from step 1. This assertion is gatekeeper's, and gatekeeper's
   alone — it is never OpenBao's issuing key, is rotatable independently,
   and is never persisted or logged.
4. **OpenBao issuance (the actual token exchange)**: gatekeeper POSTs the
   assertion to OpenBao's dedicated JWT auth mount
   (`/v1/auth/<a2a_provider.auth_mount>/login`). OpenBao independently
   verifies the assertion's signature against its own configured
   `jwt_validation_pubkeys`, narrows via `bound_subject`, and resolves `sub`
   to a **pre-registered entity-alias** on that mount's own accessor — a
   value gatekeeper cannot dictate or fabricate. Gatekeeper then reads
   `identity/oidc/token/<role>` with the resulting client token. **OpenBao
   signs the returned token; gatekeeper never does** — no signing-key
   handling, no in-process signing, anywhere in this path for the
   peer-facing credential.
5. **The wire JWT**: a standard OIDC token, signed by OpenBao, whose `sub`
   claim resolves natively to the caller's real, pre-registered OpenBao
   entity. See "What's on the wire" below for the exact claim set.
6. **Peer validation**: any standard OIDC validator can verify the token
   against OpenBao's discovery/JWKS endpoint — see
   [`docs/A2A-ATTESTATION-CONTRACT.md`](A2A-ATTESTATION-CONTRACT.md) and the
   sibling validation-contract task (`lr-baa55b`) for the peer-side
   consumption contract.

This is why the mechanism is called *attest-and-route*, not
*mint-on-behalf-of*: gatekeeper never authenticates to OpenBao pretending to
be the caller, and never asks OpenBao to trust a caller-supplied `sub`.
OpenBao independently re-derives the identity from a signature it verifies
itself, against a binding (the pre-registered entity-alias) it controls.

### What's on the wire (and what isn't)

**The peer-facing token carries a native `sub` claim (the caller's OpenBao
entity id) and a TTL bound — nothing else.** Earlier design iterations
expected additional custom claims (a caller-role claim, a target-audience
claim, a parent-session-attribution claim). Those claims were dropped from
the live-provisioned `identity/oidc/role` template — not by design choice,
but because of an unresolved upstream Vault/OpenBao parser bug (a `{{ }}`
placeholder adjacent to a JSON closing brace is misread as unbalanced
templating syntax; the `hashicorp/vault#30146` family), reproduced against
this exact deployment and tracked separately (openbao `lr-1e7c97`, not
gating). When that bug clears, the claim set widens additively — no
consumer of the token shape described here breaks.

**Do not build a side channel to carry the dropped claims.** This is a
deliberate, reasoned choice, not a gap to route around: this repository is
public and built for multiple independent consumers, and the wire format
staying a **vanilla OIDC token any standard validator handles** is what
keeps it adoptable. A bespoke out-of-band provenance envelope would make the
credential unconsumable by anyone outside a crew running gatekeeper's own
bespoke tooling.

**The authorization decision did not move** — only its restatement on the
wire did. `internal/a2apolicy` still resolves attestation and checks
entitlement before any issuance call, fail-closed, exactly as described
above. What changed is that gatekeeper's own audit record —not the wire
token — is now the place that attribution (caller identity, resolved role,
requested audience, parent session id) lives. `gatekeeper mint-a2a` writes
one audit line per mint decision (permitted or refused) to stderr, so it is
capturable by any log-collecting harness without contaminating the token
output on stdout. OpenBao's own audit device remains the mint-of-record for
the issuance event itself — gatekeeper's audit record is a separate,
additional record of the PDP decision, not a restatement of what OpenBao
already logs.

### Configuring `a2a_provider`

See the fully annotated `a2a_provider:` stanza in
[`config.example.yaml`](../config.example.yaml). In brief:

```yaml
a2a_provider:
  endpoint: https://bao.example.com
  assertion_private_key_path: secret/gatekeeper/a2a/assertion-private-key
  issuer: your-gatekeeper-issuer-id
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
```

- **Omitted, or any of `endpoint` / `assertion_private_key_path` /
  `auth_mount` empty**: `gatekeeper mint-a2a` refuses with a clear config
  error at startup. This has **zero effect** on `gatekeeper mint` (the
  GitHub-domain command) — additive, off by default, byte-identical
  existing behavior for a deployment that never sets this stanza.
- **`roles`** maps each A2A caller role named in `a2a_mapping`'s `role:`
  values to the specific OpenBao role names its issuance flows through. A
  role resolved by `a2a_mapping` with no matching entry here refuses closed
  rather than silently falling back to some other role's mapping.

### Running it

```bash
gatekeeper mint-a2a --audience peer-project-x [--config path] [--json]
```

Requires a per-spawn sidecar attestation (see "The mechanism" above) and a
covering `a2a_mapping` entry for the resolved identity/audience pair.
`--json` emits `{"token", "expires_at", "subject"}`; the default output is
the bare token string, matching `gatekeeper mint`'s own contract.

## Summary

| Layer | What it answers | Config | Fails closed? |
|-------|------------------|--------|----------------|
| 1. Attested identity | Who is asking | `attestation.configured` / `attestation.sidecars` in `config.yaml` | Yes — a broken configured/sidecar provider is a hard error, not a silent fallthrough |
| 2. Role entitlement | What that identity may mint | `roles.<name>.entitled_identities` in `config.yaml` | Yes — empty/absent list refuses to mint (see [`docs/ROLES.md`](ROLES.md)) |
| 3. Credential grantor | What credentials the role gets | Secret broker (`broker.*` in `config.yaml`) | N/A — reached only after 1 and 2 pass |
| 2a. A2A caller entitlement (`a2a_mapping`, lr-0ae541) | Which A2A role and peer audience(s) an A2A caller identity may request | `a2a_mapping` in `config.yaml` (`internal/a2apolicy`) | Yes — absent/empty mapping refuses every request; additive, off by default, no effect on layer 2 above |
| 3a. A2A issuance (`a2a_provider`, lr-890fae) | OpenBao B3 issuance surface `gatekeeper mint-a2a` brokers through once 2a permits | `a2a_provider` in `config.yaml` (`internal/a2atoken` / `internal/a2amint`) | Yes — unconfigured/partial stanza refuses with a config error; reached only after 1 and 2a pass; additive, off by default, no effect on `gatekeeper mint` |

If you set up nothing beyond the defaults, you get layer 1 via the built-in
OS-user fallback and layer 2 fully closed (no role has default entitlements).
Both are deliberate: a bare install can run, but it cannot mint anything
until you configure real entitlements — and if you configure real
attestation, a misconfiguration there will tell you loudly rather than
quietly degrading to the fallback.
