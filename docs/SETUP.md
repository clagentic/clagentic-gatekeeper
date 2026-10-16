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

0. **Identity assertion** — when `attestation.assertion` is configured, the
   signed assertion delivered through `CLAGENTIC_IDENTITY_DIR` is verified
   and used first. See "Identity Assertion provider" below.
1. **Configured provider** — your own identity source, pointed at via
   `config.yaml`. Takes precedence over the layers below when set. See below.
2. **Sidecar adapter** — reads a per-spawn or per-session identity file
   written by an external harness, when configured and present. Gatekeeper
   does not assume any specific harness exists.
3. **Built-in fallback** (deprecated) — the OS-reported invoking user. Off by
   default; it is appended only under the opt-in
   `attestation.allow_os_user: true`. See "The built-in fallback" below.

The order is fixed by `NewChain` and is not configurable. What *is*
configurable is whether layers 0, 1, 2 and 3 exist at all — an unconfigured
layer is omitted from the chain, not stubbed in.

## Identity Assertion provider

The assertion provider lets `gatekeeper mint` take the caller's identity, roles
and grade from the signed Identity Assertion defined in
[`identity-contract.md`](identity-contract.md), instead of a name that a sidecar
file or environment variable merely states.

```yaml
attestation:
  assertion: {}            # trust the local `gatekeeper serve` issuer only
  # assertion:
  #   issuers:             # and these, in addition
  #     - iss: https://issuer.example
  #       jwks: /etc/gatekeeper/issuer-example-jwks.json   # optional
roles:
  merger:
    min_grade: workload    # optional; "workload" or "harness" (default)
```

How a mint resolves with it configured:

1. `CLAGENTIC_IDENTITY_DIR` unset or empty: the provider declines
   (`ErrNoIdentity`) and the configured provider, sidecars and, under the
   `allow_os_user: true` opt-in, the OS-user fallback answer exactly as without
   it.
2. Set: the directory and `identity.jwt` are checked as the contract's
   section 6 requires (absolute path, owned by the caller with mode 0700, the
   file opened without following a symlink and a regular file, at most 16384
   bytes), then the assertion is verified in the contract's section 4 order:
   `EdDSA` or `ES256`, `iss` matched exactly against the trusted issuers, the
   key found by `kid` in that issuer's key set, `cia` equal to 1, `exp`, `nbf`
   and `iat` with zero leeway, the claim shape, no `aud`, and `dir` equal to the
   directory it was read from.
3. **Any failure here is a hard error.** The mint is refused and no later
   provider is consulted, so a forged, expired or misdirected assertion is never
   replaced by a weaker identity. An unreachable key set is also a refusal.

The trusted issuers are the local serve issuer, which is always trusted (its
`iss` is `identity.issuer`, else `unix://<socket path>`, and its key set is
`identity.jwks_path` when set, else fetched from the socket), plus each entry in
`attestation.assertion.issuers`. Trust is exactly that list; nothing a token
names is trusted. A key set locator is an absolute path or `file:` URL, an
`http(s)` URL (plain `http` only for a loopback host) or a `unix:` socket URL;
left out it is derived from `iss` by the contract's section 5.1. Network reads
time out, are capped at 65536 bytes and do not follow a redirect to another
host; a key set file must be a regular file that group and other cannot write.

What mint then decides, for an identity that came from an assertion:

- **Entitlement is the assertion's roles.** The requested role must be in them;
  otherwise the mint is refused naming the requested role and the roles the
  assertion carries. The roles are a ceiling the issuer set, so being in them is
  what entitles, not `entitled_identities`.
- **`roles.<name>.min_grade`** refuses an assertion of a lower grade, naming both
  grades. `workload` ranks above `harness`; the default is `harness`, which every
  valid assertion meets.
- **`entitled_identities` only narrows.** When it is set for the role, the
  assertion's subject (`act.sub`, else `sub`) must also be listed.
- Every decision for an assertion identity writes one audit line to stderr naming
  the subject, grade, issuer and role: `mint audit: subject=... grade=...`.
  `gatekeeper mint --json` also returns `identity` (`subject`, `source`, `grade`)
  next to `token` and `app_slug`. Neither the audit line nor `identity` appears
  unless `attestation.assertion` is configured, so a deployment without it sees
  the output it saw before.

An identity from any other provider is entitled exactly as before, by
`entitled_identities`; `min_grade` does not apply to it.

A spawned subagent whose mint runs in the per-spawn domain tries the assertion
first and then its per-spawn sidecar; a miss on both still refuses.

### Standalone and integrated

- **Standalone:** one host runs `gatekeeper serve` and `gatekeeper mint` from
  the same `config.yaml`. `assertion: {}` is enough: mint verifies against the
  key set the local serve publishes.
- **Integrated:** assertions come from an issuer that is not this host's serve
  (another service, another host). List its `iss` and, when it cannot be derived,
  its key set locator under `attestation.assertion.issuers`. Gatekeeper never
  needs to import that issuer's code: the contract and the vectors are the whole
  interface.

### Conformance

The provider is tested against the vendored conformance vectors in
[`vectors/v1`](../vectors/README.md), contract version 1.0.0 (`cia` 1): every
vector's expected outcome must match (`TestVendoredVectorsMatchProvider`). A
vector set of a different contract version fails that test until the provider is
updated to it. The verifier is written from the contract with the Go standard
library; it adds no dependency.

### Platforms

Delivery checks need file ownership and no-follow opens, so the provider works
on linux and darwin. On windows an assertion cannot be proven safe: with
`CLAGENTIC_IDENTITY_DIR` set the mint is refused, and with it unset the provider
declines as above.

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

## The built-in fallback — off by default

The **built-in fallback** is the OS-reported invoking user
(`os/user.Current()`), i.e. whatever Unix/Windows account the `gatekeeper`
process happens to be running as.

**Deprecated, and off by default.** If you configure nothing under
`attestation:`, no layer can identify a caller and every mint is refused as an
unresolvable identity; nothing is printed and no credential is read. The
fallback is appended to the chain only when you set
`attestation.allow_os_user: true`, and each mint it answers then logs a warning
on stderr. Set it only while a caller is not yet covered by an assertion,
`attestation.configured` or a sidecar, and remove it once they all are. The
opt-in itself is removed in a later release.

The fallback's "identity" is only as strong as whatever account runs the
process. On a shared host, or a container image where every agent runs as the
same user, it cannot distinguish one caller from another, which is why it is no
longer a default.

**The risk this doc exists to head off:** a consumer who sets
`attestation.allow_os_user: true` instead of `attestation.configured` (or
`attestation.sidecars`) is running the built-in fallback, not real attestation,
and mint appears to work normally. If your entitlement model
(`roles.<name>.entitled_identities` in [`docs/ROLES.md`](ROLES.md)) depends on
distinguishing individual agents or callers, you need `attestation.configured`
(or a working sidecar) pointed at a real per-caller identity source. The
built-in fallback alone will not give you that.

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
the next layer instead of erroring: refused as an unresolvable identity by
default, or, under `allow_os_user: true` (see "The built-in fallback" above),
answered by the OS-user fallback. The mint then either succeeds as the wrong
identity, or fails with an error that looks like a permissions bug rather than
what it actually is: a missing identity var on that one command. Debugging this after the fact, command by command, is exactly the
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
constructs a `DomainResolver` for every invocation. It selects
`DomainLocalSubagent` when the configured per-spawn sidecar namespace's own
`session_id_env` is set in the process environment (a per-spawn harness is
active for this invocation) and `DomainLocal` otherwise. `gatekeeper
mint-a2a` consumes `DomainA2A` for the A2A/remote-facing mint path — see "A2A
token flow" below for the full walkthrough.

## The A2A caller-attestation contract (required fields)

What a structured sidecar record must carry so gatekeeper can resolve an A2A
caller's attestation with no deployment-specific knowledge in gatekeeper
source is specified by section 4 above ("Structured sidecar records"; only
the field named by `identity_field` is required, the attribution fields are
optional) and by [`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md)
section 8. For an A2A mint the identity MUST resolve from the per-spawn
sidecar entry (section 5 above). A producer implements that by writing a file
that satisfies it; this repository never needs code that knows the
producer's identity.

The contract for what an A2A *peer* validates is the Identity Assertion
contract, [`docs/identity-contract.md`](identity-contract.md) (section 9),
which supersedes the former `docs/A2A-ATTESTATION-CONTRACT.md`.

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
end-to-end walkthrough: identity assertion -> gatekeeper's policy decision
(PDP) -> OpenBao JWT login -> OpenBao identity token -> the wire JWT -> peer
validation.

There is **one issuer key**: the `gatekeeper serve` signing key
(`identity.key_path`). Gatekeeper holds no second A2A key, signs nothing in
`mint-a2a`, and OpenBao trusts the published `gatekeeper serve` JWKS.

### The mechanism (OpenBao's documented JWT login flow)

An earlier design considered having gatekeeper mint directly through its own
OpenBao credential on behalf of an arbitrary attested caller. That does not
work: OpenBao rejects a template-supplied `sub` override on an
`identity/oidc/role` (a reserved key) and always stamps the *authenticated*
entity's own id. The flow gatekeeper implements is OpenBao's documented one:
the caller's own credential logs in, and the entity that login resolves to
requests the identity token.

1. **Identity assertion** (layer 0 above) resolves the caller's identity from
   the assertion `gatekeeper serve` issued and delivered through
   `CLAGENTIC_IDENTITY_DIR`; `mint-a2a` verifies it against the configured
   issuers exactly as `mint` does. The identity is the assertion's `act.sub`.
   An assertion with no `act` claim is **refused at gatekeeper, before any
   OpenBao call**, with the error `identity assertion for "<sub>" carries no
   act.sub`; there is no fallback to `sub`, because the mount's
   `user_claim=/act/sub` is the contract. (The plain `mint` command is
   unchanged and still resolves an assertion without `act` from `sub`.)
   `mint-a2a` needs
   `attestation.assertion` configured and uses no other identity source: a
   sidecar or configured identity carries no assertion to log in with, and an
   absent or invalid assertion refuses under `attestation.DomainA2A`'s
   fail-closed MISS policy (section 5, above), never falling through.
2. **Gatekeeper PDP**: `internal/a2apolicy.Policy.Check(identity, audience)`
   resolves the attested identity's A2A caller role and verifies that role
   covers the requested audience (`a2a_mapping` in `config.yaml`, documented
   above). An identity absent from the mapping, or a role that does not
   cover the requested audience, refuses here — **before any OpenBao call
   at all**.
3. **JWT login**: gatekeeper POSTs the assertion, unchanged, to OpenBao's
   dedicated JWT auth mount (`/v1/auth/<a2a_provider.auth_mount>/login`) with
   the role from `a2a_provider.roles.<role>.auth_role`. OpenBao independently
   verifies the signature against the `gatekeeper serve` JWKS, checks
   `bound_issuer`, and resolves the claim at `/act/sub`
   (`user_claim=/act/sub`, `user_claim_json_pointer=true`) to a **pre-registered
   entity-alias** on that mount's own accessor — a value gatekeeper cannot
   dictate or fabricate. The login returns a client token for the caller's
   real OpenBao entity. Gatekeeper holds no key that could forge an assertion.
4. **Identity token**: gatekeeper reads `identity/oidc/token/<oidc_role>` with
   that client token. **OpenBao signs the returned token; gatekeeper never
   does** — no signing-key handling, no in-process signing, anywhere in this
   path.
5. **The wire JWT**: a standard OIDC token, signed by OpenBao, whose `sub`
   claim resolves natively to the caller's real, pre-registered OpenBao
   entity. See "What's on the wire" below for the exact claim set.
6. **Peer validation**: any standard OIDC validator can verify the token
   against OpenBao's discovery/JWKS endpoint — see
   [`docs/identity-contract.md`](identity-contract.md) (section 9) for the
   peer-side validation contract.

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
  auth_mount: a2a-jwt
  roles:
    peer-builder:
      auth_role: a2a-role
      oidc_role: a2a-oidc-role
```

- **Omitted, or either of `endpoint` / `auth_mount` empty**: `gatekeeper
  mint-a2a` refuses with a clear config error at startup. This has **zero
  effect** on `gatekeeper mint` (the GitHub-domain command) — additive, off by
  default, byte-identical existing behavior for a deployment that never sets
  this stanza.
- **Removed keys**: `a2a_provider.assertion_private_key_path`,
  `a2a_provider.issuer` and `a2a_provider.assertion_ttl_seconds` configured
  gatekeeper's own assertion signing, which no longer exists. A config that
  still names one **loads**: the value is ignored and `mint`, `mint-a2a` and
  `serve` log one deprecation line to stderr naming each such key. Delete them
  from every gatekeeper config when convenient.
- **`attestation.assertion`** must be configured (`assertion: {}` trusts the
  local `serve` issuer). `mint-a2a` refuses without it.
- **`roles`** maps each A2A caller role named in `a2a_mapping`'s `role:`
  values to the specific OpenBao role names its issuance flows through. A
  role resolved by `a2a_mapping` with no matching entry here refuses closed
  rather than silently falling back to some other role's mapping.

### Running it

```bash
gatekeeper mint-a2a --audience peer-project-x [--config path] [--json]
```

Requires a delivered identity assertion (see "The mechanism" above) and a
covering `a2a_mapping` entry for the resolved identity/audience pair.
`--json` emits `{"token", "expires_at", "subject"}`; the default output is
the bare token string, matching `gatekeeper mint`'s own contract.

### Operator step: point the OpenBao JWT mount at the serve JWKS

This block is run by an operator with OpenBao admin rights, **after** the
build carrying this change is merged and **before** `mint-a2a` is used against
the mount. Gatekeeper's code never runs it and never writes OpenBao config.
Every `<...>` is a deployment value. Stop at the first check that fails and
take the branch named under it.

```bash
export BAO_ADDR=<openbao-url>        # operator token with auth/ and policy admin
MOUNT=a2a-jwt                        # a2a_provider.auth_mount
ROLE=<auth_role>                     # a2a_provider.roles.<role>.auth_role
OIDC_ROLE=<oidc_role>                # a2a_provider.roles.<role>.oidc_role
SERVE_ISS=<identity.issuer>          # the exact iss serve stamps
SERVE_JWKS_URL=<https-url>           # the published serve JWKS, reachable by OpenBao

# 1. Deployed version. Nested claim selection (user_claim_json_pointer) needs
#    OpenBao 2.4 or later.
bao status                           # read the Version line
```

If the version is older than 2.4, **stop**: the nested claim check below cannot
pass. The branch is a follow-up change in `serve` that adds a top-level copy of
`act.sub` to the assertion and a role `user_claim` naming it; it is not part of
this change and is not built.

```bash
# 2. Mount config: trust the serve JWKS and only its issuer.
bao write auth/$MOUNT/config \
  jwks_url="$SERVE_JWKS_URL" \
  bound_issuer="$SERVE_ISS"
bao read auth/$MOUNT/config          # only the JWKS source may be set; the old
                                     # jwt_validation_pubkeys must be gone

# 3. Role: select act.sub as a JSON pointer, and allow the serve algorithm
#    explicitly. The algorithm is EdDSA unless identity.alg is ES256.
bao write auth/$MOUNT/role/$ROLE \
  role_type=jwt \
  user_claim=/act/sub \
  user_claim_json_pointer=true \
  jwt_supported_algs=EdDSA \
  bound_subject="" \
  token_policies=<existing-role-policies>
bao read auth/$MOUNT/role/$ROLE      # confirm user_claim, user_claim_json_pointer
                                     # and jwt_supported_algs as written

# 4. Entity aliases: the alias name on the mount's accessor must equal the
#    assertion's act.sub value (for example agent:peer-agent-alpha). Re-register
#    any alias that carries a different spelling before the proof below.
```

**Proof, end to end.** Use a real assertion delivered by `gatekeeper serve`
(`CLAGENTIC_IDENTITY_DIR/identity.jwt` of a spawn whose `act.sub` is mapped):

```bash
JWT=$(cat "$CLAGENTIC_IDENTITY_DIR/identity.jwt")

# 5. Accept: login succeeds and the alias resolves to the pre-registered entity.
bao write -format=json auth/$MOUNT/login role=$ROLE jwt="$JWT"
#    expect auth.client_token, auth.entity_id = the pre-registered entity,
#    auth.metadata/alias name = the act.sub value

# 6. Identity token with that client token; the token's sub is the entity id.
BAO_TOKEN=<auth.client_token from step 5> bao read -format=json identity/oidc/token/$OIDC_ROLE

# 7. Refuse: an assertion signed by a key that is not in the serve JWKS.
#    Take any assertion and change one character of its signature segment, or
#    sign one with a throwaway key. Login must be refused.
bao write auth/$MOUNT/login role=$ROLE jwt="<forged assertion>"

# 8. Gatekeeper itself, from the same spawn:
gatekeeper mint-a2a --audience <a2a_mapping audience> --config <config.yaml> --json
```

Record the result of steps 1, 5, 6 and 7 on the task.

- **Step 3 or 5 refuses EdDSA** (the role write rejects the algorithm, or
  login reports it as unsupported): set `identity.alg: ES256` with a new P-256
  `identity.key_path`, restart `serve`, change the role to
  `jwt_supported_algs=ES256`, and repeat steps 5 to 8. The algorithm decision
  is tome #890 D5; both algorithms are accepted by the identity contract.
- **Step 5 reports the claim missing, or the pointer unsupported**, although the
  version is 2.4 or later: take the nested-claim branch named under step 1.

**After the merge and the proof above,** remove the old assertion material:

```bash
# The broker path that was a2a_provider.assertion_private_key_path (KV v2 shown;
# use `bao kv delete` for KV v1) and the policy that granted read on it.
bao kv metadata delete -mount=<kv-mount> <path-of-the-old-assertion-key>
bao policy delete <policy-that-granted-the-old-assertion-key>
```

Remove `assertion_private_key_path`, `issuer` and `assertion_ttl_seconds` from
every gatekeeper `a2a_provider` stanza when convenient; a build with this change
loads a config that still names them, ignores them and logs a deprecation line.

## Identity Assertion issuer (`gatekeeper serve`)

`gatekeeper serve` is a long-running service that issues the Identity
Assertion defined in [`identity-contract.md`](identity-contract.md). It
listens on a unix socket, reads each peer's uid and pid from the kernel
(`SO_PEERCRED`) and its executable and command line from `/proc`, and signs
what it finds. Nothing a client sends can change who the kernel says it is.

### Commands

| Command | Purpose |
|---------|---------|
| `gatekeeper serve [--socket <path>] [--config <path>]` | Run the issuer. Socket: `--socket`, else `identity.socket_path`, else `/run/clagentic-gatekeeper/identity.sock`. |
| `gatekeeper issue-session [--socket <path>] [--definition <name>] [--origin <origin>] [--runtime] [--runtime-id <id>] [--runtime-version <v>] [--json]` | Ask for a session assertion. Prints the token, or the full response with `--json`. |
| `gatekeeper issue-child [--socket <path>] [--parent-token-file <path>] --agent-type <name> --agent-id <id> [--json]` | Ask for a child assertion. The parent token defaults to `$CLAGENTIC_IDENTITY_DIR/identity.jwt`. |

The socket also answers `GET /.well-known/jwks.json` (HTTP/1.1), so a
verifier trusting `iss = unix:///path/to/socket` finds the keys with no extra
configuration.

`serve` runs on linux only (it needs `SO_PEERCRED` and `/proc`). On other
platforms the module still builds, the client commands (`issue-session`,
`issue-child`) and `mint` work, and `serve` reports that it is linux-only.

Who may ask is decided in-process: see "Who may ask" below. The socket is
created with `identity.socket_mode`, default `0600` (the serving uid only),
which is a second layer behind that check: widening it lets more uids connect
and never gets one of them served. The path never exists with another
mode: `serve` binds a private temporary name in the same directory, sets the
mode there, and only then links it to the socket path.

`serve` refuses to start when anything exists at the socket path (a socket, a
file, a directory, a link) and names it. It never removes or replaces any path,
including its own socket on shutdown: telling a stale socket from one a live
server is about to use cannot be done without racing that server. The service
manager removes the socket after a stop (for a systemd unit,
`RuntimeDirectory=` does this); otherwise remove a leftover socket by hand.

### Who may ask

This release serves callers that run as the serving uid, and only those. The
`SO_PEERCRED` uid of each connection is compared in-process with the serving
uid before anything is issued:

- a peer with the serving uid is served;
- any other uid receives `peer_uid_refused`, one constant message, and nothing
  is created for it;
- the peer's primary gid and supplementary groups are not consulted.

Normatively, this check, not file permissions, is the access boundary. Socket
mode, the socket directory and its ancestors are defense in depth only; a
deployment must not rely on them to exclude a uid.

`serve` issues no human assertions at all. Human requires a positive signal
that a same-uid process cannot produce by omitting or setting a request field
or its own argv, and this release has no such signal: every agent on a host
runs as the serving uid. The former `identity.operator_uid`,
`identity.operator_name` and `identity.operator_roles` keys are removed; a
config that still carries them has them ignored, and `serve` logs one
deprecation line at start naming each such key, saying it has no effect and
that `serve` issues no human assertions. Origin `human` is refused with
`origin_forbidden`. Serving callers under other uids (allow-lists, handing
delivery directories to a foreign uid) is tracked in lr-767925.

A served peer may name any definition: a definition's roles are a ceiling,
not a grant, and a consumer's own entitlement still decides what is granted.
Per-definition authorization (limiting which uids may name which definition)
is not implemented. Each definition's `trust_boundary` key is parsed and
carried but **not yet enforced**: no decision reads it. Enforcing it as a
per-definition allow-list is tracked as follow-up work.

### Trust roots

`serve` acts on, and decides from, only filesystem state that no uid other than
the serving uid and root can write. At start it verifies each trust root and
refuses to start, naming the path, when any check fails:

- the signing key's directory, `identity.definitions_dir`, `identity.spawn_root`,
  the socket's directory and the directory of `identity.jwks_path`;
- each must be owned by root or the serving uid, and neither it nor any
  ancestor may be writable by group or other. An ancestor with the sticky bit
  (a shared temporary directory) is accepted; the root itself never is;
- every regular `*.md` file in `identity.definitions_dir` must likewise be owned
  by root or the serving uid and not writable by group or other, because
  whoever can edit a definition chooses the roles it grants (a definition that
  changes after start is re-checked when it is loaded);
- a path with a symbolic link anywhere on it is refused: configure the real path;
- only the final component of the spawn root and of the socket directory is
  created when missing; any other missing directory is an error.

Each directory on the way is opened as an `O_PATH` descriptor, so an ancestor
that is traversable but not readable (mode `0711`) is accepted and the owner and
mode checked are those of the inode actually opened.

Everything `serve` later reads, writes, chmods or removes is reached
through a handle opened from a verified directory. Stale delivery directories
are aged by the creation time `serve` encoded in each directory's name, never
by the metadata of a directory the peer can change, and are removed relative to
the spawn root handle opened at start. Delivery directories belong to the
serving uid, so removing them needs no extra privilege.

### Public errors

Every refusal carries a stable `error` code and one constant message per code.
No message includes a uid, pid, path, name the client sent, or parser text; the
detail goes to the server log only. The codes are `bad_request`,
`peer_unattested`, `peer_uid_refused`, `runtime_mismatch`, `origin_forbidden`,
`definition_unknown`, `parent_invalid`, `parent_expired`, `parent_unknown`,
`uid_mismatch`, `parent_pid_mismatch`, `parent_exe_mismatch`, `lifetime_empty`, `spawn_dir` and
`internal`.

### Who gets what

- Every served peer, whatever fields its request carries or omits: grade
  `workload`, subject `runtime:<id>`; `act.sub` is `agent:<definition>` when
  `--definition` is given, else `runtime:<id>`. Roles are the definition's, else
  `identity.runtime_roles`. The default origin is `trigger`. The runtime id is
  read from the peer's executable (for an interpreter, its script name). Origin
  `human` is refused for every uid, and a child is never human: it inherits its
  parent's subject, and no parent is human.
- A definition must exist in `identity.definitions_dir`; its roles are the
  ceiling. Adding a file is enough; no gatekeeper config edit and no roster.
- `issue-child` requires a parent token this server issued, still unexpired,
  to the very process (pid and start time) now asking. The child is grade
  `harness`, its roles are the definition's roles intersected with
  `identity.delegable_roles` and with the roles of the parent token, so
  delegation never widens: a child can never hold a role its parent lacks,
  whatever the definition or `delegable_roles` allow. Its `exp` never exceeds
  the parent's. The response lists every policy that dropped a role
  (`identity.delegable_roles`, `parent_token.roles`) with the roles each
  dropped.
- Every assertion gets its own delivery directory under `identity.spawn_root`
  (mode 0700, owned by the serving uid, which is the peer's uid, with
  `identity.jwt` and `tmp/`), and the `dir` claim is bound to it.

**The runtime id is self-asserted attribution within the peer uid.** It is
derived from the peer's executable and command line, and any process can set
its own argv, so a same-uid process can always present any runtime id it
likes. The uid is the trust boundary, not the runtime id. Therefore, and
normatively: no role, role ceiling, or human-versus-workload decision may
depend on the runtime id or on any other argv-derived field or request field; it appears only
in `rt.id` and in the `runtime:<id>` subject or actor of a workload assertion
for attribution and audit. `identity.runtime_roles` is one list applied to
every runtime session regardless of its id and is never keyed by a runtime
name. Consumers must not grant anything on the strength of a `runtime:<id>`
value alone.

**What a grant rests on.** Normatively, no grant depends on a value derived
from `/proc`. Roles, grade, human versus workload, and the owner of the
delivery directory follow the `SO_PEERCRED` uid and the definition file only.
`issue-child` binds a parent token to the `SO_PEERCRED` uid and refuses with
`uid_mismatch` when the asking uid differs (a case a peer-uid check already
excludes while only the serving uid is served); the pid and process start time are
compared as well, as defense in depth. `sub` and `act.sub` of the form
`runtime:<rt>` are attribution-grade: self-asserted within the peer uid, and
not a basis for any decision.

`/proc` failures are fail-closed. If `/proc` cannot be read for a peer, if no
runtime id can be derived from it, or if a declared runtime id differs from
the derived one (`runtime_mismatch`), the request is refused and nothing is
granted. Accepted residual: a pid reused before the first `/proc` read can make
the derived runtime id describe the wrong process. That affects attribution
only, never roles, grade or ownership, because those do not read `/proc`.

### Signing key

```bash
(umask 077 && openssl genpkey -algorithm ed25519 -out identity-key.pem)
```

The umask is set before the file exists, so it is created mode 0600 and is never
readable by anyone but its owner, at any instant. A `chmod` after the write
would leave a window in which a permissive umask exposes the private key.

The published key set holds the current signing key only.

### Issuer-only and combined configs

A config with only the `identity:` section starts `serve` without any
`github`, `broker` or `roles` section; `gatekeeper mint` then reports that
minting is not configured. A config with both runs both, and `mint` behaves as
it did before.

## Summary

| Layer | What it answers | Config | Fails closed? |
|-------|------------------|--------|----------------|
| 1. Attested identity | Who is asking | `attestation.configured` / `attestation.sidecars` in `config.yaml` | Yes — a broken configured/sidecar provider is a hard error, not a silent fallthrough |
| 2. Role entitlement | What that identity may mint | `roles.<name>.entitled_identities` in `config.yaml` | Yes — empty/absent list refuses to mint (see [`docs/ROLES.md`](ROLES.md)) |
| 3. Credential grantor | What credentials the role gets | Secret broker (`broker.*` in `config.yaml`) | N/A — reached only after 1 and 2 pass |
| 2a. A2A caller entitlement (`a2a_mapping`, lr-0ae541) | Which A2A role and peer audience(s) an A2A caller identity may request | `a2a_mapping` in `config.yaml` (`internal/a2apolicy`) | Yes — absent/empty mapping refuses every request; additive, off by default, no effect on layer 2 above |
| 3a. A2A issuance (`a2a_provider`, lr-890fae) | OpenBao JWT login plus identity-token surface `gatekeeper mint-a2a` brokers through once 2a permits | `a2a_provider` in `config.yaml` (`internal/a2atoken` / `internal/a2amint`) | Yes — unconfigured/partial stanza refuses with a config error (a removed key only logs a deprecation line); an assertion without `act.sub` refuses; reached only after 1 and 2a pass; additive, off by default, no effect on `gatekeeper mint` |

If you set up nothing beyond the defaults, layer 1 has no identity source (the
built-in OS-user fallback is off unless `attestation.allow_os_user: true`) and
layer 2 is fully closed (no role has default entitlements). Both are
deliberate: a bare install cannot mint anything until you configure a real
identity source and real entitlements — and if you configure real
attestation, a misconfiguration there will tell you loudly rather than
quietly degrading to the fallback.
