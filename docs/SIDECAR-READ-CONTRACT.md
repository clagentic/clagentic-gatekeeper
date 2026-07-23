# Sidecar identity file — the read contract

This is the canonical spec for **reading** an identity sidecar file: a small
file an external harness writes to disk so a consuming tool can resolve
"who is asking" without that tool trusting a caller-supplied value. It exists
because the write side (the harness) is already solid and largely uniform
across the tools that use this pattern, while independent read
implementations have drifted in rigor. This doc fixes the read contract once,
in generalized shapes, so any reader can be brought into line with it without
adopting another tool's naming or file layout.

**Scope: read-side only.** This doc does not define how or when a harness
writes the sidecar file — that is the harness's own contract, described
wherever the harness itself is documented. Nothing here assumes a specific
harness exists.

**No tool names are normative here.** Directory paths, filename prefixes, and
environment variable names below are illustrative placeholders. Section
"Worked example" cites one reference implementation to make the shapes
concrete — it documents an example, not a required naming scheme.

## Convention, not coupling

This is a `.netrc`-style convention: every consumer that wants to read a
sidecar carries (or links to) this spec and implements the read against its
**own** configuration. There is no shared library, no runtime dependency
between consumers, and no requirement that consumers agree on directory or
prefix values. Two independently built tools can each implement this
contract, point at the same on-disk file by coincidence of matching config,
and interoperate — or run entirely independently with no knowledge of each
other. The contract is the shape of the read, not a wire protocol.

## 1. Two sidecar classes

A deployment may need to attest more than one *kind* of caller at once, and
the two kinds need different identity keys because their lifetimes differ:

- **Spawn-scoped.** Identifies one short-lived unit of work — a single
  spawned subagent invocation. Keyed by a **spawn-id** environment variable
  whose value is unique per spawn. Required when multiple spawns can be
  in flight concurrently under the same parent process/session: a
  session-keyed file would let a second concurrent spawn overwrite the
  first spawn's identity file mid-flight. A spawn-keyed file does not have
  this problem — each spawn gets its own file.

- **Session-scoped.** Identifies one longer-lived process — for example, an
  interactive lead/orchestrator that itself makes identity-bearing calls
  without going through a per-spawn harness. Keyed by a **session-id**
  environment variable that is stable for the life of that process.

A single deployment commonly configures both classes as independent
namespaces (own directory/prefix/env-var triple each), because a session
process and the subagents it spawns are different callers with different
lifetimes, even when they run as the same OS user.

## 2. Resolution order: spawn-first, then session

When both classes are configured, a reader tries the **spawn-scoped**
namespace first, then the **session-scoped** namespace. The first namespace
whose identity file is present, for the current invocation's key value,
wins — resolution stops there; later namespaces are not consulted.

Rationale: a spawned subagent's own identity must win over a session
identity it may also see in its inherited environment. Checking spawn first
means a subagent is attested as itself, not silently re-attested as its
parent session, when both sidecar files happen to be resolvable in the same
process.

If a deployment configures only one class, that class is the entire chain —
there is nothing to order.

## 3. No hit = fail closed for identity-bearing decisions

If neither configured sidecar namespace has a file present for the current
invocation, that is **absence of an attested identity from this layer**, not
an error — a well-behaved reader treats it as "this layer declines" and lets
the caller decide what happens next (e.g. fall through to another
configured identity source, or refuse outright).

What a reader must **never** do on a miss, when the caller is meant to be a
specific named identity: silently substitute the OS-reported invoking user
(`getpass.getuser()`, `os/user.Current()`, `whoami`, or equivalent) as if it
were the attested identity. An OS-user fallback answers a different
question — "what account is this process running as" — not "which named
caller is this." Conflating the two means every caller sharing an account
(a common case: multiple agents/services run as the same container user)
becomes indistinguishable, silently, with no error to signal the
degradation.

A generic "no identity source configured at all, so fail open to *some*
built-in default" behavior may still be a deliberate, documented design
choice at a higher layer (see "Worked example" below for how the reference
implementation frames this trade-off explicitly). What this section
forbids is a **sidecar reader** locally improvising an OS-user substitution
as if it satisfied the sidecar contract — that decision, if made at all,
belongs one layer up, explicitly, not folded silently into the read path.

## 4. Atomic read, symlink-safe

Reading the identity file is a security-sensitive operation: the sidecar
directory is often a shared, world-writable location (e.g. a temp
directory), so the read must not be redirectable by another process placing
a symlink or non-regular file at the expected path between check and read.

The generalized read shape:

1. Open the path with the platform's no-follow-symlink open flag (e.g.
   `O_NOFOLLOW` on POSIX, or the platform equivalent) so a symlink at the
   expected path fails the open rather than being silently followed to an
   attacker-chosen target.
2. `fstat` the **open file descriptor** (not a separate path-based stat
   call) and verify it reports a regular file before reading any bytes.
   Using the descriptor closes the TOCTOU window between "check" and
   "read" that a path-based stat-then-open (or open-then-separate-stat)
   sequence leaves open.
3. Only then read the file's contents.

Runtimes without a portable no-follow open flag may approximate this with
the strongest available equivalent (for example: `lstat` the path first to
detect a symlink or non-regular file before opening, refusing before any
open is attempted) — see "Worked example" for how the reference
implementation does this within Go's standard library idiom. The intent
that must be preserved regardless of language: **no read is ever allowed to
silently traverse a symlink**, and the regular-file check happens close
enough to the read that a race cannot substitute a different file in
between.

## 5. Symlink or non-regular file = hard failure

If the path resolves to a symlink, or to anything that is not a regular
file (device, socket, FIFO, directory, etc.), the reader must treat this as
a **hard failure of that provider**, not as "no identity" and not as
something to silently work around by resolving through it. A planted
symlink at the expected path is exactly the attack this guards against, and
treating it as a soft miss would let an attacker cause exactly the "safe"
fallback behavior described in section 3.

This is different from "file does not exist," which is a normal miss (see
section 3). A present-but-wrong-type file is treated more severely, because
its presence is itself suspicious.

## 6. Prefixes, directories, and env var names always come from config

No consumer of this contract hardcodes a sidecar's directory, filename
prefix, or key environment-variable name in its source code. All three are
read from that consumer's **own** configuration (its adapter/config
values), the same way any other deployment-specific value is configured.
This holds even when a consumer's default config ships with a specific
value pre-filled (see "Worked example") — the value lives in config, is
overridable, and the code path that reads it is generic.

This is what makes the convention work like `.netrc`: the *shape* of the
contract (two classes, spawn-first resolution, fail-closed miss handling,
symlink hard-fail) is fixed and documented once, here; the *values*
(where the file lives, what it's called, which env var keys it) are
deployment-local and never assumed by code.

## 7. The session sidecar's `lore-agent-name-` prefix is not up for renaming

One specific, already-deployed session-scoped sidecar convention uses the
filename prefix `lore-agent-name-`. That prefix is **owned by the LORE
harness that writes it**, and the name itself is the ownership signal — it
tells a reader (or a human debugging a resolution failure) which harness is
responsible for that file's contents and lifecycle. This spec does not
propose renaming it, and no consumer of this contract should propose
renaming it either. A consumer's own config simply points its session-scoped
namespace's `file_prefix` at that value if it wants to read LORE's
session sidecar; the value is still config-driven per section 6, it is just
a config value that should not casually change once other readers depend on
it.

## Worked example (illustrative — not normative naming)

Clagentic: Gatekeeper's Go reference implementation is cited here to show
one way the shapes above can be implemented. The config snippet below uses
the same field names as `config.example.yaml`'s `attestation.sidecars`,
but the directory, prefix, and env-var values are illustrative
placeholders only — not any deployment's actual configuration. Nothing in
this section is a required name, path, or environment variable for any
other consumer; per section 6, those values always come from each
consumer's own config.

**Config shape** (same fields as `config.example.yaml`'s
`attestation.sidecars`, ordered spawn-first per section 2):

```yaml
attestation:
  sidecars:
    # Spawn-scoped namespace — checked first, per section 2's spawn-first
    # resolution order. Short-lived subagent invocations, one file per
    # concurrent spawn.
    - dir: <dir>
      file_prefix: <file_prefix>
      session_id_env: <SPAWN_IDENTITY_ENV>
    # Session-scoped namespace — checked second. A lead/interactive
    # process. If pointed at LORE's session sidecar, its prefix is not
    # renamed (see section 7 above).
    - dir: <dir>
      file_prefix: <file_prefix>
      session_id_env: <SESSION_IDENTITY_ENV>
```

Both `dir`, `file_prefix`, and the id-env-var name are ordinary config
values (section 6) — a consumer's Go (or other language) source never
hardcodes them.

The order above follows section 2's spawn-first resolution
recommendation. A local deployment MAY choose a different order as its own
config decision — the list order is read straight from `config.yaml` and
Gatekeeper's chain does not enforce spawn-before-session itself (see
"Reference read implementation" below).

**Reference read implementation**
([`internal/attestation/sidecar.go`](../internal/attestation/sidecar.go)):

- One `sidecarProvider` is built per configured entry in the `sidecars`
  list (`internal/attestation/chain.go`, `NewChain`); the chain tries each
  in the configured order and returns the first identity found, giving the
  ordered "first hit wins" behavior of section 2 once entries are ordered
  per that section.
- A miss (`os.IsNotExist`) returns `ErrNoIdentity` so the chain falls
  through to the next provider — normal absence, per section 3. The
  package's built-in fallback (OS-reported invoking user) is a distinct,
  explicitly documented final layer of the chain, not something the
  sidecar provider itself substitutes on a miss — see
  [`docs/SETUP.md`](SETUP.md) for the full three-layer trust model and why
  that fallback exists as its own opt-in-by-omission layer rather than
  being folded into the sidecar read path.
- The path is checked with `os.Lstat` before any read, so a symlink at the
  expected path is detected as itself rather than resolved through — the
  Go-idiomatic approximation of section 4's no-follow-open requirement
  described there for runtimes without a portable atomic
  open-with-no-follow-and-fstat primitive in common use. `info.Mode().IsRegular()`
  is checked before the file is read; anything else (symlink, device,
  socket) is a hard failure (`fmt.Errorf`, not `ErrNoIdentity`), per
  section 5.
- The id value read from the environment is validated as a single safe
  path segment before it is joined into the file path
  (`isSafePathSegment`), and the resulting path is verified to still be a
  direct child of the configured directory (`requireContained`) — hardening
  specific to Gatekeeper's implementation, complementary to but outside
  the scope of this contract.
- `dir`, `file_prefix`, and `session_id_env` are all fields of
  `SidecarConfig`, populated only from `config.yaml` — see section 6.

## 8. Structured sidecar records — an optional, per-namespace read mode

Section 6 above describes the sidecar file's directory/prefix/env-var
naming as always config-driven. This section extends the **contents** side
of the contract: a reader MAY, per configured namespace, support reading
the sidecar file as a structured record (JSON or YAML object) instead of
treating the whole file as the bare identity string, and selecting a
configured field from that record as the identity.

This is opt-in per namespace, not a replacement for the whole-file mode —
a reader with no such option, or a namespace that leaves it unset, keeps
the whole-file behavior described in the rest of this doc unchanged.

When a namespace opts into structured reading:

- The named identity field's value becomes the identity, subject to the
  same "no hit = fail closed for identity-bearing decisions" framing as
  section 3 — except a structured record's own internal shape is a
  DIFFERENT case: **a sidecar file that is present but fails to satisfy
  the structured contract (not parseable, named field absent, named field
  present but empty or non-string type) is a hard, fail-closed failure of
  that provider — never a soft "no identity" decline.** This mirrors
  section 5's treatment of a present-but-wrong-type file: presence with a
  broken shape is more suspicious than simple absence, and must not be
  softened into the ordinary miss case.
- A structured record MAY carry additional ATTRIBUTION fields alongside
  the identity field — generic, roster-agnostic names describing which
  parent process spawned this caller and when (e.g. a parent-session id,
  a spawn id, a caller-type classification, a spawn timestamp). These are
  OPTIONAL: their absence never fails the read, unlike the identity field
  itself. A reader supporting this mode should make these fields
  available to whatever consumes the resolved identity, for
  cross-attribution/audit — but the shape of that carry-through
  (e.g. an extended identity type) is an implementation detail, not part
  of this contract's normative surface.
- Directory, prefix, and env-var-name config-sourcing (section 6) is
  unaffected; the structured-vs-whole-file choice is an additional,
  independently config-sourced per-namespace setting, never hardcoded.

**Reference implementation:** Gatekeeper's `identity_field` setting
(`internal/attestation/sidecar.go`'s `SidecarConfig.IdentityField`,
documented in `config.example.yaml`) implements this section.
`internal/attestation/structured_sidecar.go` does the parsing/field-
selection; see `docs/SETUP.md` ("Structured sidecar records") for the
consumer-facing config walkthrough and the published required-fields
contract for the A2A caller-attestation use case.

## 9. Fail-closed MISS semantics can be trust-boundary-dependent

Section 3 states the baseline: a miss (no file present) is normal absence,
and a reader must never substitute an OS-user fallback for a specific
named-identity decision. This section names a further refinement some
consumers need: **which fallback is acceptable on a miss can depend on the
trust boundary the resolved identity is used for**, even when the
provider-order shape (section 2, spawn-first-then-session) is unchanged.

Concretely: falling through from an absent spawn-scoped sidecar to a
present session-scoped sidecar (i.e. attesting a spawn as its parent
session) may be an acceptable, even necessary, design choice for a
LOCAL-facing credential — a long-lived lead/session process legitimately
has no per-spawn sidecar of its own. The same fallthrough is unacceptable
for a REMOTE-facing credential that crosses a trust boundary to a peer:
the peer authorizes by the identity in the credential, has no way to
detect a parent/spawn substitution, and the parent is systematically
higher-trust, so the fallback direction is always privilege-escalating in
that domain.

This is a property of **how the resolved identity will be used**, not of
the sidecar read mechanics themselves — this contract does not mandate a
specific mechanism for expressing it (a domain-scoped resolver wrapper is
one way; see the reference implementation below). What it does require:
a consumer that serves more than one trust-boundary domain from the same
sidecar configuration must not silently apply the local-safe fallback
policy to the remote-facing case.

**Reference implementation:** `internal/attestation.DomainResolver`
(`internal/attestation/domain_policy.go`) implements this as a policy
layered on top of the shared, unmodified provider chain — `DomainLocal`
is a pass-through to today's chain behavior; `DomainA2A` requires a
per-spawn-scoped resolver to succeed and refuses
(`ErrPerSpawnRequired`) rather than falling through on a miss. See
`docs/SETUP.md` ("Domain-aware fail-closed MISS") for the consumer-facing
walkthrough.

## See also

- [`docs/DESIGN.md`](DESIGN.md) — where `internal/attestation` sits in
  Gatekeeper's module boundaries.
- [`docs/SETUP.md`](SETUP.md) — the full three-layer trust model
  (attested identity -> role entitlement -> credential grantor), the
  built-in fallback, and the harness-wiring contract for writing sidecar
  files in the first place.
- [`internal/attestation/sidecar.go`](../internal/attestation/sidecar.go),
  [`internal/attestation/chain.go`](../internal/attestation/chain.go) —
  the reference read implementation cited above.
