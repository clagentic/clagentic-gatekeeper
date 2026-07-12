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
2. **Sidecar adapter** — reads a session-scoped identity file written by an
   external harness (e.g. the crew-manifest plugin), when configured and
   present. Gatekeeper does not assume any specific harness exists.
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

There is also a sidecar layer (`attestation.sidecar`: `dir`, `file_prefix`,
`session_id_env`), for a harness that writes a session-scoped identity file.
All three sidecar fields are required together — a partially configured
sidecar is treated as disabled, not guessed at. This is documented in
`config.example.yaml`; most consumers configuring their *own* attestation
source will use `configured`, not `sidecar` (the sidecar path exists for the
specific crew-manifest plugin convention).

**Config location:** this is Gatekeeper's own `config.yaml` (copied from
`config.example.yaml` per the main [README](../README.md#configuration)) —
there is no `.clagentic/loadout/` path in Gatekeeper itself. If you are also
running `clagentic-loadout`, its consumer-attestation configuration is a
separate setting in *that* repo's own config (`.clagentic/loadout/config.yaml`)
and is documented there — this doc covers only what Gatekeeper itself
consumes.

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
