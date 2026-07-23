<p align="center">
  <img src="media/logo/gatekeeper-lockup-256.png" alt="clagentic:gatekeeper" width="260" />
</p>

<h4 align="center">Role-scoped GitHub App tokens. Built for builders.</h4>

<p align="center">
  <a href="https://clagentic.ai"><img src="https://img.shields.io/badge/-clagentic.ai-00CFFF?style=flat&logoColor=white" alt="clagentic.ai" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-FSL--1.1--MIT-blue?style=flat" alt="License: FSL-1.1-MIT" /></a>
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white" alt="Go 1.22+" />
  <a href="https://ko-fi.com/clagentic"><img src="https://img.shields.io/badge/Ko--fi-FF5E5B?style=flat&logo=ko-fi&logoColor=white&label=support" alt="Support on Ko-fi" /></a>
</p>

Role-scoped GitHub App installation tokens for automated agents. Part of the [clagentic](https://clagentic.ai) suite.

---

Gatekeeper stands at the GitHub gate. When an automated agent needs to act on a repository, Gatekeeper mints a **short-lived, role-scoped GitHub App installation token** narrowed to exactly what that role is allowed to do — and nothing more.

It ships four generic roles out of the box:

| Role       | Can do                                                        | Cannot do                          |
|------------|---------------------------------------------------------------|------------------------------------|
| `builder`  | Push feature branches, open/update PRs                        | Merge, push to the default branch  |
| `reviewer` | Submit PR reviews (approve / request changes), comment        | Push code, merge                   |
| `merger`   | Merge PRs, push to the default branch                         | Open PRs, author feature work      |
| `security` | Post security review comments, request changes                | Push code, merge                   |

The roles are **generic**. Gatekeeper does not know or care what agents you run. You map your own agents to roles in your own configuration. Gatekeeper's only job is: given a role, return a token scoped to that role's permissions.

You can also define **custom roles** in `config.yaml` without forking code — for example a `releaser` scoped only to tagging, or a `deployer` with deployment write access. See [`docs/ROLES.md`](docs/ROLES.md) under "Adding a custom role" for the config schema.

## Why it exists

GitHub forbids an actor from approving its own pull request. A workflow where one identity builds, reviews, and merges therefore cannot produce a credible, auditable "built → reviewed → merged by separate actors" trail. Gatekeeper solves this by minting distinct, role-narrowed tokens from distinct GitHub Apps, so every PR visibly flows through separate build, review, and merge actors. An optional `security` role can add an independent security review gate on top of that core trail.

The App private keys never touch the agent. Gatekeeper reads them from a pluggable secret broker (OpenBao by default), signs the App JWT server-side, and hands the agent only a ≤1-hour installation token narrowed to its role.

## What this is NOT

- It is **not** a dispatcher, a queue, or an agent framework. It mints tokens. That is the whole surface.
- It is **not** coupled to any specific set of agents. Agent→role mapping lives in the consumer, not here.
- It does **not** store long-lived secrets. The broker does.

## Attestation substrate for agent-to-agent (A2A) callers

Gatekeeper's attestation layer (`internal/attestation`) resolves *who is
asking* before anything is minted (see [`docs/SETUP.md`](docs/SETUP.md)).
Two additions extend that substrate for a remote-facing, agent-to-agent
caller — a caller whose minted credential crosses a trust boundary to a
peer, rather than being used purely locally:

- **Structured sidecar records** (`attestation.sidecars[].identity_field`):
  a sidecar entry can opt into parsing its file as a structured (JSON or
  YAML) record and reading a named field as the attested identity, instead
  of treating the whole file as the identity string. The rest of the
  record — a parent-session id, a spawn id, a generic caller-type
  classification, a spawn timestamp — is captured for cross-attribution
  and audit whenever present. A structured record that is present but
  malformed (unparseable, or missing/empty/non-string in the named field)
  is a hard, fail-closed error naming the field — never treated as "no
  identity."
- **Domain-aware fail-closed MISS**: for a remote-facing (A2A) mint
  request, a per-spawn attestation miss now refuses outright rather than
  falling through to a session-scoped identity — closing a
  confused-deputy path where a spawn with no attestation of its own would
  otherwise mint a peer-facing credential under its parent's (higher-trust)
  identity. Local GitHub/reader mints are unaffected: a per-spawn miss
  still falls through to the session sidecar exactly as before, since a
  long-lived lead session legitimately has no per-spawn sidecar of its
  own.

**What this repository ships today:** the attestation substrate above —
structured-record parsing, the attribution fields it carries, and the
domain-aware resolution policy (`internal/attestation.DomainResolver`).
**What it does NOT yet ship:** an actual A2A token-minting command in
`gatekeeper` itself. That mint path is a separate, gated epic; this
substrate is what it will consume once it lands. See
[`docs/SETUP.md`](docs/SETUP.md#the-a2a-caller-attestation-contract-required-fields)
for the published required-fields contract a sidecar producer implements,
and [`docs/SIDECAR-READ-CONTRACT.md`](docs/SIDECAR-READ-CONTRACT.md) for
the generalized, tool-agnostic read-contract sections this substrate
follows.

## Usage

```bash
# Mint a token for the builder role, scoped to one repo.
gatekeeper mint --role builder --repo owner/name

# Returns a short-lived installation token on stdout.
```

A consumer (e.g. an agent dispatcher) calls `gatekeeper mint --role <role>` with the role mapped to its agent, then uses the returned token for the git/API operations that role permits.

## Configuration

Copy `config.example.yaml` to `config.yaml` and fill in your values. All deployment-specific values — org name, broker endpoint, broker secret paths, role→app bindings — live there. No hardcoded org names, hostnames, paths, or identities exist in the code.

```yaml
github:
  owner: your-org-name
  api_base: https://api.github.com

broker:
  type: openbao        # openbao | vault | env | file
  endpoint: https://broker.example.com
  auth: approle        # approle | token

roles:
  builder:
    app_id_path: secret/gatekeeper/builder/app-id
    installation_id_path: secret/gatekeeper/builder/installation-id
    private_key_path: secret/gatekeeper/builder/private-key
  # ... reviewer, merger
```

See [`config.example.yaml`](config.example.yaml) for the full reference.

## One-time setup (per installer, manual)

Registering a GitHub App requires a one-time manual step — Gatekeeper cannot script first-time App creation.

1. Register four GitHub Apps on your org: one each for `builder`, `reviewer`, `merger`, and `security`, with the per-role permissions in [`docs/ROLES.md`](docs/ROLES.md).
2. Install each App on the target repos.
3. Store each App's `app-id`, `installation-id`, and `private-key` in your broker at the paths your `config.yaml` points to.
4. Apply a branch ruleset (see [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md)) that requires PR + review and restricts who may push the default branch.

After that, everything is code.

## Secret broker

Gatekeeper's broker is pluggable:

| Type      | Use case           | Credentials from                                                    |
|-----------|--------------------|---------------------------------------------------------------------|
| `openbao` | Production         | `BROKER_ROLE_ID` + `BROKER_SECRET_ID` (AppRole) or `BROKER_TOKEN`  |
| `vault`   | Production (Vault) | Same env vars                                                       |
| `env`     | Local dev / CI     | Env var name is the secret path                                     |
| `file`    | Local dev / CI     | File path is the secret path                                        |

The private key is read server-side only, used to sign the App JWT, and never returned, logged, or persisted.

## Docs

- [`docs/SETUP.md`](docs/SETUP.md) — attested identity, the fail-closed trust model, and configuring your own attestation source
- [`docs/ROLES.md`](docs/ROLES.md) — per-role GitHub App permission tables
- [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) — branch ruleset and CODEOWNERS reference
- [`docs/DESIGN.md`](docs/DESIGN.md) — module architecture and security invariants

## Build

```bash
go build ./cmd/gatekeeper
```

Requires Go 1.22+. No external dependencies beyond the standard library.

## Install

```bash
make install
```

Builds the `gatekeeper` binary and installs it to `/usr/local/bin` by default. Override the destination with `PREFIX` and/or `DESTDIR` — no paths are hardcoded to any specific environment:

```bash
# Install under your home directory instead of /usr/local
PREFIX=$HOME/.local make install

# Stage into a packaging root without touching the live prefix
make install DESTDIR=/tmp/staging PREFIX=/usr
```

## Support

If clagentic:gatekeeper is useful to you: [ko-fi.com/clagentic](https://ko-fi.com/clagentic)

## Disclaimer

Not affiliated with Anthropic or OpenAI. Claude is a trademark of Anthropic. Codex is a
trademark of OpenAI. Provided "as is" without warranty. Users are responsible for
complying with their AI provider's terms of service.

## License

[FSL-1.1-MIT](LICENSE) — Functional Source License 1.1, with MIT as the Change License.

Free for personal, internal-business, evaluation, research, and non-commercial use.
Not free for offering this tool (or a substantial fork) as a competing commercial product.
Each release auto-converts to MIT on its second anniversary.
