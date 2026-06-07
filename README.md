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

It ships three generic roles out of the box:

| Role       | Can do                                                        | Cannot do                          |
|------------|---------------------------------------------------------------|------------------------------------|
| `builder`  | Push feature branches, open/update PRs                        | Merge, push to the default branch  |
| `reviewer` | Submit PR reviews (approve / request changes), comment        | Push code, merge                   |
| `merger`   | Merge PRs, push to the default branch                         | Open PRs, author feature work      |

The roles are **generic**. Gatekeeper does not know or care what agents you run. You map your own agents to roles in your own configuration. Gatekeeper's only job is: given a role, return a token scoped to that role's permissions.

## Why it exists

GitHub forbids an actor from approving its own pull request. A workflow where one identity builds, reviews, and merges therefore cannot produce a credible, auditable "built → reviewed → merged by separate actors" trail. Gatekeeper solves this by minting distinct, role-narrowed tokens from distinct GitHub Apps, so every PR visibly flows through three independent automated actors.

The App private keys never touch the agent. Gatekeeper reads them from a pluggable secret broker (OpenBao by default), signs the App JWT server-side, and hands the agent only a ≤1-hour installation token narrowed to its role.

## What this is NOT

- It is **not** a dispatcher, a queue, or an agent framework. It mints tokens. That is the whole surface.
- It is **not** coupled to any specific set of agents. Agent→role mapping lives in the consumer, not here.
- It does **not** store long-lived secrets. The broker does.

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

1. Register three GitHub Apps on your org: one each for `builder`, `reviewer`, `merger`, with the per-role permissions in [`docs/ROLES.md`](docs/ROLES.md).
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

- [`docs/ROLES.md`](docs/ROLES.md) — per-role GitHub App permission tables
- [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) — branch ruleset and CODEOWNERS reference
- [`docs/DESIGN.md`](docs/DESIGN.md) — module architecture and security invariants

## Build

```bash
go build ./cmd/gatekeeper
```

Requires Go 1.22+. No external dependencies beyond the standard library.

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
