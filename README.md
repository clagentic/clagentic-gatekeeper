# Clagentic: Gatekeeper

Generic GitHub App token-minting for role-based automated agents.

Gatekeeper stands at the GitHub gate. When an automated agent needs to act on a
repository, Gatekeeper mints a **short-lived, role-scoped GitHub App installation
token** narrowed to exactly what that role is allowed to do — and nothing more.

It ships three generic roles out of the box:

| Role       | Can do                                                        | Cannot do                          |
|------------|---------------------------------------------------------------|------------------------------------|
| `builder`  | Push feature branches, open/update PRs                        | Merge, push to the default branch  |
| `reviewer` | Submit PR reviews (approve / request changes), comment        | Push code, merge                   |
| `merger`   | Merge PRs, push to the default branch                         | Open PRs, author feature work      |

The roles are **generic**. Gatekeeper does not know or care what agents you run.
You map your own agents to roles in your own configuration. Gatekeeper's only job
is: given a role, return a token scoped to that role's permissions.

## Why it exists

GitHub forbids an actor from approving its own pull request. A workflow where one
identity builds, reviews, and merges therefore cannot produce a credible,
auditable "built → reviewed → merged by separate actors" trail. Gatekeeper solves
this by minting distinct, role-narrowed tokens from distinct GitHub Apps, so every
PR visibly flows through three independent automated actors.

The App private keys never touch the agent. Gatekeeper reads them from a pluggable
secret broker (OpenBao by default), signs the App JWT server-side, and hands the
agent only a ≤1-hour installation token narrowed to its role.

## What this is NOT

- It is **not** a dispatcher, a queue, or an agent framework. It mints tokens. That
  is the whole surface.
- It is **not** coupled to any specific set of agents. Agent→role mapping lives in
  the consumer, not here.
- It does **not** store long-lived secrets. The broker does.

## One-time setup (per installer, manual)

Registering a GitHub App is an inherently manual, UI-driven action — Gatekeeper
cannot script first-time App creation because that itself requires credentials.
You do this once per role:

1. Register three GitHub Apps on your org: one each for `builder`, `reviewer`,
   `merger`, with the per-role permissions in [`docs/ROLES.md`](docs/ROLES.md).
2. Install each App on the target repos.
3. Store each App's `app-id`, `installation-id`, and `private-key` in your broker
   at the paths your `config.yaml` points to.
4. Apply a branch ruleset (see [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md)) that
   requires PR + review and restricts who may push the default branch.

After that, everything is code.

## Usage (target shape)

```bash
# Mint a token for the builder role, scoped to one repo, for one hour.
gatekeeper mint --role builder --repo owner/name

# Returns a short-lived installation token on stdout (or via the chosen output).
```

A consumer (e.g. an agent dispatcher) calls `gatekeeper mint --role <role>` with
the role it has mapped its agent to, then uses the returned token for the git /
API operations that role permits.

## Configuration

All deployment-specific values — org name, broker endpoint, broker secret paths,
role→app bindings — live in `config.yaml`. See [`config.example.yaml`](config.example.yaml).
There are **no hardcoded org names, hostnames, paths, or identities** in the code.

## License

FSL-1.1-MIT. See [LICENSE](LICENSE).
