# Clagentic: Gatekeeper — design

## Goal

Mint short-lived, role-scoped GitHub App installation tokens for automated agents,
such that:

- Each role (builder / reviewer / merger) gets a token narrowed to its permissions.
- App private keys are read server-side from a broker and never reach the caller.
- The code is generic: no agent names, no org names, no hostnames, no PII — all
  deployment values come from config and environment.

## Module boundaries (`internal/`)

Modularity is the brief. Four packages, each with one job and a narrow interface.

```
cmd/gatekeeper/        CLI entry. Parses `mint --role <r> --repo <owner/name>`,
                       loads config, wires the modules, prints the token.

internal/roles/        The role model. Role name -> permission set (the ROLES.md
                       tables, as data). Pure, no I/O. Validates a role exists and
                       returns its GitHub permissions map + which repos it may scope.

internal/broker/       Pluggable secret broker. Interface:
                         Get(ctx, path) (string, error)
                       Implementations: openbao, vault, env, file. Selected by
                       config.broker.type. This is the ONLY place secrets are read.

internal/githubapp/    GitHub App JWT signing + installation-token exchange.
                         MintInstallationToken(ctx, appID, installID, key, perms, repos)
                       Signs the App JWT, calls POST /app/installations/{id}/access_tokens
                       with narrowed `permissions` + `repositories`. Returns token+expiry.

internal/attestation/  Resolves the ATTESTED invoking identity via a fixed-order
                       provider chain (configured -> sidecar -> built-in
                       fallback). Pure resolution, no policy — mint decides
                       what an identity is allowed to do. The sidecar layer's
                       read contract (spawn-scoped vs. session-scoped
                       classes, resolution order, fail-closed miss handling,
                       symlink hard-fail) is specified generically in
                       docs/SIDECAR-READ-CONTRACT.md, with this package's own
                       config and implementation cited there as the worked
                       example.

                       Two lr-f1bfe8/lr-2ca216 additions live in their own
                       files, kept separate from the sidecar read path and
                       the shared chain per this package's one-concern-per-
                       file rule:

                         structured_sidecar.go  Parses a structured (JSON or
                                                YAML) sidecar record and
                                                selects a named field
                                                (SidecarConfig.IdentityField)
                                                as Identity.Subject, carrying
                                                the rest of the recognized
                                                record (parent_session_id,
                                                spawn_id, agent_type,
                                                spawned_at) onto Identity for
                                                attribution/audit. Unset
                                                IdentityField is unchanged
                                                whole-file behavior.

                         domain_policy.go       DomainResolver: a per-MINT-
                                                DOMAIN MISS policy layered on
                                                top of the shared Resolver,
                                                not a change to it. DomainLocal
                                                is today's behavior unmodified
                                                (a per-spawn miss falls
                                                through to the session
                                                sidecar, lr-86779f). DomainA2A
                                                requires a per-spawn-scoped
                                                Resolver to resolve and fails
                                                closed (ErrPerSpawnRequired)
                                                rather than falling through —
                                                this is attestation substrate
                                                for the A2A epic (lr-a850d0);
                                                no A2A mint caller invokes it
                                                yet.

                         contract.go            RequiredIdentityContractFields
                                                (lr-a850d0): the single
                                                canonical Go-level list of the
                                                OPTIONAL attribution field
                                                names published by
                                                docs/A2A-ATTESTATION-CONTRACT.md,
                                                mirroring the constants
                                                structured_sidecar.go's parser
                                                already uses. No new parsing
                                                behavior — a published,
                                                mechanically-checkable
                                                reference for that contract's
                                                consumers.

internal/mint/         Orchestration. Ties attestation + roles + broker +
                       githubapp together:
                         1. attestation.Resolve(ctx) -> attested identity
                         2. verify identity is entitled to roleName (config-driven)
                         3. roles.Resolve(roleName) -> permissions, scope
                         4. broker.Get(role.app_id / installation_id / private_key)
                         5. broker.Get(role.app_slug_path); verify == role.app_slug
                         6. githubapp.MintInstallationToken(...)
                       Steps 2 and 5 are the (2)->(3) trust-layer gates (tome
                       #700): entitlement (attested identity -> role) and a
                       verifiable App-slug binding (role -> App). Both are
                       fail-closed — an unresolvable identity, an unentitled
                       identity, or a missing/mismatched App-slug binding all
                       refuse to mint, never fall back. Returns the scoped
                       token. No I/O of its own beyond the deps.
```

Dependency direction is one-way: `cmd -> mint -> {attestation, roles, broker, githubapp}`.
`roles` is pure. `attestation`, `broker`, and `githubapp` are I/O leaves. Nothing imports `cmd`.

## Secret flow (the security invariant)

```
config.yaml  ──►  mint  ──►  broker.Get(private_key_path)  ──►  githubapp (signs JWT)
                                                                      │
caller  ◄──────────  scoped installation token (≤1h)  ◄──────────────┘
```

The private key lives in the broker, is read only inside the mint path, is used
only to sign the App JWT, and is never returned, logged, or written to disk. The
caller receives only the short-lived installation token.

## Parameterization rules (release gate)

These are non-negotiable for the repo to be releasable:

1. No org name, repo name, hostname, username, email, or path constant in any `.go`
   file. All such values come from `config.yaml` or environment.
2. No secret material in the repo, ever. `.gitignore` blocks `*.pem`, `*.key`,
   `.env`. Tests use fixtures with fake keys generated at test time.
3. Broker is an interface with ≥2 implementations so no single broker is assumed.
4. The three roles are the reference model; the role model is data-driven enough
   that a consumer can add a role via config without forking.
5. Every error path that touches a secret scrubs it from the message.

## Out of scope (consumer's job)

- Mapping specific agents to roles (lives in the consumer's dispatcher).
- Registering the GitHub Apps (manual, one-time, per installer — see README).
- Configuring repo rulesets / CODEOWNERS (see GOVERNANCE.md).

## Language

Go. Matches the clagentic daemon family (relay, router, cli), ships as a single
static binary, and integrates with the `clagentic` CLI multiplexer.
