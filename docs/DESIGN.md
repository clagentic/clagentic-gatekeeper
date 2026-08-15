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
                       token. No I/O of its own beyond the deps. This is the
                       GitHub-domain mint path only — see internal/a2amint
                       below for the separate A2A-domain path.

internal/a2apolicy/    A2A caller entitlement policy (lr-0ae541): attested
                       identity -> A2A caller role -> permitted peer
                       audience(s)/scope(s). Config-driven
                       (config.A2AMapping), fail-closed by construction (a
                       nil/empty-built Policy refuses every request). Pure
                       policy, no I/O — analogous to roles.<name>.
                       entitled_identities but for the A2A domain instead of
                       the GitHub-App-role domain. Runs strictly after
                       attestation and before issuance; does not mint or
                       issue anything itself.

internal/a2atoken/     A2A issuance mechanics (lr-890fae) — the B3
                       attest-and-route mechanism settled at that task's
                       comment #4, live-provisioned per openbao lr-fbbf32.
                       An I/O leaf, the A2A-domain analog of
                       internal/githubapp: talks to OpenBao's HTTP API and
                       nothing else.
                         1. Sign a short-lived JWT ASSERTION with
                            gatekeeper's OWN key: sub = the ALREADY-attested,
                            ALREADY-entitled caller identity (this package
                            performs no attestation or entitlement check of
                            its own). No "aud" claim — present with no
                            bound_audiences configured on the receiving role
                            is a hard OpenBao validation failure.
                         2. POST the assertion to OpenBao's dedicated JWT
                            auth mount (/v1/auth/<mount>/login). OpenBao
                            independently verifies the signature against
                            jwt_validation_pubkeys and narrows via
                            bound_subject, resolving sub to a
                            PRE-REGISTERED entity-alias on that mount's own
                            accessor — never a value gatekeeper can dictate.
                         3. GET identity/oidc/token/<role> with the
                            resulting client token. OpenBao signs the
                            returned peer-facing token; gatekeeper never
                            does (AC3 — no signing-key handling, no
                            in-process signing, for the A2A domain).
                       Gatekeeper's assertion signing key is a BEARER OF
                       ATTESTATION — read from the broker like any other
                       secret, rotatable, and never conflated with OpenBao's
                       own OIDC signing key.

internal/a2amint/      A2A orchestration (lr-890fae) — mirrors
                       internal/mint's shape for the GitHub domain, but for
                       the A2A/remote-facing mint domain:
                         1. attestation.DomainResolver.Resolve(ctx,
                            attestation.DomainA2A) -> attested caller
                            identity. A per-spawn attestation MISS refuses
                            outright (ErrPerSpawnRequired) — never falls
                            through to a lower-priority provider such as the
                            session sidecar, closing the confused-deputy
                            path a remote-facing mint cannot tolerate.
                         2. a2apolicy.Policy.Check(identity, audience) ->
                            permitted role, or a fail-closed *DeniedError.
                         3. broker.Get(assertion_private_key_path) -> read
                            gatekeeper's own assertion key.
                         4. a2atoken.Issue(...) -> the OpenBao-issued
                            peer-facing token.
                       EVERY gate (1-3) runs and can refuse BEFORE step 4 —
                       an unresolvable attestation or an unentitled identity
                       never reaches the broker, let alone OpenBao. Every
                       outcome, permitted or refused, is reported to an
                       injected AuditFunc: gatekeeper's OWN audit record of
                       the mint decision (caller identity, resolved role,
                       requested audience, parent session id). The
                       peer-facing token itself carries only a native "sub"
                       claim and a TTL bound — OpenBao's identity/oidc role
                       template cannot carry the additional claims today
                       (openbao lr-fbbf32 comment #12 / lr-1e7c97, an
                       unresolved upstream parser bug) — so this audit
                       record is where that attribution actually lives, not
                       on the wire. OpenBao's own audit device remains the
                       mint-of-record for the issuance leg itself.
```

Dependency direction is one-way: `cmd -> mint -> {attestation, roles, broker, githubapp}`
for the GitHub domain, and `cmd -> a2amint -> {attestation, a2apolicy, broker, a2atoken}`
for the A2A domain (`gatekeeper mint-a2a`, lr-890fae). `roles` and `a2apolicy` are pure.
`attestation`, `broker`, `githubapp`, and `a2atoken` are I/O leaves. Nothing imports `cmd`.
`mint` and `a2amint` are peers — neither imports the other — since they orchestrate two
independent mint domains sharing only the lower `attestation`/`broker` layers.

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
