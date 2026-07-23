# A2A caller-attestation contract — required fields

This is the normative, standalone contract for what a structured sidecar
record must carry so gatekeeper can resolve an A2A (agent-to-agent,
remote-facing) caller's attestation with **no crew-specific knowledge in
gatekeeper source**. It is the CONSUMER-side contract: gatekeeper implements
the reader against this doc. A producer — for example, the crew-manifest
harness that writes the sidecar file for an A2A-caller spawn shape — reads
this doc and writes a file that satisfies it; nothing in this repository
needs to know the producer's identity, name, or internals to consume it.

This doc does not implement token minting/issuance for the A2A domain — that
is downstream (lr-890fae). It publishes the field contract the mint path will
consume once it exists.

## Scope: one sidecar source, deterministically

Gatekeeper resolves an A2A caller's attestation from exactly ONE documented
source: the **per-spawn sidecar entry** in the deployment's configured
`attestation.sidecars` list (see `config.example.yaml` and
[`docs/SETUP.md`](SETUP.md#3-multiple-sidecar-namespaces-in-one-deployment)).
There is no ambiguity between a per-spawn provider and a session provider for
this domain: `internal/attestation.DomainResolver`, given `DomainA2A`,
requires the per-spawn-scoped resolver specifically (its `PerSpawn` field) to
resolve the identity, and refuses (`ErrPerSpawnRequired`) rather than trying
any other provider in the shared chain — including the session sidecar — on
a miss. See `internal/attestation/domain_policy.go` and
[`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md#9-fail-closed-miss-semantics-can-be-trust-boundary-dependent)
section 9 for the full rationale.

## Required-fields table

A conforming producer sidecar is a JSON or YAML object (see
[`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md#8-structured-sidecar-records--an-optional-per-namespace-read-mode)
section 8 for the structured-record read mode) written to the per-spawn
sidecar file, with the following fields:

| Field | Required | Type | Meaning | Resolved onto |
|-------|----------|------|---------|----------------|
| The field named by the deployment's `identity_field` config value | **Yes** | non-empty string | The attested caller identity | `Identity.Subject` |
| `parent_session_id` | No (attribution) | string | The id of the session/process that spawned this caller | `Identity.ParentSessionID` |
| `spawn_id` | No (attribution) | string | The id of this specific spawn/invocation | `Identity.SpawnID` |
| `agent_type` | No (attribution) | string | A generic, roster-agnostic classification of the caller (e.g. `"builder"`) — never a proper agent name | `Identity.AgentType` |
| `spawned_at` | No (attribution) | string | A timestamp string for when the spawn started, passed through verbatim (not parsed/validated) | `Identity.SpawnedAt` |

"Role source" (a term used by the epic's acceptance criteria) is
`Identity.Source`, already returned by every provider (`"sidecar"` for the
sidecar path) — no additional field is needed to satisfy it.

The identity field's own NAME is a deployment config value
(`attestation.sidecars[].identity_field`), never hardcoded in gatekeeper
source or in this contract — a producer and gatekeeper agree on the name via
shared config, the same way `dir`/`file_prefix`/`session_id_env` are already
agreed on (see [`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md)
section 6). The table above writes "the field named by `identity_field`"
rather than a fixed literal name for exactly this reason.

Everything else in the parsed object is ignored — this contract is
deliberately minimal. A producer may include additional fields (e.g. its own
internal bookkeeping) without gatekeeper rejecting the record.

## Refusal on a missing required field

A sidecar record that is present but missing the `identity_field`-named
field is a **hard, fail-closed error naming the field** — never a soft
decline (`ErrNoIdentity`) and never a silent fallback to another provider.
This is `*attestation.MalformedSidecarError` with its `Field` set to the
configured `identity_field` value
(`internal/attestation/structured_sidecar.go`). The same hard-failure
treatment applies to a record that is not parseable as JSON or YAML, or
whose named field is present but empty or non-string.

For an A2A-domain mint request specifically, this hard failure propagates
straight out of `DomainResolver.Resolve` — it is one of the
"any hard error from PerSpawn is returned as-is" cases documented on
`DomainResolver.Resolve`, never downgraded to `ErrPerSpawnRequired`'s softer
"try elsewhere" framing. A missing required field and a genuinely absent
sidecar file are deliberately distinguishable failure modes: the former
names the broken field, the latter is silent absence.

## Conformance is mechanically checkable

`attestation.RequiredIdentityContractFields` (`internal/attestation/contract.go`)
is the single source of truth for the OPTIONAL attribution field names this
contract recognizes (`parent_session_id`, `spawn_id`, `agent_type`,
`spawned_at`). A producer, or a test verifying a producer's fixture sidecar
records, can import this constant list rather than hardcoding the field
names independently — see `internal/attestation/contract_test.go` for the
end-to-end regression coverage tying a conforming record, an A2A-domain
resolve, and a missing-field refusal together.

## See also

- [`docs/SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md) — the
  generalized read-side contract (two sidecar classes, resolution order,
  fail-closed miss handling, symlink hard-fail, structured-record mode).
- [`docs/SETUP.md`](SETUP.md) — the full three-layer trust model and the
  consumer-facing config walkthrough, including "The A2A caller-attestation
  contract (required fields)" section, which this doc supersedes as the
  normative, standalone reference (SETUP.md's section now points here).
- [`internal/attestation/domain_policy.go`](../internal/attestation/domain_policy.go) —
  `DomainResolver`, the domain-aware fail-closed MISS policy.
- [`internal/attestation/structured_sidecar.go`](../internal/attestation/structured_sidecar.go) —
  the structured-record parser and `MalformedSidecarError`.
- [`internal/attestation/contract.go`](../internal/attestation/contract.go) —
  the mechanically-checkable field-name contract this doc describes.
