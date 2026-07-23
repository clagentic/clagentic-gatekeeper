package attestation

// This file owns ONE concern: publishing the A2A caller-attestation
// required-fields contract (docs/A2A-ATTESTATION-CONTRACT.md, lr-a850d0) as
// a single, importable source of truth for the OPTIONAL attribution field
// names a structured sidecar record may carry. It does not add new parsing
// or resolution behavior — structured_sidecar.go already implements the
// read side; this file exists so that contract's field-name list has one
// canonical Go-level definition a producer's own fixtures/tests (or
// gatekeeper's own tests, see contract_test.go) can reference instead of
// re-typing the four field-name string literals independently.

// RequiredIdentityContractFields lists the OPTIONAL cross-attribution field
// names recognized by a structured sidecar record (see
// docs/A2A-ATTESTATION-CONTRACT.md). These mirror the
// fieldParentSessionID/fieldSpawnID/fieldAgentType/fieldSpawnedAt constants
// in structured_sidecar.go — kept as a single canonical slice (rather than
// duplicating the values inline in both places) so a future field addition
// is a one-place change reflected in both the parser and this published
// list.
//
// The identity field itself (the one REQUIRED field) has no fixed name: it
// is named by the deployment's own attestation.sidecars[].identity_field
// config value, never hardcoded here or in gatekeeper source — see
// docs/A2A-ATTESTATION-CONTRACT.md's "required-fields table" for why this
// list only contains the OPTIONAL attribution fields.
var RequiredIdentityContractFields = []string{
	fieldParentSessionID,
	fieldSpawnID,
	fieldAgentType,
	fieldSpawnedAt,
}
