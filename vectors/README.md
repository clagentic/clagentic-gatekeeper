# Conformance vectors

Signed test vectors for the [Identity Assertion contract](../docs/identity-contract.md).
A verifier or peer validator is conformant when it reproduces every expected
outcome. The set is versioned by contract major version: `v1/` is for
`cia` = `1`.

Vendor `v1/` into your own tests, pinned to a contract version, and run every
vector against your own verifier built from the specification and a standard
JWS library. Nothing here is a library to import.

## Files

| File | Content |
|------|---------|
| `v1/manifest.json` | Contract version, the trusted issuer list, and every vector. |
| `v1/jwks.json` | The public keys the tokens verify against (`ed-1` EdDSA, `es-1` ES256). |

The tokens are signed with throwaway keys generated for the set. The private
halves are discarded at generation time and are not published; the two keys in
`jwks.json` are the only key material in this repository.

## Manifest

```
contract_version   the contract version the set was written for
cia                the contract major version
trust.issuers[]    trusted issuer identifiers (exact string match)
jwks_files         trusted issuer -> JWKS file in this directory
vectors[]          see below
```

Every vector has `id`, `description`, `kind` and `expect`.

### `kind: "token"`

| Field | Meaning |
|-------|---------|
| `token` | Compact JWS to verify. |
| `mode` | `local` (section 7 of the spec) or `peer` (section 9). |
| `now` | Time to verify at, NumericDate. Run with zero leeway. |
| `observed_dir` | Local mode: the directory the token is deemed read from, for the `dir` binding. |
| `peer_id` | Peer mode: the verifier's own peer identifier. |

Expected outcome, `expect`: `{"ok": true, "actor": ..., "grade": ...}` where
`actor` is `act.sub` of the outermost `act` or else `sub`; or
`{"ok": false, "error": <code>}` with a code from section 4.1 of the spec.

### `kind: "delivery"`

The vector describes a filesystem layout to create in a scratch location owned
by the verifier's user, then the delivery checks of section 6 run on it.

| `layout` field | Values |
|----------------|--------|
| `dir` | `unset` (variable not set), `absent` (names a missing path), `present` |
| `dir_mode` | Mode to give a `present` directory: `0700` or `0755` |
| `file` | `identity.jwt` is `regular`, `symlink` (to a regular file elsewhere) or `absent` |
| `content` | What a `regular` file holds, or a `symlink` points at |

`{"ok": true}` means the file is delivered and its bytes equal `content`;
otherwise `error` is a delivery code.

## Coverage

Passing: EdDSA and ES256 sessions, a child with a two-level actor chain, unknown
claims ignored, and two peer-mode exchanged tokens (ES256, EdDSA).

Failing, one or more vectors for every code in section 4.1: expired
(including the `exp == now` boundary), not yet valid (`nbf` and `iat`), TTL cap,
untrusted issuer, forged signature, tampered payload, unknown key, `alg: none`,
HMAC algorithm confusion, malformed token, unsupported contract version,
missing `dir`, `sid`, `spawn` and `act`, unknown `grade` and `origin`, bad actor
pattern, `dir` in an exchanged token, audience unexpected and mismatched, `dir`
mismatch, and the delivery failures (unset, missing and unsafe directory,
missing and symlinked file).

## Regenerating

`go test ./vectors -run TestRegenerateVectors -args -regenerate` rewrites
`v1/` with fresh keys. The tests in this directory (`go test ./vectors`) run
the vectors against a small reference verifier written from the specification
with the Go standard library, and check that every failure code has a vector.
