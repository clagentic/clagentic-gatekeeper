# Clagentic Identity Assertion contract

Contract version: **1.0.0** (assertion version claim `cia` = `1`).

This document is normative. It defines one artifact, the **Identity
Assertion**: a signed statement of which actor is acting, on whose behalf,
under which role ceiling, and for how long. Issuers produce it, consumers and
peers verify it.

The contract is the only thing tools share. A verifier or an issuer is
implemented from this document, a standard JWS library, and the conformance
vectors in [`vectors/`](../vectors/README.md). No tool imports another tool's
code, and nothing else from this repository is required to conform.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Overview

- The assertion is a JWS in compact serialization (RFC 7515) whose payload is a
  JSON claim set (RFC 7519).
- The delegation chain uses the `act` claim of RFC 8693: `sub` is who the chain
  acts for, `act.sub` is the current actor, `act.act` is what the actor was
  spawned under, outward.
- Signing keys are published as a JWKS (RFC 7517). A verifier finds the JWKS
  from the token's `iss` by the discovery rule in section 5.
- Locally the assertion is delivered through a directory named by an
  environment variable (section 6). Toward a remote peer it travels as the
  subject token of an RFC 8693 exchange, and the peer sees an exchanged token
  of the same shape (section 9).

Any issuer whose JWKS a verifier can discover is conformant. The contract does
not say how an issuer decides what to sign; that is the issuer's attestation
(see the README section on what an attestation provider adds).

## 2. Cryptography

| JWS `alg` | Key (JWK) | Notes |
|-----------|-----------|-------|
| `EdDSA` | `kty` `OKP`, `crv` `Ed25519` | Preferred (RFC 8037). |
| `ES256` | `kty` `EC`, `crv` `P-256` | Signature is the 64-byte `R \|\| S` form of RFC 7518 section 3.4, not DER. |

- Issuers MAY use either algorithm. Verifiers MUST support both.
- Any other `alg`, including `none` and every `HS*` value, MUST be refused
  (`alg_not_allowed`).
- The protected header MUST carry `alg` and `kid`. The verifier selects the key
  by `kid` from the issuer's JWKS, and the JWK's `kty`/`crv` MUST agree with
  the header `alg`; a disagreement is `signature_invalid`.
- A verifier MUST NOT fetch or trust keys named by the token itself. The
  header members `jku`, `jwk`, `x5u` and `x5c` MUST be ignored. A header with a
  `crit` member MUST be refused (`malformed`).

## 3. Claims

The machine-readable form is [`schemas/identity-assertion.json`](../schemas/identity-assertion.json).

| Claim | Type | Meaning |
|-------|------|---------|
| `iss` | string | Issuer identifier. Matched by exact string comparison against the verifier's trusted issuers (section 5). |
| `sub` | string | Who the chain acts for: `human:<name>`, or the top-level actor (`agent:<name>` or `runtime:<name>`) when no human is involved. |
| `act` | object | RFC 8693 actor. `act.sub` is the current actor (`agent:<name>` or `runtime:<name>`), `act.act` is what it was spawned under, outward. Each level has the same shape. |
| `roles` | array of string | The role ceiling: what the holder may be granted, never what it is granted. Role names are a deployment vocabulary; the contract defines the transport, not the names (examples: `builder`, `reviewer`, `merger`, `security`, `reader`). |
| `grade` | string | `workload` or `harness`. |
| `rt` | object | The runtime: `id` (string) and `version` (string). |
| `sid` | string | Session identifier. A child carries its parent's session identifier. |
| `spawn` | string | Identifier of one spawn of a child actor. |
| `origin` | string | What started the turn: `human`, `scheduled`, `loop`, `trigger` or `agent`. |
| `dir` | string | Absolute path of the delivery directory this assertion is bound to (section 6). |
| `iat` | integer | Issued at, NumericDate (seconds). |
| `exp` | integer | Expiry, NumericDate (seconds). |
| `nbf` | integer | Optional not-before, NumericDate. |
| `jti` | string | Unique token identifier. |
| `cia` | integer | Contract major version. This document is `1`. |
| `aud` | string | Absent locally. The peer identifier when the token was exchanged for a peer (section 9). |

Name patterns: the `<name>` part of an actor string matches
`[A-Za-z0-9._-]{1,128}`. Role strings match `[a-z][a-z0-9_-]{0,63}`.

`grade` semantics:

- `workload`: an operating-system process started by a launcher, attested by
  something the process cannot forge (for example kernel peer credentials).
- `harness`: an actor that exists only inside a host process (for example an
  in-process sub-agent) and is asserted by that host. It is attribution-grade:
  it says what the host reported, with the host's authority and no more.

The grade is a label from the issuer. How much it can be trusted depends on
how well the issuer protects its key; consumers decide policy on it.

### 3.1 Required claims per grade

Always required: `iss`, `sub`, `roles`, `grade`, `rt`, `sid`, `origin`, `iat`,
`exp`, `jti`, `cia`.

| Case | Additionally required | Forbidden |
|------|-----------------------|-----------|
| `grade` = `workload`, `aud` absent (local assertion) | `dir` | |
| `grade` = `harness`, `aud` absent (local assertion) | `dir`, `spawn`, `act` (at least one level) | |
| `grade` = `workload`, `aud` present (exchanged token) | `aud` | `dir` |
| `grade` = `harness`, `aud` present (exchanged token) | `aud`, `spawn`, `act` (at least one level) | `dir` |

A verifier MUST ignore claims it does not know. It MUST refuse an unknown value
of `grade` or `origin` (`claims_invalid`); adding a value is a major version
change (section 11).

### 3.2 Reading the chain

- Who did it: `act.sub` of the outermost `act` when present, else `sub`.
- Operator-originated: `sub` is a `human:` actor and there is no `act`.
- Human-directed: `sub` is a `human:` actor and an `act` chain is present.
- Autonomous: `sub` is not a `human:` actor.

## 4. Verification

A conformant verifier performs these steps in this order and reports the first
failure by its code. The order is normative so that two verifiers agree on the
code for a token with several faults.

1. Split into three base64url segments; decode the header and payload as JSON
   objects. The header and the payload are each exactly one JSON object: any
   non-whitespace content after it, whether a second JSON value or junk, is
   `malformed`. Otherwise `malformed`. A `crit` header member is also
   `malformed`.
2. Header `alg` MUST be `EdDSA` or `ES256`. Otherwise `alg_not_allowed`.
3. Read `iss` from the payload (not yet trusted). It MUST be a string equal to
   one of the verifier's trusted issuers. Otherwise `issuer_untrusted`.
4. Resolve the issuer's JWKS (section 5) and find the key whose `kid` equals
   the header `kid`. No such key: `key_not_found`.
5. Verify the signature over `header.payload` as sent. Failure, or a key whose
   type does not match `alg`: `signature_invalid`.
6. `cia` MUST equal a contract major version the verifier supports. Otherwise
   `contract_version_unsupported`.
7. Time. `iat` and `exp` MUST be present and `nbf`, when present, MUST be an
   integer NumericDate (a JSON number with no fraction or exponent). A string,
   a fractional number, or any other type is `claims_invalid`; no comparison
   or coercion happens before this check passes. Then, with `now` read once
   and zero leeway for conformance runs:
   `exp <= now` is `expired`; `nbf` present and `now < nbf`, or `iat > now`, is
   `not_yet_valid`; `exp - iat > 43200` is `ttl_exceeded`. A deployment MAY
   configure leeway of at most 60 seconds.
8. Claim shape and the required-claims table in section 3.1, including the
   name patterns. Otherwise `claims_invalid`.
9. Audience, by the mode the verifier runs in (section 7 for local consumers,
   section 9 for peers): `audience_unexpected` or `audience_mismatch`.
10. Local consumers only: the `dir` claim MUST equal the directory the token
    was read from, both lexically normalized (no symlink resolution).
    Otherwise `dir_mismatch`.

Delivery failures (section 6) come before step 1.

A verifier MUST NOT fall back to another identity source when verification
fails. Whether to fall back is a decision of the application that embeds the
verifier.

### 4.1 Failure codes

| Code | Raised when |
|------|-------------|
| `identity_dir_missing` | The delivery variable is unset, empty, not absolute, or names a directory that does not exist or is not a directory. |
| `identity_dir_unsafe` | The delivery directory is a symlink, is not owned by the verifier's user, or has any group or other permission bit. |
| `identity_file_missing` | `identity.jwt` does not exist in the delivery directory. |
| `identity_file_symlink` | `identity.jwt` is a symlink or not a regular file. |
| `malformed` | Not a three-segment compact JWS, header or payload not exactly one JSON object (trailing content included), a `crit` header, or a file over 16384 bytes. |
| `alg_not_allowed` | Header `alg` is not `EdDSA` or `ES256`. |
| `issuer_untrusted` | `iss` is absent, not a string, or not a trusted issuer. |
| `key_not_found` | The issuer's JWKS has no key with the header `kid`. |
| `signature_invalid` | The signature does not verify, or the key type does not match `alg`. |
| `contract_version_unsupported` | `cia` is absent or not a supported major version. |
| `expired` | `exp <= now`. |
| `not_yet_valid` | `nbf` in the future, or `iat` in the future. |
| `ttl_exceeded` | `exp - iat` is greater than 43200 seconds. |
| `claims_invalid` | Wrong type, bad pattern, unknown `grade` or `origin`, a required claim missing, or a forbidden claim present. |
| `audience_unexpected` | Local mode and `aud` is present. |
| `audience_mismatch` | Peer mode and `aud` is absent or not the peer's own identifier. |
| `dir_mismatch` | Local mode and `dir` differs from the directory the token was read from. |

Every code has at least one vector in the conformance set.

## 5. Issuer trust and JWKS discovery

Trust is configuration. A verifier holds a list of trusted issuer identifiers
and accepts a token only if `iss` is exactly equal to one of them. Discovery
only says where to fetch keys for an issuer already trusted; it never extends
trust. The machine-readable form is
[`schemas/jwks-discovery.json`](../schemas/jwks-discovery.json).

### 5.1 Locating the JWKS

Each trusted issuer has a JWKS locator. It is either given explicitly in the
verifier's configuration (`jwks`) or derived from `iss`:

| `iss` form | Derived JWKS locator |
|------------|----------------------|
| `https://host[:port][/path]` | The URL `<iss>/.well-known/jwks.json` (any trailing slash of `iss` removed first). |
| `http://host[:port][/path]` | Same, permitted only for loopback hosts unless the verifier is configured otherwise. |
| `file:///absolute/path` | The file at that path. The `iss` names the JWKS document itself. |
| `unix:///absolute/socket/path` | `GET /.well-known/jwks.json` over HTTP/1.1 on that unix socket (`Host: localhost`). |
| anything else | No derivation. The verifier's configuration MUST give `jwks`. |

An explicit `jwks` locator uses the same notations, with these meanings: a
`file:` locator is the document; an `http:`/`https:` locator is the full
document URL; a `unix:` locator is the socket serving
`/.well-known/jwks.json`.

### 5.2 Fetching rules

- A file source MUST be read without following a symlink and MUST be a regular
  file. Verifiers SHOULD refuse a file writable by group or other.
- A network source MUST be bounded: a timeout, a response size cap of 65536
  bytes, and no redirect to a different host. `https` certificates are
  validated normally.
- The document is a JWKS: `{"keys": [...]}`. Each key carries `kty`, `kid`,
  `alg`, `use` (`sig`) and its public parameters. A JWKS MUST NOT contain
  private key parameters.
- Verifiers MAY cache. On an unknown `kid` a verifier SHOULD refetch once, no
  more than once per 60 seconds, so key rotation works without restarts.
  An issuer rotating a key SHOULD publish the new key before signing with it
  and keep the old key until every assertion signed with it has expired.

## 6. Local delivery

The environment variable `CLAGENTIC_IDENTITY_DIR` names the delivery
directory.

```
$CLAGENTIC_IDENTITY_DIR/        mode 0700, owned by the holder's user
    identity.jwt                the assertion, compact JWS, regular file
    tmp/                        scratch directory for the holder
```

- The value MUST be an absolute path to a directory. The directory MUST be
  owned by the verifier's user with mode `0700`, and its final path component
  MUST NOT be a symlink.
- `identity.jwt` MUST be a regular file opened without following symlinks. A
  verifier opens it with no-follow semantics and checks the open handle, not
  the path (so the check and the use refer to the same file).
- The file holds exactly one compact JWS, optionally followed by one trailing
  newline, at most 16384 bytes.
- `tmp` is on the same filesystem as the directory so an issuer can write a
  refreshed assertion into `tmp` and rename it over `identity.jwt` atomically.
  Verifiers MUST read the file on use, not at process start, so a refreshed
  assertion is picked up. The contents of `tmp` are not part of the contract.
- The `dir` claim binds the assertion to its directory (section 4, step 10).
  Copying the file to another directory makes it unusable there.

## 7. Local consumers

A consumer that reads the assertion from the delivery directory:

1. Applies the delivery checks of section 6 (codes `identity_*`).
2. Runs section 4 in **local mode**: `aud` MUST be absent
   (`audience_unexpected`), and the `dir` binding is checked.
3. Takes the actor, chain, roles, grade and origin from the claims. It treats
   `roles` as a ceiling: a role not in the list is never granted; being in the
   list is necessary, not sufficient.
4. Records which issuer and grade produced the attribution.

The consumer's configuration lists its trusted issuers and, per issuer, an
optional explicit `jwks` locator (section 5).

## 8. Lifetime

- A session assertion lives at most 12 hours (`exp - iat <= 43200`).
- A child assertion is issued with `exp` no later than its parent's `exp`. The
  verifier cannot see the parent, so this bound is an issuer obligation; the
  12-hour cap is what a verifier enforces.
- A child assertion's `roles` are a subset of its parent's `roles`: delegation
  never widens. The verifier cannot see the parent, so this too is an issuer
  obligation.
- A holder refreshes by asking its issuer for a new assertion. The previous one
  stays valid until its own `exp`; there is no revocation list. Short lifetimes
  are the revocation mechanism.

## 9. A2A peers

A peer is any party outside the holder's host that must decide whether to
accept a call from an agent. The assertion is the credential that gets it
there; the peer never sees the local assertion.

### 9.1 Exchange

The holder presents its local assertion as the **subject token** of an RFC 8693
token exchange to an exchange service:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<assertion>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
requested_token_type=urn:ietf:params:oauth:token-type:jwt
audience=<peer identifier>
```

The exchange service MUST verify the subject token as a local consumer would
(sections 4, 6 and 7). It returns an **exchanged token**: a JWS of the same
claim set with these changes:

- `aud` is set to the peer identifier. A peer identifier is an opaque string
  agreed between the peer and the exchange.
- `dir` is removed. A host path is not disclosed to a peer.
- `jti` is new, `iat` and `exp` are the exchange's own, and `exp` is not later
  than the subject token's `exp`.
- `iss` is the exchange service's issuer identifier. It need not be the issuer
  of the subject token; the exchange service is a trusted issuer for the peer.
- `sub`, `act`, `roles`, `grade`, `rt`, `sid`, `spawn`, `origin` and `cia` are
  carried over unchanged. An exchange MUST NOT widen `roles` and MUST NOT
  change `grade`.

An exchange service MAY be any service that signs conformant tokens; it can be
the issuer itself. The contract does not define the exchange's own
authentication or the policy that decides whether an exchange is allowed.

### 9.2 TTL

The lifetime of the subject token follows section 8. The lifetime of the
exchanged token is owned by the exchange: it chooses a value no greater than
the subject's remaining lifetime and no greater than 43200 seconds. A short
value (minutes) is RECOMMENDED because an exchanged token leaves the host.

### 9.3 Audience rule

- Locally, `aud` is absent. A local consumer that sees `aud` refuses the token
  (`audience_unexpected`): a token minted for a peer is not an identity for
  this host.
- When exchanged, `aud` is a string equal to the peer identifier. A peer
  accepts only a token whose `aud` is exactly its own identifier
  (`audience_mismatch` otherwise, including when `aud` is absent). A peer that
  receives a local assertion therefore refuses it.

### 9.4 Writing a peer validator

A peer validator needs only this document and a JWS library:

1. Configure its own peer identifier and its trusted issuers (the exchange
   services it relies on), each with an optional explicit `jwks` locator.
2. For each request, take the exchanged token from the transport the peer
   uses (for example an HTTP bearer header).
3. Run section 4 in **peer mode**: skip the delivery checks, require
   `aud` equal to its own identifier, and do not check `dir` (an exchanged
   token must not carry one, and its presence is `claims_invalid`).
4. Authorize from `roles`, `grade`, the chain and `origin`, by the peer's own
   policy. `roles` is a ceiling, as in section 7.

Issuer trust and key distribution are as in section 5: the peer trusts an
issuer by configuration and discovers its keys by the rule. This is the
complete peer-side validation contract.

## 10. Conformance

The vector set in [`vectors/`](../vectors/README.md) is the test of a
verifier. It covers every code in section 4.1, both algorithms, a child
assertion, and peer-mode tokens. A verifier is conformant when it reproduces
every expected outcome. The vectors are signed with throwaway keys; the
private halves are never published, only the public JWKS the vectors verify
against.

Consumers SHOULD vendor the vector set pinned to a contract version and run it
in their own tests.

## 11. Versioning

- The contract version is `MAJOR.MINOR.PATCH`. The `cia` claim carries `MAJOR`.
- PATCH: clarifications and new vectors for existing behavior.
- MINOR: backward compatible additions, such as new optional claims. A
  verifier ignores unknown claims, so a MINOR change never breaks it.
- MAJOR: anything else, including a change to required claims, to the
  verification order, to failure codes, or a new value of `grade` or `origin`.
- Vector sets are versioned by MAJOR in their path (`vectors/v1/`). A MAJOR
  version keeps its vector set for as long as the version is supported.
- An issuer emits one `cia`. A verifier accepts the set of majors it
  implements; during a transition it MAY accept two adjacent majors.
- Failure codes are stable identifiers. Adding a code is a MINOR change only if
  the situation previously produced `claims_invalid` or `malformed`.

## 12. Security considerations

- The signature proves the issuer made the statement; it does not prove the
  issuer verified the holder. Trust in a `workload` grade rests on how the
  issuer attests the holder and on the holder being unable to read the signing
  key. Verify those properties of the issuer you trust.
- `roles` is a ceiling. Treating it as a grant is a vulnerability in the
  consumer.
- Algorithm and key confusion are closed by the fixed allow-list, mandatory
  `kid`, exact `kty`/`crv` match, and ignoring key-carrying headers.
- Bound the damage of a leaked assertion with short lifetimes, the `dir`
  binding (local) and the `aud` rule (remote).
