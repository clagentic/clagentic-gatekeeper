# A2A attestation contract

This document has been superseded. The contract for agent identity, including
what an agent-to-agent (A2A) peer validates, is the Identity Assertion
contract:

- [`docs/identity-contract.md`](identity-contract.md) — normative: claims, key
  discovery, local delivery, and the A2A peer section (section 9).
- [`schemas/identity-assertion.json`](../schemas/identity-assertion.json) (major 1),
  [`schemas/identity-assertion-2.json`](../schemas/identity-assertion-2.json) (major 2) and
  [`schemas/jwks-discovery.json`](../schemas/jwks-discovery.json) — schemas.
- [`vectors/`](../vectors/README.md) — signed conformance vectors.

The sidecar field table that used to live here described the input of the
sidecar attestation reader, which is documented in
[`SIDECAR-READ-CONTRACT.md`](SIDECAR-READ-CONTRACT.md) and
[`SETUP.md`](SETUP.md). It is not part of the identity contract.
