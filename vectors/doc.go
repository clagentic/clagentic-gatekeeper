// Package vectors holds the conformance vectors of the Clagentic Identity
// Assertion contract (docs/identity-contract.md) and the tests that check
// them against a reference verifier.
//
// The package has no exported surface and is not imported by any other
// package: the contract, not this code, is what tools share. The verifier in
// the tests exists to prove the vector set is internally consistent; each tool
// implements its own verifier from the specification and vendors the vectors.
package vectors
