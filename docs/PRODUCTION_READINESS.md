# WUCI Production Readiness

WUCI-JI is not production-ready today. The current strongest defensible claim is
production-readiness evidence candidate: the repo can build deterministic local
evidence, emit SBOM/provenance artifacts, run high-attestation proof gates, and
state its non-claims explicitly.

Do not describe WUCI-JI as production crypto, a runtime sandbox, no-network
containment, post-quantum secure, independently audited, or production trust
authority until the corresponding controls exist and pass proof gates.

## Current Evidence

Run:

```sh
make high-attestation-proof
make sbom-provenance
```

These targets produce or verify:

- Assembly smoke/regression coverage.
- Static assembly immediate/caller audit.
- Pinned `qemu-x86_64 -cpu Haswell-v4` X25519 lane.
- HARDEN, CAGE, QCAGE, and Gate contract proof lanes.
- `build/wuci-sbom.json`.
- `build/wuci-provenance.json`.

## Production-Ready Claim Blockers

- Fixture authority is still test-only and must not be treated as production
  trust.
- FROST/secp256k1/X25519 evidence is classical-only and must not be called
  quantum-safe.
- Custom assembly crypto has not been independently audited or formally
  verified.
- Production publish/trust Gate commands do not exist as assembly-enforced
  authority paths.
- Runtime sandboxing and network containment are not implemented.
- KEV/CVE review is represented as policy discipline, not a live vulnerability
  attestation.

## Minimum Claim Criteria

A future production-ready claim requires all of the following:

- Non-fixture production authority roots and documented key ceremony.
- Release SBOM and provenance artifacts generated from a clean tree.
- Repeatable release build with SHA-256/SHA-384/SHA-512 public evidence.
- Independent security review or audit record covering the production surface.
- Fuzz/adversarial parser evidence for artifact, contract, witness, and ledger
  inputs.
- Explicit decision on whether WUCI is a crypto product, verifier, artifact
  format, or sandbox. Do not imply boundaries outside the implemented controls.
- If claiming quantum safety, a real pinned PQ verifier lane using reviewed
  implementations for NIST-standardized algorithms.

## Adoption License

WUCI-JI is licensed under Apache-2.0 for broad adoption, commercial use, and an
explicit patent license. See `LICENSE` and `NOTICE`.
