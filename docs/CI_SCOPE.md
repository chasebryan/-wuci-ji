# WUCI CI Scope

GitHub Actions is a public regression signal, not a release authority and not a
production-readiness certificate.

## CI Guarantees

The checked-in workflow runs on Ubuntu Linux x86_64 and currently verifies:

- Native `make clean && make test`.
- Reproducible build metadata.
- Parser and artifact boundary regression tests.
- Install regression tests.
- High-attestation metadata gates that do not depend on kernel namespace setup.
- Native self-release, anchored release, rooted publish, witness, and archive
  proof lanes.
- Zig cross-build, Zig release proofs, Zig witness verification, and Zig
  witness archive checks.

## CI Non-Claims

CI does not claim:

- Production cryptographic audit.
- Runtime sandboxing or VM containment.
- Quantum-safe verification.
- Fixture authority as production trust.
- Absence of exploitable vulnerabilities.
- Release authority for any artifact.

## Local-Only Or Runner-Dependent Gates

The following gates may depend on host CPU, kernel, or local tool availability:

- `make kernel-sandbox-proof` requires seccomp plus Linux user and network
  namespaces and fails closed if the assembly seccomp network-syscall deny
  selftest does not observe `EPERM`.
- `make carrot-policy` emits CARROT attestation with the same kernel proof.
- `make high-attestation-proof` composes the full local evidence lane and
  includes qemu, CARROT, CAGE/QCAGE, Gate, and full Linux CLI tests.
- `make rust-sandbox-build` and `make rust-sandbox-test` require `rustc`.
- `make pq-verifier-detect` records local OpenSSL/PQ verifier availability and
  does not claim quantum safety unless a real pinned verifier is detected.
