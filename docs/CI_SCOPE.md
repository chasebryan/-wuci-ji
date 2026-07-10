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
- Daylight Aperture Bastion (v19): capsule tests, doctor, committed-example
  verification, capsule demo, public artifact, and the public artifact
  firewall; the workflow uploads only the firewalled public directory
  (`daylight-v19-aperture-bastion.yml`).
- Offline live-integrity response-policy tests and repository-maintenance
  policy checks. These deterministic CI lanes perform no public network reads.
- The separate scheduled/manual `live-integrity` workflow explicitly checks
  out `main`, installs the locked Bottle dependencies with Node 22.23.1 and npm
  11.8.0, rebuilds and verifies `apps/bottle/dist`, then performs only bounded
  public GET/HEAD requests. The local build defines the Bottle request set and
  byte caps; the remote manifest cannot add paths or legitimize substituted
  bytes. The workflow also builds the deterministic Pages upload tree and
  compares every staged public file—code, claim/evidence data, discovery text,
  and media—directly with `main` under fixed local count, byte, MIME, and shared
  deadline budgets. The workflow sends no secrets or user content.
- Defensive CodeQL analysis for repository-owned JavaScript/TypeScript and
  Python. Third-party, frozen-fixture, dependency, build, and deployment-output
  paths are excluded by the checked-in CodeQL configuration.

Dependabot proposes reviewable updates for the two npm locks, GitHub Actions,
and only the first-party Cargo directories listed in `.github/dependabot.yml`.
It does not auto-merge and does not update vendored or frozen fixture trees.

## CI Non-Claims

CI does not claim:

- Production cryptographic audit.
- Runtime sandboxing or VM containment.
- Quantum-safe verification.
- Fixture authority as production trust.
- Absence of exploitable vulnerabilities.
- That CodeQL or dependency automation covers every language, dependency,
  generated artifact, or deployment behavior.
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
