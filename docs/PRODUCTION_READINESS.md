# WUCI Production Readiness

WUCI-JI is not production-ready today. The current strongest defensible claim is
production-readiness evidence candidate: the repo can build deterministic local
evidence, emit SBOM/provenance artifacts, run high-attestation proof gates, and
state its non-claims explicitly. It now includes a CARROT kernel no-network
proof lane using a seccomp network-syscall deny filter plus Linux user and
network namespace checks, but not a complete production runtime sandbox.

WUCI-JI is not post-quantum secure and is not independently audited. Production
trust authority is not established. A complete runtime sandbox and no-network
containment outside the CARROT proof lane are not claimed until corresponding
controls exist and pass proof gates.

## Current Evidence

Run:

```sh
make high-attestation-proof
make sbom-provenance
make verify-release-bundle
make daylight-npt-ci
```

These targets produce or verify:

- Assembly smoke/regression coverage.
- Static assembly immediate/caller audit.
- Pinned `qemu-x86_64 -cpu Haswell-v4` X25519 lane.
- HARDEN, CAGE, QCAGE, and Gate contract proof lanes.
- CARROT runtime policy validation and kernel no-network proof using
  `wuci-ji sandbox-seccomp-net-deny-selftest` plus namespace entry checks.
- Compiled Rust wrapper evidence through `make rust-sandbox-test`.
- Fixture-authority production rejection gates.
- Formal WJ* composition model checks through `make wjstar-model-test`, covering
  AEAD secrecy, Golden Lock v1 3-of-5 open/release authority, 4-of-5
  root/authority/audit ceremony authority, Gate policy, H-Merkle evidence, and
  witness root mapping. This is a target model, not a production claim.
- Golden Lock policy and transcript fixture checks through
  `make golden-lock-policy-matrix`, covering pressure thresholds, domain quorum,
  downgrade rejection, claim discipline, and deterministic `C14N_G` / `m_G`
  evidence. This is not a production 5-party FROST implementation.
- WJ-GOLD model validation through `make wjgold-model-test`, covering the
  repo-native artifact authorization and release-evidence predicate, allowed
  open/release actions, pressure-to-threshold/PQ-mode consistency, participant
  and custody-domain diversity, missing public evidence blockers, fail-closed
  `pq-secure`, hybrid-evidence flags, private-material rejection, and explicit
  non-claims. This model validator is not production cryptography. Runtime
  sandboxing is not implemented by this model. Production authority is not
  established. Host/PQ system security and independent audit evidence are not
  supplied.
- WJ-next canonical transcript model checks through `make wjnext-model-test`,
  covering `C14N_v2`, the `wuci/transcript/v2` authorization hash, typed
  verifier predicates, and PQ modes where `pq-secure` remains false until
  independently earned.
- Real-PQ verifier detection that fails closed for unsupported PQ-safety claims when no
  pinned verifier is available. `make pq-verifier-fips204-proof` builds the
  local Rust FIPS 204 ML-DSA verifier, runs its KAT/selftest, emits v2
  real-PQ evidence, and writes a local pin for that verifier binary. This
  clears only the real-PQ verifier evidence gate; the WUCI-JI system is not
  quantum-safe.
- Internal crypto self-audit evidence that is explicitly not an external audit.
- Signed external audit evidence tooling. `tools/wuci_external_audit.py`
  verifies report digests, required scope, current reviewed commit, and an
  OpenSSH Ed25519 signature in the `wuci-external-audit-v1` namespace. Unsigned
  verification is test-only through `--allow-unsigned-audit`.
- Deterministic local parser hardening proof through assembly parser/verifier
  surfaces and internal public parsers. The v2 evidence covers envelope, armor,
  authority roots, Gate contracts, ledger entries/heads/proofs, WJ*, and
  WJ-next model inputs with zero timeout or signal exits.
- Release bundle verification evidence in
  `build/wuci-release-bundle-verification.json`.
- Deployment-authority policy evidence that rejects fixture authority and
  requires a signed non-fixture ceremony plus assembly Gate publish/trust
  positive authority before any stronger publish/trust claim. The
  current publish and trust commands are fail-closed decision paths only.
- Daylight cap-removal evidence through `make daylight-v06-cap-removal-test`,
  proving that the current 8250/10000 cap remains active, fixture authority
  cannot satisfy publish/trust, and the publish/trust command contracts remain
  fail-closed decision-only paths with no production-authority claim.
- DaylightNPT v1 evidence through `make daylight-npt-ci`. Reviewers can inspect
  `build/daylight/npt-v1/daylight-npt.report.json` for numeric-claim precision
  findings. This is a precision gate, not production readiness, security
  certification, audit status, post-quantum security, or external endorsement.
- Machine-readable JSON outputs for Gate and install verifier tooling.
- `build/wuci-sbom.json`.
- `build/wuci-provenance.json`.

## Production-Ready Claim Blockers

- Fixture authority is still test-only and must not be treated as production
  trust.
- FROST/secp256k1/X25519 evidence is classical-only and is not quantum-safe.
- Custom assembly crypto has not been independently audited or formally
  verified.
- Production publish/trust Gate authority is incomplete. The
  `publish-authorized-rooted` and `trust-authorized-rooted` now exist as
  fail-closed decision-only assembly paths that verify rooted contracts and
  print unauthorized decisions; they do not install, execute, decrypt, write
  plaintext. Production authority is not created. Deployment-authority roots
  emitted by the verifier must still keep `allow-publish` and `allow-trust`
  false until the signed ceremony workflow and deployment-authority verifier
  acceptance are linked.
- General runtime sandboxing is not complete. Independent wrapper/seccomp
  review and VM-grade containment are also incomplete. CARROT currently proves a narrow
  network-syscall deny lane on kernels that allow seccomp filters and
  unprivileged user+net namespaces.
- Real pinned PQ verifier evidence is available only when
  `tools/wuci_pq_verifier.py verify-real` passes against reviewed pins. The
  local Rust FIPS 204 verifier path can produce local ML-DSA verifier evidence
  with `make pq-verifier-fips204-proof`, but that evidence is still only a
  verifier gate and not a quantum-safe system claim.
- Release bundle verification currently records blockers instead of a
  production-ready claim when the install manifest is not signed for the
  current build, no real pinned PQ verifier evidence exists, no signed
  non-fixture deployment-authority ceremony is supplied, or no signed
  independent external audit evidence is supplied.
- External audit evidence can only clear its blocker when an external report,
  evidence JSON, auditor root public key, and detached signature all verify.
  The current repository contains the verifier workflow, not an external audit
  report or private signing key.
- The current-build install manifest blocker can only be cleared by the install
  root key holder through `make install-sign-current
  INSTALL_SIGNING_KEY=/absolute/path/to/root-signing-key`; private keys must
  stay outside the repository.
- KEV/CVE review is represented as policy discipline, not a live vulnerability
  attestation.

## Minimum Claim Criteria

A future production-ready claim requires all of the following:

- Non-fixture deployment-authority roots and documented key ceremony.
  `tools/wuci_production_authority.py emit-root`, `ceremony`,
  `sign-ceremony`, and `verify` provide the local workflow. Production
  verification requires an external OpenSSH Ed25519 ceremony root signature;
  unsigned ceremony verification is test-only and must use
  `--allow-unsigned-ceremony`.
- Release SBOM and provenance artifacts generated from a clean tree.
- Repeatable release build with SHA-256/SHA-384/SHA-512 public evidence.
- Independent security review or audit record covering the production surface.
  `tools/wuci_external_audit.py emit`, `sign-evidence`, and `verify` provide
  the local evidence format. Production release verification requires an
  external OpenSSH Ed25519 audit root signature; unsigned audit verification is
  test-only and must use `--allow-unsigned-audit`.
- Release-grade Rust sandbox wrapper evidence, kernel no-network proof, and
  independent review of the wrapper's namespace/seccomp posture.
- Fuzz/adversarial parser evidence for artifact, contract, witness, and ledger
  inputs.
- Explicit decision on whether WUCI is a crypto product, verifier, artifact
  format, or sandbox. Do not imply boundaries outside the implemented controls.
- If claiming quantum safety, a real pinned PQ verifier lane using reviewed
  implementations for NIST-standardized algorithms.

## Adoption License

WUCI-JI is licensed under Apache-2.0 for broad adoption, commercial use, and an
explicit patent license. See `LICENSE` and `NOTICE`.
