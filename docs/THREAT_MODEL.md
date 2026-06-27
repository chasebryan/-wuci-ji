# WUCI Threat Model

Wuci-ji is a research/proof artifact. It is not production crypto, not a
runtime sandbox, not post-quantum secure, and not independently audited.

## Protected Assets

- Sealed artifacts and opened plaintext.
- Artifact key files.
- WUCI-WARRANT receipts and flat receipt contracts.
- Authority roots and their pinned group public keys.
- Witness bundles, deterministic witness archives, ledger entries, and ledger
  heads.
- Verifier binary identity and build provenance.
- The difference between release, publish, trust, and run semantics.

## Attacker Model

An attacker may provide malformed artifacts, contracts, receipts, witness
bundles, authority roots, ledger entries, archive files, and filesystem paths.
An attacker may also set non-strict environment variables, replace local mutable
files where permissions allow, or try to relabel fixture evidence as production
trust.

The model does not assume the current deterministic fixture FROST material is
secret. Fixture authority is test-only.

## Enforced Today

- Assembly enforces envelope parsing, authenticated open, no-overwrite output
  creation, artifact manifests, warrant messages, flat Gate contracts, rooted
  open/release checks, and Merkle leaf/node primitives.
- Zig verifies public witness and ledger formats for the current portable lane.
- Python still emits and verifies some fixture/reference evidence, install
  policy, CAGE/QCAGE attestations, and regression tests.
- Makefile targets compose the proof lanes. They are orchestration, not a
  cryptographic primitive.

## Not Enforced Today

- Production FROST authority or arbitrary signer material.
- Runtime sandboxing, network isolation, seccomp, namespaces, or VM containment.
- Post-quantum signature verification or quantum-safe status.
- Independent audit, formal verification, broad fuzzing, or constant-time
  certification.
- Runtime and display paths that still intentionally use the bounded
  `AEAD_OPEN_MAX` in-memory envelope path, including stdin `open`, stdin
  `manifest`, inspect, armor/dearmor, raw `aead-open`, and v3 recipient open.

## TCB Split

| Component | Current Role | Trust Status |
| --- | --- | --- |
| Assembly | Crypto primitives, envelope operations, Gate/root checks, ledger hash core | Highest implementation trust, still unaudited custom crypto |
| Zig | Portable witness/ledger/contract verifier bridge | Lower ceremony verifier bridge |
| Python | Fixture/reference emitters, policy tests, install/CAGE/QCAGE orchestration | Reference/orchestration, not the claimed metal boundary |
| Makefile | Reproducible local proof composition | Build orchestration |
| GitHub Actions | Public CI signal | Useful but not pinned/audited release authority |
| Fixture roots | Deterministic quorum anchors for proofs | Test-only, not production trust |

## Command Tiers

| Tier | Examples | Status |
| --- | --- | --- |
| Stable verifier commands | `manifest-file`, `warrant-message-file`, `authority-root-verify`, `gate-contract-verify`, `gate-contract-verify-rooted`, `release-authorized-rooted`, `ledger-leaf-file`, `ledger-node` | Current proof surface; file manifest/warrant paths stream SHA computation |
| Artifact workflow commands | `seal-file-keyfile-v2`, `open-file-keyfile`, `open-authorized-contract`, `open-authorized-rooted` | Demo/research artifact flow |
| Dev/test crypto primitives | `secp256k1-*`, `frost-secp256k1-*`, `aead-*`, `hmac-sha256`, `hkdf-sha256`, `poly1305`, `chacha20` | Developer test surface, not user-safe product UX |
| Explicitly risky public-only primitive | `secp256k1-basepoint-mul-variable-time-public-only` | Variable-time, public scalars only |
| Reserved semantics | `trust`, `publish`, general `run` | Not assembly-enforced as production trust in v1 |

## Non-Goals

- Do not market Wuci-ji as production cryptography.
- Do not claim runtime sandboxing until real OS-level enforcement exists.
- Do not claim post-quantum security until real PQ signatures are verified.
- Do not treat fixture authority roots as production trust anchors.
- Do not use Python/Zig policy emitters as a substitute for assembly-enforced
  trust claims without saying so explicitly.
