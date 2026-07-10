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
- WJ-GOLD model inputs that bind sealed artifacts, manifests, Gate contracts,
  quorum receipts, public evidence, and claim mode.
- Verifier binary identity and build provenance.
- The difference between release, publish, trust, and run semantics.

## Attacker Model

An attacker may provide malformed artifacts, contracts, receipts, witness
bundles, authority roots, ledger entries, archive files, and filesystem paths.
An attacker may provide malformed WJ-GOLD evidence inputs or try to relabel
bounded internal evidence levels as stronger security claims. An attacker may
also set non-strict environment variables, replace local mutable files where
permissions allow, or try to relabel fixture evidence as production trust.

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
- CARROT validates runtime policy intent and the local proof lane checks a
  seccomp network-syscall deny filter plus Linux user+network namespace entry
  with assembly probes.
- WJ-GOLD validates a repo-native acceptance model for open/release artifact
  authorization evidence. It checks allowed actions, pressure/PQ-mode
  discipline, threshold and custody-domain rules, public evidence presence,
  private-material absence, and overclaim rejection. It is a model gate, not a
  cryptographic verifier.

## Not Enforced Today

- Production FROST authority or arbitrary signer material.
- General runtime sandboxing is not enforced. Seccomp policy beyond the CARROT
  network-syscall deny filter, VM containment, and no-network claims outside the
  CARROT proof lane are also not enforced.
- The system is not quantum-safe; post-quantum signature verification is not
  implemented.
- WJ-GOLD does not implement production FROST or ML-DSA verification, and
  `pq-secure` remains fail-closed.
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

- Production cryptography is not claimed in Wuci-ji marketing.
- Runtime sandboxing is not claimed. Real OS-level enforcement is required
  before that boundary can change.
- Do not claim post-quantum security until real PQ signatures are verified.
- Do not treat fixture authority roots as production trust anchors.
- Do not use Python/Zig policy emitters as a substitute for assembly-enforced
  trust claims without saying so explicitly.
