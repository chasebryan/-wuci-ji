# Rust Implementation Plan

This plan keeps Daylight implementation work staged. The active minimal core
target is `../specs/daylight-minimal-core-v0.4.md`; Daylight remains
`research_draft` and production-disallowed until the M5 external-review gate.

## Phase 0: Model Only

Status: implemented in `../rust/daylight-model`.

Allowed:

- v0.4 action, profile, mode, and claim enums.
- Threshold profile constants.
- Probability arithmetic for poster checks.
- Pure validation helpers over non-secret values.
- Unit tests with deterministic values from the poster.

Forbidden in this phase:

- Encryption or decryption.
- Signature generation or verification.
- KEM encapsulation or decapsulation.
- Password hashing.
- Runtime sandboxing claims.
- Network access.

## Phase 1: Canonical Transcript Spec

Before adding parsers, resolve transcript staging:

```text
T_pre  -> m_pre  -> KEM/combine/key schedule/envelope
T_auth -> m_auth -> authorization signatures and predicates
```

The corrected design uses `T0` and `T1`:

```text
T0 -> m0 -> ML-KEM/DHKEM encapsulations -> KMAC combiner -> key schedule -> AEAD
T1 -> m_D -> authorization signatures and predicates
```

Both phases must be domain-separated and covered by fixture vectors.

Required outputs:

- ABNF or equivalent field grammar.
- Duplicate-field rejection.
- Unknown critical-field rejection.
- Stable field order.
- Size limits.
- Separate public and private material classes.
- Fixture corpus with positive and negative cases.

## Phase 2: Fail-Closed Predicate Engine

Status: partially implemented as a lower-level v0.4 surface in
`../rust/daylight-crypto`.

Implement predicate composition without cryptography:

```text
Parse_D
EnvOK placeholder interface
RootOK placeholder interface
GateOK
WitnessOK
LedgerOK
ProvenanceOK
InstallOK
NoDowngrade
Req(r,mu)
ClaimOK
```

All crypto-dependent traits must default to reject. Test doubles may return
accept only for deterministic non-secret fixtures and must be named as fixtures.

Current implemented subset:

- Typed v0.4 header, content scope, leakage, envelope, key schedule, precheck evidence, and
  open-report structures.
- `Daylight Minimal Core v4 seal/open` with both supplied-schedule and
  ML-KEM-1024+DHKEM(P-384,HKDF-SHA384)-derived key schedule paths. Both require
  supplied precheck evidence.
- Caller-supplied `CryptoRng` v4 KEM seal API for non-vector sealing.
- Deterministic-CBOR encoder subset for current transcript values.
- Deterministic-CBOR decoder subset for arrays, byte strings, text strings,
  unsigned integers, and typed v4 headers/envelopes.
- Deterministic v4 reference-vector builder, CLI printer, and persisted vector
  file checked by unit tests.
- Deterministic v4 negative parser seed corpus checked by unit tests.
- HKDF-SHA512 v4 key schedule split into `(K_E,K_COM,N_base)`.
- Built-in checks for suite id, profile/action mode rules, release-level claim
  classes, ML-KEM ciphertext length, DHKEM encapsulated public key validation,
  nonce bounds, KEM derivation rejection, AEAD rejection, hidden artifact
  commitment verification, and declared leakage verification.
- FROST-required profiles fail closed with `AuthFUnsupported`.
- Negative tests cover gate denial, downgrade denial, compact protected action,
  bad claim, missing root hash authorization, unsupported FROST requirement,
  bad KEM derivation, public precheck before private derivation, bad ciphertext,
  bad commitment, bad nonce, bad leakage, and malformed envelope bytes.
- v0.5.1/2 v6 hardening layer in `../rust/daylight-crypto/src/v6.rs`:
  deterministic CBOR maps/null/bool, exact-key v6 object schemas, `HC`/`HB`
  digest convention helpers, versioned v6 transcript/KDF labels, static policy
  object parsing, C1 schema vector generation, and rejection-stage tests. This
  layer intentionally rejects at `REJECT_AUTH_SIGNATURE` before private KEM or
  AEAD because production key-live authority is undefined.
- Imported Daylight v0.6 M1 Python fixture artifact in
  `../fixtures/daylight-v06-m1/`, with 5 valid vectors and 27 negative vectors
  wired through `make daylight-v06-m1-fixture-test`. Its KEM, signature,
  review, certificate, revocation, and log predicates are deterministic
  fixtures only.

Remaining before this can be called complete:

- Review the imported v0.6 M1 fixture profile and compare its byte-level corpus
  against the Rust v6 schema surface.
- Independent second v6 parser and cross-parser agreement.
- Coverage-guided fuzzing for the deterministic-CBOR header/envelope parser.
- OS RNG selection policy and key lifecycle handling for the KEM-derived
  Seal/Open path.
- Integrated policy, gate, witness, transparency log, provenance, and install
  validators.
- Real authorization quorum construction for ML-DSA and SLH-DSA evidence.
- Complete positive/negative vector corpus and cross-implementation fixtures.

## Phase 3: Cryptography Candidate Evaluation

No crate should be introduced just because it exists. For each candidate:

- Record upstream source, version, license, maintainers, release status, and
  audit status if available.
- Pin exact crate versions and transitive dependency versions.
- Record standard revision and errata state.
- Require KATs from the relevant standard or upstream test vectors.
- Require malformed input and negative verification tests.
- Require failure behavior that returns no plaintext and no partial authority.
- Document side-channel assumptions and platform feature requirements.

Initial status:

- `../rust/daylight-crypto` implements pinned local pieces:
  SHA2-512/SHA3-512/SHAKE256-512, SP 800-185 derivation helpers, Daylight
  `h_D`, `T0`/`T1` message derivations, the corrected KMAC combiner/key
  schedule shape, HPKE-style nonce derivation, AEAD seal/open, ML-KEM-1024,
  DHKEM(P-384,HKDF-SHA384) KEM-only operations, ML-DSA-87 verification,
  SLH-DSA-SHAKE-256s verification, and Argon2id.
- The same crate now implements a v0.4 minimal-core seal/open surface with
  deterministic-CBOR subset encoding, HKDF-SHA512 schedule derivation from
  supplied shared secrets or ML-KEM+DHKEM outputs, and supplied precheck
  evidence. It is useful for fail-closed invariant testing, but it is not full
  M2 reference completion.
- The same crate also implements the v0.5.1/2 v6 byte-level hardening surface
  for schema, transcript, KDF-label, and rejection-stage analysis. It is useful
  for M1 hardening, but it is not a successful Open implementation and does not
  claim M1 completion.
- The extracted Python v0.6 M1 fixture artifact is tracked separately under
  `../fixtures/daylight-v06-m1/`; it improves executable byte-level evidence,
  but does not replace real cryptographic providers or independent review.
- The DHKEM lane is deliberately KEM-only. It does not add a full HPKE session
  layer or change Daylight's AEAD/key schedule.
- Candidate check: `hpke = 0.14.0-pre.2` exposes
  `DhP384HkdfSha384`, but its current pre-release dependency graph did not
  build in this workspace. The current KEM-only lane instead uses pinned
  RustCrypto `p384 = 0.13.1` and `hkdf = 0.12.4`.
- `FROST-P384-SHA384` is not an RFC 9591 ciphersuite. The P-384 lane remains
  unsupported unless it is renamed `FROST_custom(P-384,SHA-384)` and a full
  ciphersuite specification is reviewed.
- The ML-DSA-87 lane is verifier-only for external callers. It includes a
  deterministic KAT selftest, but no general-purpose signing CLI.

## Phase 4: Integration With Wuci-Ji

Only after the model and verifier lanes are stable should Daylight connect to
existing Wuci-Ji proof lanes.

Potential integration points:

- Witness public-file hardening.
- Ledger history verification.
- Gate reserved-action denial.
- QCAGE digest vectors and no false quantum claim checks.
- INSTALL proof reads with symlink rejection.

Do not use Daylight to claim production authority, runtime sandboxing, or
whole-system quantum safety.
