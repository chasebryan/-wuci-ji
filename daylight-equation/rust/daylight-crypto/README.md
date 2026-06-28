# daylight-crypto

This crate is the first Daylight Equation crypto implementation lane.

It implements only pinned, locally available pieces:

- SHA2-512, SHA3-512, and SHAKE256-512 digest vectors.
- SP 800-185 encoding helpers used by cSHAKE256, TupleHash256-style hashing,
  KMAC256-style derivations, and Daylight `EncTuple` inputs.
- Deterministic-CBOR-Daylight-v1 encoder/decoder subset for v0.4 transcript
  values containing arrays, byte strings, text strings, and unsigned integers,
  plus typed v4 header and envelope decoding.
- Daylight `h_D`, pre-envelope message, authorization message,
  KEM-combiner derivation over already supplied shared secrets, corrected key
  schedule derivation, hidden artifact commitment, and HPKE-style nonce
  derivation.
- AES-256-GCM and ChaCha20-Poly1305 seal/open through pinned crates.
- ML-KEM-1024 encapsulation/decapsulation through pinned `fips203 = 0.4.3`.
- DHKEM(P-384,HKDF-SHA384) KEM-only operations through pinned
  `p384 = 0.13.1` and `hkdf = 0.12.4`.
- Daylight Minimal Core v4 seal/open with both supplied-schedule and
  ML-KEM-1024+DHKEM(P-384,HKDF-SHA384)-derived key schedule paths, including a
  caller-supplied `CryptoRng` seal API. These use supplied precheck evidence,
  HKDF-SHA512 for the v4 key schedule, and enforce
  public-precheck-before-derivation/AEAD ordering, profile/action/claim checks,
  nonce bounds, derivation rejection, AEAD rejection, hidden artifact commitment
  verification, leak verification, and fail-closed FROST requirements.
- One deterministic v4 reference vector in
  `vectors/daylight-v4-reference-vector-v1.txt`, verified by unit tests.
- One deterministic v4 negative parser seed corpus in
  `vectors/daylight-v4-negative-parser-vectors-v1.txt`, verified by unit tests.
- Daylight Envelope v0.5.1/2 v6 byte-level hardening under `src/v6.rs`,
  including deterministic CBOR map/null/bool support, exact-key typed v6
  schemas, `HC`/`HB` digest convention helpers, v6 transcript/KDF labels,
  static policy parsing, rejection-stage tests, and a C1 schema vector CLI that
  fails closed at `REJECT_AUTH_SIGNATURE` before private KEM or AEAD.
- Provider-backed v6 KEM/key-schedule evidence for the C1 schema vector,
  including ML-KEM-1024 and DHKEM(P-384,HKDF-SHA384) decapsulation agreement
  and hashed key-schedule outputs in
  `vectors/daylight-v6-provider-kem-evidence-v1.txt`. This is not a v6
  reference `Seal`/`Open` implementation.
- Provider-backed v6 private-roundtrip evidence for the C1 schema vector,
  including typed `PrivatePayload_v6` CBOR, AEAD seal/open with `AD = T0`,
  artifact commitment checking, and a persisted vector in
  `vectors/daylight-v6-provider-private-roundtrip-evidence-v1.txt`. This is a
  prechecked private-path proof only; public authorization still fails closed.
- Provider-backed v6 reference `Seal`/`Open` evidence for the C1 schema vector,
  including provider ML-KEM-1024, DHKEM(P-384,HKDF-SHA384), AEAD seal/open,
  typed private payload decoding, artifact commitment checking, and a persisted
  vector in
  `vectors/daylight-v6-reference-seal-open-evidence-v1.txt`. This lane requires
  explicit non-production external public precheck evidence and does not
  integrate production certificate, revocation, log, install, witness, publish,
  or trust authority.
- A typed v6 lifecycle where `daylight_authorized_envelope_v6` constructs a
  `DaylightAuthorizedEnvelopeV6` only after public predicates and the
  cap-limited 8250/10000 research boundary pass, and
  `daylight_open_authorized_v6_with_kems` is the provider-backed private path
  for that typed state. This is research evidence only and does not convert
  externally supplied public authority into production authority.
- A WUCI-DAYLIGHT bridge command,
  `wuci-daylight-envelope-boundary --file <artifact>`, that classifies WJSEAL
  v1/v2/v3 envelope bytes, binds them to the Daylight v0.6 8250/10000
  zero-claim boundary, and records that WUCI-GATE is still required for
  plaintext release. It does not decrypt, verify tags, or accept keys.
- A provider-backed v6 reference negative corpus in
  `vectors/daylight-v6-reference-negative-corpus-v1.txt`, covering external
  public-precheck denials, production-disallowed denial, and private-path AEAD
  and commitment mutation failures for the non-production reference lane.
- A Nightlight v6 equation battery in
  `vectors/nightlight-v6-equation-battery-v1.txt`, aggregating the v6 schema,
  provider KEM, private-roundtrip, reference `Seal`/`Open`, and reference
  negative-corpus evidence into an open-ended deterministic equation,
  domain-separation, and fail-closed efficiency gate. The current vector covers
  45 public-boundary mutation simulations plus 12 reference negative cases,
  with minimum thresholds so the corpus can grow without changing the gate
  shape. These are defensive adversarial validation simulations that force
  Daylight to reject tampered or malformed inputs; they are not attack crypto
  and do not raise the Daylight score.
- A Nightlight v6 deep assessment in
  `vectors/nightlight-v6-deep-assault-assessment-v1.txt`, applying
  `deterministic-coverage-learning-v1` over the same local fail-closed corpus.
  It scores learning arms by risk, novelty, and coverage, emits eight
  prioritized epochs, and records gap recommendations without adding
  offensive logic, network behavior, or score claims.
- ML-DSA-87 verification through pinned `fips204 = 0.4.6`, with a deterministic
  fixture selftest.
- SLH-DSA-SHAKE-256s verification through pinned `fips205 = 0.4.1`, with a
  deterministic slow fixture selftest.
- Argon2id derivation through pinned `argon2 = 0.5.3`.

It deliberately does not implement full Daylight Minimal Core M2 completion,
coverage-guided parser fuzzing, a complete cross-implementation vector corpus,
OS RNG selection policy, key lifecycle management, a full HPKE session layer,
integrated policy/gate/witness/log/provenance/install validators,
`FROST_custom(P-384,SHA-384)`, production authority, or runtime containment.
Those surfaces are reported as unsupported, externally supplied prechecks, or
fail closed.

The v6 hardening module is not an M1 completion claim. It still lacks the full
minimum C1 vector corpus and a second independent parser.
The provider-backed v6 KEM/key-schedule evidence does not make the imported
fixture artifact a real-crypto-provider artifact and does not authorize private
Open or production use.
The provider-backed v6 private-roundtrip and reference `Seal`/`Open` evidence
also do not satisfy production authority because certificate, revocation, log,
install, witness, publish, trust, and production authority predicates remain
externally supplied or absent.

The adjacent imported Python fixture artifact lives at
`../../fixtures/daylight-v06-m1/` and is run from the repository root with
`make daylight-v06-m1-fixture-test`. It is not linked into this crate and does
not convert fixture predicates into production cryptography.

```sh
cargo test --offline
cargo run --offline -- status
cargo run --offline -- v4-reference-vector
cargo run --offline -- v6-schema-vector
cargo run --offline -- v6-provider-kem-evidence
cargo run --offline -- v6-provider-private-roundtrip-evidence
cargo run --offline -- v6-reference-seal-open-evidence
cargo run --offline -- v6-reference-negative-corpus-evidence
cargo run --offline -- nightlight-v6-equation-battery
cargo run --offline -- nightlight-v6-deep-assault-assessment
cargo run --offline -- wuci-daylight-envelope-boundary --file ../../../build/wuci-gate-demo/sealed.wj
cargo run --offline -- digest --file ../../notes/daylight-eq.jpeg
cargo run --offline -- dhkem-p384-selftest
cargo run --offline -- mlkem1024-selftest
cargo run --offline -- mldsa87-selftest
```

This crate is not production cryptography and does not claim whole-system
post-quantum security.
