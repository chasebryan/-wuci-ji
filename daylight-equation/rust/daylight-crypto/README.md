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

The adjacent imported Python fixture artifact lives at
`../../fixtures/daylight-v06-m1/` and is run from the repository root with
`make daylight-v06-m1-fixture-test`. It is not linked into this crate and does
not convert fixture predicates into production cryptography.

```sh
cargo test --offline
cargo run --offline -- status
cargo run --offline -- v4-reference-vector
cargo run --offline -- v6-schema-vector
cargo run --offline -- digest --file ../../notes/daylight-eq.jpeg
cargo run --offline -- dhkem-p384-selftest
cargo run --offline -- mlkem1024-selftest
cargo run --offline -- mldsa87-selftest
```

This crate is not production cryptography and does not claim whole-system
post-quantum security.
