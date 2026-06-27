# Daylight Equation

This directory is the isolated Wuci-Ji workspace for the Daylight Equation.
It is intentionally separate from the current CAGE, QCAGE, Gate, Witness,
Ledger, INSTALL, and Golden Lock proof lanes.

Daylight is research and design work only at this stage. It is not production
cryptography, not a post-quantum security claim, not runtime sandboxing, not
publish or trust authority, and not an independently audited verifier.

## Source Material

The starting poster has been copied from the fetched web repository state:

```text
origin/main:notes/daylight-eq.jpeg
```

Local copy:

```text
notes/daylight-eq.jpeg
```

See `SOURCE.md` for commit, blob, and digest provenance.

## Directory Layout

```text
analysis/
  daylight-minimal-core-v0.4.md
                           Active minimal core math and implementation target.
  daylight-envelope-math-spec-v0.3.md
                           Prior v0.3 envelope math and maturity gate.
  poster-transcription.md  Visual transcription of the poster.
  corrected-daylight-equation.md
                           Earlier corrected math/specification pass.
  initial-analysis.md      First-pass model analysis and open issues.
  review-dissemination-plan.md
design/
  rust-implementation-plan.md
research/
  standards-baseline.md
rust/daylight-model/
  Std-only Rust model crate for threshold/profile math only.
rust/daylight-crypto/
  Pinned Rust crypto lane for hashes, SP800-185 derivations, and ML-DSA-87
  verification. Missing primitives fail closed.
```

## Working Rules

- Keep Daylight defensive and proof-oriented.
- Do not add exploit generation, vulnerability reproduction, offensive
  scanning, jailbreak harnesses, malware logic, or network attack logic.
- Do not add cryptographic implementations before algorithm choices,
  verifier sources, pins, test vectors, negative tests, and review criteria
  are explicit.
- Do not claim post-quantum security from classical-only or partial hybrid
  evidence.
- Do not treat Rust type modeling, parser tests, or threshold arithmetic as
  cryptographic assurance.
- Preserve deterministic fixtures, tempdirs, no-network test behavior, and
  stdlib-only Python for repository proof lanes.

## Current Implementation Scope

The current Daylight minimal core target is tracked in
`analysis/daylight-minimal-core-v0.4.md`. It keeps Daylight at
`research_draft`, forbids production use before maturity level M5, splits
release level `r` from cryptographic strength `s`, removes compact release
mode from the openable core, uses `D2`/`D3` profile-dependent authorization
requirements, uses deterministic-CBOR encoding, uses HKDF-SHA512 for the core
schedule, and names the classical HPKE lane as `DHKEM(P-384,HKDF-SHA384)`.

The Rust crate under `rust/daylight-model/` only models declared action sets,
v0.3 profiles, claim levels, mode requirements, downgrade arithmetic, and
threshold probability arithmetic. It does not encrypt, decrypt, sign, verify
signatures, encapsulate keys, derive keys, scan networks, or parse untrusted
Daylight artifacts.

Run it directly:

```sh
cd daylight-equation/rust/daylight-model
cargo test
```

The Rust crate under `rust/daylight-crypto/` implements the first pinned crypto
lane:

- SHA2-512, SHA3-512, and SHAKE256-512 digest vectors.
- SP 800-185 cSHAKE256, TupleHash256-style hashing, and KMAC256-style
  derivations.
- Daylight `h_D`, pre-envelope and authorization messages, KEM-combiner
  derivation over already supplied shared secrets, HPKE-style nonce derivation,
  and corrected key schedule derivation.
- ML-KEM-1024 encapsulation/decapsulation through pinned `fips203 = 0.4.3`.
- DHKEM(P-384,HKDF-SHA384) KEM-only operations through pinned RustCrypto
  `p384` and `hkdf` crates.
- v0.4 Daylight Minimal Core seal/open with supplied-schedule and
  ML-KEM-1024+DHKEM(P-384,HKDF-SHA384)-derived key schedule paths, including a
  caller-supplied `CryptoRng` seal API. These use supplied precheck evidence and
  enforce public-precheck-before-derivation/AEAD ordering, hidden artifact
  commitment verification, declared leakage verification, nonce rejection,
  profile/action/claim checks, derivation rejection, and fail-closed unsupported
  FROST requirements.
- Deterministic-CBOR-Daylight-v1 encoder/decoder subset for arrays, byte
  strings, text strings, and unsigned integers, plus typed v4 header and
  envelope decoding.
- One deterministic v4 reference vector at
  `rust/daylight-crypto/vectors/daylight-v4-reference-vector-v1.txt`.
- One deterministic v4 negative parser seed corpus at
  `rust/daylight-crypto/vectors/daylight-v4-negative-parser-vectors-v1.txt`.
- ML-DSA-87 verification through pinned `fips204 = 0.4.6`.
- SLH-DSA-SHAKE-256s verification through pinned `fips205 = 0.4.1`.
- AES-256-GCM, ChaCha20-Poly1305, and Argon2id through pinned crates.

It does not implement full Daylight Minimal Core M2 completion, coverage-guided
parser fuzzing, a complete cross-implementation vector corpus, OS RNG selection
policy, key lifecycle management, a full HPKE session layer, integrated
policy/gate/witness/log/provenance/install validators,
`FROST_custom(P-384,SHA-384)`, production authority, or runtime containment.
Those surfaces are reported as unsupported, externally supplied prechecks, or
fail closed.

Run it directly:

```sh
cd daylight-equation/rust/daylight-crypto
cargo test --offline
cargo run --offline -- status
cargo run --offline -- v4-reference-vector
```
