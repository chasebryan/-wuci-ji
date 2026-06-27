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
SCORECARD.md              Current evidence score, 1000/1000 gate, and blockers.
SCORECARD.v1.json         Machine-readable copy of the score and hard gates.
specs/
  daylight-minimal-core-v0.4.md
                           Active minimal core math and implementation target.
  daylight-envelope-hardening-v0.5.1-2.md
                           v0.6 M1-hardening delta implemented as the
                           v0.5.1/2 byte-level schema/transcript layer.
  daylight-envelope-math-spec-v0.3.md
                           Prior v0.3 envelope math and maturity gate.
analysis/
  README.md                Index for exploratory and explanatory notes.
  poster-transcription.md  Visual transcription of the poster.
  corrected-daylight-equation.md
                           Earlier corrected math/specification pass.
  initial-analysis.md      First-pass model analysis and open issues.
  review-dissemination-plan.md
design/
  rust-implementation-plan.md
fixtures/
  README.md                Boundary notes for executable fixture artifacts.
  daylight-v06-m1/         Extracted v0.6 M1 fixture artifact with Python
                           runner, vectors, fixture profile, and test results.
research/
  standards-baseline.md
references/
  README.md                Imported source/reference material.
  dlv0.5/                  Preserved v0.5 and v0.6 M1 reference docs.
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

The current evidence score and 1000/1000 gate are tracked in `SCORECARD.md`.
The active score is a research score only; it is not a production-readiness,
runtime-containment, quantum-safety, or external-review claim.

The original Daylight minimal core target is tracked in
`specs/daylight-minimal-core-v0.4.md`. The latest hardening layer is tracked in
`specs/daylight-envelope-hardening-v0.5.1-2.md`, based on
`references/dlv0.5/2.md` and the supplied v0.6 M1-hardening delta. Daylight
remains `research_draft`, production-disallowed, and not externally reviewed.

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
- Daylight Envelope v0.5.1/2 v6 byte-level hardening under `src/v6.rs`,
  including deterministic CBOR maps/null/bool, exact-key v6 schemas,
  HC/HB transcript convention helpers, v6 transcript/KDF labels, static policy
  parsing, rejection-stage tests, and a schema vector that fails closed at
  `REJECT_AUTH_SIGNATURE` before private KEM or AEAD.
- An extracted Daylight Envelope v0.6 M1 fixture artifact under
  `fixtures/daylight-v06-m1/`, wired to `make daylight-v06-m1-fixture-test`.
  This artifact uses deterministic fixture providers and the Python
  `cryptography` package, so it is intentionally separate from the stdlib-only
  WUCI proof lanes.

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
cargo run --offline -- v6-schema-vector
```

Run the imported v0.6 M1 fixture corpus explicitly:

```sh
make daylight-v06-m1-fixture-test
make daylight-v06-m1-independent-open-test
make daylight-v06-m1-static-test
```
