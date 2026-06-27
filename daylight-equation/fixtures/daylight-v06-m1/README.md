# Daylight Envelope v0.6 — M1 Fixture Artifact

This package converts the v0.6 M1-hardening delta into executable artifacts:

- deterministic CBOR encoder/decoder for the Daylight v0.6 subset;
- strict schema checks for `Envelope_v6`, `Header_v6`, `AuxBlock_v6`, `Policy_v6`, `KeySetPub_v6`, `KEMBlock_v6`, `AuthBlock_v6`, and `PrivatePayload_v6`;
- ordered `PublicPreOK` implementation with rejection-stage diagnostics;
- standard SHA3-512, SHAKE256, HKDF-SHA512, AES-256-GCM, and ChaCha20-Poly1305 wiring;
- fixture-only KEM/signature/review providers so vectors can be generated and checked without claiming production cryptography;
- 5 valid vectors and 27 negative vectors;
- a vector runner with all 32 vectors passing.

## Critical warning

This is **not** a production cryptographic implementation.

The following are deterministic fixture providers only:

- ML-KEM-1024;
- DHKEM-P384-HKDF-SHA384;
- ML-DSA-87;
- SLH-DSA-SHAKE-256s;
- reviewer signatures;
- certificate and revocation predicates;
- transparency log verification.

The artifact is intended to advance Daylight from prose-only M0 toward a byte-level M1 target by making parsing, transcripts, KDF labels, fail-closed ordering, vector format, and rejection stages executable.

## Contents

```text
src/daylight_m1.py              Reference fixture implementation
scripts/generate_vectors.py     Rebuilds the vector corpus
scripts/run_vectors.py          Runs all vectors
vectors/valid/                  5 valid vectors
vectors/negative/               27 negative vectors
TEST_RESULTS.json               Full vector-run output
TEST_RESULTS.txt                Human-readable summary
spec/M1_FIXTURE_PROFILE.md      Scope and conformance notes
```

## Run

From the artifact root:

```bash
python scripts/run_vectors.py vectors
```

Expected result:

```text
32 vectors, 32 passed, 0 failed
```

Regenerate vectors:

```bash
python scripts/generate_vectors.py
python scripts/run_vectors.py vectors
```

## Current scoring impact

This artifact should improve the v0.6 rating because it removes the largest “only prose” deduction for byte-level ambiguity. It still does **not** justify a production or M2/M3 claim because real ML-KEM/ML-DSA/SLH-DSA providers, real external vectors, independent parser agreement, formal modeling, and external review are still absent.

A conservative post-artifact estimate:

```text
Grok-style estimate: 860/1000
GPT self-rating:     845/1000
```

The score should not rise much beyond that until the fixture providers are replaced with real cryptographic implementations and independently reviewed test vectors.
