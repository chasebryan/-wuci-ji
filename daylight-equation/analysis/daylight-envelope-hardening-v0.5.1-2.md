# Daylight Envelope Hardening v0.5.1/2

This note records the implementation layer added from the supplied
`DAYLIGHT ENVELOPE -- MINIMAL MATH CORE v0.6` hardening delta over
`DLv0.5/2.md`.

## Status

```text
Status(Daylight_v0.5.1/2) = research_draft
MaturityClaim(Daylight_v0.5.1/2) = M0+
ProductionAllowed(Daylight) = 0
```

This is not a new primitive, not a production protocol, not runtime
containment, and not a quantum-safe system claim. It is a byte-level hardening
pass over the v0.5/2 math/spec surface.

## Implemented Surface

The Rust `daylight-crypto` crate now has a `v6` module for M1-style analysis:

- Deterministic CBOR encoder/decoder for unsigned integers, byte strings, text
  strings, arrays, unsigned-key maps, booleans, and null.
- Rejection of duplicate/unsorted map keys, non-minimal integer/length forms,
  indefinite lengths, unsupported CBOR tags, unsupported simple values, and
  trailing data.
- Typed `Envelope_v6`, `Header_v6`, `KEMBlock_v6`, `AuthBlock_v6`,
  `AuxBlock_v6`, `Policy_v6`, `Claims_v6`, and `KeySetPub_v6` schema surfaces.
- Exact required map-key sets for the mandatory v6 objects.
- `HC`, `HB`, `HC32`, and `HB32` digest convention helpers, with tests showing
  that raw transcript hashes are not object hashes of byte strings.
- v6 transcript builders for `T0`, `h0`, `T1`, `h1`, and `AuthMsg`.
- v6 HKDF-SHA512 `KDF2`, KEM context, KEM salt, and key schedule helpers with
  versioned labels and KEM key-id binding.
- Static policy parsing and deterministic policy-gate checks for the C1 schema
  vector path.
- Internal rejection-stage enum matching the v0.6 stage names.
- A `daylight-v6-schema-vector-v1` CLI output path.

The CLI command is:

```sh
cd daylight-equation/rust/daylight-crypto
cargo run --offline -- v6-schema-vector
```

The vector intentionally expects:

```text
expected_result=bottom
expected_rejection_stage=REJECT_AUTH_SIGNATURE
private_kem_allowed=false
aead_dec_allowed=false
```

Reason: `CertOK` and `Revoked` are not defined by a production authority lane
in this workspace. Per v0.6, undefined key-live predicates fail closed, so the
schema vector rejects before private KEM decapsulation or AEAD.

## Deliberate Non-Claims

The implementation does not claim:

- M1 completion.
- M2 reference Seal/Open completion.
- Production readiness.
- External review.
- Runtime sandboxing.
- Whole-system post-quantum safety.
- Public proof that reviewed content has no hidden material.
- FROST core support.

M1 is still blocked by the full minimum C1 vector corpus and at least two
independent parser implementations agreeing on parser vectors.

## v0.5/2 Issues Addressed

- Hash/transcript ambiguity is reduced by explicit `HC` and `HB` helpers.
- Mandatory object schemas are represented as exact-key CBOR maps.
- Abstract policy evaluation is replaced, for this layer, by a deterministic
  static policy object.
- Auth block shape is specified as bytes and exact map keys rather than an
  opaque placeholder.
- Public precheck has test-vector rejection stages and verifies that this layer
  fails before private KEM/AEAD work.
- Extensions remain separate from C1: log/install/witness/FROST are parsed as
  optional objects but are not accepted as production authority.

## Remaining Work

- Full v6 positive Open vector corpus.
- Required v6 negative corpus from `N1` through `N27`.
- Independent second parser.
- Real `CertOK`, revocation, transparency-log, install, witness, and review
  validators.
- Real authorization quorum verification over `AuthMsg` with key-live
  enforcement.
- Fuzzing and cross-implementation parser agreement.
- Constant-time review and zeroization checks for any future secret path.
