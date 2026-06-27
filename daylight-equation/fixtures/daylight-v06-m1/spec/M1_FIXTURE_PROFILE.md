# Daylight v0.6 M1 Fixture Profile

## Status

```text
Status(Daylight_v0.6_M1_Fixture) = executable_research_artifact
ProductionAllowed = 0
RealCryptoProvider = 0
M1Progress = partial
```

This profile is a byte-level fixture profile for the v0.6 spec. It exists to test deterministic encoding, object schemas, transcript construction, KDF labels, public-precheck ordering, private-open ordering, and negative-vector rejection behavior.

It does not replace the Daylight v0.6 spec and does not claim production cryptographic security.

## Implemented

```text
Deterministic-CBOR-Daylight-v6 subset
HC/HB digest split
Envelope_v6 schema
Header_v6 schema
LeakValue_v6 schema
AuxBlock_v6 schema
Policy_v6 schema
Claims_v6 schema
KeySetPub_v6 schema
KEMBlock_v6 schema
AuthBlock_v6 schema
PrivatePayload_v6 schema
T0/T1/AuthMsg construction
HKDF-SHA512 key schedule
AES-256-GCM
ChaCha20-Poly1305-IETF
Artifact commitment check
Reviewed-content hidden commitment check
Ordered PublicPreOK
Ordered private Open
Rejection-stage diagnostics
Vector manifest format
```

## Fixture-only predicates

The following predicates are deliberately simulated:

```text
ML-KEM-1024.Encaps/Decaps
DHKEM-P384-HKDF-SHA384.Encap/Decap
ML-DSA-87.Verify
SLH-DSA-SHAKE-256s.Verify
ReviewReceiptOK
CertOK
Revoked
PublicKeyValidate
TransparencyLog.VerifyInclusion
TransparencyLog.VerifyConsistency
```

A production implementation must replace these with real providers and must preserve the same byte-level transcript bindings.

## PublicPreOK order

The implementation follows the v0.6 ordered public precheck:

```text
P0  Decode deterministic CBOR
P1  Envelope_v6 schema
P2  Header_v6 schema
P3  suite/version/profile/r/mu/action/content_scope/aead_id
P4  AuxBlock schema and object hashes
P5  policy/keyset/claims schema
P6  static policy gate
P7  KEMBlock public shape and key references
P8  T0/h0/T1/h1/AuthMsg
P9  AuthBlock schema
P10 authorization signatures and quorum checks
P11 content-review preconditions
P12 no-downgrade
P13 log proof if required
P14 install/witness predicates if required
```

If any P-stage fails, the runner confirms:

```text
private_kem_called = false
aead_dec_called = false
```

## Private-open order

After `PublicPreOK = 1`:

```text
S0 fixture ML-KEM decapsulation
S1 fixture DHKEM decapsulation
S2 derive K_E, K_COM, N0
S3 AEAD.Dec(K_E,N0,C,AD=T0)
S4 decode PrivatePayload_v6
S5 check artifact commitment
S6 check leak/review private consistency
S7 return artifact
```

## Valid vectors

```text
V1_metadata_only_open
V2_public_commitment_open
V3_reviewed_content_open
V4_pq_strict_open
V5_chacha20_open
```

## Negative vectors

```text
N1_noncanonical_cbor
N2_duplicate_map_key
N3_unknown_envelope_key
N4_unknown_header_key
N5_wrong_field_type
N6_wrong_enum_value
N7_unsorted_roster
N8_unsorted_policy_array
N9_bad_suite_id
N10_bad_policy_hash
N11_bad_keyset_hash
N12_bad_claims_hash
N13_bad_kem_key_id
N14_bad_auth_block_shape
N15_bad_ml_dsa_signature
N16_insufficient_q_threshold
N17_insufficient_domain_count
N18_bad_review_receipt
N19_bad_downgrade
N20_missing_required_log
N21_bad_mlkem_ciphertext
N22_bad_dhkem_encapsulation
N23_bad_aead_tag
N24_bad_private_payload_encoding
N25_bad_artifact_commitment
N26_bad_leak_value
N27_bad_review_blind
```

## Maturity impact

This artifact supports a partial M1 claim only after review of the fixture profile itself. It does not claim M2 because the cryptographic providers are not real. It does not claim M3 because there is not yet an independent implementation or independent vector corpus. It does not claim M5 because there is no external review.
