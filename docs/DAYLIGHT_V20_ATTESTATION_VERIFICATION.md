# Daylight v20 Attestation Verification Contract

Contract for the `pinned_attestations` entries of an external evidence
bundle and the public pinned verification material they depend on. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py`; documented by
`schema/pinned-attestation.schema.json`.

## Purpose

Every external rebuild receipt, firewall-profile review, and verifier vector
must be bound to a signer-controlled attestation. The attestation proves only
that the named external identity signed the exact evidence item digest. It is
not a certification, audit, government validation, FIPS validation,
production-crypto claim, or runtime-containment claim.

Today this contract is still intentionally incomplete: the repository parses
attestations and pinned public material, but it does not yet implement a real
deterministic local signature verifier. Until that verifier lands, every
bundle remains inadmissible with:

```text
pinned cryptographic attestation verification not implemented
```

## Attestation fields

```json
{
  "attestation_id": "...",
  "subject_digest": "...",
  "statement_digest": "...",
  "signer_identity": "...",
  "signer_independence_class": "external",
  "signature_algorithm": "ed25519",
  "public_key_digest": "...",
  "signature": "...",
  "verification_material_ref": "daylight/v20-aperture-singularity/pinned/external-verification-material.v20.json",
  "fixture": false,
  "claim_usable": true
}
```

- `subject_digest` is the item binding digest for the evidence item being
  attested: rebuild receipt, firewall review, or verifier vector.
- `statement_digest` is
  `SHA-256("DAYLIGHT-v20-PINNED-ATTESTATION-STATEMENT:" +
  canonical(attestation without statement_digest and signature))`.
- `signature_algorithm` must be `ed25519`. This is a supported future
  algorithm identifier, not an implemented verification result.
- `public_key_digest` is SHA-256 over the decoded public key bytes in the
  pinned verification material registry.
- `signature` is base64 text and must not be a placeholder.
- `verification_material_ref` must point exactly at the pinned registry path
  above; absolute paths, traversal, backslashes, hidden path components, and
  alternate registries are rejected.

## Pinned verification material

The pinned registry is
`daylight/v20-aperture-singularity/pinned/external-verification-material.v20.json`.
It has this shape:

```json
{
  "schema_id": "daylight.v20.pinned-verification-material",
  "schema_version": 1,
  "non_claims_acknowledged": [],
  "pinned_signers": []
}
```

Every registry must acknowledge all v20 non-claims. Each pinned signer entry
must include:

```json
{
  "signer_identity": "...",
  "signer_independence_class": "external",
  "signature_algorithm": "ed25519",
  "public_key_digest": "...",
  "public_key_b64": "...",
  "pinned_by_commit": "..."
}
```

The verifier decodes `public_key_b64`, rejects placeholder key bytes, and
requires `SHA-256(decoded_public_key) == public_key_digest`.

## Rejection matrix

An attestation or pinned signer is rejected when:

- signer identity contains a reserved token, or independence class is not
  `external`
- `fixture` is true, or `claim_usable` is not true
- signature algorithm is unsupported
- statement digest does not recompute
- subject digest does not match the referenced evidence item
- public key is not pinned
- pinned signer identity or algorithm does not match the attestation
- signature is malformed, placeholder, too large, or not base64 text
- verification material path is unsafe or not the pinned registry
- pinned material omits any required non-claim
- pinned public key digest does not match the public key bytes
- a duplicate pinned public key digest appears
- cryptographic verification is not implemented

## Future implementation rule

`IMPLEMENTED_SIGNATURE_ALGORITHMS` must stay empty until real local signature
verification code exists. Adding `ed25519` to that set without an actual
deterministic verifier is fixture laundering and must be rejected in review.
When verification is implemented, it must be offline, deterministic, pinned to
the public key bytes in this registry, and covered by positive and negative
tests. A successful signature will still only close the attestation field; it
will not override boundary debt, non-claims, fixture flags, verifier quorum,
reproducible-build requirements, or the declaration gate.
