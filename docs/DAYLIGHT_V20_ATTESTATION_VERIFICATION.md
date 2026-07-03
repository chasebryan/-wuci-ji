# Daylight v20 Attestation Verification Contract

Contract for the `pinned_attestations` entries of an external evidence
bundle and the public pinned verification material they depend on. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py`; documented by
`schema/pinned-attestation.schema.json`.

## Purpose

Every external rebuild receipt, firewall-profile review, and verifier vector
must be bound to a signer-controlled attestation. The attestation proves only
that the named external identity signed the exact canonical evidence statement.
It is not a certification, audit, government validation, FIPS validation,
production-crypto claim, or runtime-containment claim.

Standalone v20.2 rebuild receipts depend on this pinned attestation verifier,
but they are a separate evidence class. A valid signature does not make a
rebuild receipt admissible unless the receipt's own source, artifact,
transcript, clean-checkout, fixture, claim-usable, and non-claim checks also
pass.

Daylight v20.3 verifier-family quorum also depends on this pinned attestation
verifier, but quorum is a separate evidence class. A valid signature does not
make a verifier vector admissible unless the vector's family independence,
implementation digest, canonical output digest, decision, fixture,
claim-usable, exact-three quorum, and agreement checks also pass.

Ed25519 is the only implemented signature algorithm. Shape, digest, path,
fixture, identity, pinned-material, and raw Ed25519 signature checks are local,
deterministic, and stdlib-only in
`daylight/v20-aperture-singularity/src/ed25519_verify.py`.

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
- `statement_digest` is SHA-256 over the exact signed bytes:
  `b"DAYLIGHT-v20-PINNED-ATTESTATION-STATEMENT:" +
  canonical(attestation without statement_digest and signature)`.
- `signature_algorithm` must be `ed25519`.
- `public_key_digest` is SHA-256 over the raw 32-byte Ed25519 public key in
  the pinned verification material registry.
- `signature` is base64 text containing the raw 64-byte Ed25519 signature and
  must not be a placeholder.
- `verification_material_ref` must point exactly at the pinned registry path
  above; absolute paths, traversal, backslashes, hidden path components, and
  alternate registries are rejected.

Canonical JSON is sorted keys, separators `(",", ":")`, ASCII escapes, UTF-8
bytes, and one trailing newline. The signature is over the domain-separated
canonical statement bytes above, not arbitrary text and not the raw digest
string alone.

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
requires exactly 32 bytes with
`SHA-256(decoded_public_key) == public_key_digest`.

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
- signature is malformed, placeholder, not 64 raw bytes, too large, not
  base64 text, or fails Ed25519 verification
- verification material path is unsafe or not the pinned registry
- pinned material omits any required non-claim
- pinned public key digest does not match the public key bytes
- a duplicate pinned public key digest appears

## Verification rule

Verification is local, deterministic, offline, and pinned to the raw public key
bytes in this registry. A valid signature only proves that the pinned signer
attested to the exact canonical evidence statement. It does not certify,
audit, approve, validate, or release Wuci-Ji/Daylight, and it does not override
boundary debt, non-claims, fixture flags, verifier quorum, reproducible-build
requirements, or the declaration gate.

The declaration gate remains closed unless all required external evidence
classes are present, independent, digest-bound, non-fixture, claim-usable, and
cryptographically verified.
