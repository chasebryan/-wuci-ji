# Daylight v20 Independent Rebuild Receipt

Contract for the `independent_rebuild_receipts` entries of an external
evidence bundle. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py`; documented by
`schema/independent-rebuild-receipt.schema.json`.

## Purpose

Two or more external builders independently rebuild the sealed subject
artifact from the pinned source commit and report byte-identical results.
This is observation, not endorsement: a receipt says "I built this commit
with these instructions and got these bytes", nothing more.

## Receipt fields

```json
{
  "receipt_id": "...",
  "builder_identity": "...",
  "builder_independence_class": "external",
  "builder_contact_optional": null,
  "source_commit": "...",
  "release_tag": "...",
  "build_instructions_digest": "...",
  "environment_digest": "...",
  "artifact_sha256": "...",
  "artifact_sha3_512": "...",
  "artifact_size": 0,
  "byte_reproducible": true,
  "fixture": false,
  "claim_usable": true,
  "attestation_ref": "..."
}
```

- `build_instructions_digest` - SHA-256 of the exact instructions you
  followed (canonical bytes of the build script or documented steps).
- `environment_digest` - SHA-256 of a description of your build environment
  (OS, toolchain versions, container image digest, and so on). Two receipts
  must not share an environment digest; independence includes the machine.
- `artifact_*` - the digests and size you observed, which must equal the
  bundle subject values.
- `attestation_ref` - the `attestation_id` of your pinned attestation whose
  `subject_digest` equals
  `SHA-256("DAYLIGHT-v20-EXTERNAL-REBUILD-RECEIPT:" +
  canonical(receipt without attestation_ref))`.

## Rejection matrix

A receipt (or the whole section) is rejected when:

- builder identity contains a reserved token, or independence class is not
  `external`
- `fixture` is true, or `claim_usable` is not true
- `byte_reproducible` is not true
- source commit, release tag, artifact SHA-256, artifact SHA3-512, or
  artifact size differ from the bundle subject
- build instructions digest or environment digest is missing, malformed, or a
  placeholder value
- fewer than two receipts exist
- two receipts share a builder identity or an environment digest
- the receipt is not bound to an admissible pinned attestation
- any digest field is a placeholder (one repeated character)

If your rebuild does **not** reproduce the artifact, submit nothing with
`byte_reproducible: true`. Report the mismatch to the maintainers instead;
a truthful mismatch report is a release-stopping finding and is more valuable
than a false receipt.
