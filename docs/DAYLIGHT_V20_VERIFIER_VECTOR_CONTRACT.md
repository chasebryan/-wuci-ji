# Daylight v20 Verifier Vector Contract

Contract for the `claim_usable_verifier_vectors` entries of an external
evidence bundle. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py` and
`daylight/v20-aperture-singularity/src/verifier_quorum.py`; documented by
`schema/verifier-vector-claim-usable.schema.json`.

## Purpose

Exactly three independent verifier families must verify the same subject v20
capsule and report the same pinned canonical verifier-output digest. Agreement
of three genuinely independent implementation lineages is quorum evidence.
Fixture vectors are parser coverage only and can never become quorum evidence.

## Canonical Output

The canonical verifier-output format is pinned in
`docs/DAYLIGHT_V20_CANONICAL_VERIFIER_OUTPUT.md`.

The output digest is:

```text
SHA-256(
  "DAYLIGHT-v20-CANONICAL-VERIFIER-OUTPUT:" +
  canonical_json_bytes(canonical_output)
)
```

Canonical JSON uses sorted keys, separators `(",", ":")`, UTF-8, ASCII
escapes, one trailing newline, no floats, no duplicate keys, no timestamps, no
hostnames, no usernames, no absolute paths, and no environment-dependent
fields.

## Vector Fields

```json
{
  "vector_id": "...",
  "verifier_family": "...",
  "verifier_family_independence_class": "external",
  "verifier_implementation_digest": "...",
  "verifier_implementation_kind": "source-tree",
  "input_capsule_digest": "...",
  "canonical_output_schema_id": "daylight.v20.canonical-verifier-output",
  "canonical_output_digest": "...",
  "output_digest": "...",
  "decision": "pass",
  "fixture": false,
  "claim_usable": true,
  "attestation_ref": "..."
}
```

- `verifier_family` names the independent implementation lineage. It is not a
  person, wrapper, script around the repository verifier, or rebranding of the
  same implementation.
- `verifier_family_independence_class` must be `external`.
- `verifier_implementation_digest` is SHA-256 over the exact implementation
  source tree, source tarball, binary, script, reproducible container, or
  other declared artifact.
- `verifier_implementation_kind` must be one of `source-tree`,
  `source-tarball`, `binary`, `script`, `reproducible-container`, or
  `other-declared`.
- `input_capsule_digest` must equal the bundle subject's v20 aperture capsule
  digest.
- `canonical_output_schema_id` must be
  `daylight.v20.canonical-verifier-output`.
- `canonical_output_digest` and `output_digest` must match and must equal the
  recomputed pinned canonical verifier-output digest for the supplied capsule.
- `decision` must be `pass`.
- `fixture` must be false and `claim_usable` must be true for claim evidence.
- `attestation_ref` must name a valid pinned external attestation whose
  `subject_digest` equals the vector binding digest.

## Rejection Matrix

The section is rejected when:

- no verifier vectors are supplied
- fewer than three vectors are supplied
- more than three vectors are supplied
- fewer or more than exactly three distinct verifier families are present
- any family name is duplicated
- any family identity is internal, self, local, repo-owned, harness, fixture,
  wuci, noxframe, daylight, or otherwise reserved
- any vector is fixture or not claim-usable
- any decision is not `pass`
- any vector input capsule digest differs from the subject capsule digest
- any output digest is malformed, placeholder, mismatched, or not equal to the
  pinned canonical output digest
- any implementation digest is malformed, placeholder, or duplicated
- any vector lacks an attestation
- any vector attestation is invalid, unpinned, internally signed, or bound to
  a different subject digest

## Declaration Boundary

Verifier-family quorum closes only:

```text
independent_verifier_quorum.claim_usable_3_of_3
```

It does not certify, audit, approve, validate, raise the score, or declare
Singularity. The declaration gate remains refused unless every other external
evidence-family requirement is separately satisfied.

## Fixture Boundary

`daylight/v20-aperture-singularity/examples/verifier-agreement.*.json` and
`external-evidence.verifier-quorum.valid-fixture.json` are repository-owned
fixtures. They exercise parser, canonical output, agreement, and rejection
logic. They are permanently non-claim evidence and do not satisfy this
contract.
