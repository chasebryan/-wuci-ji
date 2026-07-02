# Daylight v20 Verifier Vector Contract

Contract for the `claim_usable_verifier_vectors` entries of an external
evidence bundle. Enforced by
`daylight/v20-aperture-singularity/src/external_evidence.py`; documented by
`schema/verifier-vector-claim-usable.schema.json`.

## Purpose

Exactly three independent verifier families each verify the subject v20
capsule and report the canonical output digest they computed. Agreement of
three genuinely independent implementations is the quorum evidence; fixture
vectors (which the repository already ships for parser coverage) can never
become quorum evidence.

## Vector fields

```json
{
  "vector_id": "...",
  "verifier_family": "...",
  "verifier_implementation_digest": "...",
  "input_capsule_digest": "...",
  "output_digest": "...",
  "decision": "pass|fail",
  "fixture": false,
  "claim_usable": true,
  "attestation_ref": "..."
}
```

- `verifier_family` - a name for the independent implementation lineage
  (for example a language/runtime family). Three distinct families are
  required; sharing code between families breaks independence and, when
  detected, is a contradiction finding.
- `verifier_implementation_digest` - SHA-256 over the exact implementation
  you ran (source tarball or binary).
- `input_capsule_digest` - must equal the bundle subject's
  `aperture_capsule_digest` (the v20 capsule digest).
- `output_digest` - SHA-256 over your verifier's canonical output bytes for
  that capsule. All three families must report the same value. The canonical
  output format is fixed by the v20 capsule schema and will be pinned in this
  contract together with the first onboarded external family; until then no
  vector can be admissible, which is the intended fail-closed state.
- `decision` - `pass` only if your verifier accepted the capsule under the
  v20 rules. A `fail` decision is honest evidence but blocks the section.

## Rejection matrix

The section is rejected when:

- fewer than three vectors or fewer than three distinct families exist
- more than three distinct families are supplied (exactly three are required;
  additional families belong in a separate bundle revision)
- any family name is duplicated
- any vector is fixture or not claim-usable
- any vector's input capsule digest differs from the subject
- the output digests do not all match
- any decision is not `pass`
- any vector is not bound to an admissible pinned attestation
- any digest is malformed or a placeholder value

## Relation to the repository's fixture vectors

`daylight/v20-aperture-singularity/examples/verifier-agreement.*.json` are
repository-owned fixtures: they exercise the parser and the agreement logic
and are permanently marked `fixture: true, claim_usable: false`. They do not
satisfy this contract and are rejected by the intake verifier by
construction.
