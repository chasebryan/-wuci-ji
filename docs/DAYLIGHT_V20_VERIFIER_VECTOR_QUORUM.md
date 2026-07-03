# Daylight v20.3 Verifier-Family Quorum

A verifier vector is an external evidence item. It records the result of one
independent verifier family over the same Daylight v20 aperture capsule.

A verifier family is an implementation lineage, not a person, not a wrapper,
and not a shell around the repository's own verifier. For the current bundle
revision, exactly three distinct external verifier families are required.
Fewer than three is insufficient. More than three is rejected rather than
silently ignored.

All three vectors must:

- bind to the same v20 aperture capsule digest
- use `canonical_output_schema_id:
  daylight.v20.canonical-verifier-output`
- report the same canonical output digest
- report `decision: "pass"`
- be non-fixture
- be `claim_usable: true`
- carry distinct verifier implementation digests
- bind to a valid pinned external attestation

Any `decision: "fail"` is honest evidence, but it blocks quorum. Fixture
vectors are never claim-usable. Repository-owned vectors are never external
evidence. Self, internal, local, repo, harness, wuci, noxframe, daylight, or
fixture identities are rejected as external verifier-family evidence.

Quorum closes only:

```text
independent_verifier_quorum.claim_usable_3_of_3
```

It does not certify, approve, audit, validate, raise the score, or declare
Singularity. Singularity remains refused unless every other independent
evidence-family requirement is separately satisfied.
