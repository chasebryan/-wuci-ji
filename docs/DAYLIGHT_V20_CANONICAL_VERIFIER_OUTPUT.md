# Daylight v20 Canonical Verifier Output

Daylight v20.3 freezes the bytes that independent verifier families must hash
for verifier-vector quorum evidence. The canonical verifier output is
deterministic JSON:

- sorted keys
- separators `(",", ":")`
- UTF-8
- ASCII escapes enabled
- exactly one newline at EOF
- no floats
- no duplicate keys
- no timestamps
- no hostnames
- no usernames
- no absolute paths
- no environment-dependent fields

The canonical output object has this shape:

```json
{
  "schema_id": "daylight.v20.canonical-verifier-output",
  "schema_version": 1,
  "verifier_contract": "daylight.v20.verifier-vector-quorum",
  "subject": {
    "release_tag": "...",
    "source_commit": "...",
    "artifact_sha256": "...",
    "artifact_sha3_512": "...",
    "artifact_size": 0,
    "aperture_capsule_digest": "...",
    "score_ceiling_report_digest": "..."
  },
  "checks": {
    "capsule_schema_valid": true,
    "capsule_digest_recomputed": true,
    "subject_artifact_digest_bound": true,
    "public_artifact_manifest_verified": true,
    "score_ceiling_report_verified": true,
    "singularity_declaration_refused": true,
    "non_claims_present": true,
    "fixture_claim_rejected": true,
    "external_evidence_gate_fail_closed": true
  },
  "decision": "pass",
  "blocker_vector_digest": "...",
  "non_claims_digest": "...",
  "canonical_output_digest_domain": "DAYLIGHT-v20-CANONICAL-VERIFIER-OUTPUT:"
}
```

The output digest is:

```text
SHA-256(
  "DAYLIGHT-v20-CANONICAL-VERIFIER-OUTPUT:" +
  canonical_json_bytes(canonical_output)
)
```

`output_digest` is not embedded in the canonical output object. Verifier
vectors carry the digest externally as both `canonical_output_digest` and
`output_digest`; the two fields must match.

This format is an evidence-intake format only. Matching canonical verifier
output does not certify Wuci-Ji, claim production cryptography, claim runtime
containment, claim post-quantum safety, claim external audit completion, claim
FIPS or government validation, or declare Singularity.
