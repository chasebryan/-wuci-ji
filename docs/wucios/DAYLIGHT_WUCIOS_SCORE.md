# Daylight/WuciOS Score

The WuciOS score scale is an artifact-bound non-claim scale definition from
`0.0` to `100.0` with one decimal place.

A score is release-authoritative only if generated from a current WuciOS artifact and tied to an artifact hash.

If no artifact is scanned, the score is invalid and the value is `null`.

If only the current host repo is scanned, the score status is `DIAGNOSTIC_ONLY` and `score_valid` remains `false`.

## Categories

| Category | Weight |
| --- | ---: |
| Surface Minimization | 20.0 |
| Reproducibility / Pinning | 20.0 |
| Integrity / Provenance | 15.0 |
| Runtime Default Safety | 15.0 |
| Auditability | 15.0 |
| Claim Discipline | 10.0 |
| Reviewer Usability | 5.0 |
| Total | 100.0 |

No hand-written score is authoritative. No numeric score may be generated when required inputs are missing.

The default no-artifact output is:

```json
{
  "schema": "wucios.daylight.score.v1",
  "score_valid": false,
  "score_value": null,
  "score_scale": "0.0-100.0",
  "score_precision": "one decimal place",
  "score_status": "INVALID_WITHOUT_ARTIFACT",
  "artifact": {
    "path": "NOT_MEASURED",
    "sha256": "NOT_MEASURED"
  },
  "warning_level": "UNASSESSED",
  "warning_text": "No release-authoritative score exists because no current artifact was scanned.",
  "categories": [],
  "non_claims": []
}
```
