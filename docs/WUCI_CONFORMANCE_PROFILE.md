# Wuci-Ji / Daylight Conformance Profile

The conformance profile classifies how much authority a project can derive
from Daylight-compatible evidence. It is not a security-performance score and
does not claim certification.

## Levels

| Level | Name | Meaning |
| --- | --- | --- |
| D0 | Research Artifact | Evidence exists, but product authority is not claimed. |
| D1 | Claim-Bounded Project | Explicit non-claims exist and unsupported numeric/security claims are rejected. |
| D2 | Evidence-Bound Project | Claims must link to evidence objects. |
| D3 | Reproducible Project | Builds, scorecards, and release evidence can be regenerated. |
| D4 | Release-Gated Project | Release, publish, install, trust, decrypt, or deploy is blocked unless evidence satisfies policy. |
| D5 | Control-Mapped Project | Evidence maps to public security control families without claiming certification. |
| D6 | Continuously Monitored Project | Monitoring signals feed claim state and can downgrade authority. |
| D7 | Externally Reviewed Project | External review evidence exists and is pinned. |
| D8 | High-Assurance Product Candidate | Product boundary, evidence, monitoring, vulnerability response, and operational profile are complete. |
| D9 | Formal Authority Profile | Actual external certification, authorization, or regulatory authority exists. This level cannot be self-issued. |

## Classification Rules

- D0 requires local evidence and explicit research status.
- D1 requires forbidden-claim handling and non-claim text.
- D2 requires claim objects linked to evidence objects.
- D3 requires reproduction references for claims and scorecards.
- D4 requires release-gate objects that fail closed.
- D5 requires evidence-to-control maps with clear gaps and forbidden claims.
- D6 requires monitor-signal objects and downgrade rules.
- D7 requires signed, pinned, non-fixture external review evidence.
- D8 requires complete product boundary, adoption profile, monitoring,
  vulnerability response, and release evidence.
- D9 requires external authority. It must never be produced by a repository-only
  command.

## Manual Scoring

Manual score assertions are rejected. A conformance report must derive its
level from evidence objects and policy rules.

## Output

The canonical conformance report schema is:

```text
specs/daylight-equation/v1/daylight-conformance-report.v1.schema.json
```
