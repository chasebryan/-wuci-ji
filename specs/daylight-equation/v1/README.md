# Daylight Equation v1 Schemas

This directory contains the v1 schema set for the Daylight Equation Standard.
The schemas are JSON Schema documents, and the repository validator implements
a deterministic stdlib-only subset for local CI.

## Objects

- `daylight-equation.v1.schema.json`: standard profile and rule registry.
- `daylight-claim.v1.schema.json`: bounded security or release claim.
- `daylight-evidence.v1.schema.json`: evidence object supporting claims.
- `daylight-attestation.v1.schema.json`: signed or reviewed attestation.
- `daylight-scorecard.v1.schema.json`: evidence-derived scorecard.
- `daylight-release-gate.v1.schema.json`: allowed and blocked release actions.
- `daylight-control-map.v1.schema.json`: evidence-to-control mapping.
- `daylight-monitor-signal.v1.schema.json`: monitoring and downgrade signal.
- `daylight-conformance-report.v1.schema.json`: project conformance report.
- `daylight-claim-scan-report.v1.schema.json`: deterministic phrase-firewall report with safe-input errors and source locations.

Claim-scan reports are accepted by CI only after canonical safe regeneration
from their declared relative inputs; schema/structure validation alone is not a
provenance check.

## Non-Claims

The v1 schemas do not certify security, production readiness, government
approval, FIPS validation, FedRAMP authorization, cATO/RMF authorization, or
post-quantum safety. Runtime containment is not claimed. The schemas define
evidence obligations and refusal rules.

`daylight-claim-v1.claim_text` has a 65,536-character schema ceiling. The
stdlib validator also enforces a 65,536-byte UTF-8 ceiling and a 256 configured
phrase-occurrence ceiling before applying the claim policy, so oversized
structured claims fail closed.

## Local Validation

Run:

```sh
make daylight-standard-schema-test
make daylight-standard-examples-test
make daylight-conformance-test
make daylight-claim-firewall-ci
```
