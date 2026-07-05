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

## Non-Claims

The v1 schemas do not certify security, production readiness, government
approval, FIPS validation, FedRAMP authorization, cATO/RMF authorization,
post-quantum safety, or runtime containment. They define evidence obligations
and refusal rules.

## Local Validation

Run:

```sh
make daylight-standard-schema-test
make daylight-standard-examples-test
make daylight-conformance-test
```
