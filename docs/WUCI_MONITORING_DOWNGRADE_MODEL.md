# Wuci-Ji Monitoring and Downgrade Model

A claim that was true yesterday can become false after a vulnerability,
dependency change, environment drift, compromised release process, or expired
review. Daylight must treat assurance as living evidence, not a static score.

## Signals

The monitor-signal schema covers:

- Dependency vulnerability found.
- CISA KEV match.
- SBOM drift.
- Artifact digest mismatch.
- Release signature mismatch.
- Source tree dirty.
- Build environment changed.
- CI runner changed.
- Verifier version changed.
- Control evidence expired.
- Audit finding opened.
- Fuzz regression found.
- Policy violation found.
- External attestation revoked.

## Downgrade Actions

Allowed actions:

- Maintain score.
- Reduce confidence.
- Mark provisional.
- Block release.
- Revoke release authority.
- Require rebuild.
- Require re-audit.
- Require human risk acceptance.
- Mark claim forbidden.

## Rules

- Runtime authority requires runtime evidence.
- Release authority must fail closed on critical digest or signature mismatch.
- External attestation revocation must remove the uplift it provided.
- Expired control evidence must lower control-map authority.
- Known exploited vulnerability evidence can freeze release until reviewed.

## Output

Monitor signals are machine-readable objects validated by:

```text
specs/daylight-equation/v1/daylight-monitor-signal.v1.schema.json
```
