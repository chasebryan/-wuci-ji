# Daylight Equation Standard

The Daylight Equation Standard defines how a security claim earns authority.
It is a standard candidate for evidence-derived security assurance, not a
certification, production-security claim, government approval, or replacement
for existing security platforms.

## Formal Rules

```text
NoEvidence(x) -> NoScore(x)
NoProvenance(x) -> NoAuthority(x)
NoExecution(x) -> NoRuntimeScore(x)
NoBoundary(x) -> NoScope(x)
NoReproduction(x) -> ProvisionalOnly(x)
NoFalsificationPath(x) -> WeakClaim(x)
ManualScore(x) -> Reject(x)
ClaimBeyondEvidence(x) -> Overclaim(x)
Overclaim(x) -> NoRelease(x)
```

## Authority Equation

```text
Authority(x) =
min(
  Evidence(x),
  Provenance(x),
  Reproducibility(x),
  BoundaryPrecision(x),
  FalsificationCoverage(x),
  MonitoringContinuity(x),
  ControlMapping(x),
  VulnerabilityResponse(x)
)
```

The weakest required field governs authority. Strong evidence in one area
cannot average away missing boundary precision, missing provenance, missing
reproduction, missing monitoring, or an unsupported certification claim.

## Vocabulary

| Term | Meaning |
| --- | --- |
| Claim | A bounded statement about a project, release, artifact, control, score, or action. |
| Evidence | A machine-readable object that supports a claim through artifacts, commands, transcripts, or review outputs. |
| Provenance | The producer, time, commit, environment, and identity context for evidence. |
| Reproducibility | A command or process that can regenerate the result or explain why it is provisional. |
| Boundary | The exact scope the claim covers and the expansions it forbids. |
| Monitoring | Post-release signals that can maintain, reduce, block, or revoke authority. |
| Falsification | A defined path that would prove the claim false or incomplete. |
| Authority | The permitted release, install, trust, decrypt, publish, deploy, or score action derived from evidence. |

## Schema References

The v1 schemas are in `specs/daylight-equation/v1/`:

- `daylight-equation.v1.schema.json`
- `daylight-claim.v1.schema.json`
- `daylight-evidence.v1.schema.json`
- `daylight-attestation.v1.schema.json`
- `daylight-scorecard.v1.schema.json`
- `daylight-release-gate.v1.schema.json`
- `daylight-control-map.v1.schema.json`
- `daylight-monitor-signal.v1.schema.json`
- `daylight-conformance-report.v1.schema.json`

## Allowed Current Claims

- High-assurance research/proof artifact.
- Evidence-bound release and claim-integrity system.
- Security-claim verification framework.
- Reproducibility and audit-boundary system.
- Product-standard candidate.
- Default equation candidate for evidence-derived security assurance.

## Forbidden Current Claims

Wuci-Ji / Daylight must not be described as current production cryptography, a
general runtime sandbox, post-quantum secure, independently audited, Department
of War approved, government endorsed, cATO authorized, RMF authorized, FIPS
validated, FedRAMP authorized, NIAP/Common Criteria certified, or a replacement
for EDR, SIEM, IAM, backups, patch management, or incident response.

## Conformance Rules

1. Every positive claim must have evidence references or receive no score.
2. Every evidence object must identify producer, time, source commit, command,
   environment, and whether fixtures or private material exclusions apply.
3. Every scorecard must be derived from evidence and must reject manual score
   override.
4. External validation strengthens authority only when signed, pinned,
   non-fixture, scoped, and claim-usable.
5. Certification, authorization, and government-approval claims require actual
   evidence from the issuing authority. They cannot be self-issued.
6. Runtime score requires execution or monitoring evidence in the claimed
   runtime boundary.
7. Release, publish, install, trust, decrypt, or deploy actions must fail closed
   when the required evidence is missing.

## Examples

Examples live in `examples/daylight-standard/`. They include a minimal claim,
passing and failing release gates, unsupported certification language, control
mapping, conformance report, monitor signal, and a no-external-validation value
case.
