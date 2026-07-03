# Methodology

The score-integrity audit records compare public score claims against committed
repository evidence and the boundary under which each claim was introduced.

Score-integrity principles:

```text
NoGeneratedScore -> NoScoreClaim
NoOriginalBoundary -> NoIntegrityClaim
ScoreChanged + NoEvidence -> Reject
FixtureEvidence + ExternalClaim -> Reject
DeclarationBlocked -> NoDeclarationClaim
```

Each run records:

- the audited commit
- the generated claim ledger
- exact ratio and percentage recomputation notes
- public-surface score comparison output
- the final generated score-integrity report
- the non-claim boundary that applies to the run

The audit does not change scores. It rejects drift when a score value or
boundary no longer matches the evidence.
