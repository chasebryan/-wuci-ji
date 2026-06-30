# Daylight v14C+ Master Law

Daylight v14C+ is not a score. Daylight v14C+ is a score-generating condition.

The executable law is:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

The scorecard is admissible only when it is generated from a frozen ledger head,
a frozen corpus snapshot, exact rational arithmetic, a reproducibility receipt,
and transcript-bound evidence.

Manual scores are invalid even if the arithmetic appears correct.
