# Daylight v17 Singularity Math

Daylight v17 Singularity is a deterministic research scoring layer. It does not
replace Daylight v15/v16, does not inflate the conservative Daylight M score,
and does not certify production cryptography.

```text
S_AM+(t) = floor(10^9 * (1 - exp(-Omega(t))))

Omega(t) =
  sum_i alpha_i[-ln(1 - C_i(t))]
  - Debt(t)
  - OverclaimDebt(t)
  - StalenessDebt(t)
```

The declaration threshold is:

```text
Omega(t) >= ln(10^9)
ln(10^9) = 20.723265836946411156161923092159277868409913397658
```

The maximum declared score is `999,999,999 AM+`. The perfect score
`1,000,000,000 AM+` is mathematically reserved and must not be claimed.

Each field closure is derived only from integer credits:

```text
C_i = verified_credit_i / possible_credit_i
```

If `verified_credit_i == possible_credit_i`, the verifier applies the perfect
reserve:

```text
C_i = 1 - 1/10^12
```

Debt inputs are integer micro-omega values. JSON floats are rejected during
parsing, and Python float instances are rejected before hashing or scoring.

Collapse conditions force score `0` and status `singularity_collapsed`:

```text
contradiction_debt > 0
critical_break_debt > 0
forged_scorecard_accepted = true
opens_without_policy_evidence = true
severe_boundary_overclaim = true
manual_score_detected = true
```

Non-claims:

- Daylight v17 Singularity is a research scoring layer.
- AM+ does not modify the conservative Daylight M score.
- `999,999,999 AM+` is a residue-collapse declaration, not production certification.
- `1,000,000,000 AM+` is mathematically reserved.
- No manual score is accepted.
