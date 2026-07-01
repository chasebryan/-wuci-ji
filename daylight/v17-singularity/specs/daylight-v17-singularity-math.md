# Daylight v17 Singularity Math

Daylight v17 Singularity is a deterministic research scoring layer. It does not
replace Daylight v15/v16, does not inflate the conservative Daylight M score,
and does not certify production cryptography.

```text
R_i(t) = max(10^-12, 1 - C_i(t))
Omega_i(t) = -ln(R_i(t))
Omega_sum(t) = sum_i alpha_i Omega_i(t)
Omega_weak(t) = 5 * min_i Omega_i(t)
Omega_eff(t) = max(0, min(Omega_sum(t), Omega_weak(t)) - debts)
S_AM+(t) = min(999999999, floor(10^9 * (1 - exp(-Omega_eff(t)))))
```

The declaration threshold is:

```text
Omega_eff(t) >= ln(10^9)
ln(10^9) = 20.723265836946411156161923092159277868409913397658
```

Declaration also requires every field threshold to pass, no collapse state,
zero score inflation, zero critical break debt, and zero contradiction debt.

The maximum declared score is `999,999,999 AM+`. The perfect score
`1,000,000,000 AM+` is mathematically reserved and must not be claimed.

Each field closure is derived only from verified proof atoms:

```text
C_i = verified_credit_i / possible_credit_i
NoVerifier(atom) -> NoCredit(atom)
NoEvidence(atom) -> NoCredit(atom)
NoReplay(atom) -> NoCredit(atom)
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
manual_score_accepted = true
unsigned_external_credit = true
production_overclaim = true
whole_system_pq_overclaim = true
runtime_containment_overclaim = true
implementation_disagreement = true
parser_ambiguity = true
```

Non-claims:

- Daylight v17 Singularity is a research scoring layer.
- AM+ does not modify the conservative Daylight M score.
- `999,999,999 AM+` is a residue-collapse declaration, not production certification.
- `1,000,000,000 AM+` is mathematically reserved.
- No manual score is accepted.
