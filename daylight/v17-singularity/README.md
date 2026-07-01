# Daylight v17 Singularity

Daylight v17 Singularity is a residue-collapse research scoring layer. It does
not replace Daylight v15/v16, does not inflate the conservative Daylight M
score, and does not certify production cryptography.

```text
S_AM+(t) = floor(10^9 * (1 - exp(-Omega(t))))

Omega(t) = sum_i alpha_i[-ln(1 - C_i(t))]
           - Debt(t)
           - OverclaimDebt(t)
           - StalenessDebt(t)
```

Declaration requires:

```text
Omega(t) >= ln(10^9)
```

The maximum declared score is `999,999,999 AM+`. The perfect score
`1,000,000,000 AM+` is reserved.

AM+ is computed from deterministic proof-field closure and debt. Field closure
comes only from integer `verified_credit` and `possible_credit` state. JSON
floats are rejected. Binary floats are not used in the score path.

## Non-Claims

- Daylight v17 Singularity is a research scoring layer.
- AM+ does not modify the conservative Daylight M score.
- `999,999,999 AM+` is a residue-collapse declaration, not production certification.
- `1,000,000,000 AM+` is mathematically reserved.
- No manual score is accepted.

The boundary remains explicit: no production authority, no runtime containment
claim, no FIPS validation claim, no external certification claim, and no
whole-system post-quantum safety claim.

## Commands

```sh
make daylight-v17-singularity-score
make daylight-v17-singularity-verify
make daylight-v17-singularity-fixture-demo
make daylight-v17-singularity-test
make daylight-v17-singularity-doctor
```

The declaration fixture intentionally produces `999,999,999 AM+` with
`fixture: true` and `claim_usable: false`. It is a math fixture only, not
external certification.
