# Daylight v17 Singularity

Daylight v17 Singularity is a residue-collapse research scoring layer. It does
not replace Daylight v15/v16, does not inflate the conservative Daylight M
score, and does not certify production cryptography.

The implementation layer is the **Daylight v17.1 Event Horizon Kernel**:

```text
Singularity is the declaration.
Event Horizon is the verifier that decides whether declaration is allowed.
```

```text
S_AM+(t) = floor(10^9 * (1 - exp(-Omega(t))))

Omega_sum(t)  = sum_i alpha_i[-ln(1 - C_i(t))]
Omega_weak(t) = 5 * min_i[-ln(max(10^-12, 1 - C_i(t)))]
Omega_eff(t)  = max(0, min(Omega_sum(t), Omega_weak(t)) - debts)
```

Declaration requires:

```text
Omega_eff(t) >= ln(10^9)
all field thresholds pass
collapse = false
score_inflation_M = 0
critical and contradiction debt = 0
```

The maximum declared score is `999,999,999 AM+`. The perfect score
`1,000,000,000 AM+` is reserved.

AM+ is computed from deterministic proof-field closure and debt. Field closure
comes from proof atoms in `rules/proof-atoms.v17.json`; no atom earns credit
without a verifier command, evidence path, evidence digest, replay result when
required, and freshness check. JSON floats are rejected. Binary floats are not
used in the score path.

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
make daylight-v17-singularity-declaration-gate
make daylight-v17-singularity-test
make daylight-v17-singularity-doctor
```

The declaration fixture intentionally produces `999,999,999 AM+` with
`fixture: true` and `claim_usable: false`. It is a math fixture only, not
external certification.

The current committed proof-atom score is written to
`examples/current-scorecard.v17.json`. The Event Horizon declaration gate
refuses it by default even though the fracture suite and in-repo agreement
vector pass, because the weakest-field governor keeps `Omega_eff` below
`ln(10^9)`. Independent Rust/Zig/Lean verifier lanes remain future work; the
current agreement check is deliberately reported as an in-repo kernel check, not
external certification.
