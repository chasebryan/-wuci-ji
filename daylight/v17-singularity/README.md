# Daylight v17 Singularity

Daylight v17 Singularity is a residue-collapse research scoring layer. It does
not replace Daylight v15/v16, does not inflate the conservative Daylight M
score, and does not certify production cryptography.

The implementation layer is the **Daylight v17.1 Event Horizon Kernel**. The
diagnostic/agreement layers are **Daylight v17.2 Cross-Verifier Horizon** and
**Daylight v17.3 Triangulation Gate**:

```text
Singularity is the declaration.
Event Horizon is the verifier that decides whether declaration is allowed.
Cross-Verifier Horizon explains every refusal and validates independent output vectors.
Triangulation Gate adds the first independent Rust vector and keeps quorum fail-closed.
```

```text
S_AM+(t) = min(999999999, floor(10^9 * (1 - exp(-Omega_eff(t)))))

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
fracture_suite_passed = true
cross_verifier_agreement_passed = true
claim_usable = true
fixture = false
```

The maximum declared score is `999,999,999 AM+`. The perfect score
`1,000,000,000 AM+` is reserved.

AM+ is computed from deterministic proof-field closure and debt. Field closure
comes from proof atoms in `rules/proof-atoms.v17.json`; no atom earns credit
without an allowlisted `verifier_key`. The implementation never executes shell
commands from JSON. Evidence paths, when present, must remain inside this
package. JSON floats are rejected. Binary floats are not used in the score path.

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
make daylight-v17-event-horizon-score
make daylight-v17-event-horizon-verify
make daylight-v17-event-horizon-fixture-demo
make daylight-v17-event-horizon-fracture
make daylight-v17-event-horizon-vector
make daylight-v17-event-horizon-rust-vector
make daylight-v17-event-horizon-rust-test
make daylight-v17-event-horizon-triangulation
make daylight-v17-event-horizon-agreement
make daylight-v17-event-horizon-blockers
make daylight-v17-event-horizon-frontier
make daylight-v17-event-horizon-declaration-gate
make daylight-v17-event-horizon-test
make daylight-v17-event-horizon-doctor
```

The declaration fixture intentionally produces `999,999,999 AM+` with
`fixture: true` and `claim_usable: false`. It is a math fixture only, not
external certification.

The current committed proof-atom score is written to
`examples/current-scorecard.v17.json`. The Event Horizon declaration gate
refuses it by default. The blocker vector currently includes `omega_eff below
declaration threshold`, `score_AM_plus below declaration target`,
`cross_verifier_agreement_passed=false`, and `verifier quorum incomplete: 2/3`.
The scorecard verifies and the fracture suite passes. Python and Rust vectors
agree on the current vector, but the third verifier is intentionally absent, so
agreement remains `partial_2_of_3`.

`examples/verifier-vector.python-reference.current.v17.json` is the deterministic
Python reference vector. `examples/verifier-vector.rust-current.v17.json` is
the independent Rust vector. `examples/verifier-vectors.python-rust-current.v17.json`
is the partial 2-of-3 bundle. `examples/verifier-vectors.fake-current.v17.json`
contains intentionally fake vectors used to prove that duplicate families and
mismatched outputs do not satisfy agreement.

## Daylight Horizon Alpha

Daylight Horizon Alpha is the first product layer over the score. It enforces
policy-bound usefulness:

```text
No verified evidence -> no unlock
No proof atoms -> no release
No policy satisfaction -> no plaintext
No valid horizon state -> no authority
```

Vault commands:

```sh
python3 -m src.cli horizon-vault init
python3 -m src.cli horizon-vault seal --in secret.txt --out secret.txt.dhv
python3 -m src.cli horizon-vault open --in secret.txt.dhv --out secret.opened.txt
python3 -m src.cli horizon-vault inspect --in secret.txt.dhv
```

Release commands:

```sh
python3 -m src.cli horizon-release prepare --artifact dist.tar.gz --mode research
python3 -m src.cli horizon-release verify --release dist.tar.gz.dhr
python3 -m src.cli horizon-release gate --release dist.tar.gz.dhr
```

Focused targets:

```sh
make daylight-horizon-alpha-test
make daylight-horizon-alpha-vault-demo
make daylight-horizon-alpha-release-demo
```

Horizon Vault uses the repository's Daylight v15 pure-stdlib RFC 8439 reference
AEAD and binds open to the v17 authorization tag. Horizon Release capsules bind
artifact digest, policy, scorecard digest, blocker vector, and non-claims.
Research release can pass under research policy; declaration and production
labels remain refused until the evidence earns them.

Horizon Alpha is not production cryptography, not production release authority,
not runtime containment, not FIPS validation, not external certification, and
not a whole-system post-quantum safety claim.
