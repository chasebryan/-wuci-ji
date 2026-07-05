# Wuci-Ji Daylight v16 Analemma

> [!IMPORTANT]
> WuciOS-Fluff-Audit: historical-non-authoritative
> This file is retained as historical Daylight score material. It is not WuciOS
> v2.4 release evidence, not a current score source, and not part of Noether Core.

Daylight v16 Analemma separates self-progress measurement from conservative
claim scoring. Solstice keeps the honest claim score at the current internal
ceiling, while Analemma measures how much verified proof mass exists relative to
a pinned baseline.

```text
D_claim = conservative Solstice claim score
A_self  = self-relative proof-mass score
E_trust = external trust / attestation index
C_level = claim authority level
```

For the current repository-owned artifact:

```text
D_claim_M = 998900 / 1000000
A_self_A  = 1000000A
E_trust_M = 0 / 1000000
C_level   = C1_replayable_public_artifact
```

The designed next-score example is:

```text
P(t0) = 500000
P(t1) = 620000

A_self(t1) = floor(1000000 * 620000 / 500000)
A_self(t1) = 1240000A
```

This is not the current claim. It becomes claimable only after Daylight registers
and verifies `120000` additional proof credits over a `500000`-credit baseline.
The current implemented baseline remains `1000000A`, and the conservative claim
score remains `998900M`.

## Scoring

Analemma uses a pinned proof-unit registry:

```text
ProofMass(t) =
  sum(base_credit(u) * Closed(u,t))
  - RegressionDebt(t)
  - StalenessDebt(t)

AnalemmaScore_A(t) =
  floor(1,000,000 * ProofMass(t) / ProofMass(t0))
```

`ProofMass(t0)` is the Solstice baseline. The bundled registry sets it to
`106000`, and the current Solstice artifact closes exactly that much proof mass,
so `A_self_A = 1000000A` at baseline.

Each proof unit is defined by:

```text
base_credit = impact_weight * difficulty_weight * layer_multiplier
```

No floats are accepted. Manual credit fields and claim-score overrides reject the
report build.

## Debt

Regression debt is deliberately harsher than ordinary credit:

```text
RegressionDebt = reopened_credit * 2
```

Stale proof remains visible as debt until replayed. Critical regression flags
such as `security_bypass_regression` reject the release candidate outright.

## Boundary

Analemma does not change the Daylight M-score:

```text
D_claim_M stays bounded by Solstice/Zenith claim rules
A_self_A may exceed 1000000A through verified self-progress proof mass
score_inflation_M = 0
```

External review upgrades `C_level`; it is not required for internal self-progress
to increase. Production authority, runtime containment, and whole-system
post-quantum safety remain separate gates.

## Public Statement

```text
Current implemented baseline: 1000000A
Designed next score after added proof mass: 1240000A
Claim score remains: 998900M
Score inflation: 0
```

Clean phrasing:

```text
Daylight remains 998,900M on conservative claim closure.
Analemma measures self-progress at 1,240,000A after the added proof mass verifies.
The number did not inflate; the proof mass grew by 24%.
```
