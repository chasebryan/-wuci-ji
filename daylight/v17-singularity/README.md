# Daylight v17 Singularity

Daylight v17 Singularity is an executable residue-collapse scorecard layer over
the existing Solstice, Zenith, Analemma, and D16-AWE evidence lanes.

It implements:

```text
S_AM+(t) = floor(10^9 * (1 - exp(-Omega(t))))

Omega(t) =
  sum_i alpha_i * [-ln(1 - C_i(t))]
  - Debt(t)
  - OverclaimDebt(t)
  - StalenessDebt(t)
```

The perfect score `1,000,000,000 AM+` is reserved. The declaration target is
`999,999,999 AM+`, reached only when regenerated evidence drives residue below
one part per billion and no collapse or score-inflation condition is present.

This package is not a production authority, runtime sandbox, whole-system
post-quantum safety claim, external certification claim, or new primitive
security claim. It measures verifier evidence and rejects typed scores.

## Files

- `src/singularity.py` computes field closures, curvature, debt, residue, score,
  scorecard digests, and report artifacts.
- `src/v16_bridge.py` verifies and imports existing Daylight v15/v16 artifacts.
- `rules/field-registry.v17.json` defines the ten fields and their proof-unit
  credit surfaces.
- `tests/` covers the equation, anti-fake checks, score-inflation rejection,
  collapse rules, and report artifact verification.
- `assets/singularity.jpg` is the supplied v17 Singularity visual notice.

## CLI

```sh
PYTHONPATH=daylight/v17-singularity python3 -m src.cli score --json
PYTHONPATH=daylight/v17-singularity python3 -m src.cli report
PYTHONPATH=daylight/v17-singularity python3 -m src.cli verify-report
PYTHONPATH=daylight/v17-singularity python3 -m src.cli verify-scorecard build/daylight/v17-singularity/singularity-scorecard.json
```

## Test

```sh
make daylight-v17-singularity-test
```

