# Daylight v16 Zenith

Daylight v16 Zenith is a public assurance verifier layer over Daylight v15+
Solstice. It does not change the Daylight score:

```text
ZenithAdjustedScore_M = SolsticeScore_M
```

Zenith adds a separate assurance index over public proof obligations:

```text
Z1 = hermetic Solstice artifact
Z2 = supply-chain provenance
Z3 = reproducible builds
Z4 = multi-implementation agreement
Z5 = semantic evidence replay
Z6 = adversarial fuzzing
Z7 = signed external reviews
Z8 = transparency log
Z9 = public falsification program
Z10 = boundary discipline
```

The current repository-owned Solstice artifact is expected to remain honest:

```text
SolsticeScore_M = 998900
ZenithAdjustedScore_M = 998900
ScoreInflation_M = 0
ZenithLevel = Z3_HERMETIC_SOLSTICE
```

Higher levels require explicit public evidence; unsigned external review,
rebuild mismatch, implementation disagreement, open fuzz crash, open critical
falsification break, and production/runtime/PQ overclaims reject.

## Commands

```sh
make daylight-zenith-verify
make daylight-zenith-report
make daylight-zenith-ci
```

Direct CLI:

```sh
PYTHONPATH=daylight/v16-zenith python3 -m src.cli verify-artifact build/daylight/v15-solstice
PYTHONPATH=daylight/v16-zenith python3 -m src.cli report build/daylight/v15-solstice --out-dir build/daylight/v16-zenith
```

Boundary: DZ-1 is a public research proof standard, not production
certification. DZ-2 additionally requires production authority, runtime
containment, post-quantum evidence, and perfect Solstice external closure.
