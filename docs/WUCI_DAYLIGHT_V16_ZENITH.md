# Daylight v16 Zenith

Daylight v16 Zenith is not a bigger number. It is the verifier layer that proves
the number cannot move without moving the evidence.

```text
Meridian = evidence-derived score
Solstice = hermetic score closure
Zenith   = public assurance gates over the Solstice artifact
```

Zenith keeps the Solstice score honest:

```text
SolsticeScore_M = 998900 / 1000000
ZenithAdjustedScore_M = SolsticeScore_M
ScoreInflation_M = 0
```

It adds a separate `ZenithAssurance_M` and level:

```text
Z0_PARSE_ONLY
Z1_DIGEST_CLOSED
Z2_EVIDENCE_BOUND
Z3_HERMETIC_SOLSTICE
Z4_REPRODUCIBLE
Z5_ADVERSARIAL_REPRODUCIBLE
Z6_PUBLIC_EXTERNAL_STANDARD
Z7_PRODUCTION_ELIGIBLE
```

The current repo-owned artifact is expected to verify at
`Z3_HERMETIC_SOLSTICE`. Reaching `Z6_PUBLIC_EXTERNAL_STANDARD` requires
reproducible builds, multi-implementation agreement, fuzzing evidence, signed
external reviews, transparency logging, a public falsification program, and
boundary discipline. Reaching `Z7_PRODUCTION_ELIGIBLE` additionally requires
production authority, runtime containment, post-quantum evidence, and perfect
Solstice external closure.

Run:

```sh
make daylight-zenith-ci
```

Key rejection rules:

```text
ZenithAdjustedScore_M != SolsticeScore_M -> Reject
UnsignedExternalReviewCredit -> Reject
RebuildMismatch -> Reject
ImplementationDisagreement -> Reject
FuzzCrashOpen -> Reject
CriticalBreakOpen -> Reject
ProductionClaimWithoutAuthority -> Reject
RuntimeContainmentClaimWithoutProof -> Reject
WholeSystemPQClaimWithoutProof -> Reject
```
