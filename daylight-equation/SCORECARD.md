# Daylight Scorecard

This scorecard is the repo-owned gate for any "1000/1000" claim. It is a
research scorecard, not a production-readiness certificate.

Current valid score as of 2026-06-27:

```text
Daylight_v0.6_research_score = 855 / 1000
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
```

The score sits between the two estimates recorded with the imported v0.6 M1
fixture artifact:

```text
Grok-style estimate = 860 / 1000
GPT self-rating     = 845 / 1000
```

The midpoint is the defensible repo score because the fixture artifact removed
major byte-level ambiguity, while the same artifact profile still declares
`RealCryptoProvider = 0`, `M1Progress = partial`, no independent
implementation, no formal model, and no external review.

## Scored Evidence

```text
Byte-level schema and transcript clarity       190 / 200
Deterministic valid and negative fixture corpus 160 / 175
Fail-closed public-before-private ordering      125 / 125
Pinned Rust primitive experiments               135 / 150
Daylight v4/v6 parser and rejection behavior    120 / 125
Documentation, claim discipline, provenance     100 / 100
Independent parser and vector reproduction       25 / 75
Formal model                                      0 / 25
External review                                   0 / 25
Total                                           855 / 1000
```

This is intentionally not a production score. The current evidence supports
"strong executable research artifact", not "complete protocol" or "ready to
trust."

## 1000 Gate

The repository may claim `Daylight_v0.6_research_score = 1000 / 1000` only
after all of these are true and linked from this file:

- M1: the byte-level v6 schema, transcript labels, KDF labels, rejection
  stages, minimum valid corpus, and minimum negative corpus are frozen.
- M1: at least two independent parsers agree on every parser vector.
- M2: reference `Seal` and `Open` exist for every valid vector.
- M2: production cryptographic providers replace fixture-only predicates, or
  the score remains explicitly limited to a fixture profile.
- M2: private KEM, key schedule, AEAD, zeroization, and secret-dependent paths
  receive constant-time and failure-path review.
- M3: public positive, negative, fuzz, and cross-implementation vector corpora
  are reproducible from a clean checkout.
- M4: a formal model covers confidentiality, authorization, downgrade
  resistance, and fail-closed release behavior.
- M5: at least two independent external reviews are complete, tracked, and
  addressed.
- M6: known critical breaks are zero and production-disallowed claims have been
  replaced by assembly-enforced authority gates.

If any item is missing, the valid score is below 1000.

## Current Blockers

- The imported v0.6 M1 fixture uses deterministic fixture providers for
  ML-KEM, DHKEM, ML-DSA, SLH-DSA, reviewer signatures, certificate predicates,
  revocation predicates, and transparency-log predicates.
- The Rust `daylight-crypto` lane pins real primitive crates, but the v6
  artifact is not yet a complete provider-backed reference `Seal`/`Open`
  implementation.
- The v6 hardening module still lacks a second independent parser and full
  cross-implementation agreement.
- No public fuzz corpus or independent reproduction bundle is tracked.
- No formal model is tracked.
- No external reviews are tracked.
- No production authority, publish authority, trust authority, or runtime
  containment gate exists for Daylight.

## Next Score-Raising Work

1. Build an independent stdlib parser/vector checker that reads the v0.6 M1
   vector manifest and verifies deterministic CBOR, schema, and rejection
   stages without importing the fixture implementation.
2. Add a generated score fixture that fails if the scorecard says 1000 while
   any hard gate above is still missing.
3. Replace the fixture crypto predicates in a separate provider-backed lane,
   preserving the current fixture profile as non-production regression data.
4. Publish a clean KAT bundle with valid, negative, and parser-only vectors
   plus reproduction commands.
5. Draft the formal model surface before adding any production authority claim.

## Evidence Links

- [v0.6 M1 fixture README](fixtures/daylight-v06-m1/README.md)
- [v0.6 M1 fixture profile](fixtures/daylight-v06-m1/spec/M1_FIXTURE_PROFILE.md)
- [v0.6 M1 hardening reference](references/dlv0.5/v0.6M1-HARDENING.md)
- [v0.5.1/2 hardening note](specs/daylight-envelope-hardening-v0.5.1-2.md)
- [daylight-crypto README](rust/daylight-crypto/README.md)
- [standards baseline](research/standards-baseline.md)
