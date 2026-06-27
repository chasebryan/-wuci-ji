# Daylight Scorecard

This scorecard is the repo-owned gate for any "1000/1000" claim. It is a
research scorecard, not a production-readiness certificate.

Current valid score as of 2026-06-27:

```text
Daylight_v0.6_research_score = 890 / 1000
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
```

The score now sits slightly above the upper estimate recorded with the imported
v0.6 M1 fixture artifact because the repo adds an independent stdlib checker
for deterministic-CBOR structure, transcript hash consistency, public-precheck
rejection-stage evaluation, an independent fixture-profile private `Open`
verifier, manifest/result agreement, and SHA-256 fixture integrity:

```text
Grok-style estimate = 860 / 1000
GPT self-rating     = 845 / 1000
```

The increase beyond that estimate is defensible because the checker now
independently reproduces public-precheck accept/reject behavior and
fixture-profile private `Open` outcomes without importing the fixture
implementation. The same artifact profile still declares
`RealCryptoProvider = 0`, `M1Progress = partial`, no provider-backed v6
reference `Seal`/`Open`, no formal model, and no external review.

## Scored Evidence

```text
Byte-level schema and transcript clarity       190 / 200
Deterministic valid and negative fixture corpus 160 / 175
Fail-closed public-before-private ordering      125 / 125
Pinned Rust primitive experiments               135 / 150
Daylight v4/v6 parser and rejection behavior    120 / 125
Documentation, claim discipline, provenance     100 / 100
Independent parser and vector reproduction       60 / 75
Formal model                                      0 / 25
External review                                   0 / 25
Total                                           890 / 1000
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
- The v6 hardening module has an independent static vector checker,
  public-precheck evaluator, and fixture-profile private `Open` verifier, but
  still lacks provider-backed v6 `Seal`/`Open` and full
  cross-implementation agreement.
- No public fuzz corpus or independent reproduction bundle is tracked.
- No formal model is tracked.
- No external reviews are tracked.
- No production authority, publish authority, trust authority, or runtime
  containment gate exists for Daylight.

## Next Score-Raising Work

1. Replace the fixture crypto predicates in a separate provider-backed v6
   `Seal`/`Open` lane while preserving the fixture profile as non-production
   regression data.
2. Extend the scorecard guard into generated machine-readable score evidence,
   while preserving the current failure if the scorecard says 1000 and any hard
   gate above is still missing.
3. Add cross-implementation agreement output comparing the fixture runner,
   static/public checker, independent private `Open` verifier, and future
   provider-backed lane.
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
- [machine-readable scorecard](SCORECARD.v1.json)
- [scorecard guard](../tests/daylight_scorecard_gate.py)
- [independent static vector checker](../tests/daylight_v06_m1_static_vectors.py)
- [independent private Open verifier](../tests/daylight_v06_m1_independent_open.py)
