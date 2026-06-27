# Daylight Scorecard

This scorecard is the repo-owned gate for any "1000/1000" claim. It is a
research scorecard, not a production-readiness certificate.

Current valid score as of 2026-06-27:

```text
Daylight_v0.6_research_score = 945 / 1000
ProductionAllowed = 0
RuntimeContainmentClaim = 0
WholeSystemPostQuantumSafetyClaim = 0
ExternalReviewClaim = 0
```

The score now sits slightly above the upper estimate recorded with the imported
v0.6 M1 fixture artifact because the repo adds an independent stdlib checker
for deterministic-CBOR structure, transcript hash consistency, public-precheck
rejection-stage evaluation, an independent fixture-profile private `Open`
verifier, checked cross-implementation agreement, manifest/result agreement,
and SHA-256 fixture integrity:

```text
Grok-style estimate = 860 / 1000
GPT self-rating     = 845 / 1000
```

The increase beyond that estimate is defensible because the checker now
independently reproduces public-precheck accept/reject behavior and
fixture-profile private `Open` outcomes without importing the fixture
implementation, and the checked cross-agreement evidence shows all 32 vectors
agree across the recorded fixture runner, static public checker, and
independent private `Open` verifier. The Rust lane also now tracks
provider-backed v6 KEM/key-schedule evidence for the schema vector through
pinned ML-KEM-1024 and DHKEM(P-384,HKDF-SHA384) primitive crates, plus
provider-backed v6 private-roundtrip evidence for typed `PrivatePayload_v6`,
AEAD seal/open with `AD = T0`, artifact commitment checking, and public
precheck rejection before private work. A provider-backed v6 reference
`Seal`/`Open` lane now seals and opens the C1 schema artifact with provider
ML-KEM, DHKEM, and AEAD while requiring explicit non-production external public
precheck evidence. Provider-backed v6 vector-agreement evidence now checks the
KEM/key-schedule, private-roundtrip, reference `Seal`/`Open`, and reference
negative-corpus vectors against the same artifact and non-production
public-boundary claims. The same artifact profile still declares
`RealCryptoProvider = 0`, `M1Progress = partial`, no integrated production
public authority, no complete formal model, and no external review.

## Scored Evidence

```text
Byte-level schema and transcript clarity       190 / 200
Deterministic valid and negative fixture corpus 175 / 175
Fail-closed public-before-private ordering      125 / 125
Pinned Rust primitive experiments               150 / 150
Daylight v4/v6 parser and rejection behavior    125 / 125
Documentation, claim discipline, provenance     100 / 100
Independent parser and vector reproduction       75 / 75
Formal model                                      5 / 25
External review                                   0 / 25
Total                                           945 / 1000
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
- The Rust `daylight-crypto` lane pins real primitive crates and now includes a
  provider-backed v6 reference `Seal`/`Open` lane, but that lane is explicitly
  non-production and depends on externally supplied public precheck evidence.
- The v6 hardening module has an independent static vector checker,
  public-precheck evaluator, and fixture-profile private `Open` verifier, but
  still lacks full cross-implementation agreement with a provider-backed lane.
- The Rust v6 lane has provider-backed v6 KEM/key-schedule evidence for the
  schema vector, but this evidence intentionally stops short of private `Open`
  and does not change the `RealCryptoProvider = 0` fixture-artifact claim.
- The Rust v6 lane has provider-backed v6 private-roundtrip evidence for the
  prechecked private path, but public authorization still fails closed and the
  fixture-artifact `RealCryptoProvider = 0` claim is unchanged.
- The provider-backed reference `Seal`/`Open` remains non-production, and
  public authority remains external; certificate, revocation, transparency-log,
  install, witness, publish, trust, and production authority predicates are not
  integrated.
- The provider-backed reference negative corpus covers the current C1
  non-production lane only; it is not a full provider-backed valid/negative
  corpus and does not replace a second independent implementation.
- No public fuzz corpus or independent reproduction bundle is tracked.
- A partial fail-closed formal model is tracked for `Open = bottom` ordering
  and the public-before-private barrier, but no complete formal model is
  tracked for confidentiality, authorization, downgrade resistance, and
  fail-closed release behavior. No complete formal model is tracked.
- No external reviews are tracked.
- No production authority, publish authority, trust authority, or runtime
  containment gate exists for Daylight.

## Next Score-Raising Work

1. Expand provider-backed vector agreement from the current C1 reference
   evidence into a full valid/negative corpus and a second independent
   implementation.
2. Replace externally supplied public precheck evidence with integrated
   certificate, revocation, transparency-log, install, witness, publish, and
   trust-authority verification gates.
3. Publish a clean KAT bundle with valid, negative, and parser-only vectors
   plus reproduction commands.
4. Expand the partial fail-closed formal model into a complete M4 model before
   adding any production authority claim.

## Evidence Links

- [v0.6 M1 fixture README](fixtures/daylight-v06-m1/README.md)
- [v0.6 M1 fixture profile](fixtures/daylight-v06-m1/spec/M1_FIXTURE_PROFILE.md)
- [v0.6 M1 hardening reference](references/dlv0.5/v0.6M1-HARDENING.md)
- [v0.5.1/2 hardening note](specs/daylight-envelope-hardening-v0.5.1-2.md)
- [daylight-crypto README](rust/daylight-crypto/README.md)
- [provider-backed v6 KEM/key-schedule evidence vector](rust/daylight-crypto/vectors/daylight-v6-provider-kem-evidence-v1.txt)
- `make daylight-v6-provider-kem-evidence-test`
- [provider-backed v6 private-roundtrip evidence vector](rust/daylight-crypto/vectors/daylight-v6-provider-private-roundtrip-evidence-v1.txt)
- `make daylight-v6-provider-private-roundtrip-test`
- [provider-backed v6 reference `Seal`/`Open` evidence vector](rust/daylight-crypto/vectors/daylight-v6-reference-seal-open-evidence-v1.txt)
- `make daylight-v6-reference-seal-open-test`
- [provider-backed v6 reference negative corpus](rust/daylight-crypto/vectors/daylight-v6-reference-negative-corpus-v1.txt)
- `make daylight-v6-reference-negative-corpus-test`
- [provider-backed v6 vector-agreement evidence](evidence/daylight-v6-provider-vector-agreement.v1.json)
- [provider-backed v6 vector-agreement verifier](../tests/daylight_v6_provider_vector_agreement.py)
- `make daylight-v6-provider-vector-agreement-test`
- [partial fail-closed formal model](research/daylight-v06-fail-closed-model.md)
- [partial fail-closed formal model JSON](research/daylight-v06-fail-closed-model.v1.json)
- [partial fail-closed formal model verifier](../tests/daylight_v06_fail_closed_model.py)
- `make daylight-v06-fail-closed-model-test`
- [standards baseline](research/standards-baseline.md)
- [machine-readable scorecard](SCORECARD.v1.json)
- [cross-agreement evidence](evidence/daylight-v06-m1-cross-agreement.v1.json)
- [scorecard guard](../tests/daylight_scorecard_gate.py)
- [independent static vector checker](../tests/daylight_v06_m1_static_vectors.py)
- [independent private Open verifier](../tests/daylight_v06_m1_independent_open.py)
