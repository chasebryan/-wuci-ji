# Nightlight vs Daylight Test Cycle - 2026-06-28

## Scope

Goal: close the current deterministic defensive Nightlight gaps for Daylight v6
and rerun the local test cycle until results become repetitive.

This report covers only local defensive validation. It does not add offensive
logic, network behavior, production authority, runtime containment, whole-system
post-quantum-safety claims, or a Daylight score increase.

## Implemented Coverage

- Added a hash-bound unsupported install-manifest public simulation that reaches
  `REJECT_INSTALL`.
- Added a deterministic malformed recipient decapsulation-key negative case
  that reaches `Derive`.
- Added a deterministic metadata leak-value mismatch negative case that reaches
  `Leak` after AEAD and commitment checks.

## Current Metrics

- Nightlight adversarial cases: 60.
- Fail-closed outcomes: 60.
- Public-boundary simulations: 46.
- Reference negative cases: 14.
- Public rejection stages covered: 14 of 14.
- Private failure classes covered: 4 of 4.
- Remaining deep-assessment recommendations: sparse auth-signature, review,
  and log/witness coverage.

## Evidence Artifacts

- `daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-negative-corpus-v1.txt`
- `daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-equation-battery-v1.txt`
- `daylight-equation/rust/daylight-crypto/vectors/nightlight-v6-deep-assault-assessment-v1.txt`
- `daylight-equation/evidence/daylight-v6-provider-vector-agreement.v1.json`
- `daylight-equation/evidence/daylight-v6-kat-reproduction-bundle.v1.json`

## Verification

Final verification status: passed.

Commands run:

- `make daylight-v6-nightlight-battery-test`
- `make daylight-v6-nightlight-deep-assessment-test`
- `make daylight-v6-provider-vector-agreement-test daylight-v6-kat-reproduction-bundle-test`
- `cd daylight-equation/rust/daylight-crypto && cargo test --offline`
- `make daylight-v06-schema-freeze-test daylight-v06-fail-closed-model-test daylight-v6-provider-kem-evidence-test daylight-v6-provider-private-roundtrip-test daylight-v6-reference-seal-open-test daylight-v6-reference-negative-corpus-test daylight-scorecard-test`
- byte-for-byte CLI reproduction for the v6 schema, provider KEM,
  private-roundtrip, reference seal/open, reference negative corpus,
  Nightlight battery, and Nightlight deep-assessment vectors;
- adjacent Daylight M1/review/authority/model lanes;
- repeat focused Nightlight/evidence gates.

Repeated focused gates produced the same all-green result, so another local
test pass would be repetitive rather than productive.
