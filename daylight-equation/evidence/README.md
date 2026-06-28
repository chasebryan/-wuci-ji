# Daylight Evidence

This directory contains checked-in, machine-readable evidence derived from
Daylight research fixtures and tests. These artifacts are not production
authority, external review, runtime containment, or whole-system
post-quantum assurance.

- `daylight-v06-m1-cross-agreement.v1.json` records agreement across the
  imported fixture runner, independent static public checker, and independent
  fixture-profile private `Open` verifier.
- `daylight-v6-provider-vector-agreement.v1.json` records agreement across the
  Rust provider-backed KEM/key-schedule, private-roundtrip, reference
  `Seal`/`Open`, and reference negative-corpus evidence vectors while
  preserving the non-production, external-public-authority boundary.
- `nightlight-v6-equation-battery-v1.txt` is the Rust Nightlight defensive
  battery over the v6 evidence vectors. It checks equation invariants,
  domain separation, fail-closed negative cases, public-precheck stop counts,
  and an open-ended public mutation simulation inventory without adding
  offensive logic or changing Daylight score claims.
- `nightlight-v6-deep-assault-assessment-v1.txt` is the Rust Nightlight deep
  assessment over the same local corpus. It applies
  `deterministic-coverage-learning-v1` to rank defensive learning arms,
  select prioritized epochs, and record gap recommendations without adding
  offensive logic, network behavior, or Daylight score claims.
- `daylight-v06-external-review-packet.v1.json` records the current 975/1000
  evidence packet for outside review. It is not itself an external review and
  does not raise the score.
