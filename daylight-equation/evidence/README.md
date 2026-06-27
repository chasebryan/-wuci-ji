# Daylight Evidence

This directory contains checked-in, machine-readable evidence derived from
Daylight research fixtures and tests. These artifacts are not production
authority, external review, runtime containment, or whole-system
post-quantum assurance.

- `daylight-v06-m1-cross-agreement.v1.json` records agreement across the
  imported fixture runner, independent static public checker, and independent
  fixture-profile private `Open` verifier.
- `daylight-v6-provider-vector-agreement.v1.json` records agreement across the
  Rust provider-backed KEM/key-schedule, private-roundtrip, and reference
  `Seal`/`Open` evidence vectors while preserving the non-production,
  external-public-authority boundary.
