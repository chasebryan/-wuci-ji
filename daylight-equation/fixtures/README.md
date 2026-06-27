# Daylight Fixture Artifacts

This directory contains executable Daylight research fixtures. These files are
not WUCI production authority, runtime containment, or whole-system
post-quantum assurance.

## daylight-v06-m1

`daylight-v06-m1/` is the extracted Daylight Envelope v0.6 M1 fixture artifact.
It contains a Python reference fixture implementation, a generated vector
corpus, recorded test results, and the artifact's own fixture profile.

The fixture uses `cryptography>=46.0.0` and is therefore intentionally not part
of the stdlib-only WUCI proof lanes. Run its vector corpus explicitly:

```sh
make daylight-v06-m1-fixture-test
```

The fixture providers for ML-KEM, DHKEM, ML-DSA, SLH-DSA, reviewer signatures,
certificate predicates, revocation predicates, and transparency-log predicates
are deterministic fixtures only. Passing this corpus supports byte-level M1
research progress for parsing, transcript construction, KDF labels, fail-closed
ordering, vector format, and rejection stages. It does not claim production
cryptography, quantum-safe status, external review, publish authority, trust
authority, or OS containment.
