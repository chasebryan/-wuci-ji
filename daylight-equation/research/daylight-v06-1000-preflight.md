# Daylight V0.6 1000 Preflight

This preflight is the local gate for any future
`Daylight_v0.6_research_score = 1000 / 1000` checkpoint.

It deliberately fails closed today. The current valid score is 970/1000, and
the remaining 30 points require evidence that cannot be invented inside the
repo:

- integrated public authority;
- a mechanized proof or independent formal-methods review;
- at least two independent external reviews with production-blocking findings
  addressed;
- signed non-fixture production, publish, and trust authority evidence.

The checked source is `daylight-v06-1000-preflight.v1.json`. The verifier is
`tests/daylight_v06_1000_preflight.py` and the top-level proof target is:

```sh
make daylight-v06-1000-preflight-test
```

## Boundary

Non-claims:

```text
this preflight is not an external review
this preflight is not production authority
this preflight is not a mechanized proof
this preflight does not raise the Daylight score
this preflight does not authorize pushing a 1000 checkpoint
```
