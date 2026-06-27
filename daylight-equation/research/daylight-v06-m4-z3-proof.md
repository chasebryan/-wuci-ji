# Daylight V0.6 M4 Z3 Proof

This is a solver-checked M4 predicate proof for Daylight v0.6. It uses Z3 over
the SMT-LIB2 file `daylight-v06-m4-z3-proof.smt2` to discharge the Boolean
predicate obligations from `daylight-v06-m4-symbolic-model.v1.json`.

The proof checks 38 unsatisfiable negated obligations covering:

- `Open` succeeds if and only if all public and private predicates hold;
- every single public or private predicate failure forces `Open = bottom`;
- failed public precheck blocks private KEM, AEAD.Dec, and plaintext
  materialization;
- authorization predicates are required;
- downgrade predicates are required;
- confidential release is conditional on all modeled confidentiality
  assumptions.

The verifier is `tests/daylight_v06_m4_z3_proof.py` and the top-level target
is:

```sh
make daylight-v06-m4-z3-proof-test
```

## Boundary

Non-claims:

```text
this Z3 proof is not external review
this Z3 proof is not production authority
this Z3 proof does not prove cryptographic primitive security
this Z3 proof does not claim runtime containment
this Z3 proof does not claim whole-system post-quantum safety
this Z3 proof does not replace constant-time and failure-path review
```
