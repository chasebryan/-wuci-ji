# Daylight V0.6 Fail-Closed Model

This is a partial fail-closed ordering model for Daylight v0.6. It is not a
complete formal model, not a confidentiality proof, and not a
production-authority claim. It links the provider-backed v6 reference
`Seal`/`Open` implementation evidence, but only as a non-production reference
lane with externally supplied public precheck evidence.

The checked source is `daylight-v06-fail-closed-model.v1.json`. The verifier is
`tests/daylight_v06_fail_closed_model.py` and the top-level proof target is:

```sh
make daylight-v06-fail-closed-model-test
```

## Predicate

The model pins the v0.5/v0.6 ordering shape:

```text
Open(omega) != bottom iff
  PublicPreOK(omega)
  and exists A_prime such that PrivateOpenOK(A_prime, omega)
```

It also pins the private-operation barrier:

```text
PublicPreOK = 0 =>
  no private KEM operation,
  no AEAD.Dec,
  no plaintext materialization.
```

## Fail-Closed Invariants

Each public precheck predicate is required before private work:

```text
ParseOK
SuiteOK
AuxHashOK
KEMBlockOK
ModeOK
PolicyOK
ClaimOK
GateOK
ProvenanceOK
ContentReviewPreOK
V_Auth
NoDowngradeFinal
LogOK
InstallOK
WitnessOK
```

Each private predicate must also hold before `Open` can return anything other
than `bottom`:

```text
DeriveOK
AEAD.Dec
PayloadOK
CommitOK
LeakOK
```

The verifier checks that every single missing predicate forces `Open = bottom`
and that any failed public predicate blocks private KEM, AEAD decrypt, and
plaintext materialization.

## Implementation Link

The model now links its provider-backed reference lane to these Rust symbols in
`daylight-equation/rust/daylight-crypto/src/v6.rs`:

```text
daylight_seal_v6_with_kems_from_seed
daylight_open_v6_with_kems
daylight_reference_precheck_v6
daylight_v6_reference_seal_open_evidence
```

The linked evidence vector is
`daylight-equation/rust/daylight-crypto/vectors/daylight-v6-reference-seal-open-evidence-v1.txt`
and the checked target is:

```sh
make daylight-v6-reference-seal-open-test
```

This link is deliberately narrow. The implementation still requires explicit
non-production external public precheck evidence and records
`production_allowed=false`.

## Boundary

Non-claims:

```text
this model is not a complete Daylight formal model
this model does not prove confidentiality
this model does not make provider-backed v6 Seal/Open production authority
this model does not make fixture predicates production authority
this model does not claim runtime containment
this model does not replace independent external review
```

This model deliberately leaves these proof obligations open:

```text
complete confidentiality model
complete authorization and authority model
complete downgrade-resistance model
complete provider-backed corpus and cross-implementation model
integrated public authority model
constant-time and failure-path review
external review
```

Because those obligations are open, this model raises the tracked evidence for
formalization discipline only. It does not satisfy the 1000/1000 formal-model
gate.
