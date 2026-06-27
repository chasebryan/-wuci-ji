# Daylight V0.6 M4 Symbolic Model

This is a checked symbolic M4 model for Daylight v0.6. It covers the four M4
claim areas from the v0.6 hardening reference: confidentiality, authorization,
downgrade resistance, and fail-closed release behavior.

It is not a mechanized theorem-prover proof, not external review, and not
production authority.

The checked source is `daylight-v06-m4-symbolic-model.v1.json`. The verifier is
`tests/daylight_v06_m4_symbolic_model.py` and the top-level proof target is:

```sh
make daylight-v06-m4-symbolic-model-test
```

## Predicate

```text
Open(omega) != bottom iff
  all public_precheck_predicates
  and all private_open_predicates
```

The model exhaustively checks the Boolean predicate space for the 15 public
precheck predicates and 5 private open predicates, for 1,048,576 states. Every
single failed public or private predicate forces `Open = bottom`, and every
failed public predicate blocks private KEM, AEAD.Dec, and plaintext
materialization.

## Claim Areas

Confidentiality is modeled as conditional on these assumptions:

```text
AtLeastOneKEMSharedSecretPseudorandom
HKDF_SHA512_Extractor_PRF
AEAD_IND_CCA
PublicKeysValidate
SideChannelsBounded
```

Authorization requires:

```text
V_Auth
GateOK
PolicyOK
ClaimOK
ContentReviewPreOK
```

Downgrade resistance requires:

```text
NoDowngradeFinal
ModeOK
PolicyOK
ClaimOK
```

Fail-closed release behavior requires every public and private predicate to
hold before plaintext can materialize.

## Boundary

Non-claims:

```text
this symbolic model is not a mechanized theorem-prover proof
this symbolic model is not external review
this symbolic model is not production authority
this symbolic model does not claim runtime containment
this symbolic model does not claim whole-system post-quantum safety
this symbolic model does not replace constant-time and failure-path review
```
