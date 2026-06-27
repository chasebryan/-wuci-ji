# Review And Dissemination Plan

Daylight should be shared in stages. The goal is to get the math, threat
model, and implementation boundary reviewed before anyone treats the poster as
an executable or production-ready design.

## Stage 1: Internal Model Review

Audience:

- Wuci-Ji maintainers.
- Reviewers familiar with Gate, Witness, Ledger, CAGE, QCAGE, and INSTALL.

Material:

- Source poster and digest provenance.
- Poster transcription.
- Corrected Daylight equation.
- Initial analysis and open issues.
- Std-only Rust model crate.

Review questions:

- Is the acceptance predicate acyclic?
- Are the action sets and claim levels correct?
- Are downgrade checks represented as enforceable predicates?
- Are public and private evidence boundaries clear?
- Does any wording overclaim production, runtime, or PQ security?

## Stage 2: Cryptography Design Review

Audience:

- External cryptography reviewer or implementer familiar with hybrid KEMs,
  FROST, ML-DSA, SLH-DSA, KMAC/cSHAKE, and AEAD nonce discipline.

Required before this stage:

- Resolved transcript staging.
- Exact standard revisions and errata state.
- Candidate verifier inventory.
- KAT and negative-test plan.
- No implementation of secret-bearing crypto in Daylight.

Review questions:

- Is the ML-KEM plus DHKEM(P-384,HKDF-SHA384) combiner specified safely?
- Should Daylight use an RFC 9591 FROST ciphersuite or define and review a
  custom P-384/SHA-384 ciphersuite?
- Does the AEAD nonce derivation have a mechanical uniqueness argument?
- Does `hybrid` mean conjunctive evidence and never fallback OR evidence?
- Does `pq-strict` fail closed until whole-system evidence exists?

## Stage 3: Implementation Design Review

Audience:

- Rust implementation reviewers.
- Wuci-Ji proof-lane maintainers.

Required before this stage:

- Canonical transcript grammar.
- Parser fixtures and malformed-input corpus.
- Fail-closed predicate engine with test doubles only.
- Public evidence quarantine rules.

Review questions:

- Are all cryptographic operations behind narrow traits?
- Do default trait implementations reject?
- Are fixture-only accept paths clearly named and quarantined?
- Are symlinks, hardlinks, private material, and output overwrite paths denied?
- Can tests run deterministically without network access?

## Public Claim Rule

Until all stages are complete and independently reviewed, external wording
should say only:

```text
Daylight is a research-stage Wuci-Ji acceptance-equation design.
It does not claim production cryptography, runtime sandboxing, production
authority, or whole-system post-quantum security.
```
