# Daylight v20.2 Rebuild Receipt Protocol

Daylight v20.2 defines standalone external rebuild receipt intake for the
rebuild-receipt blocker. A rebuild receipt is external evidence, not a release
claim. It asserts that an independent reviewer rebuilt the bound public
artifact from the declared source and observed the expected bytes.

## Receipt Scope

A rebuild receipt is admissible only when it is independently signed by a
pinned external identity. The receipt must bind to:

- source repository, source commit, and source tag
- declared clean checkout
- deterministic build commands
- build environment metadata
- expected artifact digest
- produced artifact digest
- build transcript digest
- receipt statement digest
- explicit v20 non-claim acknowledgements

The receipt statement digest is:

```text
SHA-256(
  b"DAYLIGHT-v20-INDEPENDENT-REBUILD-RECEIPT-STATEMENT:" +
  canonical(receipt without receipt_statement_digest and attestation_ref)
)
```

`attestation_ref` is a pinned Ed25519 attestation. Its `subject_digest` must
equal the recomputed receipt statement digest. The signature proves only that
the pinned signer attested to the exact rebuild receipt statement.

## Non-Claims

A rebuild receipt can close only the external rebuild receipt blocker. It
cannot by itself open the Singularity declaration gate, raise the score,
certify Wuci-Ji/Daylight, prove production readiness, prove runtime
containment, prove whole-system post-quantum safety, claim FIPS or government
validation, claim external certification, or create a perfect score claim.

Fixture receipts may be structurally valid and cryptographically signed, but
they are never claim-usable evidence. Repo-owned, self-scoped, internal, local,
`wuci`, `noxframe`, `daylight`, and harness-generated identities are rejected
as external rebuild evidence.

## Acceptance

The verifier accepts a receipt as rebuild evidence only when:

- the schema is strict and deterministic
- the reviewer identity is external
- `fixture` is false
- `claim_usable` is true
- `clean_checkout_declared` is true
- source commit and source tag are present and match the bound capsule
- expected artifact digests match the pinned public release subject
- produced artifact digests match expected artifact digests
- transcript digest is present, valid, and non-placeholder
- all non-claim acknowledgements are true
- the embedded attestation verifies through the v20.1 pinned verifier

Accepted receipt reports close
`reproducible_build.non_fixture_subject_bound_rebuilds` only. All other
external evidence families remain open until separately satisfied.
