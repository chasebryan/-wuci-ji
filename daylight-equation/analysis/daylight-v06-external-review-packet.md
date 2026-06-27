# Daylight V0.6 External Review Packet

This packet collects the current Daylight v0.6 evidence set for outside review.
It is not itself an external review and does not raise the current score.

Current valid score: 975/1000.

The missing 25 points remain external-review evidence. A reviewer should treat
integrated public authority and signed production authority as open blockers,
not as implied claims.

## Local Checks

```sh
make daylight-scorecard-test
make daylight-v06-m4-z3-proof-test
make daylight-v06-m4-symbolic-model-test
make daylight-v06-1000-preflight-test
make daylight-v06-1000-claim-gate-test
make daylight-v06-1000-checkpoint-test
make daylight-v06-external-review-verifier-test
make daylight-v06-authority-verifier-test
make daylight-v6-provider-vector-agreement-test
make daylight-v06-schema-freeze-test
make daylight-v6-reference-negative-corpus-test
```

## Review Scope

Formal model:

- Does the SMT predicate model faithfully encode the Daylight v0.6 M4 `Open`
  predicate?
- Are authorization and downgrade predicates represented as necessary
  conditions?
- Are the confidentiality assumptions stated narrowly enough for a conditional
  predicate proof?

Cryptography:

- Are provider-backed ML-KEM-1024 and DHKEM(P-384,HKDF-SHA384) lanes combined
  and labeled without fallback semantics?
- Does AEAD use transcript-bound associated data consistently?
- Do the current non-claims prevent quantum-safety and production-readiness
  overreach?

Implementation boundary:

- Are fixture providers and externally supplied public authority evidence
  quarantined from production claims?
- Are public-precheck failures fail-closed before private KEM, AEAD.Dec, and
  plaintext materialization?
- Are certificate, revocation, log, install, witness, publish, and trust
  authority predicates still visibly unresolved?

## Acceptance Criteria

External review credit requires at least two independent reviews. Each review
must identify the reviewed commit, cover the formal model, provider-backed
vectors, cryptographic boundary, and production-authority blockers, and close
or explicitly preserve every production-blocking finding. Review artifacts must
be attributable and signed or otherwise independently verifiable.

The repo accepts signed review evidence through `tools/daylight_external_review.py`.
Score use requires a `daylight-v06-external-review-set-v1` manifest containing
exactly two independent signed review entries for the current commit.

Review-set assembly should use the tool path, not hand-written JSON:

```sh
python3 tools/daylight_external_review.py emit-set \
  --review-a-evidence review-a.json \
  --review-a-report review-a.md \
  --review-a-root-key review-a.pub \
  --review-a-signature review-a.sig \
  --review-b-evidence review-b.json \
  --review-b-report review-b.md \
  --review-b-root-key review-b.pub \
  --review-b-signature review-b.sig \
  --out reviews.json
python3 tools/daylight_external_review.py verify-set --repo . --manifest reviews.json
```

All review-set paths are portable relative paths under the manifest directory.
Absolute paths and `..` traversal are rejected before a review set can count
toward the score.

## Boundary

Non-claims:

```text
this packet is not an external review
this packet does not raise the Daylight score
this packet is not production authority
this packet does not make Daylight production-ready
this packet does not claim whole-system post-quantum safety
```
