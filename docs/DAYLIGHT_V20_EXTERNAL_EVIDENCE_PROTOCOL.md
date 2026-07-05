# Daylight v20 External Evidence Protocol

This document defines how real external evidence becomes admissible against
the four remaining Daylight v20 Aperture Singularity blockers. It is an input
contract, not a claim. Publishing this protocol does not change the score,
does not close any blocker, and does not declare Singularity.

## Standing truth

- `repo_owned_ceiling_reached = true`
- `singularity_possible_without_external_validation = false`
- Current truthful no-external score: `999801305 AM+` (see
  `score-ceiling.report.json` in the public artifact)

The repository has proven that repository-owned evidence cannot truthfully
reach Singularity. This protocol exists so that, if real external evidence is
ever supplied, it can be verified by machine instead of asserted by hand. The
gate stays closed until then.

## The four externally satisfiable blockers

1. **Independent rebuild receipts** - two or more external builders rebuild
   the subject artifact byte-for-byte from the pinned source commit.
   Contract: `docs/DAYLIGHT_V20_INDEPENDENT_REBUILD_RECEIPT.md`; standalone
   v20.2 intake: `docs/DAYLIGHT_V20_REBUILD_RECEIPT_PROTOCOL.md`.
2. **External firewall-profile review** - an external reviewer examines the
   public-artifact firewall profile, its rules, and its negative test cases.
   Contract: `docs/DAYLIGHT_V20_FIREWALL_PROFILE_REVIEW.md`.
3. **Claim-usable 3-of-3 verifier vectors** - exactly three independent
   verifier families reproduce the same canonical verification output for the
   subject capsule. Contracts:
   `docs/DAYLIGHT_V20_VERIFIER_VECTOR_CONTRACT.md`,
   `docs/DAYLIGHT_V20_VERIFIER_VECTOR_QUORUM.md`, and
   `docs/DAYLIGHT_V20_CANONICAL_VERIFIER_OUTPUT.md`.
4. **Pinned cryptographic attestation verification** - every evidence item is
   bound to an attestation whose signer key is pinned in the repository and
   whose signature verifies locally and deterministically.
   Contract: `docs/DAYLIGHT_V20_ATTESTATION_VERIFICATION.md`.

## Bundle format

External evidence is submitted as one JSON bundle
(schema: `external-evidence.bundle.schema.json`):

```json
{
  "schema_id": "daylight.v20.external-evidence.bundle",
  "schema_version": 1,
  "subject": {
    "release_tag": "...",
    "source_commit": "...",
    "artifact_sha256": "...",
    "artifact_sha3_512": "...",
    "artifact_size": 0,
    "aperture_capsule_digest": "...",
    "score_ceiling_report_digest": "..."
  },
  "independent_rebuild_receipts": [],
  "firewall_profile_reviews": [],
  "claim_usable_verifier_vectors": [],
  "pinned_attestations": [],
  "bundle_digest": "..."
}
```

- `subject.aperture_capsule_digest` is the `capsule_digest` of the v20
  Aperture Singularity capsule the evidence is about.
- `subject.score_ceiling_report_digest` is printed by
  `PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli
  score-ceiling-report --capsule <capsule.json>`.
- `subject.artifact_*` are the sealed subject values from the bound v19
  Aperture capsule.

## Canonicalization

Canonical JSON is: sorted keys, separators `(",", ":")`, ASCII escapes, UTF-8
bytes, one newline at end. On load: duplicate keys rejected, JSON floats
rejected. Digest rule:

```
bundle_digest = SHA-256("DAYLIGHT-v20-EXTERNAL-EVIDENCE-BUNDLE:"
                        + canonical(bundle without bundle_digest))
```

Item binding digests (what a pinned attestation's `subject_digest` must
equal) are computed the same way over the item without its `attestation_ref`,
under these domains:

- `DAYLIGHT-v20-EXTERNAL-REBUILD-RECEIPT:`
- `DAYLIGHT-v20-EXTERNAL-FIREWALL-REVIEW:`
- `DAYLIGHT-v20-EXTERNAL-VERIFIER-VECTOR:`

Pinned attestation signatures use Ed25519 only. The signed message is:

```
b"DAYLIGHT-v20-PINNED-ATTESTATION-STATEMENT:" +
canonical(attestation without statement_digest and signature)
```

The public key is raw 32-byte Ed25519 public key material, base64 encoded in
the pinned registry. `public_key_digest` is SHA-256 over those raw 32 bytes.
The signature is raw 64-byte Ed25519 signature material, base64 encoded in the
attestation. Verification is local, deterministic, offline, and fail-closed.

Standalone v20.2 rebuild receipts use the same pinned attestation verifier but
remain a separate evidence class. A rebuild receipt must recompute its own
receipt statement digest, bind to source commit, release tag, build commands,
environment metadata, expected and produced artifact digests, transcript
digest, and v20 non-claim acknowledgements. A valid signed receipt can close
only the rebuild-receipt blocker; signatures alone and receipts alone cannot
open Singularity.

Daylight v20.3 verifier vectors use the pinned canonical verifier-output
format. Each vector must include `canonical_output_schema_id:
daylight.v20.canonical-verifier-output`, matching `canonical_output_digest`
and `output_digest` fields, `verifier_family_independence_class: "external"`,
an implementation kind, and a distinct implementation digest. Exactly three
vectors are required, exactly three distinct external verifier families must
be present, all three output digests must match the recomputed canonical
output digest, and every vector must be bound to a valid pinned attestation.
Fixture vectors, duplicate families, duplicate implementation digests,
two-of-three agreement, more-than-three submissions, internal families, and
unattested vectors are rejected.

Additional hard rules enforced by the verifier: no NUL bytes, no non-UTF-8
bytes, no absolute paths, no `..`, no backslashes, no hidden path components
in path references, no symlinked or hardlinked bundle files, no placeholder
digests (a digest consisting of one repeated character is never real), and no
network access during verification. The result must not depend on wall-clock
time, hostname, username, or local paths. Staleness is digest-defined: when
the capsule, firewall profile, rules, or negative-case matrix change, old
evidence stops binding and is rejected.

## Independence rules

Every builder, reviewer, and signer must declare
`*_independence_class: "external"` and use an identity that contains none of
the reserved tokens: `self`, `internal`, `local`, `repo`, `repository`,
`harness`, `fixture`, `fixtures`, `unknown`, `wuci`, `noxframe`. Evidence
authored by this repository, its tooling, or its automation is rejected by
construction. Fixture evidence (`fixture: true`) and non-claim-usable
evidence (`claim_usable: false`) are rejected everywhere.

## Verification commands

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-external-evidence <bundle.json> \
  --capsule <v20-capsule.json> --aperture-capsule <v19-capsule.json>

PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  explain-external-blockers <bundle.json> --capsule <v20-capsule.json>

PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  score-ceiling-report --capsule <v20-capsule.json>

PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-rebuild-receipt <receipt.json> \
  --capsule <v20-capsule.json> --aperture-capsule <v19-capsule.json>

PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  canonical-verifier-output \
  --capsule <v20-capsule.json> \
  --aperture-capsule <v19-capsule.json> \
  --out canonical-verifier-output.json

PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-verifier-quorum \
  --bundle <bundle.json> \
  --capsule <v20-capsule.json> \
  --aperture-capsule <v19-capsule.json>
```

The `verify-external-evidence` report distinguishes `shape_valid`,
`bundle_digest_valid`, `pinned_material_valid`,
`external_attestation_verified`, `external_evidence_admissible`,
`declaration_allowed`, and `blockers`.

Expected behavior today, in every case:

```
declaration_allowed = false
singularity_possible_without_external_validation = false
```

With no evidence, fake evidence, self-signed evidence, internal evidence,
fixture evidence, mismatched digests, unpinned keys, or valid-shape but
unverified evidence, the bundle is rejected with named blockers and
`external_attestation_verified = false`. Properly pinned signatures may close
only the attestation field. `external_evidence_admissible` becomes true only if
all required evidence classes are also valid, and the declaration gate still
remains closed unless the bound capsule itself allows declaration.

A valid verifier-family quorum closes only the verifier-vector blocker. It
does not certify, audit, approve, validate, raise the score, or declare
Singularity.

A valid signature does not certify, validate, approve, audit, or release
anything. It only proves that the pinned signer attested to the exact canonical
evidence statement.

## What this protocol does not do

It does not certify, validate, approve, or audit anything. All v20
non-claims remain in force (see `NON_CLAIMS.md` in the public artifact),
including: not production cryptography, not an independent audit, not
covered by external-certification evidence from any outside auditor, not FIPS validated, not government validated, not
whole-system post-quantum safe, and not a perfect Daylight score claim from
repository-owned evidence.
