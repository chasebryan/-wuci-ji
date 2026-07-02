# Daylight v20 Aperture Singularity Capsule

## Purpose

The v20 capsule binds Aperture Bastion public-review evidence to the Daylight
Singularity declaration gate. It is an intake/control surface for future
external evidence, not a declaration of external closure.

Core rules:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
FixtureClaimUsable(x) -> Reject(x)
SelfSignedExternalClosure(x) -> Reject(x)
ReservedPerfectAMPlus(x) -> Reject(x)
BoundaryDebtCritical(x) -> Reject(x)
VerifierQuorumIncomplete(x) -> Reject(x)
ExternalAttestationUnverified(x) -> BlockDeclaration(x)
```

## Canonical JSON

The enforced loader rejects duplicate keys and JSON floats. The canonical digest
stream uses sorted keys, compact separators, ASCII escaping, and a newline at
EOF. Python float objects are rejected before dump.

Capsule digest:

```text
SHA-256("DAYLIGHT-v20-APERTURE-SINGULARITY-CAPSULE:" + canonical(capsule without capsule_digest))
```

## Required capsule fields

- `schema_id`
- `schema_version`
- `project`
- `layer_name`
- `source_commit`
- `release_tag`
- `fixture`
- `claim_usable`
- `input_aperture_capsule_digest`
- `input_aperture_firewall_report_digest`
- `input_firewall_profile_expansion_digest`
- `input_verifier_agreement_bundle_digest`
- `input_external_attestation_bundle_digest`
- `input_reproducible_build_bundle_digest`
- `input_falsification_bundle_digest`
- `input_boundary_debt_report_digest`
- `input_meridian_scorecard_digest`
- `input_event_horizon_scorecard_digest`
- `input_binaric_vector_chain_digest`
- `input_transition_ledger_head`
- `policy_digest`
- `proof_fields`
- `omega_sum`
- `omega_weak`
- `omega_eff`
- `score_AM_plus`
- `field_thresholds_passed`
- `verifier_agreement`
- `external_attestation_summary`
- `reproducible_build_summary`
- `falsification_summary`
- `boundary_debt_summary`
- `firewall_profile_summary`
- `claim_boundary`
- `non_claims`
- `blockers`
- `declaration_allowed`
- `capsule_digest`

The implementation also records explicit gate condition fields:
`score_inflation_M`, `critical_debt`, `contradiction_debt`,
`fracture_suite_passed`, `cross_verifier_agreement_passed`,
`verifier_quorum`, `external_attestation_verified`, and
`reserved_perfect_value_used`.

## Proof-field math

The capsule records canonical SHA-256 input digests for every evidence bundle it
summarizes. A summary without its bound bundle digest is not accepted as trace.
Top-level `fixture` and `claim_usable` are derived across claim-bearing evidence
inputs; a permissive boundary report cannot mask fixture verifier or rebuild
evidence.

Field closure comes from required evidence atoms:

```text
closure_i = verified_atoms_i / required_atoms_i
omega_i = -ln(max(1 - closure_i, 1e-9))
```

If all atoms pass, v20 applies a residue reserve:

```text
closure_i = 999999999 / 1000000000
```

Effective omega:

```text
omega_eff = max(0, min(omega_sum, 5 * min_i(omega_i)) - debts)
```

AM+ score:

```text
S_AM+(t) = min(999999999, floor(10^9 * (1 - exp(-omega_eff(t)))))
```

Declaration threshold:

```text
omega_eff >= 20.723265837
```

Per-field threshold:

```text
omega_i >= 4.144653167
closure_i >= 0.984151068
```

## External attestations

External attestation bundles are parsed structurally, reject self-scoped
signers, require scope and non-claim acknowledgement, and bind
`statement_digest` to the scoped reviewer/subject/evidence statement. They
currently cannot satisfy declaration. Until real pinned cryptographic signature
verification is implemented, every bundle carries:

```text
external attestation not cryptographically verified
```

## External evidence intake

The `src.external_evidence` intake layer binds the remaining external closure
slots to one canonical bundle:

- two or more independent rebuild receipts
- at least one external firewall-profile review
- exactly three claim-usable verifier vectors from distinct families
- pinned cryptographic attestation statements for every external evidence item
- the v20 capsule subject and the v19 Aperture capsule subject bytes
- the score-ceiling report digest

The bundle digest is:

```text
SHA-256("DAYLIGHT-v20-EXTERNAL-EVIDENCE-BUNDLE:" + canonical(bundle without bundle_digest))
```

The intake rejects repo-owned, self-scoped, internal, fixture, unpinned,
placeholder, mismatched, unsigned, or unreferenced evidence. It is intentionally
not enough for an attestation to name `ed25519`; the implementation must also
contain a deterministic local verifier before
`external_attestation_verified == true` can be reached. Until then, every
otherwise well-shaped bundle remains a non-claim and `declaration_allowed`
remains false.

## Independent verifier agreement

A verifier bundle is declaration-grade only when all vectors are valid,
non-fixture, claim-usable, from at least three distinct verifier families, and
share one canonical output digest. The bundle subject must match the expected
release subject, and every vector must declare the v20 capsule output schema
and carry a recomputable domain-separated `vector_digest` over its own vector
statement. Duplicate verifier families reject. Fixture or non-claim-usable
vectors may be kept as parser fixtures, but they do not close the
verifier-quorum field.

## Reproducible builds

Reproducible-build bundles are declaration-grade only when receipts are
non-fixture, claim-usable, independently produced by at least two builders in
distinct environments, and bound to the Aperture capsule source commit, subject
SHA-256, subject SHA3-512, and subject size. Each receipt must also carry a
recomputable domain-separated `receipt_digest` over its builder, environment,
source, instruction, artifact, size, and byte-identical statement. Structural
fixture receipts can exercise the parser, but they cannot close the
reproducible-build field.

## Falsification survival

Falsification bundles must be non-fixture, claim-usable repo-owned negative
corpus evidence. Each result row carries an evidence digest over its case id,
description, and fail-closed outcome; editing the row without regenerating the
digest reopens that proof atom.

## Public review artifact

The v20 public artifact contains:

- `aperture-singularity-capsule.v20.json`
- `aperture-singularity-capsule.schema.json`
- `verifier-agreement.bundle.schema.json`
- `external-attestation.bundle.schema.json`
- `reproducible-build.bundle.schema.json`
- `falsification-survival.bundle.schema.json`
- `boundary-debt.report.schema.json`
- `firewall-profile-expansion.bundle.schema.json`
- `external-evidence.bundle.schema.json`
- `independent-rebuild-receipt.schema.json`
- `firewall-profile-review.schema.json`
- `verifier-vector-claim-usable.schema.json`
- `pinned-attestation.schema.json`
- `DAYLIGHT_V20_EXTERNAL_EVIDENCE_PROTOCOL.md`
- `DAYLIGHT_V20_REVIEWER_PACKET.md`
- `DAYLIGHT_V20_INDEPENDENT_REBUILD_RECEIPT.md`
- `DAYLIGHT_V20_FIREWALL_PROFILE_REVIEW.md`
- `DAYLIGHT_V20_VERIFIER_VECTOR_CONTRACT.md`
- `DAYLIGHT_V20_ATTESTATION_VERIFICATION.md`
- `verifier-agreement.bundle.json`
- `external-attestation.bundle.json`
- `reproducible-build.bundle.json`
- `falsification-survival.bundle.json`
- `boundary-debt.report.json`
- `firewall-profile-expansion.bundle.json`
- `external-evidence-slot-contracts.v20.json`
- `public-artifact.manifest.v20.json`
- `omega-field-scorecard.json`
- `singularity-blocker-vector.json`
- `singularity-declaration-gate.report.json`
- `evidence-audit.report.json`
- `score-ceiling.report.json`
- `REVIEWER_GUIDE.md`
- `NON_CLAIMS.md`
- `SHA256SUMS`
- `SHA3-512SUMS`

The firewall rejects unexpected files, hidden members, symlinks, hardlinks,
private-material names or markers, SHA256/SHA3-512 drift, and any fixture public
artifact that unexpectedly declares Singularity.

The firewall report is written outside the public root as
`firewall-report.v20.json`, so the public-review directory remains a stable,
non-recursive artifact set.

`public-artifact.manifest.v20.json` binds every public-review payload file by
role, size, SHA-256, SHA3-512, and capsule digest. It also binds the schema
digests, the external-evidence slot contract digest, and internal release-tag
consistency between the capsule and verifier agreement subject. The manifest is
itself covered by `SHA256SUMS` and `SHA3-512SUMS`.
Public artifact verification also recomputes each bundled evidence JSON's
canonical input digest and compares it to the digest recorded in the capsule.

`external-evidence-slot-contracts.v20.json` names the future evidence slots for
non-fixture rebuild receipts, external firewall-profile review, independent
verifier quorum, and pinned external attestation verification. These slots are
review contracts only; they do not close any field without real machine-checked
evidence.

## Boundary

The capsule must preserve these non-claims:

- not production cryptography
- not runtime containment
- not host cleanliness proof
- not FIPS validated
- not government validated
- not externally certified
- not whole-system post-quantum safe
- not an independent audit
- not a perfect Daylight score claim from repository-owned evidence
