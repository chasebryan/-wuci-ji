# Daylight v19 — Aperture Review Capsule Format

Status: implemented, `schema_version 0.1.0`.

The Aperture Review Capsule is a deterministic, claim-bounded public review
record for a Wuci-Ji / Daylight artifact. It binds subject bytes, upstream
Daylight evidence files, and the exact public file set to digests, and it
carries an explicit claim boundary that verification enforces semantically.

## Determinism rules

- Canonical JSON: sorted keys, separators `(",", ":")`, `ensure_ascii`,
  floats rejected on both load and dump, duplicate keys rejected.
- `capsule_digest = SHA-256("DAYLIGHT-v19-APERTURE-REVIEW-CAPSULE:" + canonical(capsule minus capsule_digest))`.
- No wall-clock time, hostnames, usernames, or environment values appear in
  the capsule. `repo_commit`/`repo_dirty_state` come from git (`unknown`
  outside git); fixture capsules record the literal string `fixture` so the
  committed example stays byte-stable across commits.
- Capsule files are written as indented sorted JSON with a trailing newline
  (`json_bytes`); building twice from the same inputs is byte-identical.

## Digest semantics per field

| Field | Derivation | What an edit breaks |
| --- | --- | --- |
| `subject_sha256` / `subject_sha3_512` / `subject_size` | Streamed dual hash of the primary subject bytes | Capsule digest and subject re-hash at verify |
| `input_subjects[]` | Same, one entry per subject, unique normalized repo-relative paths | Same |
| `optional_binaric_vector_digest` | Head `vector_digest` of the supplied v18 vector chain, recomputed with domain `DAYLIGHT-v18-BINARIC-VECTOR:`; every link's `previous_vector_digest` must match | Chain break or vector edit rejects at build and re-verify |
| `optional_transition_ledger_head` | Final head after recomputing the v18 genesis and `head = H(previous_head, entry_digest)` chain with domain `DAYLIGHT-v18-BASTION-TRANSITION-HEAD:` | Ledger tamper or chain break rejects |
| `optional_meridian_scorecard_digest` | SHA-256 of the exact scorecard file bytes | Any scorecard byte edit rejects when the file is present |
| `optional_event_horizon_scorecard_digest` | SHA-256 of the exact scorecard file bytes; embedded `scorecard_digest` is also recorded | Same |
| `optional_policy_digest` | SHA-256 of the exact policy file bytes | Same |
| `public_manifest[]` | Per-file SHA-256 + size over source bytes | Manifest edit breaks `public_sha256sums` and the capsule digest; file edit breaks re-hash |
| `public_sha256sums` | SHA-256 of the canonical sums text `"<sha256>  <path>\n"` per manifest entry, sorted by path | Any manifest change |
| `capsule_digest` | Domain-separated canonical digest over everything above | Any field edit |

## Claim boundary is semantic, not only digest-bound

Re-digesting an edited capsule does not launder a claim. `validate_capsule_shape`
rejects a capsule whose `claim_boundary` sets any of these to anything but
`false`:

`production_cryptography`, `runtime_containment`, `host_cleanliness`,
`fips_validation`, `government_validation`, `external_certification`,
`whole_system_post_quantum_safety`, `independent_audit_completed`,
`perfect_daylight_score_from_repo_evidence`.

`non_claims` must contain all mandatory non-claim strings, sorted and unique.

## Upstream evidence rules

- Meridian scorecards: `manual_edit_allowed`/`manual_override` must be false,
  `final_score_M` must equal the sum of `term_contributions_M`, and a
  perfect score is accepted only with zero open obligations plus closed
  external-scope obligations carrying non-self-signed attestations
  (`signer_id` not matching `self|internal|local|repo|harness|wuci-ji`).
  Full q-vector re-derivation remains the Meridian verifier's job
  (`make daylight-meridian-verify`); the capsule pins exact bytes and applies
  these fail-closed consistency gates.
- A capsule whose Meridian reference records a perfect score is only
  verifiable while the scorecard bytes are present and re-checkable; a
  missing perfect-score reference is a blocker, not a note.
- Event Horizon scorecards: `fixture: true` plus `claim_usable: true`
  rejects; `score_AM_plus` above `999,999,999` rejects (the perfect value is
  reserved); `declared: true` without `cross_verifier_agreement_passed: true`
  rejects.
- v18 vectors and ledgers are verified by independent recomputation of the
  same domain-separated digests v18 writes; Aperture does not import v18
  code and does not re-implement its scoring.

## Verification outcomes

`verify-capsule` re-validates shape and digest, re-hashes subject and public
files under `--base-dir`, and re-checks any evidence file present at its
recorded path. Missing non-perfect evidence produces a note (the digest still
pins it); `--require-evidence` upgrades missing evidence to a blocker. Every
failure path exits nonzero.

## Public artifact layout

```text
<out-dir>/
├── aperture-review-capsule.v19.json
├── SHA256SUMS                # covers every file except itself, sorted
└── <public_manifest paths, repo-relative layout preserved>
```

The firewall report is written next to the root
(`<out-dir>.firewall-report.v19.json`), never inside it, and only after the
scan passes.
