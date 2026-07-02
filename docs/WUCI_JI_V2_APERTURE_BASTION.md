# Wuci-Ji v2 — Aperture Bastion

Daylight v19. Source: [daylight/v19-aperture-bastion/](../daylight/v19-aperture-bastion/).
Boundary tables: [APERTURE_BASTION_SECURITY_BOUNDARY.md](APERTURE_BASTION_SECURITY_BOUNDARY.md).
Format spec: [daylight/v19-aperture-bastion/specs/daylight-v19-aperture-review-capsule.md](../daylight/v19-aperture-bastion/specs/daylight-v19-aperture-review-capsule.md).

## 1. What it is

Aperture Bastion is a deterministic public-review and release-readiness layer
over the existing Wuci-Ji / Daylight stack. It produces an **Aperture Review
Capsule**: a public-safe, reproducible, tamper-evident, claim-bounded JSON
record that binds a subject artifact, upstream Daylight evidence files, and
an exact public file set to digests. It also implements a strict public
artifact firewall that must pass before anything is uploaded or released.

## 2. Why it exists

The stack below it already measures (v18), scores (v15/v17), and gates
(Gate/Horizon). What it lacked was one uniform, reviewable public record
that (a) pins exactly which bytes a review covered, (b) states exactly what
is and is not claimed, and (c) mechanically refuses to publish private
material. Aperture Bastion is that record plus the refusal machinery. It
adds review hygiene, not authority.

## 3. How it fits the stack

| Layer | Relationship |
| --- | --- |
| Wuci-Ji assembly machine / WJSEAL / Gate | Untouched. Aperture never decrypts, never accepts keys, never opens sealed material. Subjects are hashed as opaque bytes. |
| Daylight v15 Meridian | Scorecards are consumed as evidence-derived references only: bytes pinned by SHA-256, manual-edit markers rejected, `final_score_M` must equal its own term contributions, perfect scores require non-self-signed external closure. Full re-derivation stays with `make daylight-meridian-verify`. |
| Daylight v17 Singularity / Horizon | Event Horizon scorecards are pinned by file digest; fixture scorecards marked claim-usable, reserved perfect AM+ values, and declared status without cross-verifier agreement are rejected. Scoring semantics are not changed and the conservative M-score is not inflated. |
| Daylight v18 Binaric Bastion | Not replaced. v18 vectors and transition ledgers are verified by independent recomputation of the same domain-separated digests (vector digest, ledger head chain); a broken previous-vector chain rejects. Aperture sits above v18 as the public-evidence control plane. |

## 4. The Aperture Review Capsule

Required fields (see the schema for exact shapes):
`schema_id`, `schema_version`, `project`, `layer_name`, `generated_by`,
`repo_commit`, `repo_dirty_state`, `input_subjects`, `subject_sha256`,
`subject_sha3_512`, `subject_size`, `optional_binaric_vector_digest`,
`optional_transition_ledger_head`, `optional_meridian_scorecard_digest`,
`optional_event_horizon_scorecard_digest`, `optional_policy_digest`,
`public_manifest`, `public_sha256sums`, `claim_boundary`, `non_claims`,
`forbidden_private_material_profile`, `firewall_result`, `capsule_digest`.

The capsule digest is SHA-256 over a domain separator plus canonical JSON
(sorted keys, stable separators, no floats) of every field except the digest
itself. Editing any score, claim, subject digest, manifest entry, boundary
statement, or public-file hash fails verification. Forbidden authority
claims fail *semantically* as well: re-digesting an edited capsule does not
launder `production_cryptography: true`.

## 5. Measurement vs. verification vs. evidence vs. authorization vs. release vs. production authority

- **Measurement**: computing digests over bytes (v18 vectors, capsule subject
  hashes). Says what the bytes are, nothing else.
- **Verification**: recomputing and comparing (capsule digest, sums, vector
  chains, ledger heads). Says the record still matches the bytes.
- **Evidence**: verified upstream artifacts referenced by digest (scorecards,
  ledgers). Says work happened and is pinned; does not by itself authorize
  anything.
- **Authorization**: Gate/Horizon policy decisions over evidence. Aperture
  does not authorize; it records and refuses.
- **Release**: publishing a firewalled public artifact. Aperture gates this
  with the firewall but grants no authority beyond digest binding.
- **Production authority**: none exists in this repository. No capsule,
  score, or firewall result creates it.

## 6. Exact non-claims

Every capsule carries, and validation enforces, all of:

- not production cryptography
- not runtime containment or sandboxing
- not host cleanliness proof
- not FIPS validated
- not government validated
- not externally certified
- not whole-system post-quantum safe
- not an independent audit
- not a perfect Daylight score claim from repository-owned evidence

## 7. Exact commands

```sh
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli doctor
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli capsule --subject <path> --out <capsule.json>
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli verify-capsule <capsule.json>
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli public-artifact --capsule <capsule.json> --out-dir build/daylight/v19-aperture-bastion-public
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli firewall --root build/daylight/v19-aperture-bastion-public
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli explain <capsule.json>
```

All commands fail closed with nonzero exits on invalid input, missing files,
path traversal, symlinks, malformed JSON, duplicate manifest entries,
absolute manifest paths, private-material markers, digest mismatches, manual
score edits, and unsupported schema versions.

## 8. Exact make targets

```sh
make daylight-v19-aperture-bastion-doctor
make daylight-v19-aperture-bastion-capsule-demo
make daylight-v19-aperture-bastion-verify
make daylight-v19-aperture-bastion-public-artifact
make daylight-v19-aperture-bastion-firewall
make daylight-v19-aperture-bastion-test
make daylight-v19-aperture-bastion-ci
make aperture-bastion-doctor
make aperture-bastion-test
make aperture-bastion-ci
```

## 9. Exact CI behavior

`.github/workflows/daylight-v19-aperture-bastion.yml` runs on push to `main`
and on pull requests, on Ubuntu, with `permissions: contents: read`. It runs
`make daylight-v19-aperture-bastion-ci` (tests, doctor, committed-example
verify, capsule demo, public artifact, firewall), then re-runs the v19
firewall plus the repo-wide `daylight-public-artifact-firewall`, and only
then uploads `build/daylight/v19-aperture-bastion-public/` with
`if-no-files-found: error`. There is no `if: always()` upload and no upload
of unverified build directories; the workflow itself passes the repo's
`check-workflow` firewall lane.

## 10. How a reviewer verifies the capsule

```sh
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli verify-capsule <capsule.json> --base-dir <root>
```

This recomputes the capsule digest, re-hashes every subject and public
manifest file under the base directory, recomputes `public_sha256sums`, and
re-checks any referenced evidence file present at its recorded path
(`--require-evidence` makes missing evidence fatal). `explain` prints the
proofs (what is digest-bound) alongside the non-claims. Independent check
without this tooling: `sha256sum` the files against `SHA256SUMS`, then
recompute the capsule digest from the documented domain string and canonical
JSON.

## 11. How a reviewer confirms no private material was published

```sh
PYTHONPATH=daylight/v19-aperture-bastion python3 -m src.cli firewall --root <public-dir>
```

The firewall recursively rejects: private filenames (`vault.key`, `*.key`,
`smoke-secret.*`, `secret.txt`, `opened.*`, `*.opened`, private transcript
names, `id_rsa`, `id_ed25519`, `.env`, and more), private directories
(`vault-work`, `smoke-vault`, `private`, `vault`, ...), private content
markers (`PRIVATE KEY`, `BEGIN OPENSSH/RSA PRIVATE KEY`, vault key and smoke
secret markers, plaintext-oracle shapes, `WUCI_PRIVATE`,
`DAYLIGHT_PRIVATE`), symlinks, hardlinks, hidden components, key-shaped
64-hex content, oversized files, unexpected files not named by the capsule,
and SHA256SUMS drift. The report is written only after a pass, and only
outside the public root. The rules are pinned into the capsule by profile id
and digest.

## 12. What this improves, without exaggeration

Before v19, public evidence hygiene was enforced per-layer (Meridian's
artifact profile, Witness rules). Aperture Bastion adds one uniform,
tested, deterministic capsule format any layer can target, one firewall with
a pinned rule profile, byte-reproducible example evidence, and CI that
refuses to upload anything the firewall has not passed. It is code and tests
in this repository, exercised against this repository's own artifacts. It
does not add cryptographic strength, containment, external validation, or
any score movement, and it cannot make a weak artifact strong — it can only
make what exists reviewable and hard to overstate.
