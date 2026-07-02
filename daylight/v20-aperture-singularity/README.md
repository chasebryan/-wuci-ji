# Daylight v20 - Aperture Singularity Gate

Daylight v20 is a deterministic public evidence intake/control layer above
`daylight/v19-aperture-bastion` and `daylight/v17-singularity`.

It does not declare Singularity by itself. It binds an Aperture review capsule to
five proof-field families, computes weakest-field governed `omega_eff`, emits a
blocker vector, and refuses declaration unless every machine-checkable condition
passes.

Every evidence bundle summarized by the capsule is also bound by a canonical
input digest, so summaries are not accepted as trace by themselves.
Top-level `fixture` and `claim_usable` are derived from the claim-bearing input
bundles, not just from the boundary-debt report.

## Proof fields

- `reproducible_build`
- `aperture_firewall_boundary`
- `independent_verifier_quorum`
- `external_attestation`
- `falsification_survival`

Each field is computed from evidence atoms. Manual score constants are not
accepted. Complete fields use a one-part residue reserve instead of claiming
perfect closure.

Verifier vectors must also be non-fixture and claim-usable before the verifier
agreement field can pass. A 3-of-3 fixture bundle remains useful as parser
coverage, but it does not become declaration-grade evidence.
The verifier bundle subject must match the expected release subject, and every
vector must name the v20 capsule output schema and carry a recomputable
domain-separated `vector_digest`.

Reproducible-build receipts must be non-fixture, claim-usable, and bound to the
same Aperture capsule source commit, subject SHA-256, subject SHA3-512, and
subject size before the reproducible-build field can pass. Each receipt carries
a recomputable domain-separated `receipt_digest`.
The committed demo uses a clean v19 source-snapshot capsule so
`source_commit_matches_capsule` can close deterministically while fixture
receipts still remain non-claim-usable.

Falsification result rows are also digest-bound so manual edits reopen their
proof atoms instead of silently preserving a pass.

External attestation statements are digest-bound before any future signature
verification is considered; a `verification_status` string alone still cannot
close the attestation field.

## Declaration policy

The declaration gate requires:

- `omega_eff >= 20.723265837`
- `score_AM_plus == 999999999`
- `score_inflation_M == 0`
- `critical_debt == 0`
- `contradiction_debt == 0`
- all field thresholds passed
- falsification/fracture survival passed
- cross-verifier agreement passed
- verifier quorum is `3_of_3`
- `fixture == false`
- `claim_usable == true`
- external attestation is cryptographically verified
- reserved perfect AM+ value is not used

The committed fixture intentionally fails declaration. That is the correct
result: it demonstrates the gate and blocker vector without claiming production
authority, independent audit, runtime containment, FIPS/government validation, or
whole-system post-quantum safety.

## Commands

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli doctor
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli build-capsule --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json --out build/daylight/v20-aperture-singularity-capsule.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli verify-capsule daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli score-fields daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli agreement daylight/v20-aperture-singularity/examples/verifier-agreement.partial-2-of-3.v20.json --expected-subject v20-aperture-singularity-fixture
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli blockers daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli declaration-gate daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli explain daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli evidence-audit daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli score-ceiling daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli score-ceiling-report --capsule daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli verify-external-evidence daylight/v20-aperture-singularity/examples/external-evidence.valid-shape.nonclaim.json --capsule daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli explain-external-blockers daylight/v20-aperture-singularity/examples/external-evidence.valid-shape.nonclaim.json --capsule daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json --aperture-capsule daylight/v20-aperture-singularity/examples/input-aperture-capsule.source-snapshot.v19.json
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli public-artifact --capsule daylight/v20-aperture-singularity/examples/aperture-singularity-capsule.fixture.v20.json --out-dir build/daylight/v20-aperture-singularity-public --firewall-report build/daylight/firewall-report.v20.json --force
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli verify-public-artifact build/daylight/v20-aperture-singularity-public --expected-release-tag v20-aperture-singularity-fixture
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli firewall --root build/daylight/v20-aperture-singularity-public --report build/daylight/firewall-report.v20.json
```

`score-ceiling` reports whether the current AM+ value is the highest truthful
no-external-validation score for the committed capsule. When repo-owned code
gaps are zero and the remaining requirements are external evidence slots, it
keeps Singularity refused and sets
`singularity_possible_without_external_validation` to `false`.

`verify-external-evidence` is the fail-closed intake for real external closure
material. It checks independent rebuild receipts, external firewall-profile
reviews, claim-usable 3-of-3 verifier vectors, pinned attestation statements,
subject binding, score-ceiling binding, and pinned verification material. Until
a deterministic local signature verifier is implemented, structurally valid
bundles still fail with `pinned cryptographic attestation verification not
implemented` and cannot open declaration.

## Public Review Artifact

`make daylight-v20-aperture-singularity-public-artifact` emits a public-review
directory with the v20 capsule, documentation schemas for every evidence bundle,
the verifier bundle, external-attestation bundle, reproducible-build bundle,
falsification bundle, boundary-debt report, firewall-profile expansion bundle,
external-evidence slot contracts, artifact manifest, omega scorecard, blocker
vector, declaration-gate report, evidence-audit report, reviewer guide,
score-ceiling report, reviewer guide, non-claims, `SHA256SUMS`, and
`SHA3-512SUMS`. It also writes a deterministic
`.tar.gz` next to the public directory and writes `firewall-report.v20.json`
outside the public root before returning success. `verify-public-artifact`
verifies either the directory or tarball, including schema digests, manifest
file bindings, evidence-bundle canonical input digests, release-tag consistency,
sums, capsule validity, and safe tar member names.

## Non-claims

- not production cryptography
- not runtime containment
- not host cleanliness proof
- not FIPS validated
- not government validated
- not externally certified
- not whole-system post-quantum safe
- not an independent audit
- not a perfect Daylight score claim from repository-owned evidence
