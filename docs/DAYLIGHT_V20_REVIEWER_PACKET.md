# Daylight v20 Reviewer Packet

This packet is for an external reviewer or rebuilder who wants to produce
evidence for the Daylight v20 Aperture Singularity gate. Nothing in this
packet asks you to certify, approve, or audit anything. You are asked to run
deterministic checks and report exactly what you observed.

## Who counts as external

You are external only if you are not this repository, its authors, its
automation, or its execution harness. Your identity string must not contain
any reserved token (`self`, `internal`, `local`, `repo`, `repository`,
`harness`, `fixture`, `fixtures`, `unknown`, `wuci`, `noxframe`). Pick a
stable identity such as `alice-builds.example.org`. Evidence signed by the
repository about itself is rejected by machine, so do not ask the maintainers
to co-sign your results.

## What you will need

- The release tag and source commit you are reviewing.
- The public review artifact (`verify-public-artifact` accepts the directory
  or the deterministic tarball).
- Python 3.11+ with no extra packages.

## Step 1 - verify the public artifact

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-public-artifact <public-dir-or-tarball> --expected-release-tag <tag>
```

Read `score-ceiling.report.json`, `singularity-blocker-vector.json`, and
`NON_CLAIMS.md` first. The artifact is expected to refuse declaration; if it
does not, stop and report that as a critical finding.

## Step 2 - pick the evidence you can produce

1. **Independent rebuild receipt** - rebuild the subject artifact from the
   pinned source commit in your own environment and record the digests you
   observed. See `docs/DAYLIGHT_V20_INDEPENDENT_REBUILD_RECEIPT.md`.
2. **Firewall-profile review** - review the public-artifact firewall profile
   rules and negative cases and report a finding level. See
   `docs/DAYLIGHT_V20_FIREWALL_PROFILE_REVIEW.md`.
3. **Verifier vector** - implement or run an independent verifier family over
   the subject capsule and record the canonical output digest. See
   `docs/DAYLIGHT_V20_VERIFIER_VECTOR_CONTRACT.md`.

Report honestly. A `fail` decision, a `critical` finding, or a digest that
does not match is valuable evidence; the gate treats dishonest agreement as
worthless and honest disagreement as release-stopping.

## Step 3 - attest what you produced

Each evidence item must be bound to a pinned attestation you sign with your
own key. The statement and subject digests are canonical SHA-256 values
defined in `docs/DAYLIGHT_V20_ATTESTATION_VERIFICATION.md`. Your public key
is pinned into the repository by pull request as public verification
material; keep your signing key to yourself and never send it to anyone.

## Step 4 - assemble and self-check the bundle

Assemble one JSON bundle per
`docs/DAYLIGHT_V20_EXTERNAL_EVIDENCE_PROTOCOL.md` and run:

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-external-evidence <your-bundle.json> \
  --capsule <v20-capsule.json> --aperture-capsule <v19-capsule.json>
```

The verifier names every blocker it finds. Today it will always report at
least `pinned cryptographic attestation verification not implemented`; that
blocker is on the repository, not on you, and your bundle remains valid input
for when the verifier lands.

## What happens to your evidence

Admissible external evidence can, in the future, close exactly the four
external blockers listed in the protocol. It cannot raise the score by
itself, cannot bypass the declaration gate, and is never re-labeled as
anything grander than what you attested. If your evidence is rejected, the
rejection reason is machine-readable and reproducible.

## Example submissions

The repository ships worked examples under
`daylight/v20-aperture-singularity/examples/external-evidence.*.json`,
including `external-evidence.valid-shape.nonclaim.json` (a structurally
complete bundle that is still not claim evidence) and six rejection examples
(empty, self-signed, internal reviewer, fixture, digest mismatch, unpinned
key). All of them are refused by the verifier; they exist so you can see the
exact shapes and the exact rejections.
