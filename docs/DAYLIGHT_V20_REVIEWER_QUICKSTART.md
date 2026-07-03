# Daylight v20 Reviewer Quickstart

This is the shortest command path for checking a public artifact and a
Daylight v20 external-evidence bundle. It is an intake workflow, not a
certification, approval, audit, government validation, FIPS validation,
production-crypto claim, runtime-containment claim, or post-quantum-safety
claim.

## Environment

External-evidence shape checks and Ed25519 signature verification are
stdlib-only:

```sh
python3 --version
```

## Verify the public artifact

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-public-artifact <artifact-dir-or-tarball> \
  --expected-release-tag <tag>
```

The artifact is expected to refuse declaration unless all declaration-gate
requirements are satisfied.

## Verify an external-evidence bundle

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-external-evidence <external-evidence.bundle.json> \
  --capsule <v20-capsule.json> \
  --aperture-capsule <v19-capsule.json>
```

For local tests only, a temporary pinned-material registry can be supplied
without changing the committed public registry:

```sh
PYTHONPATH=daylight/v20-aperture-singularity python3 -m src.cli \
  verify-external-evidence <external-evidence.bundle.json> \
  --capsule <v20-capsule.json> \
  --aperture-capsule <v19-capsule.json> \
  --pinned-material <test-pinned-material.json>
```

The declaration gate remains closed unless all required external evidence
classes are present, independent, digest-bound, non-fixture, claim-usable, and
cryptographically verified.
