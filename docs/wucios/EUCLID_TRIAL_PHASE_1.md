# WuciOS v2.4 Euclid Trial Phase 1

Euclid Trial Phase 1 begins mechanical substrate measurement for the first
artifact cohort. It does not choose a substrate.

Selection status: `NO_SUBSTRATE_SELECTED`.

Valid trial outcomes:

- `NO_SUBSTRATE_SELECTED`
- `TRIAL_DATA_PARTIAL`
- `TRIAL_DATA_COMPARABLE`
- `TRIAL_BLOCKED`

## First Artifact Cohort

- Buildroot
- Alpine Linux
- Debian Minimal

These candidates must be measured under the same Noether Core requirements.
Phase 1 does not rank them and does not use reputation, familiarity, or
preference as evidence.

## Candidate Trial Directories

- `wucios/trials/buildroot/`
- `wucios/trials/alpine/`
- `wucios/trials/debian-minimal/`

Each directory contains the same evidence protocol:

- `trial-plan.json`
- `build-notes.md`
- `artifact-manifest.json`
- `package-manifest.txt`
- `package-count.txt`
- `image-size.txt`
- `enabled-services.txt`
- `listening-ports.txt`
- `suid-sgid.txt`
- `kernel-modules.txt`
- `dependency-tree.txt`
- `build-manifest.sha256`
- `substrate-report.json`
- `substrate-report.md`
- `failure-report.md`

Missing evidence must be written as `NOT_MEASURED`. If no build was attempted,
the candidate status remains `BUILD_NOT_ATTEMPTED`. If tooling is absent, the
candidate records `MISSING_TOOLING`. If a build is attempted and fails, the
candidate records `BUILD_ATTEMPTED_FAILED`. If a future build succeeds, the
candidate records `BUILD_SUCCEEDED` while still leaving unavailable
measurements as `NOT_MEASURED`.

## Combined Report

The runner writes:

- `build/wucios/review/euclid-trial-phase-1.md`
- `build/wucios/review/euclid-trial-phase-1.json`

The combined report includes candidate status, artifact path, artifact hash,
image size, package count, default services, listening ports, SUID/SGID count,
kernel module count, dependency tree status, Noether Core violations, and
missing measurements.

## Command

```sh
make wucios-euclid-trial-phase-1
```

No substrate may be selected after Phase 1 unless all three candidates produce
comparable generated evidence.
