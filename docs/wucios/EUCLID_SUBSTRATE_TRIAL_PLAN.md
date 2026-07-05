# Euclid Substrate Trial Plan

This is the first WuciOS v2.4 substrate trial readiness plan. It does not select
a substrate, build an image, or create a score.

Current selection status: `NO_SUBSTRATE_SELECTED`.

## First Trial Cohort

The first mechanical trial cohort is:

- Buildroot
- Alpine Linux
- Debian Minimal

These three candidates are tested first because they cover the immediate design
spread: appliance-builder, minimal practical Linux distribution, and stable
familiar Linux baseline.

## Required Trial Outputs

Each candidate must produce the same evidence outputs before comparison:

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
- `claim-boundary.md`

Missing values remain `NOT_MEASURED`.

## Phase Progression

- [EUCLID_TRIAL_PHASE_1.md](EUCLID_TRIAL_PHASE_1.md) defines the common evidence protocol.
- [EUCLID_TRIAL_PHASE_2.md](EUCLID_TRIAL_PHASE_2.md) adds safe detect-only build feasibility probes.

## Mechanical Preconditions

- Candidate source or package channels are pinned or recorded.
- Build command is captured.
- Build environment is recorded.
- Generated image path is recorded.
- Image SHA-256 is recorded before any score material is considered.
- No candidate is ranked without generated trial evidence.

## Non-Selection Rule

Small size does not select a candidate by itself. Familiarity does not select a
candidate by itself. Any future selection requires generated artifacts that are
easier to review, measure, reproduce, and defend than the alternatives.
