# Euclid Substrate Trial

Euclid Substrate Trial is the substrate comparison framework for WuciOS v2.4. It defines candidate bases, axioms, required evidence, and measurable comparison criteria.

No substrate is selected until evidence exists.

Current status: `NO_SUBSTRATE_SELECTED`.

## Candidates

- Buildroot
- Alpine Linux
- Debian Minimal
- Void Linux
- NixOS
- GNU Guix
- Yocto Project
- OpenBSD Reference Path

## Required Trial Outputs

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

Void Linux is a candidate only. Existing Void-oriented tooling is historical implementation context, not a v2.4 base decision.

## First Trial Plan

The first mechanical readiness plan is
[EUCLID_SUBSTRATE_TRIAL_PLAN.md](EUCLID_SUBSTRATE_TRIAL_PLAN.md).

The first artifact cohort protocol is
[EUCLID_TRIAL_PHASE_1.md](EUCLID_TRIAL_PHASE_1.md).

The second phase adds safe build feasibility probes:
[EUCLID_TRIAL_PHASE_2.md](EUCLID_TRIAL_PHASE_2.md).

Phase 2B expands safe build feasibility probes to the full original substrate
candidate set:
[EUCLID_TRIAL_PHASE_2B.md](EUCLID_TRIAL_PHASE_2B.md).

Phase 3A defines controlled build rooms for the full cohort:
[EUCLID_TRIAL_PHASE_3A.md](EUCLID_TRIAL_PHASE_3A.md).

Phase 3B readiness inspects backend, input, policy, and resource blockers for
the controlled build rooms without executing them:
[EUCLID_TRIAL_PHASE_3B_READINESS.md](EUCLID_TRIAL_PHASE_3B_READINESS.md).

Phase 3C-A verifies rootless backend mechanics and buildroom preparation
guardrails with a synthetic non-substrate smoke image:
[EUCLID_TRIAL_PHASE_3C_A.md](EUCLID_TRIAL_PHASE_3C_A.md).
The synthetic smoke image is not a substrate artifact and is not score eligible.

Phase 3C-B defines direct-rootfs preparation rules for Buildroot, Alpine,
Debian minimal, and Void without generating rootfs images or substrate
artifacts:
[EUCLID_TRIAL_PHASE_3C_B.md](EUCLID_TRIAL_PHASE_3C_B.md).
Phase 3C-B is integrated at `9be4dcc` and closed for automated work.

Phase 3C-C defines NixOS/Guix store-root preparation rules without building or
running NixOS or Guix, realizing store paths, generating rootfs images, or
creating artifacts:
[EUCLID_TRIAL_PHASE_3C_C.md](EUCLID_TRIAL_PHASE_3C_C.md).
Yocto and OpenBSD reference remain assigned to later dedicated policy phases.

These phases do not select a substrate, generate a score, rank candidates, or
invent measurements.
