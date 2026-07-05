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
Phase 3C-C is integrated at `c3a16e4` and closed for automated work.

Phase 3C-D defines Yocto layer/recipe preparation rules without running
BitBake, initializing a Yocto build environment, cloning or downloading Yocto
sources or layers, generating rootfs or image outputs, or creating artifacts:
[EUCLID_TRIAL_PHASE_3C_D.md](EUCLID_TRIAL_PHASE_3C_D.md).
Phase 3C-D is integrated at `8204015` and closed for automated work.

Phase 3C-E defines OpenBSD reference preparation rules without installing,
booting, inspecting runtime behavior, running package/admin commands, cloning
source trees, downloading ports trees or install media, launching VMs,
generating rootfs or image outputs, or creating artifacts:
[EUCLID_TRIAL_PHASE_3C_E.md](EUCLID_TRIAL_PHASE_3C_E.md).
Phase 3C-E is integrated at `0f06b62` and closed for automated work.

These phases do not select a substrate, generate a score, rank candidates, or
invent measurements.

## Phase 3C Aggregate Closeout

Final authority state:

- Branch: `wucios-v24-reduction-gate`
- Remote: `origin/wucios-v24-reduction-gate`
- Final Phase 3C HEAD: `0f06b62`
- Phase 3C is closed for automated work.
- Further movement requires explicit human authorization.

Integrated Phase 3C checkpoints:

- Phase 3C-A backend smoke guardrails: `93c80e6`
- Phase 3C-B direct-rootfs preparation: `9be4dcc`
- Phase 3C-C NixOS/Guix store-root preparation: `c3a16e4`
- Phase 3C-D Yocto layer/recipe preparation: `8204015`
- Phase 3C-E OpenBSD reference preparation: `0f06b62`

Candidate boundaries:

- Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs preparation candidates.
- NixOS and Guix remain Phase 3C-C store-root/declarative preparation candidates.
- Yocto remains the Phase 3C-D layer/recipe preparation candidate.
- OpenBSD remains the Phase 3C-E reference operating-system baseline only.
- OpenBSD is not selected or ranked as a WuciOS substrate.
- No candidate is selected or ranked.

Artifact and scoring boundaries:

- No WuciOS artifact exists from Phase 3C.
- No WuciOS artifact hash exists from Phase 3C.
- No numeric WuciOS score exists from Phase 3C.
- Daylight site status is not treated as a WuciOS score.

Execution boundaries preserved:

- No rootfs generation.
- No Nix/Guix store realization.
- No BitBake execution.
- No Yocto build.
- No OpenBSD boot/install/runtime inspection.
- No OpenBSD package/admin operation.
- No source clone.
- No ports tree/layer/media/image/toolchain/SDK download.
- No VM launch.
- No container build/run.
- No image pull.
- No sudo/package installation.
- No substrate artifact attempt.

Review architecture status:

- Tarski Review Appliance remains `REVIEW_PACKET_PARTIAL`.
- Phase 3C-B, 3C-C, 3C-D, and 3C-E statuses remain distinguishable in the review packet.
- Preserved warnings remain: existing Phase 3B readiness remediation human-approval boundary warning, and existing fluff-audit allowlisted non-claim phrases and skipped historical non-authoritative fixtures.

“WuciOS v2.4 Euclid Trial Phase 3C is closed at origin/wucios-v24-reduction-gate commit 0f06b62. All Phase 3C preparation lanes are integrated and bounded. No artifact, artifact hash, substrate selection, ranking, or numeric WuciOS score exists. L3 and L4 remain unauthorized. Further movement requires explicit human authorization.”

No next implementation phase is authorized or inferred by this closeout.
