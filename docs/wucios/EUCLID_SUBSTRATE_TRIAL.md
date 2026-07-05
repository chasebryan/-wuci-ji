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

These phases prepare Buildroot, Alpine Linux, and Debian Minimal first. They do
not select a substrate, generate a score, rank candidates, or invent
measurements.
