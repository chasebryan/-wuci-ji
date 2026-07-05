# WuciOS v2.4 Euclid Trial Phase 2B — Full Substrate Cohort Probe Expansion

## Purpose

Phase 2B expands build feasibility probes to every originally named substrate candidate.

## Full Candidate Set

- Buildroot
- Alpine
- Debian minimal
- Void
- NixOS
- GNU Guix
- Yocto
- OpenBSD reference path

## Non-Selection Rule

Phase 2B cannot select a substrate. The selection status remains `NO_SUBSTRATE_SELECTED`.

## No Emotional Testing

Candidates are not judged by preference, reputation, aesthetics, familiarity, project loyalty, or subjective confidence.

## Execution Mode

Safe detect-only mode is the default. It records local tooling, source, image, and policy blockers without installing packages, using `sudo`, or attempting builds.

## Candidate Evidence Files

Each candidate writes the same generated files under `build/wucios/trials/<candidate>/phase-2/`:

- `status.json`
- `status.txt`
- `tool-detection.json`
- `build-log.txt`
- `build-notes.md`
- `artifact-manifest.json`
- `package-manifest.txt`
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
- `noether-static-check.json`
- `noether-static-check.md`
- `missing-measurements.txt`

## OpenBSD Reference Boundary

OpenBSD reference is non-Linux and is not a drop-in Linux base equivalent. Linux-only measurements may be recorded as `NOT_APPLICABLE_NON_LINUX`.

## Host Store Boundary

NixOS and Guix may require store behavior outside `build/wucios/`. Build attempts are blocked unless a future explicit host-store or build-room policy exists.

## Runtime Measurement Boundary

Listening ports and loaded kernel modules require runtime inspection. They remain `NOT_MEASURED_RUNTIME_REQUIRED` unless a later boot scan exists.

## Score Boundary

Phase 2B does not generate a numeric WuciOS score unless artifact-bound score requirements are satisfied.

## Next Definition Layer

Phase 3A defines controlled build rooms for the full cohort. The build room is not the substrate; the build room is the measuring chamber. Phase 3A does not execute builds, run containers, launch VMs, select a substrate, rank candidates, or generate a numeric WuciOS score.

## Commands

```sh
make wucios-euclid-trial-phase-2b
make wucios-euclid-trial-phase-2b-json
make wucios-euclid-probe-void
make wucios-euclid-probe-nixos
make wucios-euclid-probe-guix
make wucios-euclid-probe-yocto
make wucios-euclid-probe-openbsd-reference
```
