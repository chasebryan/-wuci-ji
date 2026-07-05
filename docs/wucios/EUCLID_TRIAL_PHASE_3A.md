# WuciOS v2.4 Euclid Trial Phase 3A — Controlled Build Room Definitions

## Purpose

Phase 3A defines controlled build rooms for the full substrate cohort. It adds tracked build-room definitions, backend policy, schemas, and safe readiness reporting for all eight candidates.

## Not An Artifact Build

Phase 3A does not build containers, run containers, launch VMs, produce WuciOS artifacts, select substrates, rank candidates, or generate a numeric score.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## Full Candidate Cohort

- Buildroot
- Alpine
- Debian minimal
- Void
- NixOS
- Guix
- Yocto
- OpenBSD reference

## Execution Classes

- Direct rootfs/image build rooms: Buildroot, Alpine, Debian minimal, Void
- Store-aware build rooms: NixOS, Guix
- Heavy source/build-system room: Yocto
- Reference runtime room: OpenBSD reference

## Backend Detection

Phase 3A detects Docker, Podman, Buildah, Nix, Guix, QEMU, and KVM readiness without executing build rooms. Detection is limited to binary presence, safe version or info probes where applicable, and `/dev/kvm` presence.

Backend detection failure is recorded as readiness evidence. It does not select or reject a substrate.

## Host Mutation Boundary

No sudo, no package installation, no source cloning, no image downloads, no host-store writes, no container pulls, no container builds, no container runs, and no VM launches occur by default.

## Store-Aware Boundary

NixOS and Guix require a future explicit host-store or isolated-store policy. Phase 3A records that blocker and does not run `nix build`, `guix system`, or store-mutating commands.

## Reference Runtime Boundary

OpenBSD is a non-Linux reference runtime path and requires a future explicit runtime/VM inspection plan. Phase 3A does not launch QEMU and does not measure an OpenBSD runtime.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3a.md`
- `build/wucios/review/euclid-trial-phase-3a.json`
- `build/wucios/buildrooms/<candidate>/phase-3a/`

## Phase 3B Readiness

Phase 3B readiness adds backend remediation diagnostics and a future test authorization matrix without executing build rooms:
[EUCLID_TRIAL_PHASE_3B_READINESS.md](EUCLID_TRIAL_PHASE_3B_READINESS.md).

## Commands

```sh
make wucios-euclid-buildrooms-phase-3a
make wucios-euclid-buildrooms-phase-3a-json
make buildroom-readiness
make wucios-euclid-buildrooms-phase-3b-readiness
```
