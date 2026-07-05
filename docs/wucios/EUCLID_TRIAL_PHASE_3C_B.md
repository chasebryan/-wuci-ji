# WuciOS v2.4 Euclid Trial Phase 3C-B — Direct Rootfs Buildroom Preparation

## Purpose

Phase 3C-B defines controlled preparation rules for the direct-rootfs group. It records policy, command-shape, cache, output, and evidence requirements before any future direct-rootfs artifact attempt is considered.

## In Scope

- Buildroot
- Alpine
- Debian minimal
- Void

## Out Of Scope But Preserved

- NixOS and Guix -> Phase 3C-C Store-Aware Buildroom Policy
- Yocto -> Phase 3C-D Heavy Source Buildroom Policy
- OpenBSD reference -> Phase 3C-E Reference Runtime Policy

## Not An Artifact Attempt

Phase 3C-B does not generate rootfs images or substrate artifacts. Candidate command shapes are policy records only and are not executed in this phase.

## Authorized Scope

L1 policy validation is authorized by default. L1 may read policy files, detect backend and helper-tool availability, validate future command shapes as non-executable policy, and generate ignored review reports under `build/wucios/`.

L2 non-artifact scaffolding is authorized only when `WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1` is present and the scaffold target or `--l2-scaffold` runner flag is used. L2 scaffolding may create candidate preparation directories and placeholder manifests under `build/wucios/` only.

## Not Authorized

L3 substrate artifact attempts and L4 runtime inspection are not authorized. Phase 3C-B does not run rootfs generation, container builds, container runs, image pulls, networked builds, VM launches, package installation, source cloning, OS image downloads, substrate selection, candidate ranking, or numeric WuciOS scoring.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## Pull / Pinning / Cache / Output Rules

Phase 3C-B allows no image pulls, network use, substrate source downloads, or OS image downloads. Future L3 work must pin images by digest if images are used, record local source-tree identity if a local source tree is used, record package repository configuration if package repositories are used, keep caches under `build/wucios/cache/` unless a later policy overrides that, and write artifacts, logs, manifests, and hashes under `build/wucios/`.

## Future Command Shapes

Future command shapes are policy-only records. They describe what a future L3 attempt would need to control, but Phase 3C-B does not execute them.

## Future Evidence Requirements

Future L3 attempts must emit artifact manifests, hashes, build logs, build commands, build environment records, source policy, package manifests, size records, static Noether checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records before any artifact-bound score can be considered. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.

## Guardrails

Guardrail checks require unauthorized L2 scaffold refusal, existing Phase 2 attempt refusal, Phase 3C-A smoke refusal without its authorization, and a scan for default-path execution commands that would cross into rootfs generation, container builds or runs, image pulls, VM execution, source cloning, package installation, or scoring.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3c-b.md`
- `build/wucios/review/euclid-trial-phase-3c-b.json`
- `build/wucios/buildrooms/direct-rootfs/<candidate>/phase-3c-b/`

## Commands

- `make wucios-euclid-direct-rootfs-phase-3c-b`
- `make wucios-euclid-direct-rootfs-phase-3c-b-json`
- `make wucios-euclid-direct-rootfs-phase-3c-b-guardrails`
- `WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-direct-rootfs-phase-3c-b-scaffold`
- `WUCIOS_PHASE3CB_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-direct-rootfs-phase-3c-b-scaffold-json`

## Non-Selection Rule

Preparation readiness does not select or rank any substrate.

## Score Boundary

Phase 3C-B cannot produce a numeric WuciOS score.

## Phase 3C-C Boundary

Phase 3C-C follows Phase 3C-B by defining NixOS/Guix store-root preparation rules. Phase 3C-C must not reuse direct-rootfs assumptions without explicit policy justification. It does not authorize L3 substrate artifact attempts, L4 runtime inspection, store realization, substrate selection, candidate ranking, artifact hashes, or numeric WuciOS scoring.
