# WuciOS v2.4 Euclid Trial Phase 3C-D — Yocto Layer/Recipe Preparation

## Purpose

Phase 3C-D defines controlled preparation rules for Yocto as a build-system, metadata-layer, recipe, configuration, and image-construction candidate. It records policy, schema, guardrail, and non-artifact scaffold requirements before any future Yocto artifact attempt is considered.

## In Scope

- Yocto layer/recipe preparation only.

## Out Of Scope But Preserved

- Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs candidates.
- NixOS and Guix remain Phase 3C-C store-root candidates.
- OpenBSD reference remains deferred to Phase 3C-E Reference Runtime Policy.

## Yocto Preparation Concept

Yocto preparation is not ordinary rootfs generation and is not store-root realization. It requires policy for metadata layers, recipes, machine configuration, distro configuration, image targets, source mirrors, SDK or toolchain boundaries, and build output evidence before any future attempt can be considered.

## Direct-Rootfs And Store-Root Separation

Direct-rootfs assumptions from Phase 3C-B are insufficient because Yocto image construction is driven by metadata, recipes, layers, machine configuration, and BitBake task graphs rather than a single direct package-manager rootfs command. Store-root assumptions from Phase 3C-C are insufficient because Yocto does not use a Nix or Guix declarative store-root model. Phase 3C-D may reference earlier phases only for read-only cross-phase status reporting.

## Metadata, Scaffold, Build, And Artifact Boundaries

Metadata preparation records the policies and manifests that a future Yocto attempt would need. Layer/recipe scaffold generation writes review placeholders only under `build/wucios/`. BitBake execution initializes and runs Yocto build tasks. Build-environment initialization prepares an actual Yocto build directory. Rootfs or image generation creates build output. Artifact generation creates WuciOS substrate evidence. Phase 3C-D authorizes only policy validation and optional non-artifact scaffolding.

## Authorized Scope

L1 policy validation is authorized by default. L1 may read Phase 3C-D policy files, validate schemas, report candidate status, detect missing Yocto preparation inputs, run forbidden-command guardrail checks, and write ignored review reports under `build/wucios/`.

L2 non-artifact scaffold generation is authorized only with `WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag. L2 scaffold files must remain non-executable, non-artifact, not score eligible, Yocto-build forbidden, BitBake forbidden, and marked as requiring future L3 authorization.

## Not Authorized

L3 substrate artifact attempts and L4 runtime inspection are not authorized. Phase 3C-D does not run `bitbake`, `oe-init-build-env`, `devtool`, `kas`, `repo init`, `repo sync`, clone Yocto or layer sources, download layers, recipes, SDKs, toolchains, images, or source mirrors, initialize a build environment, generate rootfs or image outputs, run containers, pull images, launch VMs, install packages, select a substrate, rank candidates, generate artifact hashes, or generate numeric WuciOS scores.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## Future Evidence Requirements

Future L3 Yocto attempts require metadata input manifests, layer identity records, recipe identity records, machine and distro configuration records, source mirror policy, build command records, build environment records, BitBake log records, artifact manifests, artifact hashes, package manifests, image size records, Noether static checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.

## Guardrails

Phase 3C-D guardrails require unauthorized L2 scaffold refusal, existing Phase 2 attempt refusal, Phase 3C-C unauthorized scaffold refusal, and safe-path scans for forbidden Yocto, container, VM, package-manager, network-download, source-clone, rootfs, image, artifact, and scoring execution forms.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3c-d.md`
- `build/wucios/review/euclid-trial-phase-3c-d.json`
- `build/wucios/buildrooms/yocto-layer/<candidate>/phase-3c-d/`

## Commands

- `make wucios-euclid-yocto-phase-3c-d`
- `make wucios-euclid-yocto-phase-3c-d-json`
- `make wucios-euclid-yocto-phase-3c-d-guardrails`
- `WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-yocto-phase-3c-d-scaffold`
- `WUCIOS_PHASE3CD_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-yocto-phase-3c-d-scaffold-json`

## Non-Selection Rule

Yocto preparation readiness does not select or rank any substrate.

## Score Boundary

Phase 3C-D cannot produce a numeric WuciOS score. It does not create a WuciOS artifact, artifact hash, rootfs, image, SDK, Yocto build output, or score-eligible evidence.
