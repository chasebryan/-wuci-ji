# WuciOS v2.4 Euclid Trial Phase 3C-E — OpenBSD Reference Preparation

## Purpose

Phase 3C-E defines controlled preparation rules for OpenBSD as a reference operating-system baseline. It records policy, schema, guardrail, and non-artifact scaffold requirements before any future OpenBSD reference action is considered.

## In Scope

- OpenBSD reference preparation only.

## Out Of Scope But Preserved

- Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs candidates.
- NixOS and Guix remain Phase 3C-C store-root candidates.
- Yocto remains the Phase 3C-D layer/recipe preparation candidate.

## Reference Preparation Concept

OpenBSD reference preparation records the policies and manifests required to discuss OpenBSD as a reference baseline. It is not substrate selection, runtime validation, artifact eligibility, package operation, install media acquisition, source checkout, VM boot, rootfs generation, or image generation.

## Direct-Rootfs, Store-Root, And Yocto Separation

Direct-rootfs assumptions from Phase 3C-B are insufficient because OpenBSD reference preparation is not a Linux rootfs package-manager operation. Store-root assumptions from Phase 3C-C are insufficient because OpenBSD does not use a Nix or Guix declarative store-root model. Yocto layer and recipe assumptions from Phase 3C-D are insufficient because OpenBSD reference preparation is not BitBake-driven metadata or image construction. Phase 3C-E may reference earlier phases only for read-only cross-phase status reporting.

## Reference, Scaffold, Runtime, And Artifact Boundaries

Reference preparation records policy and manifests. Reference scaffold generation writes review placeholders only under `build/wucios/`. Runtime validation boots or inspects an operating system. Package/admin operation changes or queries an OpenBSD system. Source/media acquisition downloads or clones OpenBSD material. VM boot launches a runtime environment. Rootfs or image generation creates build output. Artifact generation creates WuciOS substrate evidence. Phase 3C-E authorizes only policy validation and optional non-artifact scaffolding.

## Authorized Scope

L1 policy validation is authorized by default. L1 may read Phase 3C-E policy files, validate schemas, report reference status, detect missing OpenBSD reference inputs, run forbidden-command guardrail checks, and write ignored review reports under `build/wucios/`.

L2 non-artifact scaffold generation is authorized only with `WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag. L2 scaffold files must remain non-executable, non-artifact, not score eligible, OpenBSD runtime forbidden, OpenBSD install forbidden, OpenBSD download forbidden, substrate-selection forbidden, and marked as requiring future L3 authorization.

## Not Authorized

L3 substrate artifact attempts and L4 runtime inspection are not authorized. Phase 3C-E does not boot OpenBSD, install OpenBSD, inspect OpenBSD runtime behavior, run `pkg_add`, `pkg_info`, `syspatch`, `sysupgrade`, `fw_update`, `rcctl`, `doas`, `mount`, `disklabel`, `installboot`, or `sysctl`, clone OpenBSD source trees, download OpenBSD install media, sets, packages, ports trees, snapshots, signatures, source archives, or mirrors, launch VMs, run containers, pull images, install packages, generate rootfs or image outputs, select a substrate, rank candidates, generate artifact hashes, or generate numeric WuciOS scores.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## Future Evidence Requirements

Future L3/L4 movement requires OpenBSD reference input manifests, media/source acquisition policy, runtime authorization policy, command records, environment records, reference manifest records, artifact manifests, artifact hashes, package manifests, surface records, static Noether checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.

## Guardrails

Phase 3C-E guardrails require unauthorized L2 scaffold refusal, existing Phase 2 attempt refusal, Phase 3C-D unauthorized scaffold refusal, and safe-path scans for forbidden OpenBSD, VM, hypervisor, container, package-manager, network-download, source-clone, rootfs, image, artifact, and scoring execution forms.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3c-e.md`
- `build/wucios/review/euclid-trial-phase-3c-e.json`
- `build/wucios/buildrooms/openbsd-reference/<reference>/phase-3c-e/`

## Commands

- `make wucios-euclid-openbsd-reference-phase-3c-e`
- `make wucios-euclid-openbsd-reference-phase-3c-e-json`
- `make wucios-euclid-openbsd-reference-phase-3c-e-guardrails`
- `WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-openbsd-reference-phase-3c-e-scaffold`
- `WUCIOS_PHASE3CE_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-openbsd-reference-phase-3c-e-scaffold-json`

## Non-Selection Rule

OpenBSD reference preparation readiness does not select or rank any substrate.

## Score Boundary

Phase 3C-E cannot produce a numeric WuciOS score. It does not create a WuciOS artifact, artifact hash, rootfs, image, VM, OpenBSD installation, OpenBSD runtime result, package result, source checkout, media download, or score-eligible evidence.
