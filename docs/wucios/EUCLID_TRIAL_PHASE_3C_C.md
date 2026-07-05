# WuciOS v2.4 Euclid Trial Phase 3C-C — NixOS/Guix Store-Root Preparation

## Purpose

Phase 3C-C defines controlled preparation rules for NixOS and Guix as store-rooted, declarative-system candidates. It records policy, schema, guardrail, and non-artifact scaffold requirements before any future store-rooted artifact attempt is considered.

## In Scope

- NixOS store-root preparation.
- Guix store-root preparation.

## Out Of Scope But Preserved

- Buildroot, Alpine, Debian minimal, and Void remain Phase 3C-B direct-rootfs candidates.
- Yocto remains deferred to Phase 3C-D Heavy Source Buildroom Policy.
- OpenBSD reference remains deferred to Phase 3C-E Reference Runtime Policy.

## Store-Root Preparation Concept

NixOS and Guix are not ordinary direct-rootfs candidates. Their system definitions are tied to store-rooted, declarative inputs, channel or flake identity, store realization policy, and activation boundaries. Phase 3C-C therefore separates declarative-input preparation from direct-rootfs command assumptions.

## Rootfs, Store, Input, And Scaffold Boundaries

Rootfs generation creates a filesystem image or archive. Store realization creates or materializes Nix or Guix store paths. Declarative input preparation records the policies and manifests that a future store-rooted attempt would need. Non-artifact scaffold generation writes review placeholders only under `build/wucios/` and does not evaluate, build, realize, activate, run, or score anything.

## Authorized Scope

L1 policy validation is authorized by default. L1 may read Phase 3C-C policy files, validate schemas, report candidate status, detect missing declarative inputs, and write ignored review reports under `build/wucios/`.

L2 non-artifact scaffold generation is authorized only with `WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1` and an explicit scaffold target or runner flag. L2 scaffold files must remain non-executable, non-artifact, not score eligible, store-realization forbidden, and marked as requiring future L3 authorization.

## Not Authorized

L3 substrate artifact attempts and L4 runtime inspection are not authorized. Phase 3C-C does not run `nix-build`, `nixos-rebuild`, `nix develop`, `nix shell`, `nix flake check`, `guix build`, `guix system`, `guix shell`, `guix environment`, `guix pull`, store realization, derivation builds, package builds, system activation, rootfs generation, container builds, container runs, image pulls, network fetches, VM launches, package installation, source cloning, OS image downloads, substrate selection, candidate ranking, or numeric WuciOS scoring.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## Direct-Rootfs Separation

Direct-rootfs assumptions from Phase 3C-B are insufficient for NixOS and Guix because store identity, declarative inputs, channels or flakes, and store realization policy must be controlled before any artifact attempt can be considered. Phase 3C-C may reference Phase 3C-B only for read-only cross-phase status reporting.

## Declarative Input Rules

Future L3 work must define pinned declarative inputs, store policy, source identity, channel or flake identity, cache policy, output paths, and evidence hooks before any store realization or artifact generation is considered.

## Future Evidence Requirements

Future L3 store-root attempts require declarative input manifests, store policy records, source or channel identity, build command records, environment records, store realization logs, artifact manifests, artifact hash records, package or closure manifests, Noether static checks, Godel boundary notes, substrate reports, failure reports, and missing-measurement records. Runtime-only measurements remain `NOT_MEASURED_RUNTIME_REQUIRED` until runtime inspection is explicitly authorized.

## Guardrails

Phase 3C-C guardrails require unauthorized L2 scaffold refusal, existing Phase 2 attempt refusal, Phase 3C-B unauthorized scaffold refusal, and safe-path scans for forbidden Nix, Guix, container, VM, package-manager, network-download, and source-clone execution forms.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3c-c.md`
- `build/wucios/review/euclid-trial-phase-3c-c.json`
- `build/wucios/buildrooms/store-root/<candidate>/phase-3c-c/`

## Commands

- `make wucios-euclid-store-root-phase-3c-c`
- `make wucios-euclid-store-root-phase-3c-c-json`
- `make wucios-euclid-store-root-phase-3c-c-guardrails`
- `WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-store-root-phase-3c-c-scaffold`
- `WUCIOS_PHASE3CC_ALLOW_L2_SCAFFOLD=1 make wucios-euclid-store-root-phase-3c-c-scaffold-json`

## Non-Selection Rule

Store-root preparation readiness does not select or rank any substrate.

## Score Boundary

Phase 3C-C cannot produce a numeric WuciOS score. It does not create a WuciOS artifact, artifact hash, or score-eligible evidence.

## Phase 3C-D Boundary

Phase 3C-D follows Phase 3C-C by defining Yocto layer/recipe preparation rules. Phase 3C-D must not reuse store-root assumptions without explicit policy justification. It does not authorize L3 substrate artifact attempts, L4 runtime inspection, BitBake execution, Yocto build-environment initialization, Yocto source or layer acquisition, rootfs generation, image generation, substrate selection, candidate ranking, artifact hashes, or numeric WuciOS scoring.
