# WuciOS v2.4 Reduction Gate

## Decision

WuciOS v2.3 is retired as the expansion path. WuciOS v2.4 is the reduction path.

## Purpose

WuciOS v2.4 is a reduction-controlled, evidence-bound operating environment for Wuci-Ji, Daylight, Wuci-Prism, and high-assurance-oriented review.

## Not A General Desktop OS

WuciOS v2.4 is not attempting to ship a large consumer desktop OS. The serious base is a small, TTY-first, GUI-free, network-minimized profile.

## Profiles

- Noether Core
- Birkhoff Bastion
- Tarski Review Appliance
- Developer Desktop

## Substrate Neutrality

Void is one candidate only. The project will compare Buildroot, Alpine, Debian minimal, Void, NixOS, Guix, Yocto, and OpenBSD reference before selecting any final base.

Current measured trial substrate selection status: `SUBSTRATE_SELECTED: Alpine` for WuciOS v2.4 substrate trial scope only.

The first trial readiness plan is [EUCLID_SUBSTRATE_TRIAL_PLAN.md](EUCLID_SUBSTRATE_TRIAL_PLAN.md).
The first artifact cohort protocol is [EUCLID_TRIAL_PHASE_1.md](EUCLID_TRIAL_PHASE_1.md).
The build feasibility probe phase is [EUCLID_TRIAL_PHASE_2.md](EUCLID_TRIAL_PHASE_2.md).
The full-cohort probe expansion is [EUCLID_TRIAL_PHASE_2B.md](EUCLID_TRIAL_PHASE_2B.md).
The controlled build-room definition layer is [EUCLID_TRIAL_PHASE_3A.md](EUCLID_TRIAL_PHASE_3A.md).
The backend readiness and future authorization matrix is [EUCLID_TRIAL_PHASE_3B_READINESS.md](EUCLID_TRIAL_PHASE_3B_READINESS.md).
The rootless backend smoke guardrail layer is [EUCLID_TRIAL_PHASE_3C_A.md](EUCLID_TRIAL_PHASE_3C_A.md).
The direct-rootfs preparation policy layer is [EUCLID_TRIAL_PHASE_3C_B.md](EUCLID_TRIAL_PHASE_3C_B.md).
The NixOS/Guix store-root preparation policy layer is [EUCLID_TRIAL_PHASE_3C_C.md](EUCLID_TRIAL_PHASE_3C_C.md).
The Yocto layer/recipe preparation policy layer is [EUCLID_TRIAL_PHASE_3C_D.md](EUCLID_TRIAL_PHASE_3C_D.md).
The OpenBSD reference preparation policy layer is [EUCLID_TRIAL_PHASE_3C_E.md](EUCLID_TRIAL_PHASE_3C_E.md).

## Alpine Substrate Trial Status

WuciOS v2.4 Alpine Substrate Trial produced a bounded trial artifact under
`build/wucios/full-trial/alpine/` from an Alpine release minirootfs `3.24.1`
x86_64 input recorded in generated input evidence.

- Artifact SHA-256: `95f3cb750357eeb2cd840ddfc7b62c6addf08b2d66079871a4d8e8efdd9ae45f`
- Generated score evidence: `build/wucios/full-trial/alpine/wucios-alpine-substrate-trial-score.json` records `score_value: 96.0`
- Selection decision: `SUBSTRATE_SELECTED: Alpine`
- Selection scope: WuciOS v2.4 substrate trial
- Artifact eligibility: trial artifact only
- External validation: `NO`
- Production readiness: `NO`
- Runtime validation: `NO`

The generated score evidence records that the earlier Daylight Candidate
Readiness Score was not reused as an artifact/security score.

## Runtime Validation Status Preservation

Runtime Gates 5 through 9 are summarized in [v2.4/runtime-validation-status.md](v2.4/runtime-validation-status.md). Latest completed runtime gate: `RUNTIME_GATE_10_RUNTIME_STATUS_PRESERVATION_DECISION_PUSHED`. Gate 10 is a preservation/status commit, not a runtime test. The raw runtime evidence remains local/ignored unless separately authorized. No full runtime validation, bootability, production readiness, external validation, complete hardening, complete network security, or broad runtime safety claim is made.

## Evidence Requirement

WuciOS is incomplete without a generated review packet. A bootable image alone is not a release. The review packet must include artifact manifests, surface inventory, claim boundaries, score material, and `NOT_MEASURED` for missing data.

## Non-Claims

See [GODEL_BOUNDARY.md](GODEL_BOUNDARY.md).

## Validation Commands

```sh
make wucios-validate
make wucios-fluff-audit
make wucios-review
make wucios-substrate-matrix
make wucios-euclid-trial-phase-1
make wucios-euclid-trial-phase-2
make wucios-euclid-trial-phase-2b
make wucios-euclid-buildrooms-phase-3a
make wucios-euclid-buildrooms-phase-3b-readiness
make wucios-euclid-buildrooms-phase-3c-a
make wucios-euclid-buildrooms-phase-3c-a-guardrails
make wucios-euclid-direct-rootfs-phase-3c-b
make wucios-euclid-direct-rootfs-phase-3c-b-guardrails
make wucios-euclid-store-root-phase-3c-c
make wucios-euclid-store-root-phase-3c-c-guardrails
make wucios-euclid-yocto-phase-3c-d
make wucios-euclid-yocto-phase-3c-d-guardrails
make wucios-euclid-openbsd-reference-phase-3c-e
make wucios-euclid-openbsd-reference-phase-3c-e-guardrails
```

## Controlling Doctrine

1. Nothing enters Noether Core unless it boots the system, protects the system, verifies the system, explains the system, or produces reviewer evidence.
2. GUI components are forbidden in Noether Core.
3. Browsers, media players, office tools, large icon themes, wallpaper packs, casual desktop packages, and general user-app bundles are forbidden in Noether Core.
4. Default network services are forbidden in Noether Core unless explicitly justified in the component register and accepted by the Boole Gate.
5. Any listening port in Noether Core is a failure unless explicitly allowed by a current profile rule.
6. Compilers, development headers, and general build toolchains are forbidden in the runtime Noether Core image unless explicitly justified. Build tools belong in build environments, not in the runtime image.
7. Ratpoison is only a Birkhoff Bastion candidate. It is not automatically accepted.
8. DWM is only a Birkhoff Bastion candidate. Because it introduces owned C attack surface if patched or vendored, it must pass a stricter acceptance gate before use.
9. Xfce must not be part of Noether Core. If retained, it belongs only in a non-authoritative Developer Desktop profile.
10. Void Linux must not be treated as the chosen base. It is one substrate candidate.
11. The authoritative WuciOS v2.4 output is not only a bootable image. The release is incomplete unless it produces an evidence packet.
12. A Daylight/WuciOS score is invalid unless generated from the current artifact or explicitly marked `DIAGNOSTIC_ONLY`.
13. No hand-written score is authoritative.
14. No document may claim external certification, military approval, government approval, perfect security, unbreakability, or production authority.
15. Every current claim must point to evidence, a command, a generated report, or a documented non-claim boundary.
16. The build room is not the substrate; the build room is the measuring chamber.
17. A Phase 3C-A synthetic smoke image is not a WuciOS artifact, not a substrate artifact, and not score eligible.
18. Phase 3C-B direct-rootfs preparation rules do not generate rootfs images, select a substrate, rank candidates, or generate a numeric WuciOS score.
19. Phase 3C-C NixOS/Guix store-root preparation rules do not realize store paths, build NixOS or Guix systems, select a substrate, rank candidates, generate artifact hashes, or generate a numeric WuciOS score.
20. Phase 3C-D Yocto layer/recipe preparation rules do not run BitBake, initialize a Yocto build environment, clone or download Yocto sources or layers, generate rootfs or image outputs, select a substrate, rank candidates, generate artifact hashes, or generate a numeric WuciOS score.
21. Phase 3C-E OpenBSD reference preparation rules do not install, boot, inspect runtime behavior, run package/admin commands, clone source trees, download ports trees or install media, launch VMs, select a substrate, rank candidates, generate artifact hashes, or generate a numeric WuciOS score.
22. Phase 3C is closed at `origin/wucios-v24-reduction-gate` commit `0f06b62`; no next implementation phase is authorized or inferred by this closeout.
23. The Alpine substrate trial decision is scoped to WuciOS v2.4 substrate trial evidence. It does not claim production readiness, external validation, runtime validation, or broader substrate certification.
