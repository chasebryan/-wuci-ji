# WuciOS v2.4 Euclid Trial Phase 3C-A — Rootless Backend Smoke and Buildroom Preparation Guardrails

## Purpose

Phase 3C-A verifies rootless backend mechanics and controlled buildroom preparation guardrails using a tiny synthetic non-substrate smoke image.

## Authorized Scope

L1 backend detection is authorized by default for backend binary detection, backend info commands, readonly host checks, guardrail negative tests, and ignored report generation.

L2 synthetic buildroom preparation is authorized only when `WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1` is set and a smoke-specific target or `--l2-smoke` runner flag is used.

## Not Authorized

L3 substrate artifact attempts and L4 runtime inspection are not authorized. Phase 3C-A does not authorize substrate selection, candidate ranking, numeric WuciOS scoring, Yocto execution, Nix execution, Guix execution, OpenBSD runtime execution, or uncontrolled host mutation.

## Synthetic Smoke Boundary

The smoke image is not a WuciOS artifact, not a substrate artifact, and not score eligible. It exists only to test controlled backend mechanics and evidence capture.

## No Network / No Pull Boundary

The smoke context is generated locally under `build/wucios` and uses `FROM scratch`, `--pull=never`, and `--network=none` or the safest equivalent. No image pull is required or allowed.

## Backend Scope

Rootless Podman and rootless Buildah are allowed for the synthetic smoke. Docker is detection-only in this phase and must not be used for smoke image building.

## Guardrail Tests

Unauthorized L2 smoke and existing substrate attempt targets must refuse execution. The guardrail target must not run L2 smoke with authorization and must not build images.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3c-a.md`
- `build/wucios/review/euclid-trial-phase-3c-a.json`
- `build/wucios/buildrooms/synthetic-smoke/phase-3c-a/`

## Commands

```sh
make wucios-euclid-buildrooms-phase-3c-a
make wucios-euclid-buildrooms-phase-3c-a-json
make wucios-euclid-buildrooms-phase-3c-a-guardrails
WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 make wucios-euclid-buildrooms-phase-3c-a-smoke
WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1 make wucios-euclid-buildrooms-phase-3c-a-smoke-json
```

## Non-Selection Rule

Backend smoke success does not select or rank any substrate.

## Score Boundary

Phase 3C-A cannot produce a numeric WuciOS score.

## Phase 3C-B Boundary

Phase 3C-B follows Phase 3C-A by defining direct-rootfs preparation rules for Buildroot, Alpine, Debian minimal, and Void:
[EUCLID_TRIAL_PHASE_3C_B.md](EUCLID_TRIAL_PHASE_3C_B.md).

Phase 3C-B remains a policy and non-artifact scaffold layer. It does not authorize L3 substrate artifact attempts, L4 runtime inspection, substrate selection, candidate ranking, or numeric WuciOS scoring.
