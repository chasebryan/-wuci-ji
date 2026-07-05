# WuciOS v2.4 Euclid Trial Phase 3B Readiness — Backend Remediation and Test Authorization Matrix

## Purpose

Phase 3B readiness identifies backend, input, policy, and resource blockers before controlled build-room execution.

## Not Execution

This phase does not build containers, run containers, launch VMs, install packages, clone sources, download images, produce artifacts, select substrates, rank candidates, or generate scores.

## Build Room Rule

The build room is not the substrate; the build room is the measuring chamber.

## X200 Boundary

The current X200 can be used for readiness testing and lightweight future experiments only if explicitly authorized. Heavy tests may be deferred to the T490 or another stronger controlled machine if resource/backend blockers remain.

This statement does not rank machines and does not make the X200 proof of artifact readiness.

## Full Candidate Cohort

- Buildroot
- Alpine
- Debian minimal
- Void
- NixOS
- Guix
- Yocto
- OpenBSD reference

## Readiness Classes

- `BACKEND_BLOCKED`: required backend tooling is absent, permission blocked, configuration blocked, or not currently usable.
- `INPUTS_BLOCKED`: local source trees, images, rootfs strategy inputs, or required input tooling are missing.
- `POLICY_BLOCKED`: future execution, host-store writes, runtime inspection, or acquisition policy is not authorized by this phase.
- `RESOURCE_BLOCKED`: local CPU, memory, disk, KVM, or runtime acceleration conditions block or require review before execution.
- `READY_FOR_FUTURE_CONTROLLED_ATTEMPT`: no local blocker was detected, but execution still requires a future authorization level.
- `REFERENCE_RUNTIME_BLOCKED`: the non-Linux reference runtime path requires future explicit runtime inspection policy.

## Test Authorization Levels

- `L0`: definition and readiness only. This is the only level authorized by default.
- `L1`: backend dry-run authorization. It requires future explicit authorization.
- `L2`: controlled buildroom image preparation. It requires future explicit authorization.
- `L3`: controlled substrate artifact attempt. It requires future explicit authorization.
- `L4`: runtime inspection. It requires future explicit authorization.

## Backend Remediation Boundary

Remediation requires human approval and is not performed by this phase. Phase 3B readiness detects blockers only and does not edit host configuration.

## Store-Aware Boundary

NixOS and Guix remain blocked until a host-store or isolated-store policy exists. Phase 3B readiness does not run store-mutating commands.

## Reference Runtime Boundary

OpenBSD reference requires a future explicit runtime/VM inspection plan. Phase 3B readiness does not launch a VM and does not inspect a runtime.

## Generated Outputs

- `build/wucios/review/euclid-trial-phase-3b-readiness.md`
- `build/wucios/review/euclid-trial-phase-3b-readiness.json`
- `build/wucios/buildrooms/<candidate>/phase-3b-readiness/`

## Commands

```sh
make wucios-euclid-buildrooms-phase-3b-readiness
make wucios-euclid-buildrooms-phase-3b-readiness-json
make buildroom-remediation-plan
make test-authorization-matrix
```

## Phase 3C-A Boundary

Phase 3C-A is the next controlled layer after Phase 3B readiness. It authorizes L1 backend detection by default and allows L2 synthetic non-substrate smoke only with explicit `WUCIOS_PHASE3CA_ALLOW_L2_SMOKE=1` authorization:
[EUCLID_TRIAL_PHASE_3C_A.md](EUCLID_TRIAL_PHASE_3C_A.md).

Phase 3C-A does not authorize L3 substrate artifact attempts, L4 runtime inspection, substrate selection, candidate ranking, or numeric WuciOS scoring.
