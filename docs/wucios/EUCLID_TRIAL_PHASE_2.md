# WuciOS v2.4 Euclid Trial Phase 2 — Build Feasibility Probes

## Purpose

Phase 2 tests build feasibility for Buildroot, Alpine, and Debian minimal. It
checks whether each candidate can move from protocol placeholders toward early
Noether Core-style build artifacts under identical reporting rules.

## Non-Selection Rule

Phase 2 cannot select a substrate. The output remains
`NO_SUBSTRATE_SELECTED` until comparable measured evidence exists.

## No Emotional Testing

Candidates are not judged by preference, reputation, aesthetics, familiarity,
or project loyalty. Candidates are judged only by comparable evidence.

## Execution Modes

`SAFE_DETECT_ONLY` is the default. It detects host tooling, checks for local
source or probe prerequisites, writes evidence files, and does not build,
install, clone, require root, or use network access.

Safe validation targets must not modify tracked files. Generated evidence with
timestamps is written to ignored `build/wucios/` outputs.

`EXPLICIT_BUILD_ATTEMPT` is opt-in. It requires `--attempt-builds` and
`WUCIOS_EUCLID_ALLOW_ATTEMPT=1`. Network-dependent commands also require
`--allow-network`. The probes do not call `sudo`.

## First Cohort

- Buildroot
- Alpine Linux
- Debian Minimal

## Candidate Evidence Files

Each candidate writes the same generated files under
`build/wucios/trials/<candidate>/phase-2/`:

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

## Combined Reports

- `build/wucios/review/euclid-trial-phase-2.md`
- `build/wucios/review/euclid-trial-phase-2.json`

## Runtime Measurements

Listening ports and loaded kernel modules require a booted runtime. In Phase 2,
they remain `NOT_MEASURED_RUNTIME_REQUIRED` unless a later runtime boot scan
exists.

## Score Boundary

Phase 2 does not generate a numeric WuciOS score unless artifact-bound score
requirements are satisfied.

## Commands

```sh
make wucios-euclid-trial-phase-2
make wucios-euclid-trial-phase-2-json
make wucios-euclid-probe-buildroot
make wucios-euclid-probe-alpine
make wucios-euclid-probe-debian-minimal
```

Attempt mode:

```sh
WUCIOS_EUCLID_ALLOW_ATTEMPT=1 make wucios-euclid-trial-phase-2-attempt
```

Attempt mode may use network access and is not part of default validation.
