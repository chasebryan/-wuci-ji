# Wuci-Ji / 无此机

Wuci-Ji is a defensive research repository for sealed artifacts, receipt-bound release checks, public evidence, and claim discipline.

It is local evidence only. It is not externally certified. It is not production authorized. It is not a general runtime sandbox. It is not post-quantum safe from classical-only evidence.

## Current Focus: WuciOS v2.4 Reduction Gate

WuciOS v2.4 is the current reduction-controlled design path. The larger v2.3 direction is retired. v2.4 is organized around Noether Core, Birkhoff Bastion, Tarski Review Appliance, and the Euclid Substrate Trial.

- [WuciOS v2.4 Reduction Gate](docs/wucios/WUCIOS_V24_REDUCTION_GATE.md)
- [Noether Core](docs/wucios/NOETHER_CORE.md)
- [Euclid Substrate Trial](docs/wucios/EUCLID_SUBSTRATE_TRIAL.md)
- [Euclid Trial Phase 1](docs/wucios/EUCLID_TRIAL_PHASE_1.md)
- [Euclid Trial Phase 2](docs/wucios/EUCLID_TRIAL_PHASE_2.md)
- [Euclid Trial Phase 2B](docs/wucios/EUCLID_TRIAL_PHASE_2B.md)
- [Tarski Review Appliance](docs/wucios/TARSKI_REVIEW_APPLIANCE.md)
- [Gödel Boundary](docs/wucios/GODEL_BOUNDARY.md)
- [Mathematician Naming Scheme](docs/wucios/MATHEMATICIAN_NAMING_SCHEME.md)

Validation commands:

```sh
make wucios-validate
make wucios-fluff-audit
make wucios-review
make wucios-substrate-matrix
make wucios-euclid-trial-phase-1
make wucios-euclid-trial-phase-2
```

Status: Local evidence only. Not externally certified. Not production authorized.

## WuciOS v2.4 Boundary

Noether Core is the serious base profile: TTY-first, GUI-free, network-minimized, evidence-bound, and substrate-neutral.

Birkhoff Bastion is optional operator shell material. Ratpoison and DWM are candidates only. They are not part of Noether Core.

Tarski Review Appliance generates the review packet. A WuciOS release is incomplete without this packet.

Euclid Substrate Trial compares Buildroot, Alpine, Debian minimal, Void, NixOS, Guix, Yocto, and OpenBSD reference. Void is one candidate only. No substrate is selected in this pass.

Euclid Trial Phase 1 prepares the first artifact cohort: Buildroot, Alpine, and Debian minimal. It standardizes comparable evidence outputs and reports `NO_SUBSTRATE_SELECTED` until generated trial data exists.

Euclid Trial Phase 2B expands safe detect-only build feasibility probes to the full original substrate candidate set: Buildroot, Alpine, Debian minimal, Void, NixOS, Guix, Yocto, and OpenBSD reference. It records tooling blockers and missing evidence without selecting or ranking a substrate.

Developer Desktop is non-authoritative convenience material. Xfce belongs there only if retained at all.

## Core Repository Surfaces

| Surface | Purpose |
| --- | --- |
| [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) | Existing Wuci-Ji security and non-claim boundary. |
| [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) | Existing production blockers and readiness limits. |
| [daylight-equation/](daylight-equation/) | Daylight equation, scorecard, fixtures, evidence, and analysis. |
| [wucios/](wucios/) | WuciOS v2.4 machine-readable profiles, substrates, budgets, sets, schemas, and component register. |
| [tools/wucios/](tools/wucios/) | WuciOS v2.4 validation, scan, matrix, inventory, and review-packet tools. |

## Current Non-Claims

Wuci-Ji and WuciOS v2.4 do not claim external certification, government approval, military approval, production authority, perfect security, unbreakability, runtime sandboxing, or quantum safety from classical-only signatures.

Every current claim must point to evidence, a command, a generated report, or a documented non-claim boundary.
