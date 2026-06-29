<img width="2172" height="724" alt="wsj-banner-github" src="https://github.com/user-attachments/assets/3e20bf66-1376-46b0-9f25-0ec619bf7224" />

# Wuci-Ji / 无此机

<p align="center">
  <strong>Sealed artifacts. Receipt-bound release. Public evidence.</strong><br>
  A defensive x86_64 assembly research machine for turning security claims into
  deterministic proof lanes.
</p>

> [!IMPORTANT]
> Wuci-Ji is a research/proof artifact. It is not production cryptography, not a
> general runtime sandbox, not post-quantum secure, not production authority,
> and not independently audited.

## What This Is

Wuci-Ji explores a narrow question: can a small artifact machine make its own
security claims executable, reviewable, and hard to overstate?

The repository composes sealed WJSEAL artifacts, authorization receipts, Gate
open/release checks, public witness bundles, ledger history, signed local
installation evidence, and Daylight protocol-state evidence into one inspectable
research system.

| It aims to prove | It refuses to claim |
| --- | --- |
| Artifact bytes were sealed, warranted, checked, and surfaced through explicit proof lanes. | Production cryptography, production authority, or independent audit status. |
| Public evidence bundles exclude private material and can be committed into deterministic history. | General OS containment or runtime sandboxing from CAGE/Witness/Gate alone. |
| Quantum-risk labels and migration debt are explicit. | Quantum safety from classical signatures or placeholder post-quantum stubs. |
| Install proof reads signed local manifests and a copied local root key. | Remote install authority, remote-code shell pipelines, or fixture authority as production trust. |

## Read First

| Need | Entry point |
| --- | --- |
| Current handoff checkpoint | [BUILD_NOTES.md](BUILD_NOTES.md) |
| Exact claim boundary | [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) |
| Fresh-machine continuation | [docs/MACHINE_PASSOFF.md](docs/MACHINE_PASSOFF.md) |
| Proof and test targets | [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) |
| Threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Production blockers | [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) |
| Daylight workspace | [daylight-equation/](daylight-equation/) |

## System Shape

```text
sealed artifact
      |
authorization receipt
      |
Gate contract check
      |
controlled plaintext release
      |
public witness bundle
      |
ledger history + Daylight review boundary
```

| Surface | Role | Boundary |
| --- | --- | --- |
| Envelope | WJSEAL artifact sealing/opening through the current assembly path. | Secrecy and final-output safety are assembly-owned. |
| Warrant | Deterministic fixture quorum receipt for review workflows. | Fixture authority only. |
| Gate / Root / Anchor | Flat and rooted contract checks for open/release, plus fail-closed publish/trust decision evidence. | Positive publish/trust authority remains unimplemented; denial evidence is not production authority. |
| Witness | Public, keyless release evidence bundle. | Excludes private keys, plaintext binaries, and private transcripts. |
| Ledger | Hash-only transparency history for witness bundles. | Local deterministic history, not an operated public log service. |
| HARDEN | Verifier identity, safe I/O, fixture quarantine, action policy, and public-file hardening. | Defensive perimeter checks only. |
| CAGE | Artifact legitimacy airlock around public evidence. | Not OS runtime containment. |
| QCAGE | Quantum-aware evidence labels, digest vectors, and migration-debt checks. | Not a post-quantum safety claim. |
| INSTALL | Noninteractive signed local install proof lane. | Requires a local copied root key and signed manifests. |
| WJ-next / Golden Lock | Composition models for transcript and review boundaries. | Model gates, not production cryptography. |
| Daylight | Typed protocol-state, score boundary, evidence, and Rust review lanes. | Research evidence, not external certification. |

## Quick Orientation

From macOS or another non-Linux host, these targets give a fast local read of
the current project shape:

```sh
make build-linux
make machine-passoff-test
make wuci-daylight-bridge-test
make wjnext-model-test
```

Native `make test` requires Linux x86_64 with GNU `as`/`ld`. The full native
lane also expects the current assembly X25519 BMI2/AVX instruction surface. See
[docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) for Linux, qemu, Daylight, Gate,
CAGE, QCAGE, HARDEN, INSTALL, and high-attestation lanes.

## Command Deck

Run shared build/proof lanes serially unless the Make target already composes
the dependencies.

Build the Linux artifact:

```sh
make build-linux
```

Run the core Daylight/WUCI bridge:

```sh
make wuci-daylight-bridge-test
```

Run Daylight protocol-state and cap-removal checks:

```sh
make daylight-v06-protocol-state-test
make daylight-v06-cap-removal-test
```

Run Gate proof lanes:

```sh
make gate-boundary
make gate-workflow
make gate-policy-matrix
make gate-receipt-contract
make gate-contract-asm
make gate-contract-zig
```

Inspect sealed WJSEAL artifacts without keys or plaintext release:

```sh
tools/wuci-prism inspect sealed.wj
tools/wuci-prism inspect sealed.wj --json
tools/wuci-prism manifest sealed.wj
tools/wuci-prism explain sealed.wj
tools/wuci-prism boundary sealed.wj
tools/wuci-prism inspect sealed.wj --ticker always
```

Wuci-Prism emits `wuci-prism-report-v1` public evidence for visible WJSEAL
structure, artifact hashes, and Gate-required status. It does not decrypt,
unlock, recover, accept secret keys, verify AEAD tags, or release plaintext.
The progress ticker is a stderr-only rainbow triangle display; it is automatic
on interactive terminals, can be forced with `--ticker always` or
`WUCI_TICKER=always`, and can be disabled with `--ticker never`. It stays out
of JSON and manifest stdout. The same ticker switch is available on key Python
wait lanes for Gate, CAGE, QCAGE, parser corpus replay, and INSTALL hashing or
proof subprocess stages.

Run defensive perimeter proof lanes:

```sh
make harden0-proof
make harden-proof
make cage-proof
make qcage-proof
```

Run the signed local install proof lane from a checked-out release:

```sh
make install-local
```

This single command copies the repository install root key into the local trust
path, verifies the signed install manifest and binary digest vector, installs
to `$HOME/.local`, and runs the install audit.

Build local self-release evidence:

```sh
make self-release-bundle
make self-release-witness-bundle
make self-release-ledger-bundle
```

Run the composed high-attestation lane:

```sh
make high-attestation-proof
```

High-attestation output is local evidence strengthening only. It is not a claim
of general runtime sandboxing, production authority, quantum safety, government
validation, or absence of vulnerabilities.

Run NOXFRAME:

```sh
make noxframe-launch
```

`WUCI-NOXFRAME` boots through a Wuci-Ji Systems splash, asks whether to boot the
Wuci-Ji substrate, and uses an animated full-screen boot frame while waiting for
that answer on real TTYs. It then clears into a bounded operator console in
interactive terminals. Use `tools/wuci-noxframe --no-console` to run the launch
matrix directly.

The console carries Phase1-style discovery commands: `help --compact`,
`man <command>`, `complete <prefix>`, and `capabilities`. It implements local
substrate, virtual filesystem, text, process, system, history, and session
commands while keeping host/network passthrough routes non-executing by
default. The `codex` command is the explicit opt-in bridge: `codex status` and
`codex handoff` are metadata-only. Start the console with:

```sh
tools/wuci-noxframe --console --allow-codex
```

Then use `codex start`, `codex exec <prompt>`, or `codex resume` with Codex
pinned to this checkout. That bridge uses Codex's own host/API configuration
and is not a NOXFRAME no-network or runtime-containment claim.

By default, it uses its local 7-day clock. It boots in quick mode between
weekly checks, then runs the full proof matrix when the clock is due. The full
matrix covers Wuci-Ji, Wuci-Prism, Daylight, Nightlight, Gate, HARDEN, CAGE,
QCAGE, install verification, release-bundle verification, and high-attestation
lanes. It writes a readable launch report and SHA-256/SHA-384/SHA-512 self-seal
to [docs/noxframe/](docs/noxframe/), with substrate state and seal files under
`build/noxframe/`. `wuci-black-ice` remains a compatibility alias for the
working-title boot lander.

## Daylight

Daylight lives in [daylight-equation/](daylight-equation/). It keeps Wuci-Ji's
active WJSEAL surface in place while adding typed protocol-state and
claim-boundary evidence around it.

| Entry point | Purpose |
| --- | --- |
| [daylight-equation/README.md](daylight-equation/README.md) | Directory map and working rules. |
| [daylight-equation/SCORECARD.md](daylight-equation/SCORECARD.md) | Repo-owned research scorecard and hard gates. |
| [daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.md](daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.md) | 10,000-point review model. |
| [daylight-equation/analysis/daylight-v06-written-code-protocol-state.md](daylight-equation/analysis/daylight-v06-written-code-protocol-state.md) | Written-code Daylight v0.6 protocol-state boundary. |
| [daylight-equation/research/daylight-v06-cap-removal-plan.md](daylight-equation/research/daylight-v06-cap-removal-plan.md) | Fail-closed plan for clearing the current 8250/10000 hard caps. |
| [daylight-equation/research/daylight-v06-m4-z3-proof.md](daylight-equation/research/daylight-v06-m4-z3-proof.md) | Mechanized predicate proof. |
| [daylight-equation/evidence/README.md](daylight-equation/evidence/README.md) | Machine-readable evidence bundles. |
| [daylight-equation/fixtures/README.md](daylight-equation/fixtures/README.md) | Fixture boundaries. |
| [daylight-equation/rust/daylight-model/README.md](daylight-equation/rust/daylight-model/README.md) | Std-only Rust model crate. |
| [daylight-equation/rust/daylight-crypto/README.md](daylight-equation/rust/daylight-crypto/README.md) | Pinned Rust crypto and WUCI-DAYLIGHT bridge lane. |

The WUCI-DAYLIGHT bridge classifies WJSEAL v1/v2/v3 envelope bytes, records the
current 8250/10000 Daylight research boundary, keeps zero-claim fields at zero,
and requires WUCI-GATE for plaintext release.

After generating the disposable Gate demo artifact:

```sh
make gate-demo
make wuci-daylight-bridge-test
cd daylight-equation/rust/daylight-crypto
cargo run --offline -- wuci-daylight-envelope-boundary --file ../../../build/wuci-gate-demo/sealed.wj
```

The bridge does not decrypt, accept keys, verify AEAD tags, replace Gate, add
production authority, prove runtime containment, or prove whole-system
post-quantum safety.

## Safety Boundaries

This repository is defensive and proof-oriented. Do not use it to add exploit
generation, vulnerability reproduction, offensive scanning, jailbreak
harnesses, malware logic, or network attack logic.

Current hard boundaries:

- Fixture FROST material is test evidence only, not production authority.
- CAGE verifies artifact legitimacy; it does not enforce OS containment.
- QCAGE labels quantum risk; it does not make classical signatures quantum-safe.
- INSTALL requires a local copied root key and signed manifests; it is not a
  remote install pipeline.
- Daylight scoring and protocol-state evidence are research review artifacts,
  not external certification.

The exact boundary text is maintained in
[docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md).

## Repository Map

```text
src/                    Assembly source for the Wuci-Ji artifact machine.
include/                Assembly include files.
tools/                  Python, Zig, and Rust proof tools.
tests/                  Deterministic regression and proof tests.
authority/              Fixture authority roots used by proof lanes.
install/                Local signed-install root material and installer files.
docs/                   Threat model, build targets, policies, and models.
daylight-equation/      Daylight math, analysis, evidence, fixtures, and Rust code.
DLv0.5/                 Preserved earlier Daylight reference material.
```

Continuation and contributor documents:

- [docs/MACHINE_PASSOFF.md](docs/MACHINE_PASSOFF.md)
- [docs/CONTRIBUTOR_BOOTSTRAP.md](docs/CONTRIBUTOR_BOOTSTRAP.md)
- [docs/CI_SCOPE.md](docs/CI_SCOPE.md)
- [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md)
- [docs/FUZZING.md](docs/FUZZING.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
