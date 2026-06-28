<img width="2172" height="724" alt="wsj-banner-github" src="https://github.com/user-attachments/assets/3e20bf66-1376-46b0-9f25-0ec619bf7224" />

# Wuci-Ji

Wuci-Ji / 无此机 is a defensive research project for a small x86_64 assembly
artifact machine. It explores how sealed artifacts, authorization receipts,
Gate release checks, public witness bundles, ledger history, installation
receipts, and Daylight protocol-state evidence can be composed into a reviewable
proof system.

**Status:** research/proof artifact only. It is not production cryptography,
not a runtime sandbox, not post-quantum secure, not production authority, and
not independently audited.

The practical goal is narrow: make the repo's security claims executable,
deterministic, and easy to inspect without overstating what is proved.

## Start Here

- [BUILD_NOTES.md](BUILD_NOTES.md) is the current handoff checkpoint.
- [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) is the main claim
  boundary.
- [docs/MACHINE_PASSOFF.md](docs/MACHINE_PASSOFF.md) is the continuation
  pattern for another machine.
- [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) lists the proof and test
  targets.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) explains what the project
  defends against and what remains out of scope.
- [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md) tracks why this
  is not a production system.
- [daylight-equation/](daylight-equation/) is the Daylight subdirectory.

For a quick local orientation on macOS or another non-Linux host:

```sh
make build-linux
make wuci-daylight-bridge-test
make wjnext-model-test
```

Native `make test` requires Linux x86_64 with GNU `as`/`ld`; the full native
test lane also expects the current assembly X25519 instruction surface. See
[docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) for the Linux, qemu, Daylight,
Gate, CAGE, QCAGE, HARDEN, INSTALL, and high-attestation targets.

## How The Pieces Fit

Wuci-Ji separates secrecy, authorization, release, public evidence, and review
claims:

1. **Envelope** seals bytes with the WJSEAL artifact format.
2. **Warrant** binds a quorum authorization receipt to an artifact and action.
3. **Gate** refuses plaintext release unless the flat contract, authority root,
   key, artifact, and output path checks pass.
4. **Witness** strips private material and builds public review bundles.
5. **Ledger** commits public bundles into deterministic hash history.
6. **HARDEN, CAGE, QCAGE, and INSTALL** add defensive proof checks around safe
   I/O, fixture quarantine, evidence legitimacy, quantum-risk labeling, and
   signed local installation.
7. **Daylight** adds a typed protocol-state and claim-boundary layer around
   the envelope path, including explicit zero-claims for production,
   containment, whole-system PQ safety, external review, and official
   endorsement.

```text
ENVELOPE preserves secrecy.
WARRANT proves authorization.
GATE enforces authorization.
WITNESS and LEDGER make release evidence inspectable.
DAYLIGHT records the protocol-state boundary for review.
```

## Daylight Subdirectory

Daylight lives in its own project area:
[daylight-equation/](daylight-equation/).

Use these entry points:

- [daylight-equation/README.md](daylight-equation/README.md) for the Daylight
  directory map and working rules.
- [daylight-equation/SCORECARD.md](daylight-equation/SCORECARD.md) for the
  repo-owned research scorecard and hard gates.
- [daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.md](daylight-equation/analysis/daylight-v06-peer-review-scoring-model-10000.md)
  for the 10,000-point review model.
- [daylight-equation/analysis/daylight-v06-written-code-protocol-state.md](daylight-equation/analysis/daylight-v06-written-code-protocol-state.md)
  for the written-code Daylight v0.6 protocol-state boundary.
- [daylight-equation/research/daylight-v06-cap-removal-plan.md](daylight-equation/research/daylight-v06-cap-removal-plan.md)
  for the fail-closed plan to clear the current 8250/10000 hard caps.
- [daylight-equation/research/daylight-v06-m4-z3-proof.md](daylight-equation/research/daylight-v06-m4-z3-proof.md)
  for the mechanized predicate proof.
- [daylight-equation/evidence/README.md](daylight-equation/evidence/README.md)
  for machine-readable evidence bundles.
- [daylight-equation/fixtures/README.md](daylight-equation/fixtures/README.md)
  for fixture boundaries.
- [daylight-equation/rust/daylight-model/README.md](daylight-equation/rust/daylight-model/README.md)
  for the std-only Rust model crate.
- [daylight-equation/rust/daylight-crypto/README.md](daylight-equation/rust/daylight-crypto/README.md)
  for the pinned Rust crypto and WUCI-DAYLIGHT bridge lane.

The WUCI-DAYLIGHT bridge keeps Wuci-Ji's active WJSEAL encryption surface in
place and adds Daylight evidence around it. It classifies WJSEAL v1/v2/v3
envelope bytes, records the current 8250/10000 Daylight research boundary,
keeps the zero-claim fields at zero, and requires Gate-authorized plaintext
release.

```sh
make wuci-daylight-bridge-test
cd daylight-equation/rust/daylight-crypto
cargo run --offline -- wuci-daylight-envelope-boundary --file ../../../build/wuci-gate-demo/sealed.wj
```

The bridge does not decrypt, accept keys, verify AEAD tags, replace Gate, add
production authority, prove runtime containment, or prove whole-system
post-quantum safety.

## Component Map

| Area | What it is | Main links |
| --- | --- | --- |
| Envelope | WJSEAL artifact sealing/opening surface using the current assembly path. | [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md), [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) |
| FROST/Warrant | Deterministic fixture quorum authorization receipt for review workflows. | [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md), [docs/wuci_wjstar_model.md](docs/wuci_wjstar_model.md) |
| Gate/Root/Anchor | Assembly-enforced open/release contract checks and fixture authority anchors. | [docs/wuci_gate_boundary.json](docs/wuci_gate_boundary.json), [docs/wuci_authority_root.json](docs/wuci_authority_root.json) |
| Witness | Public, keyless release evidence bundle. | [docs/wuci_publish_witness.json](docs/wuci_publish_witness.json), [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) |
| Ledger | Hash-only transparency history for witness bundles. | [docs/wuci_ledger_format.json](docs/wuci_ledger_format.json), [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) |
| HARDEN | Defensive perimeter checks for verifier identity, safe I/O, fixture quarantine, and action policy. | [docs/wuci_hardening_policy.json](docs/wuci_hardening_policy.json), [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md) |
| CAGE | Artifact legitimacy airlock; not OS runtime containment. | [docs/wuci_cage_policy.json](docs/wuci_cage_policy.json), [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) |
| QCAGE | Quantum-aware evidence labeling and migration-debt checks; not a PQ safety claim. | [docs/wuci_qcage_model.md](docs/wuci_qcage_model.md), [docs/wuci_qcage_policy.json](docs/wuci_qcage_policy.json) |
| INSTALL | Noninteractive signed local installer proof lane. | [docs/wuci_install_model.md](docs/wuci_install_model.md), [install/](install/) |
| WJ-next / Golden Lock | Composition models for stronger transcript and review boundaries. | [docs/wuci_wjnext_model.md](docs/wuci_wjnext_model.md), [docs/wuci_golden_lock_model.md](docs/wuci_golden_lock_model.md) |
| Daylight | Typed protocol-state, scoring, evidence, and Rust model/crypto review lanes. | [daylight-equation/](daylight-equation/), [docs/wuci_wjnext_model.md](docs/wuci_wjnext_model.md) |

## Common Commands

Build the Linux artifact from a non-Linux host:

```sh
make build-linux
```

Run the core Daylight/WUCI bridge check:

```sh
make wuci-daylight-bridge-test
```

Run the Daylight protocol-state check without the WJSEAL bridge:

```sh
make daylight-v06-protocol-state-test
```

Run the Daylight cap-removal blocker check:

```sh
make daylight-v06-cap-removal-test
```

Run Gate proof lanes:

```sh
make gate-workflow
make gate-contract-asm
make gate-contract-zig
```

Run defensive perimeter proof lanes:

```sh
make harden0-proof
make harden-proof
make cage-proof
make qcage-proof
```

Run the signed local install proof lane:

```sh
mkdir -p ~/.config/wuci-ji
cp install/wuci-install-root.v1.pub ~/.config/wuci-ji/install-root.pub
make install-proof INSTALL_ROOT_KEY=$HOME/.config/wuci-ji/install-root.pub INSTALL_PREFIX=$HOME/.local
~/.local/bin/wuci-ji-audit
```

Build a self-release evidence bundle:

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
tools/                  Python and Zig proof tools.
tests/                  Deterministic regression and proof tests.
authority/              Fixture authority roots used by proof lanes.
install/                Local signed-install root material and installer files.
docs/                   Threat model, build targets, policies, and models.
daylight-equation/      Daylight math, analysis, evidence, fixtures, and Rust code.
DLv0.5/                 Preserved earlier Daylight reference material.
```

Machine continuation is in [docs/MACHINE_PASSOFF.md](docs/MACHINE_PASSOFF.md).
Contributor setup is in
[docs/CONTRIBUTOR_BOOTSTRAP.md](docs/CONTRIBUTOR_BOOTSTRAP.md). CI scope is in
[docs/CI_SCOPE.md](docs/CI_SCOPE.md). Release requirements are in
[docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md). Parser/fuzzing status is in
[docs/FUZZING.md](docs/FUZZING.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
