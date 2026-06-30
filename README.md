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
| Daylight v14C+ execution package | [daylight/v14c-plus/](daylight/v14c-plus/) |

## Daylight C+ / v14C+

Daylight v14C+ is a deterministic execution package, not a manually asserted
score. The package under [daylight/v14c-plus/](daylight/v14c-plus/) regenerates
the candidate score from a frozen ledger, frozen corpus snapshot, exact rational
arithmetic, q-evaluator rules, and a reproducibility receipt:

```text
NoProof(x) -> NoClaim(x) -> NoRelease(x)
NoEvidence(x) -> NoScore(x) -> NoRelease(x)
NoTrace(x) -> NoTrust(x)
ManualScore(x) -> Reject(x)
```

Run the focused C+ lane:

```sh
make daylight-cplus-test
PYTHONPATH=daylight/v14c-plus python3 -m src.cli score --ledger daylight/v14c-plus/examples/ledger.seed.jsonl --corpus daylight/v14c-plus/examples/corpus.seed.jsonl --out daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json
PYTHONPATH=daylight/v14c-plus python3 -m src.cli verify-scorecard daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json
```

The expected generated candidate score is `998,200M / 1,000,000M`. It remains a
candidate score until non-fixture release gates pass.

## Daylight v15 Meridian

Daylight v15 Meridian under [daylight/v15-meridian/](daylight/v15-meridian/) is the
successor to v14C+. It fixes the one design weakness in v14C+: q-values were
asserted `target` constants gated only by evidence *presence*, so a reviewer could
narrate any target up to a perfect score. Meridian makes every q-value
evidence-derived (`q_i = closed-obligation weight / 1000`) and has the verifier
*re-derive* the q-vector from a pinned obligation registry plus the sealed
closed-obligation set, so editing a number is rejected rather than trusted. See
[docs/WUCI_DAYLIGHT_V15_MERIDIAN.md](docs/WUCI_DAYLIGHT_V15_MERIDIAN.md).

```sh
make daylight-meridian-test
make daylight-meridian-frontier
make daylight-meridian-perfect-demo
```

Meridian's honest internal ceiling is `998,900M / 1,000,000M` (`+700M` over v14C+,
every point earned by added internal evidence). The residual `1,100M` is held by
external obligations the harness cannot self-issue (external red-team, post-quantum
and crypto audit, independent replication, external falsification, and independent
audits). A perfect `1,000,000M` is reachable only by closing those with genuine
non-harness external attestations; claiming it from inside the repository is exactly
the overclaim `ManualScore(x) -> Reject(x)` forbids.

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

Install from a checked-out release with one atomic command:

```sh
tools/wuci-install
```

This copies the repository install root key into the local trust path, verifies
the signed install manifest and binary digest vector, runs the install proof
lanes, installs to `$HOME/.local`, writes an audit receipt, and records a
Kitty/Ghostty terminal setup plan. It detects `kitty` or `ghostty` when already
present. If neither terminal is present, it writes
`$HOME/.local/share/wuci-ji/terminal-setup.json` with platform-specific
package-manager argv suggestions, but it does not run package managers, `sudo`,
or remote installers from inside WUCI-INSTALL.

The lower-level install target is still available:

```sh
make install-local
```

Build local self-release evidence:

```sh
make self-release-bundle
make self-release-witness-bundle
make self-release-ledger-bundle
```

NOXFRAME exposes the same self-release lane inside its bounded console:

```text
self-release plan
self-release status
self-release run all
self-release shell
```

The convenience target writes the self-release, witness, and ledger artifacts
under `build/noxframe/`:

```sh
make noxframe-self-release
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

`WUCI-NOXFRAME` boots through a quiet Wuci-Ji Systems Substrate splash with the
prompt: "Welcome to the Wuci-Ji system substrate, hacker. Would you like to
enter your system?" The default boot renderer profiles the terminal first:
the rich mechanics-terminal boot requires Kitty, WezTerm, Ghostty, iTerm2, or a
similar terminal. If the launch starts from a generic local terminal and `kitty`
is installed, NOXFRAME opens a Kitty window and continues there. Generic, tmux,
SSH, dumb, and unknown terminals otherwise use a reduced-motion screen that
avoids rapid full-screen clearing and prints an install hint instead of forcing
the rich renderer. Pass `--no-terminal-handoff` to stay in the current terminal,
`--boot-renderer gui` to open the explicit stdlib graphical canvas with a
black/crimson Wuci-Ji Systems console, box-grid lattice, modular motion
matrices, data rails, strategic pink/purple signal accents, and the
`无此机系统` identity line, `--boot-renderer terminal` to force the current
terminal, `--no-boot-voice` for visual-only boot, or
`--no-boot-animation` for the plain prompt. It then clears into a bounded
operator console in interactive terminals. Use `tools/wuci-noxframe
--no-console` to run the launch matrix directly.

The console carries Phase1-style discovery commands: `help --compact`,
`man <command>`, `complete <prefix>`, `capabilities`, and bash-style `TAB`
completion in interactive TTYs. One entered line can contain multiple NOXFRAME
commands separated by semicolons, or it can start with `multi`; semicolons
inside quotes stay inside the command. It implements local
substrate, Phase/Optics, virtual filesystem, text, process, system, history,
session, learning, nesting, plugin/WASI catalog, Base1/B1/B2 metadata, and
quality-check commands while keeping host/network passthrough routes
non-executing by default. Formerly reserved host, network, dev, and hardware
names now resolve to bounded local handlers or metadata-only dry-runs.

The NOXFRAME environment is session-local. `env`, `set`, `export`, `unset`,
`alias`, `unalias`, `which`, and `profile` operate inside the console only, and
the VFS exposes `/env/profile`, `/env/variables`, `/env/aliases`, and
`/env/security` for read-only inspection. Phase1-style metadata surfaces are
available through `phase`, `whereami`, `nest`, `learn`, `plugins`, `wasm`,
`kaiju`, `base1`, `doctor`, `selftest`, and `quality`, with virtual paths under
`/phase`, `/learn`, `/nests`, `/kaiju`, and `/dev`.

`xframe-split 2`, `xframe-split 3`, and `xframe-split 4` open a session-local
xframe deck inside one `make noxframe-launch` console. Two frames render
left/right, three render top-left/top-right/bottom, and four render a quadrant
layout. `xframe-next` cycles frames and is bound to Shift+Tab and F6 in
interactive readline terminals. Desktop-level Alt+Shift+Tab is not used because
window managers usually intercept it before the terminal can deliver it to
NOXFRAME. `xframe-drop 1` removes the last slot (right, bottom, or bottom-right
depending on the current layout), and `xframe-drop all` returns to the original
single NOXFRAME frame.

`wuci-kaiju` maps Kali Linux metapackage/menu purposes into a checked-in
metadata catalog at `docs/noxframe/wuci_kaiju_manifest.json`. It selects one
representative tool per purpose, with small companion sets for offline evidence
types such as disk and memory forensics. Inspect it with `tools/wuci-kaiju
verify`, `tools/wuci-kaiju list`, or the NOXFRAME `kaiju` command. It can copy
an operator-supplied Kali ISO into `build/noxframe/kaiju/iso/`, create a raw VM
disk, and boot it through an explicit non-graphical QEMU bridge:

```sh
tools/wuci-kaiju iso install /path/to/kali-linux.iso
tools/wuci-kaiju disk create --size-mib 32768
tools/wuci-noxframe --console --allow-kaiju-boot
```

Inside NOXFRAME, use `kaiju boot` for installer mode and `kaiju boot
--boot-disk --allow-network` for the installed Kali disk. Installed
disk mode reads the kernel/initrd pair from the raw disk and passes a serial
console command line so the terminal path bypasses GRUB when possible. Use
`kaiju boot --dry-run`, `kaiju boot --boot-disk --dry-run`, or `cat
/kaiju/boot-plan` to inspect the exact QEMU argv. The default boot plan uses
`-net none`; network is not enabled unless explicitly requested. `--share-repo`
is optional and only works on QEMU builds with `virtio-9p-pci`, so the portable
inner-NOXFRAME demo path uses `--allow-network` plus `git clone`. WUCI-KAIJU
does not expose Kali tools as NOXFRAME commands, scan networks, open radios,
start vulnerable lab targets, or claim runtime containment.

`learn` stores notes only in the current console session. Plugin/WASI commands
are catalogs and policy views, not module execution. `version --compare`
reports the Phase1 idea map and confirms that NOXFRAME imports no Phase1 code.
Nested substrate prompts show their substratisphere depth, rotate through
lattice color themes, and support `exit` for one level or `exit all` for every
nested NOXFRAME level.

`Wuci-OS` is the `x86_64-musl` image lane for future NOXFRAME-native systems.
It starts from an operator-supplied musl live ISO, records digest evidence,
verifies the expected live layout, and emits a serial-friendly QEMU boot plan.
Base attribution stays in source evidence and license metadata; the operator
surface is Wuci-OS.

```sh
tools/wuci-os source install ./base-live-x86_64-musl-YYYYMMDD.iso --force
tools/wuci-os source verify
tools/wuci-os plan
tools/wuci-os iso-plan
tools/wuci-os demo-commands
tools/wuci-os source-kit
tools/wuci-os overlay --force
tools/wuci-os keygen --force
tools/wuci-os seal-overlay --force --ticker always
tools/wuci-os final-iso --force --remaster-rootfs --install-suite-packages
tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo
```

Before installing from the ISO, read
[docs/WUCI_OS_OFFLINE_INSTALL.md](docs/WUCI_OS_OFFLINE_INSTALL.md). The same
instructions are embedded in the ISO at `/wuci-os/OFFLINE-INSTALL.txt` and in
the live system at `/usr/share/wuci-os/OFFLINE-INSTALL.txt`. The live installer
command is uppercase `INSTALL`; it self-escalates through sudo when needed, and
`wuci-install` is only a compatibility alias for that automated Wuci installer.

The boot payload carries both the Wuci-OS overlay and a deterministic source-kit
tar that uses fixed archive metadata and extracts the current Wuci-Ji checkout
into `/opt/wuci-os/source/wuci-ji` inside the guest. `wuci-update` can update
system packages and fast-forward or clone a live Wuci-Ji checkout from the repo
when the embedded source is a deterministic snapshot. The overlay defaults to
terminal-first XFCE4, kitty with Ghostty/xfce4-terminal/xterm fallbacks,
ratpoison, emacs, vim, Wi-Fi/network firmware tooling, PipeWire/ALSA/Pulse
audio, Mesa/video helpers, Bluetooth/printing/scanning/portal helpers, an
SDR/radio software lane for GNU Radio, Gqrx, RTL-SDR, HackRF, Airspy, SoapySDR,
and USB SDR helpers, an original generated Wuci-OS boot chime, and the Wuci
splash in ISOLINUX/GRUB menus. It also includes Wuci-OS wallpaper setup, a plan-only
Codex/Copilot/Grok Build setup guide, guided `wuci-guide` / `wuci-auto`
operation, and a live/demo `wj` login whose prompt identity is `WJ>_`.
The security profile is SELinux-first, targeted/enforcing,
LUKS-required for installed high-assurance systems, and includes
Kicksecure-inspired hardening ideas. Daylight/WJSEAL evidence is required for
generated components. `tools/wuci-os final-iso --force --remaster-rootfs`
rewrites the boot menu, embeds the splash, applies the Wuci rootfs identity, and
records final ISO evidence under `build/wuci-os/final/`. Add
`--install-suite-packages` when host `xbps-install` or root chroot access is
available so the Wi-Fi/audio/video/developer suite is baked into
`LiveOS/squashfs.img`.
Package operations use
`sudo wj install <packages...>` on top of the current package repository. See
[docs/WUCI_OS.md](docs/WUCI_OS.md). Wuci-OS v0 is image evidence, overlay
sealing, source payload, and boot-planning work; it does not claim runtime
sandboxing, host containment, quantum safety, or independent OS authority.

Wrap the NOXFRAME substrate and its inner dimensions into a local WJSEAL v2
artifact bound to Daylight public anchors:

```sh
mkdir -p build/noxframe
build/wuci-ji keygen > build/noxframe/daylight-wrap.key
tools/wuci-noxframe daylight-wrap --daylight-wrap-keyfile build/noxframe/daylight-wrap.key
```

`daylight-wrap` refuses symlinked or hardlinked keyfiles, rejects drifted
substrate state, reads the keyfile through a no-follow safe path, invokes the
existing assembly `seal-file-keyfile-v2` path with `shell=False` using a
temporary key copy, and writes `build/noxframe/daylight-wrap/manifest.json` plus
a sealed `noxframe-inner-dimensions.wj` artifact. The manifest records
SHA-256/SHA-384/SHA-512 digest vectors for the sealed artifact, the wrapped
NOXFRAME cells, virtual dimensions, substrate state/seal, and Daylight anchors.
This is local artifact sealing and public evidence binding; it is not a
runtime-containment, production-authority, independent-audit, or
whole-system post-quantum safety claim.

The `codex` command is the explicit opt-in bridge: `codex status` and
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
