# WUCI-NOXFRAME

`WUCI-NOXFRAME` is the local substrate and proof launcher for Wuci-Ji and
Daylight surfaces. It turns the Phase1-style terminal/operator-console idea
into a WUCI-native console, state record, and self-seal.

It does not import Phase1 code. It does not add a kernel, host filesystem
authority, runtime sandboxing, offensive scanning, production authority,
independent audit status, or whole-system post-quantum safety.

Boot the substrate:

```sh
make noxframe-launch
```

In an interactive terminal, the boot screen asks:

```text
Would you like to boot the Wuci-Ji substrate?
```

When stdin and stderr are both attached to a TTY, that prompt is shown inside a
full-screen animated NOXFRAME boot frame. The animation only runs while waiting
for the operator's answer and can be disabled with `--no-boot-animation`.
Noninteractive runs, pipes, and tests keep the plain banner and prompt.

Accepting clears the splash and opens a bounded NOXFRAME console. The console is
not a host shell. It uses a Phase1-style command registry with `help`,
`help --compact`, `man <command>`, `complete <prefix>`, and `capabilities`.

Implemented local command families include substrate commands (`status`, `seal`,
`verify`, `contract`, `launch [auto|smoke|full]`), virtual filesystem commands
(`pwd`, `ls`, `cd`, `cat`, `tree`), text commands (`grep`, `wc`, `head`,
`tail`, `find`), process/system views (`ps`, `top`, `sysinfo`, `dash`,
`dmesg`, `audit`, `opslog`), user/session commands (`env`, `history`,
`security`, `theme`, `banner`, `tips`, `exit`), and the bounded Codex bridge
command (`codex`).

Phase1 host, network, dev, hardware-mutation, and plugin route names are
discoverable through `help` and `capabilities`, but they do not execute host
tools, perform network fetches, or open a shell from inside NOXFRAME by
default.

Codex is the explicit opt-in bridge. Inside the console, `codex status`,
`codex handoff`, and `cat /dev/codex` are metadata-only and always available.
To let NOXFRAME launch Codex as a host process, start the console with:

```sh
tools/wuci-noxframe --console --allow-codex
```

Then use:

```text
codex start
codex exec tighten the NOXFRAME docs without expanding security claims
codex resume --last
```

The bridge invokes Codex with `shell=False`, pins the working checkout with
`--cd`, uses `--sandbox workspace-write`, and requests
`--ask-for-approval on-request`. Codex may use its own host/API configuration.
This bridge is not a NOXFRAME runtime sandbox or no-network guarantee.

Run the launch matrix directly instead of entering the console:

```sh
tools/wuci-noxframe --no-console
```

The default launch profile is `--profile auto`. Auto mode initializes into
quick mode and keeps using quick mode until the local NOXFRAME clock reaches
seven days. When the clock is due, the default launch runs the full proof matrix
and resets the 7-day anchor after a successful full run.

Direct command form:

```sh
tools/wuci-noxframe
```

Compatibility command:

```sh
tools/wuci-black-ice
```

The launch matrix streams colored live status, starts with a slow boot
countdown, runs Wuci-Prism over the generated Gate demo artifact, and writes two
local evidence files:

```text
docs/noxframe/WUCI_NOXFRAME_LAUNCH_REPORT.md
docs/noxframe/WUCI_NOXFRAME_SELF_SEAL.json
```

The clock state is stored outside the docs tree:

```text
build/noxframe/WUCI_NOXFRAME_CLOCK.json
```

The substrate state and substrate seal are stored outside the docs tree:

```text
build/noxframe/WUCI_NOXFRAME_STATE.json
build/noxframe/WUCI_NOXFRAME_SUBSTRATE_SEAL.json
```

Substrate command forms:

```sh
tools/wuci-noxframe contract
tools/wuci-noxframe init
tools/wuci-noxframe status
tools/wuci-noxframe seal
tools/wuci-noxframe verify
```

The self-seal binds fixed public anchors from Wuci-Ji and Daylight with
SHA-256, SHA-384, and SHA-512 digest vectors. Anchor reads reject symlinks and
hardlinks. The seal records skipped operator-supplied or optional-dependency
lanes instead of faking production authority, real PQ verifier evidence, local
install mutation, or unavailable Daylight fixture dependencies.

The full profile is intentionally heavy. It runs native Wuci-Ji tests, PRISM,
Daylight, Nightlight, Gate, HARDEN, CAGE, QCAGE, install verification,
release-bundle verification, public verification, and the high-attestation
lane. Lanes that require operator-supplied external evidence or optional local
Python dependencies are recorded in the report and self-seal instead of being
claimed.

Use the smoke profile for a short local check:

```sh
tools/wuci-noxframe --profile smoke --no-countdown
make noxframe-launch-test
```

Force the full matrix at any time:

```sh
tools/wuci-noxframe --profile full
```
