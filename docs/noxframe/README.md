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
Welcome to the Wuci-Ji system substrate, hacker. Would you like to enter your system?
```

When stdin and stderr are both attached to a TTY, that prompt is shown inside a
NOXFRAME boot frame. `--boot-renderer auto` profiles the terminal first:
the rich mechanics-terminal boot requires Kitty, WezTerm, Ghostty, iTerm2, or a
similar terminal. If the launch starts from a generic local terminal and `kitty`
is installed, NOXFRAME opens a Kitty window and continues there. Tmux, SSH,
dumb, unknown, and generic terminals otherwise use a reduced-motion screen that
avoids rapid full-screen clearing and prints an install hint instead of forcing
the rich renderer. `--no-terminal-handoff` keeps the current terminal.
`--boot-renderer gui` explicitly opens a stdlib graphical canvas with a
black/crimson Wuci-Ji Systems console, box-grid lattice, modular motion
matrices, data rails, strategic pink/purple signal accents, and the
`无此机系统` identity line. The animation can be disabled with
`--no-boot-animation`, or forced with `--boot-renderer terminal`. If a local
host text-to-speech tool is available, NOXFRAME speaks only that quoted
sentence once during interactive boot; pass `--no-boot-voice` to keep boot
visual-only. Noninteractive runs, pipes, and tests keep the plain banner and
prompt and do not start voice output.

Accepting clears the splash and opens a bounded NOXFRAME console. The console is
not a host shell. It uses a Phase1-style command registry with `help`,
`help --compact`, `man <command>`, `complete <prefix>`, `capabilities`, and
bash-style `TAB` completion in interactive TTYs. One entered line can contain
multiple NOXFRAME commands separated by semicolons, or it can start with
`multi`; semicolons inside quotes stay inside the command. These are still
registry commands, not host shell pipelines.

Implemented local command families include substrate commands (`status`, `seal`,
`verify`, `contract`, `launch [auto|smoke|full]`, `self-release`), Phase/Optics
commands (`phase`, `whereami`, `compass`), virtual filesystem commands (`pwd`,
`ls`, `cd`, `cat`, `tree`), text commands (`grep`, `wc`, `head`, `tail`,
`find`, `wiki`), process/system views (`ps`, `top`, `sysinfo`, `dash`,
`dmesg`, `doctor`, `selftest`, `quality`, `audit`, `opslog`), user/session
commands (`env`, `set`, `export`, `unset`, `alias`, `unalias`, `which`,
`profile`, `history`, `security`, `theme`, `banner`, `tips`, `xframe-split`,
`xframe-next`, `xframe-drop`, `exit`), local learning notes (`learn`), nested
metadata contexts (`nest`), metadata-only plugin/WASI catalogs (`plugins`,
`wasm`), guarded Base1/B1/B2 metadata (`base1`), and the bounded Codex bridge
command (`codex`).

Phase1 host, network, dev, hardware-mutation, and plugin route names are
discoverable through `help` and `capabilities`, but they do not execute host
tools, perform network fetches, or open a shell from inside NOXFRAME by
default. Formerly reserved names now resolve to bounded local handlers or
metadata-only dry-run outputs.
Plugin and WASI routes are catalogs and policy views only; `wasm run` and host
plugin execution remain unavailable.

`xframe-split` divides one NOXFRAME console session into session-local frame
boxes without starting host shells or subprocess terminals. `xframe-split 2`
renders left/right frames, `xframe-split 3` renders top-left/top-right/bottom,
and `xframe-split 4` renders the maximum quadrant layout. Each xframe carries
its own cwd, history, aliases, notes, virtual files, and simulated jobs.
`xframe-next` cycles through open frames in a circular order; interactive
readline terminals bind the same action to Alt+Shift+Tab. `xframe-drop 1`
removes the last frame slot: right when two are open, bottom when three are open,
and bottom-right when four are open. `xframe-drop all` collapses back to the
original single NOXFRAME frame.

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

The console environment is session-local. `env`, `set KEY=value`, `set -o`,
`alias NAME=COMMAND`, `unalias NAME`, `which <command>`, and `profile` inspect
or update only the NOXFRAME console state. The virtual filesystem mirrors this
state under `/env/profile`, `/env/variables`, `/env/aliases`, and
`/env/security`, with `/env/self-release` showing the noxframe-scoped
self-release workspace status. Phase, learning, and nesting metadata are
available under `/phase`, `/learn`, and `/nests`; plugin policy is exposed under
`/dev/plugins` and `/dev/wasi`. These commands do not open host shell
execution, host network routes, or runtime containment claims.

`learn add <text>` stores session-local notes only. `nest enter <context>`
moves the console context to a fixed metadata cell such as `gate` or `qcage`;
`nest spawn` and `nest destroy` are blocked. `version --compare` prints the
Phase1 idea map and confirms that NOXFRAME imports no Phase1 code.

Inside the console, `self-release plan` and `self-release status` are metadata
views. `self-release run bundle|witness|ledger|all` runs the existing make
targets with subprocess argument vectors and `shell=False`, writing under
`build/noxframe/`. `self-release shell` enters a nested NOXFRAME metadata prompt
for that context; it is not a host shell. Nested substrate prompts carry a
substratisphere depth label such as `L0/root`, `L1/wuci-ji/self-release`, and
`L2/wuci-ji/self-release`. Each depth rotates through a lattice color theme and
prints the active lattice in `phase compass`, `phase whereami`, `nest status`,
and the console header. `exit` leaves one level; `exit all` unwinds every
nested NOXFRAME level.

`daylight-wrap` seals the NOXFRAME substrate state, substrate seal, cell map,
virtual dimensions, and Daylight anchor records into a local WJSEAL v2 artifact:

```sh
mkdir -p build/noxframe
build/wuci-ji keygen > build/noxframe/daylight-wrap.key
tools/wuci-noxframe daylight-wrap --daylight-wrap-keyfile build/noxframe/daylight-wrap.key
```

The command requires an operator-supplied local keyfile, rejects symlinks and
hardlinks before sealing, refuses drifted substrate state, reads the keyfile
through a no-follow safe path, and invokes the existing assembly
`seal-file-keyfile-v2` command with `shell=False` using a temporary key copy. It
writes `build/noxframe/daylight-wrap/noxframe-inner-dimensions.wj` and
`build/noxframe/daylight-wrap/manifest.json`. The manifest binds the sealed
artifact to SHA-256/SHA-384/SHA-512 digest vectors for the inner dimensions and
Daylight anchors. It does not claim runtime sandboxing, production authority,
independent audit status, or whole-system post-quantum safety.

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
tools/wuci-noxframe daylight-wrap --daylight-wrap-keyfile build/noxframe/daylight-wrap.key
```

NOXFRAME-scoped self-release convenience target:

```sh
make noxframe-self-release
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
