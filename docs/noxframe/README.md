# WUCI-NOXFRAME

`WUCI-NOXFRAME` is the local proof launcher for Wuci-Ji and Daylight surfaces.
It turns the Phase1-style terminal/operator-console idea into a WUCI-native
launcher and self-seal record.

It does not import Phase1 code. It does not add a kernel, host filesystem
authority, runtime sandboxing, offensive scanning, production authority,
independent audit status, or whole-system post-quantum safety.

Run the default launch:

```sh
make noxframe-launch
```

The default launch uses `--profile auto`. Auto mode initializes into quick mode
and keeps using quick mode until the local NOXFRAME clock reaches seven days.
When the clock is due, the default launch runs the full proof matrix and resets
the 7-day anchor after a successful full run.

Direct command form:

```sh
tools/wuci-noxframe
```

Compatibility command:

```sh
tools/wuci-black-ice
```

The launcher streams colored live status, starts with a slow boot countdown,
runs Wuci-Prism over the generated Gate demo artifact, and writes two local
evidence files:

```text
docs/noxframe/WUCI_NOXFRAME_LAUNCH_REPORT.md
docs/noxframe/WUCI_NOXFRAME_SELF_SEAL.json
```

The clock state is stored outside the docs tree:

```text
build/noxframe/WUCI_NOXFRAME_CLOCK.json
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
