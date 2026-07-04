# Wuci-OS Release Runbook

Status: the released-OS gate is intentionally **blocked**. This runbook is the
exact, ordered path that retires every blocker. It exists so "make Wuci-OS
release-ready" is a checklist with verifiable evidence — not a claim.

Doctrine: `NoProof(x) -> NoClaim(x) -> NoRelease(x)`. The release gate
(`wuci-os-substract-release-gate-v1`, emitted by `build_final_iso`) is
fail-closed: a blocker stays active until its evidence is present **and**
verifies. The gate's `blocker_requirements` field documents each active blocker;
nothing in this runbook lets a missing artifact be waved through.

## Where the gate lives

- Computed in `tools/wuci_os.py` (`build_final_iso`), field `release_gate`.
- `release_allowed` is `true` only when `blockers` is empty.
- Model: [WUCI_OS_SUBSTRACT_SUBSTRATE.md](WUCI_OS_SUBSTRACT_SUBSTRATE.md).
- Current evidence candidate: [WUCI_OS_V0_RELEASE.md](WUCI_OS_V0_RELEASE.md).

## The blockers and what retires each

These are listed in dependency order. Earlier steps are reproducible on the
build host; the last three require evidence that **cannot** come from a build
environment — reference hardware, the release authority key, and the operated
witness ledger — by design.

Before any public upload, run the local artifact hygiene checks:

```sh
make daylight-ssv
make site-validate
make wuci-os-privacy-audit
```

This release lane is ISO-only. Do not include stale VirtualBox, OVF, or OVA
artifacts in the public bundle unless a future release explicitly re-enables
and revalidates that lane.

The ISO-only public bundle is generated with:

```sh
make wuci-os-release-bundle
```

The release evidence gate is checked with:

```sh
make wuci-os-release-gate
```

It writes `build/wuci-os/release-evidence/release-gate.json`. A blocker only
retires when its evidence file is bound to the exact final ISO and
`build/wuci-os/final/manifest.json` digests.

Generate the digest-bound off-host evidence packet with:

```sh
make wuci-os-release-contingencies
```

It writes `build/wuci-os/release-contingencies/`:

- `HARDWARE-TRACE.txt` for the physical boot operator.
- `SIGNING-REQUEST.txt` for the production release-key operator.
- `WITNESS-REQUEST.txt` for the operated WUCI-WITNESS ledger.
- `FINALIZE-COMMANDS.txt` for the final local gate commands.

This packet is not release authority. It only records the exact final
manifest/ISO digests and the commands needed to bind real off-host evidence.

### 1. `deterministic-rootfs-not-remastered`
Build host. Retired by rebuilding with `--remaster-rootfs` so the live rootfs is
deterministically remastered with the Wuci-OS overlay (not payload-preview mode).
The gate clears this automatically when `remaster_rootfs` is true.

### 2. `package-closure-fixed-point-missing`
Build host. Retired by baking the full install suite into the remaster so
`suite_package_install` reports `status=pass` and the package dependency graph
reaches a sealed fixed point. Until the full desktop/media/SDR suite resolves to
a closed graph, do **not** describe the artifact as package-closure proven.

### 3. `qemu-boot-trace-not-bound-to-final-manifest`
Build host. A QEMU boot trace of the final ISO already reaches the `WJ>_` prompt
(see V0 release notes). The blocker is the *binding*: capture the trace of THIS
final ISO and record the final-ISO manifest `sha256` inside the trace artifact so
the trace provably belongs to the released image, not an earlier build.

After producing a serial log, bind it with:

```sh
python3 tools/wuci_release_gate.py qemu-trace \
  --manifest build/wuci-os/final/manifest.json \
  --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \
  --boot-log build/wuci-os/boot/final-qemu-serial-latest.log
```

### 4. `hardware-boot-trace-missing`
**Off-host evidence.** Boot the final ISO on the reference hardware (ThinkPad
X200s) and record a boot trace reaching `WJ>_` with the live Wi-Fi/admin surface
present (cfg80211/mac80211/iwlwifi, `nmcli`, `INSTALL`). This cannot be produced
in CI or a sandbox; it requires the physical machine.

Capture the transcript to a text file and bind it with:

```sh
wuci-release-hardware-trace /tmp/wuci-hardware-boot.log

python3 tools/wuci_release_gate.py hardware-trace \
  --manifest build/wuci-os/final/manifest.json \
  --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \
  --boot-log /path/to/wuci-hardware-boot.log \
  --hardware-id "ThinkPad X200s:<serial-or-local-id>" \
  --operator "<operator>" \
  --observed-at-utc "2026-07-03T00:00:00Z"
```

`wuci-release-hardware-trace` emits the required release markers and a sanitized
hardware/network/install surface. It does not read Wi-Fi SSIDs, Wi-Fi
passwords, API keys, shell history, mail/chat data, or home-directory contents.

### 5. `final-iso-manifest-signature-missing`
**Off-host evidence.** Sign the final-ISO manifest digest with the Wuci-OS
release authority key and publish the detached signature alongside the ISO. The
fixture authority roots in `authority/` are **not** the release key; signing with
a fixture would be an overclaim, not a release.

One supported path is minisign:

```sh
minisign -S -s /path/to/wuci-os-release.key \
  -m build/wuci-os/final/manifest.json \
  -x build/wuci-os/final/manifest.json.minisig

python3 tools/wuci_release_gate.py verify-signature \
  --manifest build/wuci-os/final/manifest.json \
  --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \
  --signature build/wuci-os/final/manifest.json.minisig \
  --public-key-file /path/to/wuci-os-release.pub
```

### 6. `witness-ledger-entry-missing`
**Off-host evidence.** Append the signed final-ISO manifest digest to the
WUCI-WITNESS ledger and record its inclusion proof, so the release is publicly
transparent and consistent with prior heads.

After the operated ledger has an entry and inclusion proof:

```sh
python3 tools/wuci_release_gate.py witness \
  --manifest build/wuci-os/final/manifest.json \
  --iso build/wuci-os/final/Wuci-OS-x86_64-musl.iso \
  --signature-evidence build/wuci-os/release-evidence/manifest-signature.json \
  --ledger-entry /path/to/ledger-entry.txt \
  --ledger-head /path/to/ledger-head.txt \
  --inclusion-proof /path/to/inclusion-proof.txt \
  --operated-ledger-id "wuci-witness-production" \
  --operator "<operator>" \
  --ledger-url "https://example.org/wuci-witness/ledger-head.txt"
```

## Definition of done

`build_final_iso` emits `release_gate.release_allowed == true` only when all six
blockers are absent. At that point — and only then — Wuci-OS may be described as
release-gate passed. Until then the honest description is: **evidence candidate,
not release-ready.** Steps 1–3 are reproducible here; steps 4–6 gate on
real-world evidence that the build host cannot manufacture.
