# Wuci-OS

`Wuci-OS` is the Wuci-Ji operating-system image lane. The product surface is
Wuci-OS: prompt, user accounts, desktop profile, security commands, wallpaper,
and operator tooling all present Wuci-OS as the system.

This lane is intentionally evidence-first. It verifies an operator-supplied
upstream musl ISO, records SHA-256/SHA-384/SHA-512 evidence, checks the expected
live layout, and emits a serial-friendly QEMU boot plan. The upstream base
lineage stays in source evidence and license/build metadata; it is not the
operator-facing product identity.

The lane follows the Substract Substrate model in
[`docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md`](WUCI_OS_SUBSTRACT_SUBSTRATE.md):
every public OS claim is either proven by local evidence or subtracted from the
release surface.

The current local v0 evidence-candidate label is recorded in
[`docs/WUCI_OS_V0_RELEASE.md`](WUCI_OS_V0_RELEASE.md), including the final ISO
digest, boot-smoke evidence, Daylight v8/v9/v10 payload paths, kernel hardware
closure status, and release-gate blockers that still prevent a release-gate
pass.

Daylight v8 extends that lane in
[`docs/WUCI_DAYLIGHT_V8.md`](WUCI_DAYLIGHT_V8.md): evidence sheaves, subtractive
capability algebra, meet-style gate algebra, transcript-bound cryptographic
wire state, proof-carrying artifacts, boot/build bisimulation, double-entry
ledger accounting, and claim subtraction.

Daylight v9 locks v8 at `973/1000` and converts the remaining 27 points into a
formal spine in [`docs/WUCI_DAYLIGHT_V9.md`](WUCI_DAYLIGHT_V9.md): a
proof-carrying subtractive cryptographic operating substrate with a commutative
evidence-sheaf condition, a Z3 fail-closed semilattice proof box, a Lean-style
gate sketch, and explicit attack-surface closure. The v9 target range is
`990-995`, but current Wuci-OS builds still subtract release-ready claims until
package closure, signature, ledger, QEMU trace binding, and hardware trace
evidence exist.

Daylight v10 compresses that model into
[`docs/WUCI_DAYLIGHT_V10.md`](WUCI_DAYLIGHT_V10.md): a minimal verified release
kernel with an initializer gate, standard crypto profile, meet-only proof
kernel, freshness ledger, attack-surface closure calculus, boot-bound crypto
wire, negative-evidence ledger, and conservative diagnostic utility. The v10
utility score is evidence telemetry only; it cannot override the fail-closed
publish gate.

The Daylight v8 sheet is shipped at
[`docs/wuci-os/assets/wuci-daylight-v8-sheet.png`](wuci-os/assets/wuci-daylight-v8-sheet.png)
and embedded at `/wuci-os/wuci-daylight-v8-sheet.png` and
`/usr/share/wuci-os/wuci-daylight-v8-sheet.png`. The earlier Daylight/WUCI wire
diagram is shipped at
[`docs/wuci-os/assets/wuci-daylight-wire-model.png`](wuci-os/assets/wuci-daylight-wire-model.png).
The ISO also embeds it at `/wuci-os/wuci-daylight-wire-model.png`, and the live
rootfs carries it at `/usr/share/wuci-os/wuci-daylight-wire-model.png`.
The Daylight v8 text is embedded at `/wuci-os/WUCI_DAYLIGHT_V8.md` and
`/usr/share/wuci-os/WUCI_DAYLIGHT_V8.md`.
The Daylight v9 text is embedded at `/wuci-os/WUCI_DAYLIGHT_V9.md` and
`/usr/share/wuci-os/WUCI_DAYLIGHT_V9.md`; its primary formal-spine sheet is
embedded at `/wuci-os/wuci-daylight-v9-sheet.png` and
`/usr/share/wuci-os/wuci-daylight-v9-sheet.png`. The editable companion SVG is
embedded at `/wuci-os/wuci-daylight-v9-spine.svg` and
`/usr/share/wuci-os/wuci-daylight-v9-spine.svg`.
The Daylight v10 release-kernel text is embedded at
`/wuci-os/WUCI_DAYLIGHT_V10.md` and
`/usr/share/wuci-os/WUCI_DAYLIGHT_V10.md`. Its scoreboard image is shipped at
[`docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png`](wuci-os/assets/wuci-daylight-v10-scoreboard.png)
and embedded at `/wuci-os/wuci-daylight-v10-scoreboard.png` and
`/usr/share/wuci-os/wuci-daylight-v10-scoreboard.png`.
The Daylight v13 Sovereign profile is a roadmap document, not a current crypto
implementation claim. It is embedded at
`/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md` and
`/usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md`. Its Sovereign Mathematics
sheet is shipped at
[`docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png`](wuci-os/assets/wuci-daylight-v13-sovereign-math.png)
and embedded at `/wuci-os/wuci-daylight-v13-sovereign-math.png` and
`/usr/share/wuci-os/wuci-daylight-v13-sovereign-math.png`.
The Daylight v14C+ Ascendant Candidate sheets are execution-package visuals, not
release authority. They are shipped at
[`docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png`](wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png),
[`docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png`](wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png),
and
[`docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png`](wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png),
and embedded under `/wuci-os/` and `/usr/share/wuci-os/` with matching
filenames.
The executable v14C+ package is also copied into the live rootfs at
`/usr/share/wuci-os/daylight/v14c-plus`; run
`wuci-daylight-v14c-plus verify` to verify the packaged scorecard, or
`wuci-daylight-v14c-plus score` to regenerate the candidate scorecard from the
frozen package inputs into `/tmp`.

## Boundary

Wuci-OS v0 does not claim runtime sandboxing, host containment, quantum safety,
or independent operating-system authority. It is a local image-evidence and
boot-planning lane for building a NOXFRAME-native Wuci-OS substrate. Required
source attribution stays in evidence metadata and build documentation.

This lane must remain defensive. Do not add exploit payloads, offensive
scanning, jailbreak harnesses, malware logic, or network attack tooling.

## Default Profile

The generated Wuci-OS overlay defaults to an XFCE4 desktop, `kitty` as the
preferred terminal, Ghostty as the alternate terminal, `xfce4-terminal`/`xterm`
as fallbacks, a ratpoison window-manager profile, and both `emacs` and `vim`.
It includes Wi-Fi/network tooling around NetworkManager, firmware package
groups, PipeWire/ALSA/Pulse audio helpers, Mesa/video helpers, Bluetooth,
printing/scanning, desktop portals, SDR/radio packages for GNU Radio, Gqrx,
RTL-SDR, HackRF, Airspy, SoapySDR, USB SDR access helpers, the Wuci splash image
for bootloader menus, and an original generated Wuci-OS boot chime.

Hardware Wi-Fi is a kernel closure claim, not just a userspace tool claim.
Current builds must prove that the live rootfs contains a module tree matching
the ISO boot kernel and that it provides `cfg80211`, `mac80211`, the X200s-era
Intel `iwlwifi`/`iwldvm` path, Netgear A8000/MT7921U fallback modules, module
metadata, udev hotplug files, and matching firmware. If that proof fails, the
builder fails before calling the image hardware-Wi-Fi ready.

The live/demo account profile is:

```sh
wj       # prompt identity WJ>_, admin live/demo account, password is Enter
wj_low   # lower-privilege account, password is Enter
```

`WJ>_` is the prompt identity. The portable Unix login name is `wj`.
The empty-password admin account is a live/demo default only. Installed
high-assurance systems must rotate it before the security status can honestly
pass.

## High-Assurance Security Profile

The overlay is SELinux-first. `wuci-security-apply` writes a Fedora-style
`/etc/selinux/config` with `SELINUX=enforcing` and `SELINUXTYPE=targeted`, adds
SELinux kernel flags, requests SELinux packages, applies a high-assurance
sysctl profile, writes default-deny inbound `nftables`, and marks the system for
relabel.

Run inside Wuci-OS:

```sh
wuci-users-apply
wuci-enter
wuci-network-apply
wuci-media-apply
wuci-sdr-apply
wuci-boot-chime
wuci-dev-install
wuci-security-apply
wuci-security-status
wuci-selinux-status
```

If SELinux packages or policy are not available on the active package snapshot,
Wuci-OS reports a hard blocker. AppArmor is not treated as a SELinux substitute.
LUKS/dm-crypt is required for installed high-assurance targets, but disk
selection stays operator-confirmed to avoid destructive writes.

The Kicksecure-inspired pieces are local hardening ideas: sysctl/kernel
hardening, reduced kernel information exposure, and default-deny network
posture. They are adapted into Wuci-OS configuration instead of importing
Kicksecure packages.

## AI And Developer Tooling

The developer profile includes package groups for C/C++, Python,
JavaScript/TypeScript, Rust, Go, JVM languages, Ruby, PHP, Perl/Lua, databases,
containers/VMs, and systems languages. The AI setup command is plan-only: it
prints a reviewed setup checklist for Codex CLI, GitHub Copilot CLI, and the
Wuci-OS Grok Build helper without downloading remote installers, running global
package installs, or embedding credentials.

```sh
wuci-ai-status
wuci-ai-setup
export XAI_API_KEY=...
wuci-grok-build "build a defensive Wuci-OS task checklist"
```

Codex, Copilot, and xAI credentials remain operator-supplied.

## Guided Operation

Wuci-OS should guide the operator through high-assurance setup. A new user
should not need to know the command order.

Inside a live boot, after applying the overlay, run:

```sh
wuci-guide
```

For a mostly automated live workstation setup:

```sh
wuci-auto
```

The guide applies users, checks Daylight evidence, applies the wallpaper, offers
developer setup, prints the AI tool setup plan, applies the SELinux-first
hardening profile, and shows final verification. Destructive disk actions remain
outside `wuci-auto` and must be operator-confirmed.

Package operations use the Wuci command surface. The backend packages come from
the current package repository, but users should not need to learn the backend
package-manager commands:

```sh
sudo wuci-network-connect
sudo wj update
sudo wj install vim emacs kitty
wj search rust
wj info python3
```

`wuci-network-connect` is the first-boot network credential prompt. It tries
wired DHCP first, then asks locally for Wi-Fi credentials through NetworkManager
or a `wpa_supplicant` fallback when those tools are present. `wj install`,
`wj update`, and `wuci-update` call the prompt before repository sync if no
network route exists.

Daylight/WJSEAL is treated as a required evidence lane for every major generated
component. The current implemented seal covers the generated overlay. The
finished ISO lane must additionally seal the final ISO, rootfs manifest, package
metadata, install profile, and release receipt bundle.

## Source Install

Place the upstream musl live ISO in the repository root, then install it into
the Wuci-OS source-evidence workspace:

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
```

The beginning-to-end offline install checklist is
[WUCI_OS_OFFLINE_INSTALL.md](WUCI_OS_OFFLINE_INSTALL.md). The ISO also carries it
at `/wuci-os/OFFLINE-INSTALL.txt`, and the live profile exposes it at
`/usr/share/wuci-os/OFFLINE-INSTALL.txt`.

The source ISO is copied under `build/wuci-os/source/`, which is ignored by Git.
The source ISO is an operator-supplied input, not repository source. Source ISO
install rejects symlinked output parents, rejects symlink/hardlinked source
inputs, copies through a same-directory temporary file, fsyncs the destination
parent, re-reads the installed artifact digest vector, and only then writes the
source manifest. Forced source replacement verifies the temporary candidate
layout before replacing an existing installed source, so a bad candidate leaves
the prior source evidence in place. If replacement reaches the manifest update
and then fails, the installer restores the previous ISO and source manifest from
same-directory rollback copies. Source verification rejects symlinked source
roots, refuses manifest `image_path` values outside the source workspace, and
requires a valid plain `.iso` `image_name`; the recorded path must name that
direct ISO under the source workspace. Verification also requires Wuci-OS
product identity, `operator_supplied: true`, and the current boundary-denial
vector. Upstream base attribution remains in source evidence and license
metadata, with a release stamp derived from the installed ISO filename.
Verification recomputes the expected live layout and requires it to match the
layout evidence stored in the source manifest. Rollback staging re-opens existing files
with no-follow semantics and verifies the staged same-directory backup still
matches the inspected file identity before it can be used for restore.
`tools/wuci-os overlay --force` performs a deterministic rebuild of the overlay
tree: it rejects symlinked overlay output parents, validates the existing tree,
rejects stale symlinks or hardlinked files, clears regular stale
files/directories, and then writes the current overlay profile. The wallpaper
asset is copied with a no-follow, fstat-verified, single-link streaming copy.
Generated overlay scripts and configuration files are created with no-follow,
exclusive writes and verified against their expected digest before they are
recorded.
The overlay manifest records both the generated regular-file set and the full
overlay path walk, including the manifest path itself, so command output and
durable JSON describe the same tree. Manifest path lists must be string-only and
duplicate-free; the full path walk is checked in deterministic path order. It
also records current content records for regular files other than the manifest
itself, and the Daylight/WJSEAL seal lane rejects stale overlay manifests before
writing seal outputs.
Deterministic overlay and source-kit tar payload reads use no-follow,
fstat-verified opens and reject hardlinked files. The
Daylight/WJSEAL overlay keyfile is read through the same no-follow,
fstat-verified single-link discipline before a temporary sealing copy is made;
keyfile creation and seal output directories reject symlinked output parents.
Forced overlay reseals write the new sealed artifact in a private temporary
directory first and only replace the previous artifact and manifest after the
seal command succeeds; if the seal manifest update fails after artifact
replacement begins, the previous sealed artifact and manifest are restored from
same-directory rollback copies.
Generated overlay and source-kit tar archives reject symlink output parents,
write to same-directory temporary files, validate, atomically move into place,
fsync through the parent directory, re-open, and validate again before use.
Validation requires relative member paths, directory/regular-file-only entries,
root/root deterministic metadata, and no duplicate, symlink, hardlink, device, or
FIFO members. The source-kit tar manifest uses a fixed archive epoch rather than
wall-clock time so unchanged source input produces byte-reproducible payloads.
Source-kit tar validation also re-reads the archived manifest copies and every
regular file member, requiring target paths, modes, byte counts, and digest
vectors to match the recorded source-kit manifest before and after the atomic
archive move.
The source-kit file list is collected before any output tar temporary file is
created, so repo-local output paths cannot capture the in-progress archive as
source evidence. Stale same-directory source-kit output temporary files are
rejected if they are visible in the source snapshot, because generated archive
state is not onboard source evidence.
This is archive evidence discipline, not a runtime containment claim.

`tools/wuci-os final-iso --force` builds a bootable payload-preview ISO at
`build/wuci-os/final/Wuci-OS-x86_64-musl.iso`. It preserves the upstream live ISO
boot catalog, embeds `/wuci-os/` payloads, writes
`Wuci-OS-x86_64-musl.iso.sha256`, emits `manifest.json`, and copies the Daylight
seal manifest to `daylight-manifest.json`.

`tools/wuci-os final-iso --force --remaster-rootfs` is the Wuci first-boot
identity path. It rewrites ISOLINUX labels to `Wuci-Ji Systems / Wuci-OS
x86_64-musl`, rewrites GRUB entries when GRUB configs are present, embeds the
Wuci splash under `/boot/isolinux/wuci-splash.png` and
`/boot/grub/wuci-splash.png`, applies the Wuci overlay into
`LiveOS/squashfs.img`, replaces `/etc/os-release`, issue/MOTD, hostname,
terminal defaults, update helpers, network/media helpers, and removes the upstream
live login banner from the remastered rootfs. Physical ISO boot entries preserve
the upstream live-root discovery arguments and add only the legacy BIOS live
compatibility profile: `console=tty0 rd.driver.pre=loop
live.hostname=wuci-os-live`.

`--install-suite-packages` adds the finished suite package bake: Wi-Fi/network
support, firmware, audio, video, Bluetooth, printing/scanning, portals, editors,
SDR/radio software, USB SDR helpers, developer toolchains, and security
packages. This requires host `xbps-install` with rootfs support, or root chroot
access to a rootfs that already contains `/usr/bin/xbps-install`. If those tools
are unavailable, the remaster reports a blocker instead of claiming that
packages were baked. SDR package availability can vary by base snapshot, so the
package-bake manifest records whether the suite completed fully or partially and
lists any package names that were unavailable.

Failed ISO candidates are negative evidence, not release bases. Record them
with:

```sh
tools/wuci-os failure ingest path/to/failed.iso path/to/notes.json
```

The ingest lane writes a digest-addressed manifest under
`build/wuci-os/failures/`, records the failed ISO digest and boot notes, and
refuses to overwrite an existing specimen.

## Live Boot

Inspect the QEMU plan first:

```sh
tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo
```

Run the live base over the serial terminal:

```sh
tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo --run
```

The QEMU boot plan extracts `boot/vmlinuz` and `boot/initrd` from the source ISO
into a transient `build/wuci-os/boot/` directory, attaches the ISO as read-only
CD media, and appends the direct-kernel fast-live profile for VM runs. Physical
ISO boot menus use the safer live-root compatibility profile described above.
Wuci-OS also generates a deterministic source-kit tar so the current checkout is
present inside the live system under `/opt/wuci-os/source/wuci-ji`. If QEMU does not
support `virtio-9p-pci`, Wuci-OS attaches the generated overlay and source kit as
read-only tar block devices. Existing overlay tar-drive payloads are only built
after the overlay manifest passes the same current-content check used by the
Daylight/WJSEAL seal lane. During `--run`, the mutable boot plan records digest
evidence for the generated kernel/initrd files and validation evidence for the
generated overlay/source-kit tar payloads. If payload generation fails after
transient files have been written, Wuci-OS removes the artifacts created during
that failed build and clears stale generated-artifact evidence from the plan.
Boot artifact cleanup refuses symlinked cleanup roots and only removes the known
single-link regular transient artifact files; failed-build cleanup reports
symlink or hardlink drift instead of silently unlinking suspicious artifacts.

Inside the guest, if the tar-drive fallback is used:

```sh
for dev in /dev/vd? /dev/sd?; do tar -tf "$dev" >/dev/null 2>&1 && tar -xf "$dev" -C /; done
wuci-live-banner
wuci-users-apply
wuci-source-status
wuci-enter
wuci-guide
wuci-status
```

If 9p is available, use the boot plan's mount hint and run:

```sh
sh /mnt/wuci/tools/wuci-os-live-activate
```

Exit QEMU with `Ctrl-a x`.

## Next Build Lane

The current Wuci-OS ISO lane can build either a payload-preview ISO or a
squashfs-remastered Wuci first-boot identity ISO. The next Wuci-OS step is to
make the remastered distro lane routine on the target build host:

1. install host `squashfs-tools` and package-baking support,
2. boot-smoke-test the remastered ISO on BIOS and UEFI paths,
3. build Wuci-Ji tools as XBPS packages where practical,
4. verify SDR hardware/udev behavior on target hardware,
5. emit Wuci-Ji receipts for generated ISO/rootfs/package artifacts,
6. keep required upstream attribution in source evidence and license metadata,
   while the running operator surface remains Wuci-OS.

The current final artifacts are:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
build/wuci-os/final/Wuci-OS-x86_64-musl.iso.sha256
build/wuci-os/final/manifest.json
build/wuci-os/final/daylight-manifest.json
build/wuci-os/final/rootfs-manifest.json
build/wuci-os/final/wuci-os-overlay.tar
build/wuci-os/final/wuci-os-source-kit.tar
```

Most of this lane should move to Rust:

- `wuci-os-manifest`: typed schemas and canonical JSON.
- `wuci-os-overlay-builder`: deterministic rootfs overlay and tar writer.
- `wuci-os-daylight-sealer`: WJSEAL/Daylight artifact sealing wrapper.
- `wuci-os-guide`: terminal guide with explicit next-step states.
- `wuci-os-installer-profile`: LUKS, SELinux, nftables, users, and receipt
  verifier.
