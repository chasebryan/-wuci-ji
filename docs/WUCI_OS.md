# Wuci-OS

`Wuci-OS` is the Wuci-Ji operating-system image lane. The product surface is
Wuci-OS: prompt, user accounts, desktop profile, security commands, wallpaper,
and operator tooling all present Wuci-OS as the system.

This lane is intentionally evidence-first. It verifies an operator-supplied
upstream musl ISO, records SHA-256/SHA-384/SHA-512 evidence, checks the expected
live layout, and emits a serial-friendly QEMU boot plan. The upstream base
lineage stays in source evidence and license/build metadata; it is not the
operator-facing product identity.

## Boundary

Wuci-OS v0 does not claim runtime sandboxing, host containment, quantum safety,
or independent operating-system authority. It is a local image-evidence and
boot-planning lane for building a NOXFRAME-native Wuci-OS substrate. Required
source attribution stays in evidence metadata and build documentation.

This lane must remain defensive. Do not add exploit payloads, offensive
scanning, jailbreak harnesses, malware logic, or network attack tooling.

## Default Profile

The generated Wuci-OS overlay defaults to an XFCE4 desktop, `kitty` as the
preferred terminal, `xfce4-terminal` as the fallback terminal, a ratpoison
window-manager profile, and both `emacs` and `vim`.

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
sudo wj update
sudo wj install vim emacs kitty
wj search rust
wj info python3
```

Daylight/WJSEAL is treated as a required evidence lane for every major generated
component. The current implemented seal covers the generated overlay. The
finished ISO lane must additionally seal the final ISO, rootfs manifest, package
metadata, install profile, and release receipt bundle.

## Source Install

Place the upstream musl live ISO in the repository root, then install it into
the Wuci-OS source-evidence workspace:

```sh
tools/wuci-os source install ./void-live-x86_64-musl-20250202-base.iso --force
tools/wuci-os source verify
tools/wuci-os plan
tools/wuci-os iso-plan
tools/wuci-os demo-commands
tools/wuci-os source-kit
tools/wuci-os overlay --force
tools/wuci-os keygen --force
tools/wuci-os seal-overlay --force --ticker always
```

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
vector. Upstream base attribution must remain Void Linux, musl, live base ISO,
and `VOID_LIVE`, with a release stamp derived from the installed ISO filename.
Verification recomputes the Void live layout and requires it to match the layout
evidence stored in the source manifest. Rollback staging re-opens existing files
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

## Live Boot

Inspect the QEMU plan first:

```sh
tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo
```

Run the live base over the serial terminal:

```sh
tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo --run
```

The boot plan extracts `boot/vmlinuz` and `boot/initrd` from the source ISO into a
transient `build/wuci-os/boot/` directory, attaches the ISO as read-only CD
media, and appends `console=ttyS0,115200n8` for the terminal demo path. Wuci-OS
also generates a deterministic source-kit tar so the current checkout is present
inside the live system under `/opt/wuci-os/source/wuci-ji`. If QEMU does not
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

The next Wuci-OS step is to add a finished bootable ISO lane:

1. fetch and review the upstream live-image source tooling into a reproducible
   Wuci-OS build workspace,
2. replace live boot banners, `/etc/os-release`, issue/MOTD, desktop defaults,
   installer context, and package profile with Wuci-OS identity,
3. build Wuci-Ji tools as XBPS packages where practical,
4. emit Wuci-Ji receipts for generated ISO/rootfs artifacts,
5. keep required upstream attribution in source evidence and license metadata,
   while the running operator surface remains Wuci-OS.

The intended final artifacts are:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
build/wuci-os/final/Wuci-OS-x86_64-musl.iso.sha256
build/wuci-os/final/manifest.json
build/wuci-os/final/wuci-os.iso.wj
build/wuci-os/final/daylight-manifest.json
```

Most of this lane should move to Rust:

- `wuci-os-manifest`: typed schemas and canonical JSON.
- `wuci-os-overlay-builder`: deterministic rootfs overlay and tar writer.
- `wuci-os-daylight-sealer`: WJSEAL/Daylight artifact sealing wrapper.
- `wuci-os-guide`: terminal guide with explicit next-step states.
- `wuci-os-installer-profile`: LUKS, SELinux, nftables, users, and receipt
  verifier.
