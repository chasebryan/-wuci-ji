# Wuci-OS v0

Status: evidence candidate, not release-gate pass.

Local artifact:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
```

Current digest:

```text
SHA-256: b228e48ffa534d1e548d5738abef302a8ac75c39953eea4bc0e94175db0bd424
```

Label:

```text
v0
```

Validated on the build host:

```text
sha256sum -c Wuci-OS-x86_64-musl.iso.sha256
make wuci-os-test
QEMU direct-kernel BIOS smoke reached:
  Wuci-OS live profile
  Wuci-OS x86_64-musl base
  wuci-os-live login:
```

Bound v0 payloads:

```text
/wuci-os/WUCI_DAYLIGHT_V8.md
/wuci-os/WUCI_DAYLIGHT_V9.md
/wuci-os/wuci-daylight-v8-sheet.png
/wuci-os/wuci-daylight-v9-sheet.png
/wuci-os/wuci-daylight-v9-spine.svg
/wuci-os/wuci-daylight-wire-model.png
/wuci-os/OFFLINE-INSTALL.txt
```

Live rootfs payloads:

```text
/usr/share/wuci-os/WUCI_DAYLIGHT_V9.md
/usr/share/wuci-os/wuci-daylight-v9-sheet.png
/usr/share/wuci-os/wuci-daylight-v9-spine.svg
```

Release gate blockers intentionally kept:

```text
package-closure-fixed-point-missing
qemu-boot-trace-not-bound-to-final-manifest
hardware-boot-trace-missing
final-iso-manifest-signature-missing
witness-ledger-entry-missing
```

Package-suite note:

```text
The extracted rootfs contains /usr/bin/xbps-install, but this host did not grant
the root/chroot package transaction needed to bake the full package suite.
Therefore the v0 manifest must keep package closure blocked.
```

Do not describe v0 as production ready, package-closure proven, hardware-trace
proven, or release-gate passed until the blockers above have evidence.
