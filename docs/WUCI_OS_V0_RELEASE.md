# Wuci-OS v0

Status: evidence candidate, not release-gate pass.

Local artifact:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
```

Current digest:

```text
SHA-256: 334c86d28e8a464f9d276b7626b260c8d7a31b95b7c5439dbaee2da76b11ebc1
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
QEMU live prompt check reached WJ>_ as wj without a password-change trap.
QEMU command-surface check found:
  sudo, su, ip, dhcpcd, iw, rfkill, wpa_supplicant, wpa_passphrase,
  xbps-install, wuci-network-connect
QEMU no-Wi-Fi check:
  wuci-network-connect printed tool status and exited cleanly instead of hanging.
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
The extracted rootfs now contains the minimum live Wi-Fi/admin surface:
sudo, su, ip, dhcpcd, iw, rfkill, wpa_supplicant, wpa_passphrase, xbps-install,
and wuci-network-connect. The full desktop/media/SDR package suite is still not
release-closure proven because this host did not grant the root/chroot package
transaction needed to bake every full-suite package.
```

Do not describe v0 as production ready, package-closure proven, hardware-trace
proven, or release-gate passed until the blockers above have evidence.
