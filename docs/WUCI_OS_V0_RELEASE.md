# Wuci-OS v0

Status: evidence candidate, not release-gate pass.

Local artifact:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
```

Current digest:

```text
SHA-256: 23aa1490108e77c16dba2b764749baa70033fedee6d825f7f895b8d0bb6bc648
```

Label:

```text
wuci-os-v0.3
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
  sudo, su, sv, ip, dhcpcd, iw, rfkill, wpa_supplicant, wpa_passphrase,
  nmcli, NetworkManager, dbus-daemon, xbps-install, wuci-network-connect
Final rootfs firmware check found:
  /usr/lib/firmware/iwlwifi-5000-5.ucode.zst for X200s-era Intel Wi-Fi.
QEMU runit service check:
  dbus and NetworkManager were enabled and running.
QEMU network helper check:
  wuci-network-connect printed tool status immediately and connected through ens3.
QEMU NetworkManager check:
  nmcli device status returned connected ethernet state.
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
sudo, su, sv, ip, dhcpcd, iw, rfkill, wpa_supplicant, wpa_passphrase, nmcli,
NetworkManager, dbus-daemon, linux-firmware-network, xbps-install, and
wuci-network-connect. The full desktop/media/SDR package suite is still not
release-closure proven because this host did not grant the root/chroot package
transaction needed to bake every full-suite package.
```

Do not describe v0 as production ready, package-closure proven, hardware-trace
proven, or release-gate passed until the blockers above have evidence.
