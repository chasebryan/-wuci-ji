# Wuci-OS v0

Status: evidence candidate, not release-gate pass.

Local artifact:

```text
build/wuci-os/final/Wuci-OS-x86_64-musl.iso
```

Current digest:

```text
SHA-256: d474003903fd5cf93d258a31f3f18d4f4e23505283d233a993e51e6a7a8eff7b
```

Label:

```text
wuci-os-v0.4
```

Validated on the build host:

```text
sha256sum -c Wuci-OS-x86_64-musl.iso.sha256
make wuci-os-test

Final ISO boot kernel:
  6.12.94_1

Final ISO boot payloads:
  /boot/vmlinuz
    sha256 f2836ab1c0087f49e086c983c4f7c082c20b01de20c00987561314a9aefea4cf
  /boot/initrd
    sha256 b3dddba9a486dde783865cc75576aa15f2db89ea50a33fadb223f78ec32dee0b

Rootfs hardware surface:
  status pass
  kernel release 6.12.94_1
  cfg80211 present
  mac80211 present
  X200s Intel iwlwifi/iwldvm present
  Netgear A8000 / MT7921U fallback modules present
  udev hotplug files present
  USB host controller modules xhci/ehci/uhci present
  lsusb/lspci/iw/rfkill/nmcli/NetworkManager present
  X200s Intel firmware iwlwifi-5000-5.ucode.zst present
  MT7961 firmware present
  depmod refresh pass
  sudo/su normalized to root-owned setuid mode in generated rootfs image

QEMU direct-kernel BIOS smoke against the final ISO reached:
  Linux 6.12.94_1
  dracut live root resolution for CDLABEL=VOID_LIVE
  Mounted root filesystem LiveOS_rootfs
  Welcome to Wuci-OS!
  runit stage 1 complete
  runit stage 2 entered
  QEMU e1000 Ethernet link up

QEMU serial prompt status:
  not reached before the bounded 180 second smoke timeout
  likely local-tty-only getty behavior; still a blocker for serial boot proof
```

Bound v0 payloads:

```text
/wuci-os/WUCI_DAYLIGHT_V8.md
/wuci-os/WUCI_DAYLIGHT_V9.md
/wuci-os/WUCI_DAYLIGHT_V10.md
/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md
/wuci-os/wuci-daylight-v8-sheet.png
/wuci-os/wuci-daylight-v9-sheet.png
/wuci-os/wuci-daylight-v9-spine.svg
/wuci-os/wuci-daylight-v10-scoreboard.png
/wuci-os/wuci-daylight-v13-sovereign-math.png
/wuci-os/wuci-daylight-v14c-plus-ascendant.png
/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png
/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png
/wuci-os/wuci-daylight-wire-model.png
/wuci-os/OFFLINE-INSTALL.txt
```

Live rootfs payloads:

```text
/usr/share/wuci-os/WUCI_DAYLIGHT_V9.md
/usr/share/wuci-os/WUCI_DAYLIGHT_V10.md
/usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md
/usr/share/wuci-os/wuci-daylight-v9-sheet.png
/usr/share/wuci-os/wuci-daylight-v9-spine.svg
/usr/share/wuci-os/wuci-daylight-v10-scoreboard.png
/usr/share/wuci-os/wuci-daylight-v13-sovereign-math.png
/usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant.png
/usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png
/usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png
```

Release gate blockers intentionally kept:

```text
package-closure-fixed-point-missing
qemu-serial-login-prompt-not-reached
qemu-boot-trace-not-bound-to-final-manifest
hardware-boot-trace-missing
final-iso-manifest-signature-missing
witness-ledger-entry-missing
```

Package-suite note:

```text
The extracted rootfs now contains the minimum live Wi-Fi/admin surface:
sudo, su, sv, ip, dhcpcd, iw, rfkill, wpa_supplicant, wpa_passphrase, nmcli,
NetworkManager, dbus-daemon, dracut, parted, linux-firmware-network,
linux-firmware-intel, usbutils, pciutils, xbps-install, and
wuci-network-connect.

The hardware Wi-Fi module closure that failed on the ThinkPad X200s is now a
hard builder gate. The final ISO no longer boots the stale 6.12.11_1 kernel; it
rewrites /boot/vmlinuz and /boot/initrd to the 6.12.94_1 rootfs kernel pair
whose module tree contains cfg80211/mac80211/iwlwifi/iwldvm/MT7921U support.

The full desktop/media/SDR package suite is still not release-closure proven.
Do not describe this artifact as package-closure proven until the full suite
dependency graph is sealed and the release gate is updated.
```

Do not describe v0 as production ready, package-closure proven, hardware-trace
proven, serial-prompt proven, or release-gate passed until the blockers above
have evidence.
