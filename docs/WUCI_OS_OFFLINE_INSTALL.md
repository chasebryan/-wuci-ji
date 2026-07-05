# Wuci-OS Offline Install Guide

> [!IMPORTANT]
> This is legacy offline-install documentation for the earlier image lane. It is
> not Noether Core and is not WuciOS v2.4 release evidence. Current WuciOS v2.4
> doctrine is in [WuciOS v2.4 Reduction Gate](wucios/WUCIOS_V24_REDUCTION_GATE.md).

This is the offline checklist to use after booting the ISO. The same guide is
embedded in the ISO at `/wuci-os/OFFLINE-INSTALL.txt` and in the live system at
`/usr/share/wuci-os/OFFLINE-INSTALL.txt`.

## 1. Boot

1. Insert the Wuci-OS USB or attach the ISO.
2. Open the firmware boot menu.
3. Choose the Wuci-OS USB or virtual CD entry.
4. Select `Wuci-Ji Systems / Wuci-OS live`.
5. Wait for the Wuci prompt, banner, or XFCE desktop.
6. On legacy BIOS machines such as the ThinkPad X200s, a `no EFI` message is
   expected and is not a failure.
7. The default Wuci live entry already includes `console=tty0` and
   `rd.driver.pre=loop` for legacy BIOS live-root setup.
8. If you see `losetup /dev/loop0 failed` or `failed to find root filesystem`,
   stop using that USB image and reflash the newest Wuci-OS ISO.
9. If the desktop does not start, log in as `wj`, press Enter at the password
   prompt, and run `startx`.

## 2. First Checks

Run:

```sh
wuci-status
wuci-terminal --print
wuci-network-status
wuci-media-status
wuci-sdr-status
wuci-source-status
wuci-daylight-v14c-plus verify
ls /usr/share/wuci-os/WUCI_DAYLIGHT_V9.md /usr/share/wuci-os/WUCI_DAYLIGHT_V10.md /usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md /usr/share/wuci-os/wuci-daylight-v9-sheet.png /usr/share/wuci-os/wuci-daylight-v9-spine.svg /usr/share/wuci-os/wuci-daylight-v10-scoreboard.png /usr/share/wuci-os/wuci-daylight-v13-sovereign-math.png /usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant.png /usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png /usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png
ls /usr/share/wuci-os/daylight/v14c-plus/README.md /usr/share/wuci-os/daylight/v14c-plus/src/cli.py /usr/share/wuci-os/daylight/v14c-plus/examples/expected-scorecard.v14c-plus.json
```

Open the preferred terminal with:

```sh
wuci-terminal
```

To regenerate the Daylight v14C+ candidate score from onboard frozen inputs:

```sh
wuci-daylight-v14c-plus score
```

## 3. Network

```sh
ip link
wuci-network-connect
doas wuci-network-connect    # if using the opendoas package
sudo wuci-network-apply
nmcli device wifi list
nmcli --ask device wifi connect "YOUR_WIFI_NAME"
ip addr
ping -c 3 1.1.1.1
```

`wuci-network-connect` is the first-boot credential prompt. It asks for the
Wi-Fi SSID and password locally; no network IDs or passwords are baked into the
image. For noninteractive setup you may use `WUCI_WIFI_SSID`,
`WUCI_WIFI_PASSWORD`, and optional `WUCI_WIFI_IFACE` / `WUCI_WIFI_HIDDEN=1`.
The network-fixed image includes NetworkManager/`nmcli`, `dbus`, `sv`,
`wpa_supplicant`, `wpa_passphrase`, `dhcpcd`, `iw`, `rfkill`,
`linux-firmware-network`, `sudo`, and `opendoas` at the live prompt. Use
`wuci-network-connect` first; use direct `nmcli` commands only if you want to
drive NetworkManager manually.

If NetworkManager marks a working Wi-Fi device unavailable, use the direct
`wpa_supplicant` fallback:

```sh
sudo mkdir -p /run/wuci-network
sudo wpa_passphrase "YOUR_WIFI_NAME" "YOUR_WIFI_PASSWORD" | sudo tee /run/wuci-network/wpa.conf >/dev/null
sudo wpa_supplicant -B -i wlp2s0 -c /run/wuci-network/wpa.conf
sudo dhcpcd -n wlp2s0
```

If Wi-Fi does not work, use wired Ethernet if possible. If no network is
available, continue the local install and run `sudo wuci-update --network` after
first boot once networking is fixed.

If `iw`, `nmcli`, or `wuci-network-connect` cannot see Wi-Fi hardware, check the
kernel module closure before trying more passwords:

```sh
uname -r
ls -ld /lib/modules/$(uname -r) /usr/lib/modules/$(uname -r)
find /lib/modules/$(uname -r) /usr/lib/modules/$(uname -r) -iname '*cfg80211*' -o -iname '*mac80211*' -o -iname '*iwlwifi*' -o -iname '*mt7921*' 2>/dev/null
lspci -nnk | grep -A4 -iE 'network|wireless|wifi'
lsusb
dmesg | grep -iE 'cfg80211|mac80211|nl80211|firmware|iwlwifi|usb|xhci|mt76|mt7921'
```

If `cfg80211` is missing for the running kernel, Wi-Fi cannot work on the
built-in X200s adapter or the Netgear A8000 USB adapter. Use Ethernet, then run:

```sh
sudo xbps-install -S
sudo xbps-install -f linux6.12
sudo xbps-install -Sy linux-firmware linux-firmware-network linux-firmware-intel NetworkManager wpa_supplicant iw rfkill pciutils usbutils kmod
sudo depmod -a "$(uname -r)"
sudo reboot
```

After reboot:

```sh
sudo modprobe cfg80211
sudo modprobe mac80211
sudo modprobe iwlwifi
sudo rfkill unblock all
iw dev
nmcli device status
wuci-network-connect
```

## 4. Media And SDR

```sh
sudo wuci-media-apply
wuci-media-status
sudo wuci-sdr-apply
wuci-sdr-status
wuci-boot-chime --once
```

Unavailable package messages are not fatal during installation. Re-run
`wuci-update --network`, `wuci-media-apply`, and `wuci-sdr-apply` after first
boot when networking is available.

## 5. Auto Install To Disk

Inspect disks first:

```sh
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
```

Run the uppercase Wuci installer:

```sh
INSTALL
```

`INSTALL` automates partitioning, formatting, XBPS base install, network and
desktop packages, GRUB, Wuci target activation, services, users, and
verification. It self-updates `xbps` before package transactions when the
repository requires it, installs the `opendoas` package for the `doas` command,
and self-escalates through `sudo` first, then `doas` when needed. It does not
call an external installer backend.

For safety, it shows the target disk and requires the confirmation word
`INSTALL` before erasing. Useful forms:

```sh
INSTALL
INSTALL --disk /dev/sda
INSTALL --disk /dev/sda --yes
WUCI_INSTALL_DISK=/dev/sda INSTALL
INSTALL --disk /dev/sda --kernel-package linux6.12
```

For two disks, the supported combined mode is an explicit RAID1 mirror:

```sh
sudo INSTALL --disk /dev/sda --disk /dev/sdb --raid1
```

Repeating `--disk` without `--raid1` is refused. Wuci-OS does not silently
span or stripe disks during install.

Single-disk legacy BIOS machines such as the ThinkPad X200/X200s use one ext4
root partition and GRUB on the disk. Single-disk UEFI machines get a 512 MiB
EFI partition plus an ext4 root partition. RAID1 installs create matching
partitions on each target disk and an mdadm mirrored root. After the
confirmation, do not interrupt the install.

`wuci-install` is kept as a compatibility alias for `INSTALL`.

## 6. Verify Before Reboot

`INSTALL` runs these checks automatically. If needed, re-run them:

```sh
sudo chroot /mnt /usr/local/bin/wuci-status
sudo chroot /mnt /usr/local/bin/wuci-users-status
sudo chroot /mnt /usr/local/bin/wuci-network-status
sudo chroot /mnt /usr/local/bin/wuci-media-status
sudo chroot /mnt /usr/local/bin/wuci-source-status
```

If target activation needs to be replayed manually:

```sh
sudo mount /dev/YOUR_ROOT_PARTITION /mnt
sudo wuci-install-target-activate /mnt
sync
sudo umount -R /mnt
```

## 7. Reboot

```sh
sync
sudo umount -R /mnt
sudo reboot
```

Remove the USB or detach the ISO when the machine restarts.

## 8. First Boot From Disk

1. Choose the installed Wuci-OS boot entry.
2. The system should autologin to `wj` on tty1.
3. If XFCE is installed, Wuci-OS starts it automatically with `startx`.
4. If XFCE does not start, run:

```sh
wuci-status
sudo wuci-network-apply
sudo wuci-media-apply
sudo wuci-dev-install
startx
```

Rotate passwords immediately:

```sh
sudo passwd root
passwd
```

Update once networking works:

```sh
sudo wuci-update --network
```

Enter the onboard project checkout:

```sh
cd /opt/wuci-os/source/wuci-ji
wuci-source-status
```

If the embedded source is a snapshot instead of a Git checkout:

```sh
wuci-update --source-only --live-repo "$HOME/wuci-ji-live"
cd "$HOME/wuci-ji-live"
```

## 9. Recovery

```sh
wuci-live-banner
wuci-status
wuci-terminal --print
wuci-network-status
wuci-media-status
wuci-sdr-status
wuci-security-status
wuci-daylight-status
wuci-source-status
```

To replay target activation from the live ISO:

```sh
sudo mount /dev/YOUR_ROOT_PARTITION /mnt
sudo wuci-install-target-activate /mnt
sync
sudo umount -R /mnt
```
