# Wuci-OS Offline Install Guide

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
ls /usr/share/wuci-os/WUCI_DAYLIGHT_V9.md /usr/share/wuci-os/wuci-daylight-v9-sheet.png /usr/share/wuci-os/wuci-daylight-v9-spine.svg
```

Open the preferred terminal with:

```sh
wuci-terminal
```

## 3. Network

```sh
ip link
wuci-network-connect
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
`wpa_supplicant`, `wpa_passphrase`, `dhcpcd`, `iw`, `rfkill`, and `sudo`
at the live prompt. Use `wuci-network-connect` first; use direct `nmcli`
commands only if you want to drive NetworkManager manually.

If Wi-Fi does not work, use wired Ethernet if possible. If no network is
available, continue the local install and run `sudo wuci-update` after first
boot once networking is fixed.

## 4. Media And SDR

```sh
sudo wuci-media-apply
wuci-media-status
sudo wuci-sdr-apply
wuci-sdr-status
wuci-boot-chime --once
```

Unavailable package messages are not fatal during installation. Re-run
`wuci-update`, `wuci-media-apply`, and `wuci-sdr-apply` after first boot when
networking is available.

## 5. Install To Disk

Inspect disks first:

```sh
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
```

Start the Wuci installer context:

```sh
sudo wuci-install
```

Recommended choices:

1. Keyboard: your physical layout, usually `us`.
2. Network: the active connection already configured.
3. Hostname: `wuci-os`.
4. Timezone: your local timezone.
5. Root password: set a strong temporary admin password.
6. User: create `wj` if asked for a normal user.
7. Bootloader: install GRUB to the target disk.
8. UEFI partitioning: 512 MiB FAT32 EFI partition at `/boot/efi`, root at `/`,
   swap optional.
9. Legacy BIOS partitioning: root at `/`, swap optional, bootloader on the disk.
10. Review the selected target disk carefully before confirming writes.
11. Let the installer finish, but do not reboot yet.

## 6. Apply Wuci Before Reboot

After the installer completes, return to a terminal. The installed target is
usually mounted at `/mnt`.

If needed, mount it manually:

```sh
sudo mount /dev/YOUR_ROOT_PARTITION /mnt
sudo mkdir -p /mnt/boot/efi
sudo mount /dev/YOUR_EFI_PARTITION /mnt/boot/efi
```

Apply Wuci-OS to the installed target:

```sh
sudo wuci-install-target-activate /mnt
```

Verify:

```sh
sudo chroot /mnt /usr/local/bin/wuci-status
sudo chroot /mnt /usr/local/bin/wuci-users-status
sudo chroot /mnt /usr/local/bin/wuci-network-status
sudo chroot /mnt /usr/local/bin/wuci-media-status
sudo chroot /mnt /usr/local/bin/wuci-source-status
```

If chroot checks cannot run, confirm the files are present:

```sh
sudo ls /mnt/usr/local/bin/wuci-status
sudo ls /mnt/usr/share/wuci-os/OFFLINE-INSTALL.txt
sudo cat /mnt/etc/os-release
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
sudo wuci-update
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
