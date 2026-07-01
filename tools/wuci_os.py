#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Sequence

import wuci_kaiju
import wuci_progress


PRODUCT_NAME = "Wuci-OS"
IMAGE_ID = "wuci-os"
SOURCE_SCHEMA = "wuci-os-void-musl-source-v1"
SOURCE_VERIFY_SCHEMA = "wuci-os-void-musl-source-verification-v1"
BUILD_PLAN_SCHEMA = "wuci-os-build-plan-v1"
BOOT_SCHEMA = "wuci-os-live-boot-plan-v1"
OVERLAY_SCHEMA = "wuci-os-overlay-v1"
OVERLAY_SEAL_SCHEMA = "wuci-os-daylight-overlay-seal-v1"
OVERLAY_SEAL_BUNDLE_SCHEMA = "wuci-os-daylight-overlay-bundle-v1"
SOURCE_KIT_SCHEMA = "wuci-os-source-kit-v1"
ISO_PLAN_SCHEMA = "wuci-os-finished-iso-plan-v1"
FINAL_ISO_SCHEMA = "wuci-os-final-iso-v1"
FAILURE_SPECIMEN_SCHEMA = "wuci-os-failure-specimen-v1"
BOOT_SPLASH_SCHEMA = "wuci-os-boot-splash-v1"
DEFAULT_SOURCE_ROOT = Path("build/wuci-os/source")
DEFAULT_BOOT_ROOT = Path("build/wuci-os/boot")
DEFAULT_OVERLAY_ROOT = Path("build/wuci-os/overlay")
DEFAULT_SEAL_ROOT = Path("build/wuci-os/daylight")
DEFAULT_FINAL_ROOT = Path("build/wuci-os/final")
DEFAULT_ROOTFS_SOURCE_ROOT = Path("build/wuci-os/rootfs")
DEFAULT_FAILURE_ROOT = Path("build/wuci-os/failures")
DEFAULT_WALLPAPER_SOURCE = Path("docs/wuci-os/assets/wallpaper1.png")
DEFAULT_BOOT_SPLASH_SOURCE = Path("docs/wuci-os/assets/wuci-os-boot-splash.svg")
DEFAULT_MODEL_DIAGRAM_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-wire-model.png")
DEFAULT_DAYLIGHT_V8_DIAGRAM_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v8-sheet.png")
DEFAULT_DAYLIGHT_V9_SHEET_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v9-sheet.png")
DEFAULT_DAYLIGHT_V9_DIAGRAM_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v9-spine.svg")
DEFAULT_DAYLIGHT_V10_SCOREBOARD_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v10-scoreboard.png")
DEFAULT_DAYLIGHT_V13_MATH_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v13-sovereign-math.png")
DEFAULT_DAYLIGHT_V14C_IMAGE_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant.png")
DEFAULT_DAYLIGHT_V14C_MATH_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-math.png")
DEFAULT_DAYLIGHT_V14C_WIDE_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v14c-plus-ascendant-wide.png")
DEFAULT_DAYLIGHT_V15_SOLSTICE_SOURCE = Path("docs/wuci-os/assets/wuci-daylight-v15-plus-solstice.png")
DEFAULT_DAYLIGHT_V14C_PACKAGE_SOURCE = Path("daylight/v14c-plus")
DEFAULT_DAYLIGHT_V15_PACKAGE_SOURCE = Path("daylight/v15-meridian")
SUBSTRACT_MODEL_DOC = Path("docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md")
DAYLIGHT_V8_MODEL_DOC = Path("docs/WUCI_DAYLIGHT_V8.md")
DAYLIGHT_V9_MODEL_DOC = Path("docs/WUCI_DAYLIGHT_V9.md")
DAYLIGHT_V10_MODEL_DOC = Path("docs/WUCI_DAYLIGHT_V10.md")
DAYLIGHT_V13_MODEL_DOC = Path("docs/WUCI_DAYLIGHT_V13_SOVEREIGN.md")
BOOT_SPLASH_PNG_NAME = "wuci-os-boot-splash.png"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
OVERLAY_WALLPAPER_PATH = Path("usr/share/backgrounds/wuci-os/wallpaper1.png")
DEFAULT_WUCI_BIN = Path("build/wuci-ji")
FINAL_ISO_NAME = "Wuci-OS-x86_64-musl.iso"
SOURCE_KIT_PREFIX = Path("opt/wuci-os/source/wuci-ji")
UPSTREAM_SOURCE_PREFIX = Path("opt/wuci-os/source/upstream")
SOURCE_KIT_GUEST_MANIFEST = Path("usr/share/wuci-os/source-kit.json")
SOURCE_KIT_TAR_NAME = "wuci-os-source-kit.tar"
SOURCE_KIT_DETERMINISTIC_CREATED_UTC = "1970-01-01T00:00:00Z"
DEFAULT_UPSTREAM_ROOT = Path("build/wuci-os/upstream")
SOURCE_MANIFEST_NAME = "source.json"
VOID_LIVE_LABEL = "VOID_LIVE"
VOID_ISO_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\.iso")
VOID_RELEASE_RE = re.compile(r"void-live-[^-]+-musl-(\d{8})")
DEFAULT_QEMU_BIN = wuci_kaiju.DEFAULT_QEMU_BIN
DEFAULT_QEMU_CANDIDATES = wuci_kaiju.DEFAULT_QEMU_CANDIDATES
DEFAULT_MEMORY_MIB = 2048
DEFAULT_CPUS = 2
REQUIRED_VOID_PATHS = (
    "boot/vmlinuz",
    "boot/initrd",
    "LiveOS/squashfs.img",
    "boot/isolinux/isolinux.cfg",
)
BOUNDARY_DENIALS = (
    "source evidence is local digest evidence, not upstream signature authority",
    "Wuci-OS does not claim runtime sandboxing or host containment",
    "Wuci-OS does not claim quantum safety from the base image",
    "upstream base attribution remains in source evidence and license metadata",
    "no offensive scanning or exploit tooling is added by this lane",
    "SELinux, LUKS, and Daylight/WJSEAL status must be verified on the installed system before security claims",
)

LIVE_COMMAND_SURFACE_REQUIRED = (
    "usr/bin/sudo",
    "usr/bin/su",
    "usr/bin/sv",
    "usr/bin/ip",
    "usr/bin/dhcpcd",
    "usr/bin/iw",
    "usr/bin/rfkill",
    "usr/bin/wpa_supplicant",
    "usr/bin/wpa_passphrase",
    "usr/bin/nmcli",
    "usr/bin/NetworkManager",
    "usr/bin/dbus-daemon",
    "usr/bin/xbps-install",
    "usr/local/bin/INSTALL",
    "usr/local/bin/wuci-network-connect",
    "usr/local/bin/wuci-install",
    "usr/local/bin/wuci-install-target-activate",
    "usr/local/bin/wj",
)

MINIMUM_LIVE_NETWORK_PACKAGES = (
    "sudo",
    "kmod",
    "pciutils",
    "usbutils",
    "iproute2",
    "dhcpcd",
    "iw",
    "rfkill",
    "wpa_supplicant",
    "iwd",
    "dbus",
    "NetworkManager",
    "dracut",
    "parted",
    "libkmod",
    "linux-firmware-network",
    "linux-firmware-intel",
)

MINIMUM_LIVE_NETWORK_REQUIRED_PATHS = (
    "usr/bin/sudo",
    "usr/bin/sv",
    "usr/bin/depmod",
    "usr/bin/modprobe",
    "usr/bin/lspci",
    "usr/bin/lsusb",
    "usr/bin/udevadm",
    "usr/bin/udevd",
    "usr/bin/ip",
    "usr/bin/dhcpcd",
    "usr/bin/iw",
    "usr/bin/rfkill",
    "usr/bin/wpa_supplicant",
    "usr/bin/wpa_passphrase",
    "usr/bin/nmcli",
    "usr/bin/NetworkManager",
    "usr/bin/dbus-daemon",
    "usr/bin/dracut",
    "usr/bin/parted",
    "usr/lib/firmware/iwlwifi-5000-5.ucode.zst",
    "usr/lib/firmware/mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin.zst",
    "usr/lib/firmware/mediatek/WIFI_RAM_CODE_MT7961_1.bin.zst",
)

LIVE_KERNEL_MODULE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "nl80211-cfg80211": ("kernel/net/wireless/cfg80211.ko*",),
    "mac80211-core": ("kernel/net/mac80211/mac80211.ko*",),
    "x200s-intel-iwlwifi": (
        "kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko*",
        "kernel/drivers/net/wireless/intel/iwlwifi/dvm/iwldvm.ko*",
    ),
    "netgear-a8000-mt7921u": (
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921u.ko*",
        "kernel/drivers/net/wireless/mediatek/mt76/mt7921/mt7921-common.ko*",
        "kernel/drivers/net/wireless/mediatek/mt76/mt76-usb.ko*",
        "kernel/drivers/net/wireless/mediatek/mt76/mt76.ko*",
    ),
    "usb-host-controllers": (
        "kernel/drivers/usb/host/xhci*.ko*",
        "kernel/drivers/usb/host/ehci*.ko*",
        "kernel/drivers/usb/host/uhci*.ko*",
    ),
}

LIVE_USB_HOTPLUG_REQUIRED_PATHS = (
    "etc/sv/udevd",
    "etc/runit/runsvdir/default/udevd",
    "usr/lib/udev/rules.d/80-drivers.rules",
    "usr/lib/udev/hwdb.d/20-usb-vendor-model.hwdb",
    "usr/lib/udev/rules.d/75-net-description.rules",
)

AUTH_SETUID_REQUIRED_PATHS = (
    "usr/bin/sudo",
    "usr/bin/su",
)
AUTH_SETUID_OPTIONAL_PATHS = (
    "usr/bin/doas",
)



DESKTOP_PACKAGES = (
    "xorg",
    "xinit",
    "xfce4",
    "xfce4-terminal",
    "kitty",
    "ghostty",
    "xterm",
    "ratpoison",
    "dbus",
    "elogind",
    "polkit",
    "NetworkManager",
    "ImageMagick",
    "feh",
    "xwallpaper",
    "dmenu",
    "firefox",
)

AUDIO_PACKAGES = (
    "alsa-utils",
    "pipewire",
    "wireplumber",
    "pulseaudio-utils",
    "pavucontrol",
    "ffmpeg",
    "mpv",
    "vlc",
    "gstreamer1",
    "gst-plugins-base1",
    "gst-plugins-good1",
    "gst-plugins-bad1",
    "gst-plugins-ugly1",
)

NETWORK_PACKAGES = (
    "NetworkManager",
    "NetworkManager-openvpn",
    "wpa_supplicant",
    "iwd",
    "dhcpcd",
    "dhclient",
    "iproute2",
    "iputils",
    "iw",
    "wireless_tools",
    "rfkill",
    "openresolv",
    "nftables",
    "chrony",
    "avahi",
    "ModemManager",
    "mobile-broadband-provider-info",
    "openvpn",
)

FIRMWARE_PACKAGES = (
    "linux-firmware",
    "linux-firmware-network",
    "linux-firmware-intel",
    "linux-firmware-amd",
)

VIDEO_PACKAGES = (
    "mesa-dri",
    "mesa-vaapi",
    "mesa-vdpau",
    "mesa-vulkan-intel",
    "mesa-vulkan-radeon",
    "vulkan-loader",
    "vulkan-tools",
    "libva",
    "libva-utils",
    "vdpauinfo",
    "xf86-video-amdgpu",
    "xf86-video-intel",
    "xf86-video-nouveau",
    "xf86-video-vesa",
    "xf86-video-fbdev",
    "brightnessctl",
)

PERIPHERAL_PACKAGES = (
    "bluez",
    "bluez-alsa",
    "cups",
    "cups-filters",
    "system-config-printer",
    "sane",
    "simple-scan",
    "xdg-desktop-portal",
    "xdg-desktop-portal-gtk",
    "gvfs",
    "udisks2",
    "upower",
)

SDR_PACKAGES = (
    "gnuradio",
    "gqrx",
    "rtl-sdr",
    "hackrf",
    "airspy",
    "airspyhf",
    "SoapySDR",
    "SoapyRTLSDR",
    "SoapyHackRF",
    "SoapyAirspy",
    "gr-osmosdr",
    "inspectrum",
    "sigutils",
    "liquid-dsp",
    "uhd",
    "soapysdr",
    "usbutils",
)

SDR_OPTIONAL_PACKAGES = (
    "sdrangel",
    "cubicsdr",
    "qspectrumanalyzer",
    "dump1090",
    "multimon-ng",
    "fldigi",
)

TERMINAL_CANDIDATES = (
    "kitty",
    "ghostty",
    "xfce4-terminal",
    "xterm",
    "alacritty",
    "foot",
    "wezterm",
    "st",
    "urxvt",
    "rxvt",
)

FAST_BOOT_KERNEL_ARGS = (
    "console=ttyS0,115200n8",
    "console=tty0",
    "nomodeset",
    "rd.md=0",
    "rd.dm=0",
    "rd.luks=0",
    "rd.lvm=0",
    "rd.auto=0",
    "rd.udev.log_level=3",
    "loglevel=3",
    "modprobe.blacklist=raid456,async_raid6_recov,dm_raid,md_mod,btrfs",
)

FAST_BOOT_MODPROBE_BLACKLIST = (
    "raid456",
    "async_raid6_recov",
    "dm_raid",
    "md_mod",
    "btrfs",
)

LEGACY_BIOS_LIVE_KERNEL_ARGS = (
    "console=tty0",
    "rd.driver.pre=loop",
    "live.hostname=wuci-os-live",
)

BOOT_ENTRY_LABELS = {
    "linux": "Wuci-Ji Systems / Wuci-OS live",
    "linuxram": "Wuci-OS live (copy to RAM)",
    "linuxnogfx": "Wuci-OS live (safe graphics)",
    "linuxa11y": "Wuci-OS accessibility (speech)",
    "linuxa11yram": "Wuci-OS accessibility (speech, copy to RAM)",
    "linuxa11ynogfx": "Wuci-OS accessibility (speech, safe graphics)",
    "c": "Boot first hard disk",
    "memtest": "Wuci-OS memory test",
    "uefifw": "UEFI firmware settings",
    "restart": "Restart",
    "reboot": "Reboot",
    "poweroff": "Power off",
}

BASE_DEV_PACKAGES = (
    "ca-certificates",
    "curl",
    "wget",
    "git",
    "git-lfs",
    "openssh",
    "gnupg2",
    "pinentry",
    "bash",
    "zsh",
    "fish-shell",
    "tmux",
    "screen",
    "make",
    "cmake",
    "ninja",
    "pkg-config",
    "autoconf",
    "automake",
    "libtool",
    "gettext",
    "patch",
    "diffutils",
    "ripgrep",
    "fd",
    "fzf",
    "jq",
    "yq",
    "tree",
    "file",
    "less",
    "man-pages",
    "mandoc",
    "zip",
    "unzip",
    "p7zip",
    "xz",
    "zstd",
    "rsync",
    "shellcheck",
    "shfmt",
    "hyperfine",
)

LANGUAGE_PACKAGE_GROUPS: dict[str, tuple[str, ...]] = {
    "c_cpp": (
        "gcc",
        "clang",
        "llvm",
        "lld",
        "gdb",
        "lldb",
        "valgrind",
        "strace",
        "ltrace",
        "linux-headers",
        "musl-devel",
    ),
    "python": (
        "python3",
        "python3-pip",
        "python3-virtualenv",
        "python3-setuptools",
        "python3-wheel",
        "python3-devel",
    ),
    "javascript_typescript": (
        "nodejs",
        "npm",
        "yarn",
    ),
    "rust": (
        "rust",
        "cargo",
        "rust-analyzer",
    ),
    "go": (
        "go",
        "gopls",
    ),
    "java_jvm": (
        "openjdk17",
        "maven",
        "gradle",
        "ant",
        "kotlin",
        "scala",
        "sbt",
        "clojure",
    ),
    "ruby": (
        "ruby",
        "ruby-devel",
    ),
    "php": (
        "php",
        "php-devel",
        "composer",
    ),
    "perl_lua": (
        "perl",
        "lua",
        "lua-devel",
        "luarocks",
    ),
    "data_science": (
        "R",
        "julia",
    ),
    "systems_extras": (
        "zig",
        "nim",
        "crystal",
        "erlang",
        "elixir",
        "ocaml",
        "opam",
        "ghc",
        "cabal-install",
        "racket",
        "sbcl",
    ),
    "databases": (
        "sqlite",
        "postgresql-libs",
        "mariadb-client",
        "redis",
    ),
    "containers_vm": (
        "podman",
        "buildah",
        "skopeo",
        "qemu",
        "libvirt",
    ),
}

SECURITY_PACKAGES = (
    "cryptsetup",
    "lvm2",
    "nftables",
    "openssh",
    "openssl",
    "audit",
    "sudo",
    "opendoas",
)

SELINUX_CANDIDATE_PACKAGES = (
    "libselinux",
    "libsepol",
    "libsemanage",
    "checkpolicy",
    "policycoreutils",
    "selinux-python",
    "setools",
    "selinux-policy",
)

KICKSECURE_INSPIRED_HARDENING = (
    "kernel.kptr_restrict=2",
    "kernel.dmesg_restrict=1",
    "kernel.yama.ptrace_scope=3",
    "kernel.randomize_va_space=2",
    "kernel.unprivileged_bpf_disabled=1",
    "kernel.perf_event_paranoid=3",
    "kernel.kexec_load_disabled=1",
    "kernel.sysrq=0",
    "kernel.core_uses_pid=1",
    "fs.suid_dumpable=0",
    "net.core.bpf_jit_harden=2",
    "fs.protected_hardlinks=1",
    "fs.protected_symlinks=1",
    "fs.protected_fifos=2",
    "fs.protected_regular=2",
    "dev.tty.ldisc_autoload=0",
    "user.max_user_namespaces=0",
    "net.ipv4.tcp_syncookies=1",
    "net.ipv4.conf.all.rp_filter=1",
    "net.ipv4.conf.default.rp_filter=1",
)

SELINUX_GRUB_FLAGS = (
    "security=selinux",
    "selinux=1",
    "enforcing=1",
    "lsm=landlock,lockdown,yama,integrity,selinux,bpf",
)


def full_suite_packages() -> tuple[str, ...]:
    language_packages: list[str] = []
    for packages in LANGUAGE_PACKAGE_GROUPS.values():
        language_packages.extend(packages)
    return tuple(
        sorted(
            set(
                BASE_DEV_PACKAGES
                + DESKTOP_PACKAGES
                + AUDIO_PACKAGES
                + NETWORK_PACKAGES
                + FIRMWARE_PACKAGES
                + VIDEO_PACKAGES
                + PERIPHERAL_PACKAGES
                + SDR_PACKAGES
                + SDR_OPTIONAL_PACKAGES
                + SECURITY_PACKAGES
                + SELINUX_CANDIDATE_PACKAGES
                + tuple(language_packages)
                + ("vim", "emacs", "nano")
            )
        )
    )


DAYLIGHT_REQUIRED_COMPONENTS = (
    "source ISO digest manifest",
    "overlay manifest",
    "account profile",
    "developer package profile",
    "security profile",
    "wallpaper asset digest",
    "deterministic overlay tar",
    "QEMU boot plan",
    "generated rootfs image",
    "generated install image",
    "package repository metadata",
    "release receipt bundle",
)

RUST_REDESIGN_COMPONENTS = (
    {
        "component": "wuci-os-manifest",
        "target": "Rust serde model and canonical JSON writer",
        "priority": 1,
        "boundary": "must preserve current Python JSON schema and digest vectors",
    },
    {
        "component": "wuci-os-overlay-builder",
        "target": "Rust deterministic filesystem tree and tar writer",
        "priority": 1,
        "boundary": "must reject symlinks/hardlinks and match current overlay records",
    },
    {
        "component": "wuci-os-daylight-sealer",
        "target": "Rust wrapper around WJSEAL/Daylight artifact sealing",
        "priority": 1,
        "boundary": "must keep key material local and never embed credentials",
    },
    {
        "component": "wuci-os-guide",
        "target": "Rust terminal guide with explicit check/next-step states",
        "priority": 2,
        "boundary": "must remain non-offensive and high-assurance focused",
    },
    {
        "component": "wuci-os-installer-profile",
        "target": "Rust install profile verifier for LUKS, SELinux, nftables, users, and receipts",
        "priority": 2,
        "boundary": "must not perform destructive disk writes without explicit operator selection",
    },
)


class WuciOSError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def utc_now() -> str:
    return wuci_kaiju.utc_now()


def resolve_repo_path(value: str | None, default: Path) -> Path:
    path = default if value is None else Path(value)
    if path.is_absolute():
        return path
    return repo_root() / path


def safe_iso_name(name: str) -> str:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise WuciOSError("ISO name must be a plain filename")
    if not VOID_ISO_RE.fullmatch(name):
        raise WuciOSError("ISO name must be a plain .iso filename")
    return name


def source_manifest_path(source_root: Path) -> Path:
    return source_root / SOURCE_MANIFEST_NAME


def read_source_manifest(source_root: Path) -> dict[str, Any]:
    try:
        return wuci_kaiju.read_public_json(source_manifest_path(source_root), "Wuci-OS source manifest")
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc


def wuci_public_source_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    public_manifest = json.loads(json.dumps(manifest))
    base = public_manifest.get("base")
    if isinstance(base, dict) and base.get("distribution") == "Void Linux":
        base["distribution"] = "Wuci-OS live base"
    return public_manifest


def release_stamp_from_name(name: str) -> str:
    match = VOID_RELEASE_RE.search(name)
    return match.group(1) if match else "unknown"


def _extract_iso_text(image_path: Path, subpath: str) -> str:
    data = wuci_kaiju._extract_iso_file_content(image_path, subpath)
    if data is None:
        try:
            import pycdlib  # type: ignore[import-not-found]

            iso = pycdlib.PyCdlib()
            iso.open(str(image_path))
            try:
                for key in ("rr_path", "joliet_path", "iso_path"):
                    handle = io.BytesIO()
                    try:
                        iso.get_file_from_iso_fp(handle, **{key: "/" + subpath.lstrip("/")})
                    except Exception:
                        continue
                    data = handle.getvalue()
                    break
            finally:
                iso.close()
        except Exception:
            data = None
    if data is None:
        return ""
    return data.decode("utf-8", "replace")


def _extract_iso_bytes(image_path: Path, subpath: str, label: str) -> bytes:
    data = wuci_kaiju._extract_iso_file_content(image_path, subpath)
    if data is not None:
        return data
    try:
        import pycdlib  # type: ignore[import-not-found]
    except ImportError as exc:
        raise WuciOSError(f"could not extract {label}: pycdlib is required for fallback ISO reads") from exc
    iso = pycdlib.PyCdlib()
    try:
        iso.open(str(image_path))
        for key in ("rr_path", "joliet_path", "iso_path"):
            handle = io.BytesIO()
            try:
                iso.get_file_from_iso_fp(handle, **{key: "/" + subpath.lstrip("/")})
            except Exception:
                continue
            data = handle.getvalue()
            if data:
                return data
    finally:
        iso.close()
    raise WuciOSError(f"source ISO does not contain {label}: {subpath}")


def inspect_void_iso(image_path: Path) -> dict[str, Any]:
    found: dict[str, dict[str, int]] = {}
    missing: list[str] = []
    for subpath in REQUIRED_VOID_PATHS:
        try:
            loc = wuci_kaiju._locate_iso_file(image_path, subpath)
        except Exception as exc:
            missing.append(f"{subpath}: {exc}")
            continue
        if loc is None:
            missing.append(subpath)
            continue
        offset, size = loc
        found[subpath] = {"offset": offset, "bytes": size}
    append = ""
    boot_menu = ""
    if "boot/isolinux/isolinux.cfg" in found:
        boot_menu = _extract_iso_text(image_path, "boot/isolinux/isolinux.cfg")
        append = first_isolinux_append(boot_menu)
    problems: list[str] = []
    if missing:
        problems.append("missing required live image paths: " + ", ".join(missing))
    if append and f"root=live:CDLABEL={VOID_LIVE_LABEL}" not in append:
        problems.append("isolinux APPEND line does not target the expected live label")
    if not append:
        problems.append("missing isolinux APPEND line")
    return {
        "schema": "wuci-os-void-musl-layout-v1",
        "status": "pass" if not problems else "fail",
        "label": VOID_LIVE_LABEL,
        "required_paths": list(REQUIRED_VOID_PATHS),
        "found": found,
        "append": append,
        "problems": problems,
    }


def first_isolinux_append(text: str) -> str:
    in_linux = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        upper = line.upper()
        if upper.startswith("LABEL "):
            in_linux = line.split(maxsplit=1)[1] == "linux"
            continue
        if in_linux and upper.startswith("APPEND "):
            return line.split(maxsplit=1)[1].strip()
    for raw in text.splitlines():
        line = raw.strip()
        if line.upper().startswith("APPEND "):
            return line.split(maxsplit=1)[1].strip()
    return ""


def _append_kernel_arg(parts: list[str], required: str) -> None:
    if required.startswith("console="):
        if required not in parts:
            parts.append(required)
        return
    if "=" in required:
        prefix = required.split("=", 1)[0] + "="
        parts[:] = [part for part in parts if not part.startswith(prefix)]
    if required not in parts:
        parts.append(required)


def wuci_fast_boot_append(append: str, *, include_initrd: bool, fast_boot: bool = True) -> str:
    parts = [part for part in append.split() if include_initrd or not part.startswith("initrd=")]
    required_args = FAST_BOOT_KERNEL_ARGS if fast_boot else ("console=ttyS0,115200n8", "console=tty0", "nomodeset")
    for required in required_args:
        _append_kernel_arg(parts, required)
    return " ".join(parts)


def wuci_legacy_bios_live_append(append: str, *, include_initrd: bool) -> str:
    parts = [part for part in append.split() if include_initrd or not part.startswith("initrd=")]
    for required in LEGACY_BIOS_LIVE_KERNEL_ARGS:
        _append_kernel_arg(parts, required)
    return " ".join(parts)


def serial_append_from_void(append: str, *, fast_boot: bool = True) -> str:
    if fast_boot:
        return wuci_fast_boot_append(append, include_initrd=False)
    parts = [part for part in append.split() if not part.startswith("initrd=")]
    for required in ("console=ttyS0,115200n8", "console=tty0", "nomodeset"):
        _append_kernel_arg(parts, required)
    return " ".join(parts)


def wuci_boot_entry_label(entry_id: str | None, original_label: str) -> str:
    key = (entry_id or "").strip().strip('"').strip("'").lower()
    if key in BOOT_ENTRY_LABELS:
        return BOOT_ENTRY_LABELS[key]
    lowered = original_label.lower()
    if "void linux" in lowered or "wuci-os" in lowered:
        if "speech" in lowered and "ram" in lowered:
            return BOOT_ENTRY_LABELS["linuxa11yram"]
        if "speech" in lowered and "graphics" in lowered:
            return BOOT_ENTRY_LABELS["linuxa11ynogfx"]
        if "speech" in lowered:
            return BOOT_ENTRY_LABELS["linuxa11y"]
        if "ram" in lowered:
            return BOOT_ENTRY_LABELS["linuxram"]
        if "graphics" in lowered:
            return BOOT_ENTRY_LABELS["linuxnogfx"]
        return BOOT_ENTRY_LABELS["linux"]
    if "memtest" in lowered or "ram test" in lowered:
        return BOOT_ENTRY_LABELS["memtest"]
    if "restart" in lowered or "reboot" in lowered:
        return BOOT_ENTRY_LABELS["restart"]
    if "shutdown" in lowered or "power off" in lowered:
        return BOOT_ENTRY_LABELS["poweroff"]
    normalized = original_label.replace("^", "")
    normalized = re.sub(r"Void Linux\s+[^\s()]+", "Wuci-OS", normalized)
    normalized = normalized.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS")
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized or "Wuci-OS boot option"


def _grub_entry_id(text: str) -> str | None:
    match = re.search(r"--id(?:=|\s+)(?:[\"']?)([^\"'\s{]+)", text)
    return match.group(1) if match else None


def _replace_grub_title(line: str, label: str, keyword: str) -> str | None:
    match = re.match(rf"^(\s*{keyword}\s+)([\"'])(.*?)(\2)(.*)$", line)
    if not match:
        return None
    return f"{match.group(1)}{match.group(2)}{label}{match.group(4)}{match.group(5)}"


def _append_grub_live_kernel_args(line: str) -> str:
    if "root=live:" not in line:
        return line
    indent = line[: len(line) - len(line.lstrip())]
    suffix = ""
    body = line.strip()
    if body.endswith("\\"):
        suffix = " \\"
        body = body[:-1].rstrip()
    parts = body.split()
    for required in LEGACY_BIOS_LIVE_KERNEL_ARGS:
        _append_kernel_arg(parts, required)
    return indent + " ".join(parts) + suffix


def rewrite_isolinux_config_for_wuci(text: str) -> str:
    rows: list[str] = []
    inserted_title = False
    inserted_background = False
    current_label: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        upper = stripped.upper()
        indent = line[: len(line) - len(line.lstrip())]
        if upper.startswith("LABEL "):
            current_label = stripped.split(maxsplit=1)[1].strip() if len(stripped.split(maxsplit=1)) == 2 else None
            rows.append(line)
            continue
        if upper.startswith("MENU TITLE "):
            rows.append(f"{indent}MENU TITLE Wuci-OS")
            inserted_title = True
            continue
        if upper.startswith("MENU BACKGROUND "):
            rows.append(f"{indent}MENU BACKGROUND /boot/isolinux/wuci-splash.png")
            inserted_background = True
            continue
        if upper.startswith("MENU LABEL "):
            original_label = stripped.split(maxsplit=2)[2] if len(stripped.split(maxsplit=2)) == 3 else ""
            rows.append(f"{indent}MENU LABEL {wuci_boot_entry_label(current_label, original_label)}")
            continue
        if upper.startswith("APPEND "):
            append = stripped.split(maxsplit=1)[1] if len(stripped.split(maxsplit=1)) == 2 else ""
            if current_label and current_label.lower().startswith("linux"):
                rows.append(f"{indent}APPEND {wuci_legacy_bios_live_append(append, include_initrd=True)}")
            else:
                rows.append(line.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
            continue
        rows.append(line.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
    if not inserted_title:
        rows.insert(0, "MENU TITLE Wuci-OS")
    if not inserted_background:
        insert_at = 1 if rows and rows[0].strip().upper().startswith("MENU TITLE ") else 0
        rows.insert(insert_at, "MENU BACKGROUND /boot/isolinux/wuci-splash.png")
    return "\n".join(rows) + "\n"


def rewrite_grub_config_for_wuci(text: str) -> str:
    rows: list[str] = []
    inserted_background = False
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if stripped.startswith("menuentry "):
            original = re.match(r"^\s*menuentry\s+([\"'])(.*?)(\1)", line)
            original_label = original.group(2) if original else ""
            label = wuci_boot_entry_label(_grub_entry_id(stripped), original_label)
            rows.append(_replace_grub_title(line, label, "menuentry") or line.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
            continue
        if stripped.startswith("submenu "):
            rows.append(_replace_grub_title(line, "Wuci-Ji Systems recovery and tools", "submenu") or line.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
            continue
        if stripped.startswith("background_image "):
            rows.append("background_image /boot/grub/wuci-splash.png")
            inserted_background = True
            continue
        if "root=live:" in stripped:
            rows.append(_append_grub_live_kernel_args(line).replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
            continue
        rows.append(line.replace("Void Linux", "Wuci-OS").replace("Void", "Wuci-OS"))
    header = [
        "set menu_color_normal=white/black",
        "set menu_color_highlight=black/light-red",
        "if [ -f /boot/grub/wuci-splash.png ]; then",
        "  background_image /boot/grub/wuci-splash.png",
        "fi",
    ]
    if not inserted_background:
        rows = header + rows
    return "\n".join(rows) + "\n"


def discover_qemu(qemu_bin: str = DEFAULT_QEMU_BIN) -> str | None:
    return wuci_kaiju.discover_qemu(qemu_bin)


def install_source(
    source: Path,
    *,
    source_root: Path | None = None,
    name: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    root = DEFAULT_SOURCE_ROOT if source_root is None else source_root
    _prepare_output_directory(root, "Wuci-OS source workspace")
    try:
        source_info = wuci_kaiju.require_regular_local_file(source, "Wuci-OS base live ISO source")
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    iso_name = safe_iso_name(name or source.name)
    dest = root / iso_name
    if source.resolve() == dest.resolve():
        raise WuciOSError("Wuci-OS source ISO source and destination must differ")
    _prepare_replacement_output_path(dest, "Wuci-OS source ISO", force=force)

    tmp_fd = -1
    tmp_name = ""
    dest_installed = False
    dest_backup_name = ""
    manifest_backup_name = ""
    manifest_write_started = False
    manifest_path = source_manifest_path(root)
    try:
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{iso_name}.", dir=str(root))
        digests = {
            "sha256": hashlib.sha256(),
            "sha384": hashlib.sha384(),
            "sha512": hashlib.sha512(),
        }
        source_fd = os.open(source, os.O_RDONLY | wuci_kaiju._cloexec() | wuci_kaiju._nofollow())
        total = 0
        try:
            opened = os.fstat(source_fd)
            if not stat.S_ISREG(opened.st_mode):
                raise WuciOSError(f"Wuci-OS source ISO changed type while opening: {source}")
            if opened.st_ino != source_info.st_ino or opened.st_dev != source_info.st_dev:
                raise WuciOSError(f"Wuci-OS source ISO changed while opening: {source}")
            if opened.st_size != source_info.st_size or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(source_info.st_mode):
                raise WuciOSError(f"Wuci-OS source ISO changed while opening: {source}")
            if opened.st_nlink != 1:
                raise WuciOSError(f"Wuci-OS source ISO must not be hardlinked: {source}")
            with os.fdopen(tmp_fd, "wb") as out_handle:
                tmp_fd = -1
                while True:
                    chunk = os.read(source_fd, wuci_kaiju.READ_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    for digest in digests.values():
                        digest.update(chunk)
                    out_handle.write(chunk)
                out_handle.flush()
                os.fsync(out_handle.fileno())
        finally:
            os.close(source_fd)
        if total == 0:
            raise WuciOSError("Wuci-OS source ISO is empty")
        if total != opened.st_size:
            raise WuciOSError(f"Wuci-OS source ISO changed while reading: {source}")
        copied_digest_vector = {digest_name: digest.hexdigest() for digest_name, digest in digests.items()}
        tmp_path = Path(tmp_name)
        try:
            tmp_digest_vector, tmp_size = wuci_kaiju.file_digest_vector(tmp_path, "Wuci-OS source ISO candidate")
        except wuci_kaiju.KaijuError as exc:
            raise WuciOSError(str(exc)) from exc
        if tmp_size != total or tmp_digest_vector != copied_digest_vector:
            raise WuciOSError("Wuci-OS source ISO digest changed before install")
        layout = inspect_void_iso(tmp_path)
        if layout.get("status") != "pass":
            problems = "; ".join(str(problem) for problem in layout.get("problems", []))
            raise WuciOSError(f"Wuci-OS base live ISO layout verification failed: {problems}")
        try:
            wuci_kaiju.reject_unsafe_existing_path(manifest_path, "Wuci-OS source manifest")
        except wuci_kaiju.KaijuError as exc:
            raise WuciOSError(str(exc)) from exc
        dest_backup_name = _backup_existing_regular_file(dest, "Wuci-OS source ISO")
        manifest_backup_name = _backup_existing_regular_file(manifest_path, "Wuci-OS source manifest")
        os.replace(tmp_name, dest)
        dest_installed = True
        tmp_name = ""
        _fsync_parent(dest)
        try:
            dest_digest_vector, dest_size = wuci_kaiju.file_digest_vector(dest, "Wuci-OS source ISO")
        except wuci_kaiju.KaijuError as exc:
            raise WuciOSError(str(exc)) from exc
        if dest_size != total or dest_digest_vector != copied_digest_vector:
            raise WuciOSError("Wuci-OS source ISO digest changed after copy")
        manifest: dict[str, Any] = {
            "schema": SOURCE_SCHEMA,
            "created_utc": utc_now(),
            "product": PRODUCT_NAME,
            "image_id": IMAGE_ID,
            "base": {
                "distribution": "Wuci-OS live base",
                "libc": "musl",
                "image_kind": "live base ISO",
                "upstream_label": VOID_LIVE_LABEL,
                "release_stamp": release_stamp_from_name(iso_name),
            },
            "operator_supplied": True,
            "source_path": str(source),
            "image_name": iso_name,
            "image_path": str(dest),
            "image_bytes": dest_size,
            "digest_vector": dest_digest_vector,
            "layout": layout,
            "boundary_denials": list(BOUNDARY_DENIALS),
        }
        manifest_write_started = True
        wuci_kaiju.write_json_atomic(manifest_path, manifest)
        _fsync_parent(manifest_path)
        _discard_temporary_path(dest_backup_name)
        dest_backup_name = ""
        _discard_temporary_path(manifest_backup_name)
        manifest_backup_name = ""
        return manifest
    except Exception as exc:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        rollback_errors = []
        try:
            if dest_backup_name:
                _restore_backup_file(dest, dest_backup_name, "Wuci-OS source ISO")
            elif dest_installed:
                _unlink_existing_path(str(dest))
        except WuciOSError as rollback_exc:
            rollback_errors.append(str(rollback_exc))
        try:
            if manifest_backup_name:
                _restore_backup_file(manifest_path, manifest_backup_name, "Wuci-OS source manifest")
            elif manifest_write_started:
                _unlink_existing_path(str(manifest_path))
        except WuciOSError as rollback_exc:
            rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise WuciOSError(
                f"source install failed and rollback failed: {exc}; {'; '.join(rollback_errors)}"
            ) from exc
        raise


def verify_source(source_root: Path | None = None, *, require_layout: bool = True) -> dict[str, Any]:
    root = DEFAULT_SOURCE_ROOT if source_root is None else source_root
    problems: list[str] = []
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        root_info = None
    except OSError as exc:
        return {
            "schema": SOURCE_VERIFY_SCHEMA,
            "status": "fail",
            "source_root": str(root),
            "problems": [f"could not inspect source root: {exc}"],
            "non_claims": list(BOUNDARY_DENIALS),
        }
    if root_info is not None:
        if stat.S_ISLNK(root_info.st_mode):
            return {
                "schema": SOURCE_VERIFY_SCHEMA,
                "status": "fail",
                "source_root": str(root),
                "problems": [f"source root must not be a symlink: {root}"],
                "non_claims": list(BOUNDARY_DENIALS),
            }
        if not stat.S_ISDIR(root_info.st_mode):
            return {
                "schema": SOURCE_VERIFY_SCHEMA,
                "status": "fail",
                "source_root": str(root),
                "problems": [f"source root must be a directory: {root}"],
                "non_claims": list(BOUNDARY_DENIALS),
            }
    try:
        manifest = read_source_manifest(root)
    except WuciOSError as exc:
        return {
            "schema": SOURCE_VERIFY_SCHEMA,
            "status": "missing",
            "source_root": str(root),
            "problems": [str(exc)],
        }
    if manifest.get("schema") != SOURCE_SCHEMA:
        problems.append("source manifest schema mismatch")
    if manifest.get("product") != PRODUCT_NAME:
        problems.append("source manifest product mismatch")
    if manifest.get("image_id") != IMAGE_ID:
        problems.append("source manifest image_id mismatch")
    if manifest.get("operator_supplied") is not True:
        problems.append("operator_supplied must be true")
    if manifest.get("boundary_denials") != list(BOUNDARY_DENIALS):
        problems.append("boundary_denials mismatch")
    image_path_value = manifest.get("image_path")
    image_path = Path(str(image_path_value)) if isinstance(image_path_value, str) else root / "missing.iso"
    if not isinstance(image_path_value, str):
        problems.append("image_path missing")
    image_name_value = manifest.get("image_name")
    expected_image_name = ""
    if isinstance(image_name_value, str):
        try:
            expected_image_name = safe_iso_name(image_name_value)
        except WuciOSError as exc:
            problems.append(f"image_name invalid: {exc}")
    else:
        problems.append("image_name must be a plain .iso filename")
    base = manifest.get("base")
    if not isinstance(base, dict):
        problems.append("source base metadata missing")
    else:
        distribution = base.get("distribution")
        if distribution not in {"Wuci-OS live base", "Void Linux"}:
            problems.append("source base distribution mismatch")
        expected_base = {
            "libc": "musl",
            "image_kind": "live base ISO",
            "upstream_label": VOID_LIVE_LABEL,
        }
        for key, expected_value in expected_base.items():
            if base.get(key) != expected_value:
                problems.append(f"source base {key} mismatch")
        if expected_image_name and base.get("release_stamp") != release_stamp_from_name(expected_image_name):
            problems.append("source base release_stamp mismatch")
    root_resolved = root.resolve(strict=False)
    image_resolved = image_path.resolve(strict=False)
    image_path_safe = True
    try:
        image_relative = image_resolved.relative_to(root_resolved)
    except ValueError:
        image_path_safe = False
        problems.append("image_path must stay under source_root")
        image_relative = Path()
    if image_path_safe and (len(image_relative.parts) != 1 or image_relative.suffix != ".iso"):
        image_path_safe = False
        problems.append("image_path must name one direct source_root ISO")
    if image_path_safe and expected_image_name and image_relative.as_posix() != expected_image_name:
        image_path_safe = False
        problems.append("image_path must match image_name")
    if image_path_safe:
        try:
            digest_vector, size = wuci_kaiju.file_digest_vector(image_path, "Wuci-OS source ISO")
        except wuci_kaiju.KaijuError as exc:
            digest_vector, size = {}, -1
            problems.append(str(exc))
    else:
        digest_vector, size = {}, -1
    expected = manifest.get("digest_vector", {})
    if isinstance(expected, dict):
        for key in ("sha256", "sha384", "sha512"):
            if digest_vector.get(key) != expected.get(key):
                problems.append(f"{key} digest mismatch")
    else:
        problems.append("digest_vector missing")
    if size >= 0 and manifest.get("image_bytes") != size:
        problems.append("image_bytes mismatch")
    layout = inspect_void_iso(image_path) if size >= 0 else {"status": "fail", "problems": ["image unavailable"]}
    manifest_layout = manifest.get("layout")
    if not isinstance(manifest_layout, dict):
        problems.append("layout missing")
    elif manifest_layout != layout:
        problems.append("source manifest layout mismatch")
    if require_layout and layout.get("status") != "pass":
        for problem in layout.get("problems", []):
            problems.append(str(problem))
    return {
        "schema": SOURCE_VERIFY_SCHEMA,
        "status": "pass" if not problems else "fail",
        "source_root": str(root),
        "image_path": str(image_path),
        "image_bytes": size,
        "digest_vector": digest_vector,
        "layout": layout,
        "problems": problems,
        "non_claims": list(BOUNDARY_DENIALS),
    }


def source_status_text(source_root: Path | None = None) -> str:
    result = verify_source(source_root, require_layout=False)
    rows = [
        "schema: wuci-os-source-status-v1",
        f"status: {result['status']}",
        f"source_root: {result['source_root']}",
    ]
    if result.get("image_path"):
        rows.extend(
            [
                f"image: {result['image_path']}",
                f"bytes: {result['image_bytes']}",
                f"sha256: {result.get('digest_vector', {}).get('sha256', '')}",
                f"layout: {result.get('layout', {}).get('status', 'unknown')}",
            ]
        )
    for problem in result.get("problems", []):
        rows.append(f"problem: {problem}")
    return "\n".join(rows) + "\n"


def build_plan(source_root: Path | None = None) -> dict[str, Any]:
    verify = verify_source(source_root, require_layout=True)
    ready = verify["status"] == "pass"
    return {
        "schema": BUILD_PLAN_SCHEMA,
        "status": "ready" if ready else "blocked",
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "base": "Wuci-OS x86_64-musl live source base",
        "source": verify,
        "build_strategy": "rebuild generated Wuci-OS images from reviewed live-image tooling and Wuci-Ji overlays; do not hand-edit downloaded ISOs",
        "planned_tooling": [
            "void-mklive for generated live/rootfs images",
            "xbps-src for reviewed Wuci-OS package recipes",
            "Wuci-Ji digest/receipt evidence for generated artifacts",
            "NOXFRAME console route for operator-facing proof and demo controls",
        ],
        "first_overlay_goals": [
            "serial-first boot defaults for QEMU and nested demos",
            "Wuci-Ji source checkout or packaged proof tools",
            "NOXFRAME console launcher",
            "read-only boundary docs inside /usr/share/wuci-os",
            "Wuci-OS welcome/status/attestation commands for live demos",
            "XFCE4 desktop with kitty, xfce4-terminal fallback, ratpoison, emacs, and vim",
            "SELinux-first high-assurance profile with targeted/enforcing verification",
            "Codex, Copilot, and Grok Build setup hooks without embedded credentials",
            "Daylight/WJSEAL overlay sealing evidence",
        ],
        "non_claims": list(BOUNDARY_DENIALS),
    }


def finished_iso_plan(source_root: Path | None = None) -> dict[str, Any]:
    verify = verify_source(source_root, require_layout=True)
    ready = verify["status"] == "pass"
    return {
        "schema": ISO_PLAN_SCHEMA,
        "status": "ready-for-build-lane" if ready else "blocked",
        "product": PRODUCT_NAME,
        "goal": "finished bootable Wuci-OS ISO with Wuci identity baked into boot, rootfs, desktop, installer context, security profile, and Daylight evidence",
        "source": verify,
        "required_outputs": [
            "build/wuci-os/final/Wuci-OS-x86_64-musl.iso",
            "build/wuci-os/final/Wuci-OS-x86_64-musl.iso.sha256",
            "build/wuci-os/final/manifest.json",
            "build/wuci-os/final/daylight-manifest.json",
            "build/wuci-os/final/rootfs-manifest.json",
        ],
        "build_phases": [
            {
                "phase": 1,
                "name": "source import",
                "automation": "tools/wuci-os source install/verify",
                "status": "implemented",
            },
            {
                "phase": 2,
                "name": "Wuci overlay",
                "automation": "tools/wuci-os overlay",
                "status": "implemented",
            },
            {
                "phase": 3,
                "name": "Daylight overlay seal",
                "automation": "tools/wuci-os keygen + seal-overlay",
                "status": "implemented",
            },
            {
                "phase": 4,
                "name": "rootfs rebuild",
                "automation": "tools/wuci-os final-iso --remaster-rootfs",
                "status": "implemented; requires squashfs-tools on the build host",
                "requirements": [
                    "replace os-release and issue/MOTD with Wuci-OS identity",
                    "create wj and wj_low accounts in the baked rootfs",
                    "include wuci-guide and wuci-auto as first-login entry points",
                    "apply SELinux targeted/enforcing defaults and relabel marker",
                    "include wallpaper and XFCE/kitty/ratpoison defaults",
                ],
            },
            {
                "phase": 5,
                "name": "bootable ISO assembly",
                "automation": "tools/wuci-os final-iso",
                "status": "implemented",
                "requirements": [
                    "preserve the source ISO boot catalog",
                    "embed Wuci-OS overlay and source-kit payloads under /wuci-os",
                    "rewrite ISOLINUX/GRUB entries with Wuci-Ji Systems naming",
                    "embed the Wuci splash image for supported boot menus",
                    "include Daylight-sealed overlay evidence and final ISO manifest",
                    "record whether LiveOS/squashfs.img and suite packages were remastered",
                ],
            },
            {
                "phase": 6,
                "name": "suite package bake",
                "automation": "tools/wuci-os final-iso --remaster-rootfs --install-suite-packages",
                "status": "implemented; requires host xbps-install or root chroot package access",
                "requirements": [
                    "install Wi-Fi/network and firmware packages",
                    "install audio/video/Bluetooth/printing/scanning/portal packages",
                    "install developer/editor/language package groups",
                    "record package install status in the rootfs manifest",
                ],
            },
            {
                "phase": 7,
                "name": "release verification",
                "automation": "future Rust verifier plus current WJSEAL/QCAGE/CAGE proof lanes",
                "status": "planned",
                "requirements": [
                    "verify ISO digest vector",
                    "verify Daylight/WJSEAL artifact",
                    "verify no symlink/hardlink public evidence",
                    "verify no unsupported security claims",
                ],
            },
        ],
        "non_claims": list(BOUNDARY_DENIALS),
    }


def demo_command_text() -> str:
    rows = [
        "1. cd /home/ckbryan/-wuci-ji",
        "2. tools/wuci-os source verify",
        "3. tools/wuci-os overlay --force",
        "4. tools/wuci-os keygen --force",
        "5. tools/wuci-os seal-overlay --force --ticker always",
        "6. tools/wuci-os final-iso --force --remaster-rootfs --install-suite-packages",
        "7. tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo --run",
        "8. login: root",
        "9. password: press Enter for wj after Wuci-OS remaster; payload-preview images keep the base live login",
        '10. for dev in /dev/vd? /dev/sd?; do tar -tf "$dev" >/dev/null 2>&1 && tar -xf "$dev" -C /; done',
        "11. wuci-live-banner",
        "12. wuci-users-apply",
        "13. wuci-source-status",
        "14. wuci-guide",
        "15. sudo wj install vim emacs kitty",
        "16. wuci-enter",
        "17. wuci-attest",
        "18. wuci-security-status",
        "19. wuci-daylight-status",
        "20. exit QEMU with Ctrl-a x",
    ]
    return "\n".join(rows) + "\n"


def offline_install_guide_text() -> str:
    return """# Wuci-OS Offline Install Guide

Keep this file available during the install. It is copied into the ISO at
`/wuci-os/OFFLINE-INSTALL.txt` and into the live system at
`/usr/share/wuci-os/OFFLINE-INSTALL.txt`.

## 1. Boot The ISO

1. Insert the Wuci-OS USB or attach the Wuci-OS ISO.
2. Power on the machine and open the firmware boot menu.
3. Choose the USB or virtual CD entry for Wuci-OS.
4. In the boot menu choose `Wuci-Ji Systems / Wuci-OS live`.
5. Wait for the Wuci-OS prompt, banner, or XFCE desktop.
6. On legacy BIOS machines such as the ThinkPad X200s, a `no EFI` message is
   expected and is not a failure.
7. The default Wuci live entry already includes `console=tty0` and
   `rd.driver.pre=loop` for legacy BIOS live-root setup.
8. If you see `losetup /dev/loop0 failed` or `failed to find root filesystem`,
   stop using that USB image and reflash the newest Wuci-OS ISO.
9. If the desktop does not start, log in as `wj` and press Enter at the password prompt.
10. If you are at a text prompt, run:

```sh
startx
```

10. If `startx` is not available, stay in the text console and continue with the install steps.

## 2. Open A Terminal

If XFCE is running, open the default Wuci terminal:

```sh
wuci-terminal
```

If you are already at a text console, continue there.

Run these checks:

```sh
wuci-status
wuci-terminal --print
wuci-network-status
wuci-media-status
wuci-sdr-status
wuci-source-status
wuci-daylight-v14c-plus verify
```

The preferred terminal order is kitty, ghostty, xfce4-terminal, xterm, then a
plain shell fallback.

## 3. Network And Wi-Fi

Network setup is local and does not need online instructions.

1. Check devices:

```sh
ip link
wuci-network-status
```

2. Enable the Wuci network profile:

```sh
sudo wuci-network-connect
sudo wuci-network-apply
```

`wuci-network-connect` is the first-boot credential prompt. It asks for the
Wi-Fi SSID and password locally. No network IDs or passwords are baked into
the image.

3. List Wi-Fi networks manually, if needed:

```sh
nmcli device wifi list
```

4. Connect manually, if needed:

```sh
nmcli --ask device wifi connect "YOUR_WIFI_NAME"
```

If NetworkManager marks a working Wi-Fi device unavailable, use the direct
`wpa_supplicant` fallback:

```sh
sudo mkdir -p /run/wuci-network
sudo wpa_passphrase "YOUR_WIFI_NAME" "YOUR_WIFI_PASSWORD" | sudo tee /run/wuci-network/wpa.conf >/dev/null
sudo wpa_supplicant -B -i wlp2s0 -c /run/wuci-network/wpa.conf
sudo dhcpcd -n wlp2s0
```

5. Check the connection:

```sh
ip addr
ping -c 3 1.1.1.1
```

If Wi-Fi is unavailable, use wired Ethernet if possible and continue the install.
If no network is available, continue with the local install and run `wuci-update`
after the first boot once networking is fixed.

## 4. Audio, Video, And SDR Checks

Run:

```sh
sudo wuci-media-apply
wuci-media-status
sudo wuci-sdr-apply
wuci-sdr-status
wuci-boot-chime --once
```

If a package command reports unavailable packages, continue the install. The
status commands will show what is already present and what needs to be updated
after first boot.

## 5. Auto Install To Disk

Before writing disks, confirm the target disk:

```sh
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL
```

Run the uppercase Wuci installer:

```sh
INSTALL
```

`INSTALL` automates partitioning, formatting, XBPS base install, network and
desktop packages, GRUB, Wuci target activation, package reconfiguration
(initramfs), account passwords, services, and verification. It matches the
target package architecture to the live system, seeds the target's XBPS
repository configuration, and unmounts the target automatically if it fails
partway through. It self-escalates through sudo when needed and does not call
the missing upstream installer backend. For safety, it shows the target disk
and requires the confirmation word `INSTALL` before erasing.

Unlike the live demo accounts, an installed disk is given a real password on
`root` and `wj`. Supply it with `--password` / `WUCI_INSTALL_PASSWORD`, or you
are prompted once during install. Use `--empty-passwords` only when you
deliberately want the passwordless live behavior on disk.

Useful forms:

```sh
INSTALL
INSTALL --disk /dev/sda
INSTALL --disk /dev/sda --password 'choose-a-strong-one'
WUCI_INSTALL_DISK=/dev/sda WUCI_INSTALL_PASSWORD='secret' WUCI_INSTALL_ASSUME_YES=1 INSTALL
```

Legacy BIOS machines such as the ThinkPad X200/X200s use one ext4 root
partition and GRUB on the disk. UEFI machines get a 512 MiB EFI partition plus
an ext4 root partition. After the confirmation, do not interrupt the install.

`wuci-install` is kept as a compatibility alias for `INSTALL`.

## 6. Verify Before Reboot

`INSTALL` runs these checks automatically. If you need to re-run them:

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

## 7. Reboot Into The Installed System

Unmount cleanly:

```sh
sync
sudo umount -R /mnt
```

If unmount says the target is busy, close terminals that are inside `/mnt` and
try again.

Reboot:

```sh
sudo reboot
```

Remove the USB or detach the ISO when the machine restarts.

## 8. First Boot From Disk

1. Choose the installed Wuci-OS boot entry.
2. The system should autologin to `wj` on tty1.
3. If XFCE is installed, Wuci-OS starts it automatically with `startx`.
4. If XFCE does not start, log in as `wj`, press Enter for the live/demo password if still configured, and run:

```sh
wuci-status
wuci-network-status
sudo wuci-network-apply
sudo wuci-media-apply
sudo wuci-dev-install
startx
```

5. Rotate passwords immediately:

```sh
sudo passwd root
passwd
```

6. Run the update lane once networking is available:

```sh
sudo wuci-update
```

7. Enter the onboard project checkout:

```sh
cd /opt/wuci-os/source/wuci-ji
wuci-source-status
```

If the embedded source is a snapshot instead of a Git checkout, run:

```sh
wuci-update --source-only --live-repo "$HOME/wuci-ji-live"
cd "$HOME/wuci-ji-live"
```

## 9. Daily Recovery Commands

Use these when something does not look right:

```sh
wuci-live-banner
wuci-status
wuci-terminal --print
wuci-network-status
wuci-media-status
wuci-sdr-status
wuci-security-status
wuci-daylight-status
wuci-daylight-v14c-plus verify
wuci-source-status
```

Use this to replay the target activation from the live ISO:

```sh
sudo mount /dev/YOUR_ROOT_PARTITION /mnt
sudo wuci-install-target-activate /mnt
sync
sudo umount -R /mnt
```
"""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest_vector(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": hashlib.sha384(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def discover_host_image_tools() -> dict[str, dict[str, Any]]:
    specs = {
        "pycdlib": ["python-import:pycdlib"],
        "xorriso": ["xorriso"],
        "mksquashfs": ["mksquashfs"],
        "unsquashfs": ["unsquashfs"],
        "debugfs": ["debugfs"],
        "e2fsck": ["e2fsck"],
        "mke2fs": ["mke2fs", "mkfs.ext4"],
        "tar": ["tar"],
        "qemu": list(DEFAULT_QEMU_CANDIDATES),
        "xbps-install": ["xbps-install"],
    }
    result: dict[str, dict[str, Any]] = {}
    for tool, candidates in specs.items():
        discovered = ""
        if tool == "pycdlib":
            try:
                import pycdlib  # type: ignore[import-not-found]

                discovered = getattr(pycdlib, "__file__", "python import available")
            except ImportError:
                discovered = ""
        else:
            for candidate in candidates:
                if "/" in candidate:
                    if os.access(candidate, os.X_OK):
                        discovered = candidate
                        break
                else:
                    path = shutil.which(candidate)
                    if path:
                        discovered = path
                        break
        result[tool] = {
            "status": "available" if discovered else "missing",
            "path": discovered,
            "candidates": candidates,
        }
    return result


def _iso_add_directory_once(iso: Any, iso_path: str, *, rr_name: str, joliet_path: str) -> None:
    try:
        iso.get_record(iso_path=iso_path)
        return
    except Exception:
        pass
    iso.add_directory(iso_path, rr_name=rr_name, joliet_path=joliet_path)


def _iso_add_bytes(
    iso: Any,
    data: bytes,
    *,
    iso_path: str,
    rr_name: str,
    joliet_path: str,
    mode: int = 0o644,
) -> dict[str, Any]:
    iso.add_fp(
        io.BytesIO(data),
        len(data),
        iso_path=iso_path,
        rr_name=rr_name,
        joliet_path=joliet_path,
        file_mode=mode,
    )
    return {
        "iso_path": iso_path,
        "rock_ridge_name": rr_name,
        "joliet_path": joliet_path,
        "bytes": len(data),
        "digest_vector": digest_vector(data),
    }


def _iso_add_local_file(
    iso: Any,
    source: Path,
    *,
    iso_path: str,
    rr_name: str,
    joliet_path: str,
    label: str,
) -> dict[str, Any]:
    info = _verified_regular_file_info(source, label)
    iso.add_file(
        str(source),
        iso_path=iso_path,
        rr_name=rr_name,
        joliet_path=joliet_path,
        file_mode=stat.S_IMODE(info.st_mode),
    )
    digest, size = wuci_kaiju.file_digest_vector(source, label)
    return {
        "source_path": str(source),
        "iso_path": iso_path,
        "rock_ridge_name": rr_name,
        "joliet_path": joliet_path,
        "bytes": size,
        "digest_vector": digest,
    }


def _xorriso_stage_bytes(staging_root: Path, relative: str, data: bytes, label: str, *, mode: int = 0o644) -> Path:
    path = staging_root / relative
    _prepare_exclusive_output_path(path, label, force=True)
    _write_verified_new_file(path, data, label, mode=mode)
    return path


def _xorriso_add_map(args: list[str], source: Path, iso_path: str, *, mode: int | None = 0o644) -> None:
    args.extend(["-map", str(source), iso_path])
    if mode is not None:
        args.extend(["-chmod", f"{mode:04o}", iso_path, "--"])


def _xorriso_replay_final_iso(
    *,
    xorriso: str,
    source_iso: Path,
    final_iso: Path,
    staging_root: Path,
    wuci_boot_menu: str,
    grub_rewrites: dict[str, str],
    boot_splash: Path,
    boot_splash_source: Path,
    model_diagram_source: Path,
    daylight_v8_diagram_source: Path,
    daylight_v9_sheet_source: Path,
    daylight_v9_diagram_source: Path,
    daylight_v10_scoreboard_source: Path,
    daylight_v13_math_source: Path,
    daylight_v14c_image_source: Path,
    daylight_v14c_math_source: Path,
    daylight_v14c_wide_source: Path,
    daylight_v15_solstice_source: Path,
    readme_bytes: bytes,
    offline_install_bytes: bytes,
    daylight_v8_model_bytes: bytes,
    daylight_v9_model_bytes: bytes,
    daylight_v10_model_bytes: bytes,
    daylight_v13_model_bytes: bytes,
    replacement_kernel_path: Path | None,
    replacement_initrd_path: Path | None,
    onboard_manifest_bytes: bytes,
    source_manifest_bytes: bytes,
    seal_manifest_bytes: bytes,
    remaster_manifest_bytes: bytes,
    overlay_tar_path: Path,
    source_kit_path: Path,
    sealed_overlay_path: Path,
    activate_path: Path,
    remaster_result: dict[str, Any],
    remaster_rootfs: bool,
) -> dict[str, Any]:
    tmp_iso = staging_root / "xorriso-replay.iso"
    _prepare_exclusive_output_path(tmp_iso, "Wuci-OS xorriso replay ISO", force=True)
    args = [
        xorriso,
        "-indev",
        str(source_iso),
        "-outdev",
        str(tmp_iso),
        "-boot_image",
        "any",
        "replay",
        "-volid",
        VOID_LIVE_LABEL,
    ]
    if wuci_boot_menu:
        _xorriso_add_map(
            args,
            _xorriso_stage_bytes(staging_root, "boot/isolinux/isolinux.cfg", wuci_boot_menu.encode("utf-8"), "Wuci-OS staged ISOLINUX config"),
            "/boot/isolinux/isolinux.cfg",
        )
    _xorriso_add_map(args, boot_splash, "/boot/isolinux/wuci-splash.png")
    _xorriso_add_map(args, boot_splash, "/boot/grub/wuci-splash.png")
    for grub_path, grub_text in sorted(grub_rewrites.items()):
        _xorriso_add_map(
            args,
            _xorriso_stage_bytes(
                staging_root,
                grub_path,
                grub_text.encode("utf-8"),
                f"Wuci-OS staged GRUB config {grub_path}",
            ),
            "/" + grub_path,
        )
    if remaster_rootfs:
        _xorriso_add_map(
            args,
            Path(str(remaster_result["remastered_squashfs"]["path"])),
            "/LiveOS/squashfs.img",
        )
        if replacement_kernel_path is not None:
            _xorriso_add_map(args, replacement_kernel_path, "/boot/vmlinuz")
        if replacement_initrd_path is not None:
            _xorriso_add_map(args, replacement_initrd_path, "/boot/initrd")
    staged_payloads = (
        ("wuci-os/boot-splash.svg", boot_splash_source, None, 0o644),
        ("wuci-os/wuci-daylight-wire-model.png", model_diagram_source, None, 0o644),
        ("wuci-os/wuci-daylight-v8-sheet.png", daylight_v8_diagram_source, None, 0o644),
        ("wuci-os/wuci-daylight-v9-sheet.png", daylight_v9_sheet_source, None, 0o644),
        ("wuci-os/wuci-daylight-v9-spine.svg", daylight_v9_diagram_source, None, 0o644),
        ("wuci-os/wuci-daylight-v10-scoreboard.png", daylight_v10_scoreboard_source, None, 0o644),
        ("wuci-os/wuci-daylight-v13-sovereign-math.png", daylight_v13_math_source, None, 0o644),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant.png", daylight_v14c_image_source, None, 0o644),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant-math.png", daylight_v14c_math_source, None, 0o644),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png", daylight_v14c_wide_source, None, 0o644),
        ("wuci-os/wuci-daylight-v15-plus-solstice.png", daylight_v15_solstice_source, None, 0o644),
        ("wuci-os/README.txt", None, readme_bytes, 0o644),
        ("wuci-os/OFFLINE-INSTALL.txt", None, offline_install_bytes, 0o644),
        ("wuci-os/WUCI_DAYLIGHT_V8.md", None, daylight_v8_model_bytes, 0o644),
        ("wuci-os/WUCI_DAYLIGHT_V9.md", None, daylight_v9_model_bytes, 0o644),
        ("wuci-os/WUCI_DAYLIGHT_V10.md", None, daylight_v10_model_bytes, 0o644),
        ("wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md", None, daylight_v13_model_bytes, 0o644),
        ("wuci-os/manifest.json", None, onboard_manifest_bytes, 0o644),
        ("wuci-os/source.json", None, source_manifest_bytes, 0o644),
        ("wuci-os/daylight-manifest.json", None, seal_manifest_bytes, 0o644),
        ("wuci-os/rootfs-manifest.json", None, remaster_manifest_bytes, 0o644),
        ("wuci-os/wuci-os-overlay.tar", overlay_tar_path, None, 0o644),
        (f"wuci-os/{SOURCE_KIT_TAR_NAME}", source_kit_path, None, 0o644),
        ("wuci-os/wuci-os-overlay.wj", sealed_overlay_path, None, 0o644),
    )
    for iso_relative, local_path, data, mode in staged_payloads:
        source = local_path
        if source is None:
            source = _xorriso_stage_bytes(
                staging_root,
                "payloads/" + iso_relative,
                data or b"",
                f"Wuci-OS staged payload {iso_relative}",
                mode=mode,
            )
        _xorriso_add_map(args, Path(source), "/" + iso_relative, mode=mode)
    if activate_path.is_file():
        _xorriso_add_map(args, activate_path, "/wuci-os/wuci-os-live-activate", mode=0o755)

    result = subprocess.run(
        args,
        cwd=staging_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    if result.returncode != 0:
        raise WuciOSError(f"xorriso replay ISO assembly failed: {result.stderr.strip() or result.stdout.strip()}")
    os.replace(tmp_iso, final_iso)
    _fsync_parent(final_iso)
    return {
        "schema": "wuci-os-xorriso-replay-assembly-v1",
        "status": "pass",
        "tool": xorriso,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
    }


def developer_package_manifest() -> dict[str, Any]:
    language_groups = {name: list(packages) for name, packages in LANGUAGE_PACKAGE_GROUPS.items()}
    all_dev_packages: list[str] = []
    for packages in language_groups.values():
        all_dev_packages.extend(packages)
    return {
        "schema": "wuci-os-developer-package-profile-v1",
        "desktop": {
            "default": "terminal-first",
            "desktop_environment": "xfce4",
            "window_manager": "ratpoison",
            "preferred_terminal": "kitty",
            "alternate_terminal": "ghostty",
            "fallback_terminal": "xfce4-terminal",
            "terminal_candidates": list(TERMINAL_CANDIDATES),
            "packages": list(DESKTOP_PACKAGES),
        },
        "audio": {
            "boot_chime": "original Wuci-OS generated chime via wuci-boot-chime",
            "packages": list(AUDIO_PACKAGES),
            "fallback": "terminal bell when no PCM player or audio server is available",
        },
        "network": {
            "default": "NetworkManager with Wi-Fi support",
            "wifi": ["NetworkManager", "wpa_supplicant", "iwd", "iw", "rfkill", "wireless_tools"],
            "firmware": list(FIRMWARE_PACKAGES),
            "packages": list(NETWORK_PACKAGES),
        },
        "video": {
            "default": "Mesa plus common Xorg/Vulkan/VAAPI drivers",
            "packages": list(VIDEO_PACKAGES),
        },
        "peripherals": {
            "default": "Bluetooth, printing, scanning, desktop portals, and removable media helpers",
            "packages": list(PERIPHERAL_PACKAGES),
        },
        "sdr": {
            "default": "GNU Radio, Gqrx, RTL-SDR, HackRF, Airspy, SoapySDR, and RF analysis helpers where available in the active package repository",
            "core_packages": list(SDR_PACKAGES),
            "optional_packages": list(SDR_OPTIONAL_PACKAGES),
            "hardware_notes": [
                "USB SDR devices usually need the operator account in plugdev, usb, dialout, or uucp-style groups when present",
                "udev rules and kernel driver detach behavior are hardware-specific and must be verified on the installed target",
            ],
        },
        "editors": {
            "default_terminal_editors": ["vim", "emacs"],
            "packages": ["vim", "emacs", "nano"],
        },
        "base_developer_packages": list(BASE_DEV_PACKAGES),
        "language_package_groups": language_groups,
        "all_developer_packages": sorted(set(BASE_DEV_PACKAGES + tuple(all_dev_packages))),
        "full_suite_packages": list(full_suite_packages()),
        "ai_tools": {
            "codex": {
                "setup": "operator-reviewed official installer or local package only",
                "npm_fallback": "@openai/codex",
                "credential": "OPENAI_API_KEY or interactive login",
                "automation_boundary": "wuci-ai-setup prints a plan; it does not download or execute remote installers",
            },
            "github_copilot": {
                "setup": "operator-reviewed GitHub CLI/Copilot install flow or local package only",
                "npm_fallback": "@github/copilot",
                "credential": "GH_TOKEN, GITHUB_TOKEN, or interactive login",
                "automation_boundary": "wuci-ai-setup prints a plan; it does not download or execute remote installers",
            },
            "grok_build": {
                "api": "https://api.x.ai/v1/responses",
                "model": "grok-build-0.1",
                "credential": "XAI_API_KEY",
            },
        },
    }


def security_profile_manifest() -> dict[str, Any]:
    return {
        "schema": "wuci-os-high-assurance-security-profile-v1",
        "threat_level": "high",
        "priority": "security-over-privacy",
        "selinux": {
            "default": True,
            "mode": "enforcing",
            "policy": "targeted",
            "fedora_style": "SELINUX=enforcing with SELINUXTYPE=targeted and relabel-on-boot marker",
            "required_packages": list(SELINUX_CANDIDATE_PACKAGES),
            "kernel_flags": list(SELINUX_GRUB_FLAGS),
            "fallback_policy": "blocker, not substitute; AppArmor is not treated as SELinux",
        },
        "disk_encryption": {
            "default": "required for installed targets",
            "mechanism": "LUKS/dm-crypt through cryptsetup during installation",
            "automation_boundary": "disk selection is intentionally operator-confirmed to avoid destructive writes",
        },
        "daylight_wjseal": {
            "default": "seal generated Wuci-OS overlays and evidence bundles",
            "scope": "artifact sealing and public evidence binding",
            "non_claim": "not full-disk encryption, runtime containment, or production authority",
        },
        "kicksecure_inspired": {
            "scope": "hardening profile ideas adapted locally without importing Kicksecure packages",
            "sysctl": list(KICKSECURE_INSPIRED_HARDENING),
            "network": "nftables default-deny inbound, allow established and loopback",
        },
        "security_packages": list(SECURITY_PACKAGES),
        "accounts": {
            "operator_login": "wj",
            "operator_prompt": "WJ>_",
            "operator_live_password": "empty password for live/demo console only",
            "operator_privilege": "wheel admin with passwordless sudo/doas in the live profile",
            "lower_privilege_login": "wj_low",
            "installed_system_requirement": "rotate the live empty password before high-assurance installed status can pass",
        },
        "non_claims": list(BOUNDARY_DENIALS),
    }


def package_manifest() -> dict[str, Any]:
    return {
        "schema": "wuci-os-package-manifest-v1",
        "created_utc": utc_now(),
        "product": PRODUCT_NAME,
        "developer": developer_package_manifest(),
        "security": security_profile_manifest(),
        "daylight_required_components": list(DAYLIGHT_REQUIRED_COMPONENTS),
        "rust_redesign_components": list(RUST_REDESIGN_COMPONENTS),
    }


def _read_regular_bytes(path: Path, label: str) -> bytes:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise WuciOSError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise WuciOSError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise WuciOSError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise WuciOSError(f"{label} must not be hardlinked: {path}")
    flags = os.O_RDONLY | wuci_kaiju._cloexec() | wuci_kaiju._nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise WuciOSError(f"could not open {label}: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise WuciOSError(f"{label} changed type while opening: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise WuciOSError(f"{label} changed while opening: {path}")
        if opened.st_size != info.st_size or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode):
            raise WuciOSError(f"{label} changed while opening: {path}")
        if opened.st_nlink != 1:
            raise WuciOSError(f"{label} must not be hardlinked: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, wuci_kaiju.READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            chunks.append(chunk)
        if total != opened.st_size:
            raise WuciOSError(f"{label} changed while reading: {path}")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _validate_png_bytes(data: bytes, label: str) -> None:
    if not data.startswith(PNG_SIGNATURE):
        raise WuciOSError(f"{label} is not a PNG image")


def _extract_embedded_png_from_svg(source: Path, source_bytes: bytes) -> bytes | None:
    try:
        root = ET.fromstring(source_bytes)
    except ET.ParseError as exc:
        raise WuciOSError(f"Wuci-OS boot splash SVG is not valid XML: {source}") from exc
    for element in root.iter():
        for attr, value in element.attrib.items():
            attr_name = attr.rsplit("}", 1)[-1]
            if attr_name != "href":
                continue
            if not value.startswith("data:image/png;base64,"):
                continue
            encoded = re.sub(r"\s+", "", value.split(",", 1)[1])
            try:
                png = base64.b64decode(encoded, validate=True)
            except ValueError as exc:
                raise WuciOSError(f"Wuci-OS boot splash SVG contains invalid embedded PNG data: {source}") from exc
            _validate_png_bytes(png, "Wuci-OS embedded boot splash")
            return png
    return None


def _render_svg_with_host_tool(source: Path) -> tuple[bytes, str] | None:
    rsvg = shutil.which("rsvg-convert")
    if rsvg:
        result = subprocess.run(
            [rsvg, "--format=png", str(source)],
            cwd=repo_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if result.returncode != 0:
            raise WuciOSError(f"rsvg-convert failed for Wuci-OS boot splash: {result.stderr.decode('utf-8', 'replace').strip()}")
        _validate_png_bytes(result.stdout, "Wuci-OS rendered boot splash")
        return result.stdout, "rsvg-convert"
    magick = shutil.which("magick")
    if magick:
        result = subprocess.run(
            [magick, str(source), "png:-"],
            cwd=repo_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if result.returncode != 0:
            raise WuciOSError(f"magick failed for Wuci-OS boot splash: {result.stderr.decode('utf-8', 'replace').strip()}")
        _validate_png_bytes(result.stdout, "Wuci-OS rendered boot splash")
        return result.stdout, "magick"
    convert = shutil.which("convert")
    if convert:
        result = subprocess.run(
            [convert, str(source), "png:-"],
            cwd=repo_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
        )
        if result.returncode != 0:
            raise WuciOSError(f"convert failed for Wuci-OS boot splash: {result.stderr.decode('utf-8', 'replace').strip()}")
        _validate_png_bytes(result.stdout, "Wuci-OS rendered boot splash")
        return result.stdout, "convert"
    return None


def render_boot_splash_png(source: Path, dest: Path, *, force: bool) -> dict[str, Any]:
    source_digest, source_size = wuci_kaiju.file_digest_vector(source, "Wuci-OS boot splash source")
    source_bytes = _read_regular_bytes(source, "Wuci-OS boot splash source")
    suffix = source.suffix.lower()
    render_method = ""
    if suffix == ".png":
        _validate_png_bytes(source_bytes, "Wuci-OS boot splash source")
        png = source_bytes
        render_method = "source-png"
    elif suffix == ".svg":
        embedded = _extract_embedded_png_from_svg(source, source_bytes)
        if embedded is not None:
            png = embedded
            render_method = "embedded-svg-png"
        else:
            rendered = _render_svg_with_host_tool(source)
            if rendered is None:
                raise WuciOSError("Wuci-OS boot splash SVG requires an embedded PNG, rsvg-convert, magick, or convert")
            png, render_method = rendered
    else:
        raise WuciOSError(f"Wuci-OS boot splash must be SVG or PNG: {source}")

    _prepare_exclusive_output_path(dest, "Wuci-OS rendered boot splash PNG", force=force)
    rendered_digest, rendered_size = _write_verified_new_file(
        dest,
        png,
        "Wuci-OS rendered boot splash PNG",
        mode=0o644,
    )
    return {
        "schema": BOOT_SPLASH_SCHEMA,
        "source_path": str(source),
        "source_bytes": source_size,
        "source_digest_vector": source_digest,
        "rendered_path": str(dest),
        "render_method": render_method,
        "bytes": rendered_size,
        "digest_vector": rendered_digest,
    }


def _verified_regular_file_info(path: Path, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise WuciOSError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise WuciOSError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise WuciOSError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise WuciOSError(f"{label} must not be hardlinked: {path}")
    return info


@contextlib.contextmanager
def _open_verified_regular_file(path: Path, label: str, *, expected_info: os.stat_result | None = None) -> Any:
    info = _verified_regular_file_info(path, label) if expected_info is None else expected_info
    flags = os.O_RDONLY | wuci_kaiju._cloexec() | wuci_kaiju._nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise WuciOSError(f"could not open {label}: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise WuciOSError(f"{label} changed type while opening: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise WuciOSError(f"{label} changed while opening: {path}")
        if opened.st_size != info.st_size or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode):
            raise WuciOSError(f"{label} changed while opening: {path}")
        if opened.st_nlink != 1:
            raise WuciOSError(f"{label} must not be hardlinked: {path}")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            yield handle
    finally:
        if fd >= 0:
            os.close(fd)


def overlay_manifest_path(overlay_root: Path) -> Path:
    return overlay_root / "usr/share/wuci-os/overlay-manifest.json"


def overlay_file_records(overlay_root: Path, *, ticker_mode: str = "auto") -> list[dict[str, Any]]:
    try:
        root_info = os.lstat(overlay_root)
    except FileNotFoundError as exc:
        raise WuciOSError(f"overlay root is missing: {overlay_root}") from exc
    except OSError as exc:
        raise WuciOSError(f"could not inspect overlay root: {overlay_root}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise WuciOSError(f"overlay root must not be a symlink: {overlay_root}")
    if not stat.S_ISDIR(root_info.st_mode):
        raise WuciOSError(f"overlay root must be a directory: {overlay_root}")
    records: list[dict[str, Any]] = []
    paths = sorted(overlay_root.rglob("*"), key=lambda path: path.relative_to(overlay_root).as_posix())
    ticker = wuci_progress.TriangleTicker(ticker_mode, label="wuci-os overlay")
    for index, path in enumerate(paths):
        rel = path.relative_to(overlay_root).as_posix()
        info = os.lstat(path)
        ticker.tick(index, len(paths), detail=rel)
        if stat.S_ISLNK(info.st_mode):
            raise WuciOSError(f"overlay must not contain symlinks: {rel}")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise WuciOSError(f"overlay file must not be hardlinked: {rel}")
            digest, size = wuci_kaiju.file_digest_vector(path, f"Wuci-OS overlay file {rel}")
            records.append(
                {
                    "path": rel,
                    "type": "file",
                    "mode": oct(stat.S_IMODE(info.st_mode)),
                    "bytes": size,
                    "digest_vector": digest,
                }
            )
        elif stat.S_ISDIR(info.st_mode):
            records.append(
                {
                    "path": rel,
                    "type": "directory",
                    "mode": oct(stat.S_IMODE(info.st_mode)),
                }
            )
        else:
            raise WuciOSError(f"overlay contains unsupported file type: {rel}")
    ticker.finish(ok=True)
    return records


def _overlay_content_records(records: list[dict[str, Any]], manifest_relative: str) -> list[dict[str, Any]]:
    return [
        record
        for record in records
        if record.get("type") == "file" and record.get("path") != manifest_relative
    ]


def _manifest_string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise WuciOSError(f"Wuci-OS overlay manifest {label} must be a list")
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise WuciOSError(f"Wuci-OS overlay manifest {label} entries must be strings")
        if item in seen:
            raise WuciOSError(f"Wuci-OS overlay manifest {label} contains duplicate path: {item}")
        seen.add(item)
        items.append(item)
    return items


def validate_overlay_manifest_current(
    overlay_root: Path,
    manifest: dict[str, Any],
    *,
    records: list[dict[str, Any]] | None = None,
    ticker_mode: str = "auto",
) -> list[dict[str, Any]]:
    if manifest.get("schema") != OVERLAY_SCHEMA:
        raise WuciOSError("Wuci-OS overlay manifest schema mismatch")
    manifest_relative = "usr/share/wuci-os/overlay-manifest.json"
    if manifest.get("manifest_path") != manifest_relative:
        raise WuciOSError("Wuci-OS overlay manifest_path mismatch")
    if records is None:
        records = overlay_file_records(overlay_root, ticker_mode=ticker_mode)
    current_paths = [str(record.get("path")) for record in records]
    current_files = {str(record.get("path")) for record in records if record.get("type") == "file"}
    manifest_paths = _manifest_string_list(manifest.get("recorded_paths"), "recorded_paths")
    manifest_files = _manifest_string_list(manifest.get("files"), "files")
    if manifest_paths != current_paths:
        raise WuciOSError("Wuci-OS overlay manifest recorded_paths mismatch")
    if set(manifest_files) != current_files:
        raise WuciOSError("Wuci-OS overlay manifest files mismatch")
    manifest_records = manifest.get("content_records")
    current_content_records = _overlay_content_records(records, manifest_relative)
    if not isinstance(manifest_records, list) or manifest_records != current_content_records:
        raise WuciOSError("Wuci-OS overlay manifest content_records mismatch")
    return records


def clear_overlay_root_for_rebuild(overlay_root: Path) -> None:
    resolved = overlay_root.resolve(strict=False)
    repo = repo_root().resolve(strict=False)
    if resolved in {Path("/"), repo}:
        raise WuciOSError(f"refusing to clear unsafe overlay root: {overlay_root}")
    if not overlay_root.exists():
        return
    try:
        root_info = os.lstat(overlay_root)
    except OSError as exc:
        raise WuciOSError(f"could not inspect overlay root: {overlay_root}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise WuciOSError(f"overlay root must not be a symlink: {overlay_root}")
    if not stat.S_ISDIR(root_info.st_mode):
        raise WuciOSError(f"overlay root must be a directory: {overlay_root}")

    entries: list[tuple[Path, int]] = []
    for path in sorted(overlay_root.rglob("*"), key=lambda item: len(item.relative_to(overlay_root).parts), reverse=True):
        rel = path.relative_to(overlay_root).as_posix()
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise WuciOSError(f"overlay rebuild path disappeared: {rel}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WuciOSError(f"overlay rebuild refuses symlink: {rel}")
        if stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise WuciOSError(f"overlay rebuild refuses hardlinked file: {rel}")
        elif not stat.S_ISDIR(info.st_mode):
            raise WuciOSError(f"overlay rebuild refuses unsupported file type: {rel}")
        entries.append((path, info.st_mode))

    for path, mode in entries:
        try:
            if stat.S_ISDIR(mode):
                path.rmdir()
            else:
                path.unlink()
        except OSError as exc:
            rel = path.relative_to(overlay_root).as_posix()
            raise WuciOSError(f"could not clear overlay rebuild path: {rel}") from exc


LIVE_UPDATE_SCHEMA = "wuci-os-live-update-v1"

# The overlay manifest is a build record that re-digests the timestamped
# packages.json, so it can never be byte-stable across two builds. It is metadata
# about the build, not a functional system file, so live-update does not sync it.
_LIVE_UPDATE_METADATA_SKIP = {"usr/share/wuci-os/overlay-manifest.json"}


def _strip_build_timestamps(value: Any) -> Any:
    """Return a copy of a decoded-JSON value with every ``created_utc`` removed."""
    if isinstance(value, dict):
        return {k: _strip_build_timestamps(v) for k, v in value.items() if k != "created_utc"}
    if isinstance(value, list):
        return [_strip_build_timestamps(item) for item in value]
    return value


def _overlay_file_is_current(target_file: Path, staging_bytes: bytes, old_sha: str | None, new_sha: str) -> bool:
    """True when the live file already matches the presented one.

    Byte-identical files match directly. Files that differ only by an embedded
    ``created_utc`` build stamp (e.g. packages.json) are treated as current so a
    pure timestamp never counts as a functional change.
    """
    if old_sha is None:
        return False
    if old_sha == new_sha:
        return True
    try:
        target_json = json.loads(target_file.read_bytes())
        staging_json = json.loads(staging_bytes)
    except (ValueError, OSError):
        return False
    return _strip_build_timestamps(target_json) == _strip_build_timestamps(staging_json)


def _apply_overlay_file_to_target(staging_file: Path, target_file: Path, mode: int) -> None:
    """Atomically install one overlay file into a live root (tmp write + rename)."""
    if target_file.is_symlink():
        raise WuciOSError(f"live update refuses to overwrite a symlink: {target_file}")
    target_file.parent.mkdir(parents=True, exist_ok=True)
    data = staging_file.read_bytes()
    tmp = target_file.with_name(target_file.name + ".wuci-update.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, target_file)


def live_update_system(
    *,
    target_root: Path = Path("/"),
    apply: bool = False,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    """Measure (and optionally apply) the repo-presented overlay onto a live root.

    This is the no-reflash update path: it regenerates the Wuci-OS overlay that the
    repository *presents* into an isolated staging directory, then compares it, file
    by file, against ``target_root`` by content digest. In preview mode it only
    measures (add/update/unchanged per file). With ``apply=True`` it installs every
    changed file atomically and then re-reads it and verifies its digest against the
    freshly built overlay. Fail-closed: any post-write digest mismatch aborts.

    Scope: the Wuci overlay layer only -- ``/usr/local/bin`` commands,
    ``/usr/share/wuci-os`` (including the Daylight execution packages), ``os-release``
    identity, ``profile.d``, autostart, and skel. It never removes files and never
    touches the kernel or base xbps packages; those update with ``xbps-install -Su``.
    """
    target_root = Path(target_root)
    if not (target_root / "usr").is_dir():
        raise WuciOSError(f"target root does not look like a system root: {target_root}")

    staging_parent = tempfile.mkdtemp(prefix="wuci-live-update.")
    staging = Path(staging_parent) / "overlay"
    try:
        create_overlay(staging, force=True)
        records = overlay_file_records(staging, ticker_mode=ticker_mode)
        changes: list[dict[str, Any]] = []
        counts = {
            "files": 0, "directories": 0, "unchanged": 0,
            "update": 0, "add": 0, "applied": 0, "verified": 0, "skipped_metadata": 0,
        }
        for record in records:
            rel = str(record["path"])
            if record.get("type") == "directory":
                counts["directories"] += 1
                if apply:
                    (target_root / rel).mkdir(parents=True, exist_ok=True)
                continue
            if rel in _LIVE_UPDATE_METADATA_SKIP:
                counts["skipped_metadata"] += 1
                continue
            counts["files"] += 1
            staging_file = staging / rel
            target_file = target_root / rel
            new_sha = record["digest_vector"]["sha256"]
            mode = int(str(record["mode"]), 0)
            old_sha: str | None = None
            if target_file.is_file() and not target_file.is_symlink():
                old_sha = hashlib.sha256(target_file.read_bytes()).hexdigest()
            if _overlay_file_is_current(target_file, staging_file.read_bytes(), old_sha, new_sha):
                counts["unchanged"] += 1
                continue
            status = "add" if old_sha is None else "update"
            counts[status] += 1
            applied = False
            verified = False
            if apply:
                _apply_overlay_file_to_target(staging_file, target_file, mode)
                counts["applied"] += 1
                applied = True
                written = hashlib.sha256(target_file.read_bytes()).hexdigest()
                if written != new_sha:
                    raise WuciOSError(
                        f"live update verification failed for {rel}: wrote {written}, expected {new_sha}"
                    )
                counts["verified"] += 1
                verified = True
            changes.append(
                {
                    "path": rel,
                    "status": status,
                    "old_sha256": old_sha,
                    "new_sha256": new_sha,
                    "bytes": record.get("bytes"),
                    "mode": record.get("mode"),
                    "applied": applied,
                    "verified": verified,
                }
            )
        overlay_fingerprint = hashlib.sha256(
            "\n".join(
                f"{r['path']}:{r.get('digest_vector', {}).get('sha256', 'dir')}" for r in records
            ).encode("utf-8")
        ).hexdigest()
    finally:
        shutil.rmtree(staging_parent, ignore_errors=True)

    return {
        "schema": LIVE_UPDATE_SCHEMA,
        "created_utc": utc_now(),
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "target_root": str(target_root),
        "source_root": str(repo_root()),
        "mode": "applied" if apply else "preview",
        "overlay_fingerprint_sha256": overlay_fingerprint,
        "counts": counts,
        "changes": changes,
        "scope_note": (
            "Wuci overlay layer only (commands, /usr/share/wuci-os incl. Daylight "
            "packages, os-release, profile.d, autostart, skel). Kernel and base "
            "packages are untouched; update those with xbps-install -Su."
        ),
    }


def _fsync_parent(path: Path) -> None:
    try:
        fd = os.open(str(path.parent), os.O_RDONLY | wuci_kaiju._cloexec())
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink_existing_path(path_name: str) -> None:
    if not path_name:
        return
    try:
        os.unlink(path_name)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WuciOSError(f"could not remove temporary path: {path_name}") from exc


def _discard_temporary_path(path_name: str) -> None:
    if not path_name:
        return
    try:
        os.unlink(path_name)
    except OSError:
        pass


def _backup_existing_regular_file(path: Path, label: str) -> str:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise WuciOSError(f"could not inspect existing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise WuciOSError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise WuciOSError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise WuciOSError(f"{label} must not be hardlinked: {path}")

    flags = os.O_RDONLY | wuci_kaiju._cloexec() | wuci_kaiju._nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise WuciOSError(f"could not open existing {label} for rollback: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise WuciOSError(f"{label} changed type while staging rollback: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise WuciOSError(f"{label} changed while staging rollback: {path}")
        if opened.st_size != info.st_size or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode):
            raise WuciOSError(f"{label} changed while staging rollback: {path}")
        if opened.st_nlink != 1:
            raise WuciOSError(f"{label} must not be hardlinked while staging rollback: {path}")
    finally:
        os.close(fd)

    tmp_fd, backup_name = tempfile.mkstemp(prefix=f".{path.name}.old.", dir=str(path.parent))
    os.close(tmp_fd)
    try:
        os.unlink(backup_name)
        os.replace(path, backup_name)
        backup_info = os.lstat(backup_name)
        if stat.S_ISLNK(backup_info.st_mode):
            raise WuciOSError(f"rollback copy of {label} must not be a symlink: {backup_name}")
        if not stat.S_ISREG(backup_info.st_mode):
            raise WuciOSError(f"rollback copy of {label} must be a regular file: {backup_name}")
        if backup_info.st_nlink != 1:
            raise WuciOSError(f"rollback copy of {label} must not be hardlinked: {backup_name}")
        if (
            backup_info.st_ino != info.st_ino
            or backup_info.st_dev != info.st_dev
            or backup_info.st_size != info.st_size
            or stat.S_IMODE(backup_info.st_mode) != stat.S_IMODE(info.st_mode)
        ):
            raise WuciOSError(f"{label} changed while staging rollback: {path}")
        _fsync_parent(path)
    except (OSError, WuciOSError) as exc:
        try:
            os.unlink(backup_name)
        except OSError:
            pass
        if isinstance(exc, WuciOSError):
            raise
        raise WuciOSError(f"could not stage previous {label} for rollback: {path}") from exc
    return backup_name


def _restore_backup_file(path: Path, backup_name: str, label: str) -> None:
    backup = Path(backup_name)
    _verified_regular_file_info(backup, f"previous {label}")
    _reject_symlink_output_parents(path, label)
    try:
        os.replace(backup, path)
        _fsync_parent(path)
    except OSError as exc:
        raise WuciOSError(f"could not restore previous {label}: {path}") from exc


def _reject_symlink_output_parents(path: Path, label: str) -> None:
    parents: list[Path] = []
    current = path.parent
    while True:
        parents.append(current)
        if current == current.parent:
            break
        current = current.parent
    for parent in reversed(parents):
        try:
            info = os.lstat(parent)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise WuciOSError(f"could not inspect {label} parent: {parent}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WuciOSError(f"{label} parent must not be a symlink: {parent}")
        if not stat.S_ISDIR(info.st_mode):
            raise WuciOSError(f"{label} parent must be a directory: {parent}")


def _prepare_atomic_tar_output_path(tar_path: Path, label: str) -> None:
    _reject_symlink_output_parents(tar_path, label)
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(tar_path, label)
    try:
        wuci_kaiju.reject_unsafe_existing_path(tar_path, label)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc


def _prepare_atomic_tar_path(tar_path: Path, label: str) -> Path:
    _prepare_atomic_tar_output_path(tar_path, label)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{tar_path.name}.", suffix=".tmp", dir=str(tar_path.parent))
    os.close(tmp_fd)
    return Path(tmp_name)


def _prepare_output_directory(path: Path, label: str) -> None:
    marker = path / ".wuci-output-check"
    _reject_symlink_output_parents(marker, label)
    path.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(marker, label)


def _prepare_replacement_output_path(path: Path, label: str, *, force: bool) -> None:
    _reject_symlink_output_parents(path, label)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(path, label)
    try:
        wuci_kaiju.prepare_output_path(path, label, force=force)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc


def _prepare_exclusive_output_path(path: Path, label: str, *, force: bool) -> None:
    _prepare_replacement_output_path(path, label, force=force)
    if force:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _finish_atomic_tar_path(tmp_path: Path, tar_path: Path, label: str) -> dict[str, Any]:
    validate_tar_member_policy(tmp_path, label)
    os.replace(tmp_path, tar_path)
    _fsync_parent(tar_path)
    return validate_tar_member_policy(tar_path, label)


def _copy_verified_regular_file(
    source: Path,
    dest: Path,
    label: str,
    *,
    expected_info: os.stat_result | None = None,
    mode: int = 0o644,
) -> tuple[dict[str, str], int]:
    info = _verified_regular_file_info(source, label) if expected_info is None else expected_info
    _reject_symlink_output_parents(dest, label)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(dest, label)
    try:
        wuci_kaiju.reject_unsafe_existing_path(dest, label)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    tmp_fd = -1
    tmp_name = ""
    dest_installed = False
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    total = 0
    try:
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{dest.name}.", dir=str(dest.parent))
        with _open_verified_regular_file(source, label, expected_info=info) as source_handle:
            with os.fdopen(tmp_fd, "wb") as out_handle:
                tmp_fd = -1
                while True:
                    chunk = source_handle.read(wuci_kaiju.READ_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    for digest in digests.values():
                        digest.update(chunk)
                    out_handle.write(chunk)
                out_handle.flush()
                os.fsync(out_handle.fileno())
        if total != info.st_size:
            raise WuciOSError(f"{label} changed while reading: {source}")
        tmp_path = Path(tmp_name)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dest)
        dest_installed = True
        _fsync_parent(dest)
        expected_digest = {name: digest.hexdigest() for name, digest in digests.items()}
        final_digest, final_bytes = wuci_kaiju.file_digest_vector(dest, label)
        if final_bytes != total or final_digest != expected_digest:
            raise WuciOSError(f"{label} digest changed after copy: {dest}")
        return final_digest, final_bytes
    except Exception:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        if dest_installed:
            try:
                dest.unlink()
            except OSError:
                pass
        raise


def _write_verified_new_file(path: Path, data: bytes, label: str, *, mode: int) -> tuple[dict[str, str], int]:
    _reject_symlink_output_parents(path, label)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(path, label)
    try:
        wuci_kaiju.reject_unsafe_existing_path(path, label)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    fd = -1
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | wuci_kaiju._cloexec() | wuci_kaiju._nofollow(), mode)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
        _fsync_parent(path)
        info = _verified_regular_file_info(path, label)
        if stat.S_IMODE(info.st_mode) != mode:
            raise WuciOSError(f"{label} mode drift after write: {path}")
        digest, size = wuci_kaiju.file_digest_vector(path, label)
        expected_digest = digest_vector(data)
        if size != len(data) or digest != expected_digest:
            raise WuciOSError(f"{label} digest changed after write: {path}")
        return digest, size
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def write_deterministic_overlay_tar(
    overlay_root: Path,
    tar_path: Path,
    *,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    paths = sorted(overlay_root.rglob("*"), key=lambda path: path.relative_to(overlay_root).as_posix())
    ticker = wuci_progress.TriangleTicker(ticker_mode, label="wuci-os tar")
    tmp_path = _prepare_atomic_tar_path(tar_path, "Wuci-OS overlay tar")
    try:
        with tarfile.open(tmp_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for index, path in enumerate(paths):
                rel = path.relative_to(overlay_root).as_posix()
                info = os.lstat(path)
                ticker.tick(index, len(paths), detail=rel)
                if stat.S_ISLNK(info.st_mode):
                    raise WuciOSError(f"overlay must not contain symlinks: {rel}")
                tar_info = tarfile.TarInfo(rel)
                tar_info.mtime = 0
                tar_info.uid = 0
                tar_info.gid = 0
                tar_info.uname = "root"
                tar_info.gname = "root"
                tar_info.mode = stat.S_IMODE(info.st_mode)
                if stat.S_ISDIR(info.st_mode):
                    tar_info.type = tarfile.DIRTYPE
                    tar_info.size = 0
                    archive.addfile(tar_info)
                elif stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        raise WuciOSError(f"overlay file must not be hardlinked: {rel}")
                    tar_info.type = tarfile.REGTYPE
                    tar_info.size = info.st_size
                    with _open_verified_regular_file(path, f"Wuci-OS overlay tar file {rel}", expected_info=info) as handle:
                        archive.addfile(tar_info, handle)
                else:
                    raise WuciOSError(f"overlay contains unsupported file type: {rel}")
        validation = _finish_atomic_tar_path(tmp_path, tar_path, "Wuci-OS overlay tar")
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        ticker.finish(ok=False)
        raise
    ticker.finish(ok=True)
    return validation


def tar_extraction_policy() -> dict[str, Any]:
    return {
        "schema": "wuci-os-tar-extraction-policy-v1",
        "allowed_member_types": ["directory", "regular-file"],
        "forbidden_member_types": ["symlink", "hardlink", "device", "fifo", "sparse", "unknown"],
        "forbidden_paths": ["absolute", "parent-directory-segment", "empty-component", "duplicate-member"],
        "required_metadata": {
            "mtime": 0,
            "uid": 0,
            "gid": 0,
            "uname": "root",
            "gname": "root",
        },
        "claim": "locally generated payload archive member policy; not runtime sandboxing or host containment",
    }


def validate_tar_member_policy(tar_path: Path, label: str) -> dict[str, Any]:
    policy = tar_extraction_policy()
    members = 0
    files = 0
    directories = 0
    seen: set[str] = set()
    try:
        with _open_verified_regular_file(tar_path, label) as handle:
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                for member in archive:
                    raw_name = member.name
                    if "\\" in raw_name:
                        raise WuciOSError(f"{label} contains unsafe tar member path: {raw_name}")
                    parts = raw_name.split("/")
                    if raw_name.startswith("/") or raw_name == "" or any(part in {"", ".", ".."} for part in parts):
                        raise WuciOSError(f"{label} contains unsafe tar member path: {raw_name}")
                    if raw_name in seen:
                        raise WuciOSError(f"{label} contains duplicate tar member: {raw_name}")
                    seen.add(raw_name)
                    if member.mtime != 0:
                        raise WuciOSError(f"{label} contains nondeterministic mtime: {raw_name}")
                    if member.uid != 0 or member.gid != 0:
                        raise WuciOSError(f"{label} contains non-root numeric owner: {raw_name}")
                    if member.uname != "root" or member.gname != "root":
                        raise WuciOSError(f"{label} contains non-root named owner: {raw_name}")
                    if member.isdir():
                        directories += 1
                    elif member.isfile():
                        files += 1
                    else:
                        raise WuciOSError(f"{label} contains unsupported tar member type: {raw_name}")
                    members += 1
    except tarfile.TarError as exc:
        raise WuciOSError(f"{label} is not a readable tar archive: {tar_path}") from exc
    return {
        "schema": "wuci-os-tar-validation-v1",
        "status": "pass",
        "tar_path": str(tar_path),
        "members": members,
        "regular_files": files,
        "directories": directories,
        "extraction_policy": policy,
    }


def _tar_member_bytes_and_digest(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    label: str,
) -> tuple[dict[str, str], int]:
    handle = archive.extractfile(member)
    if handle is None:
        raise WuciOSError(f"{label} could not read tar member: {member.name}")
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    total = 0
    with handle:
        while True:
            chunk = handle.read(wuci_kaiju.READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    return {digest_name: digest.hexdigest() for digest_name, digest in digests.items()}, total


def _tar_member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo, label: str) -> bytes:
    handle = archive.extractfile(member)
    if handle is None:
        raise WuciOSError(f"{label} could not read tar member: {member.name}")
    with handle:
        return handle.read()


def validate_source_kit_tar_manifest(
    tar_path: Path,
    manifest: dict[str, Any],
    *,
    label: str = "Wuci-OS source-kit tar",
) -> dict[str, Any]:
    tar_validation = validate_tar_member_policy(tar_path, label)
    expected_manifest_bytes = canonical_json_bytes(manifest) + b"\n"
    expected_manifest_paths = [
        (SOURCE_KIT_PREFIX / ".wuci-os-source-kit.json").as_posix(),
        SOURCE_KIT_GUEST_MANIFEST.as_posix(),
    ]
    expected_file_members = set(expected_manifest_paths)
    records = manifest.get("files")
    if not isinstance(records, list):
        raise WuciOSError(f"{label} manifest files must be a list")
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("target_path"), str):
            raise WuciOSError(f"{label} manifest file record missing target_path")
        expected_file_members.add(str(record["target_path"]))

    try:
        with _open_verified_regular_file(tar_path, label) as handle:
            with tarfile.open(fileobj=handle, mode="r:") as archive:
                members = {member.name: member for member in archive.getmembers()}
                actual_file_members = {name for name, member in members.items() if member.isfile()}
                if actual_file_members != expected_file_members:
                    raise WuciOSError(f"{label} regular file members do not match manifest records")
                for manifest_path in expected_manifest_paths:
                    member = members.get(manifest_path)
                    if member is None or not member.isfile():
                        raise WuciOSError(f"{label} missing manifest member: {manifest_path}")
                    if _tar_member_bytes(archive, member, label) != expected_manifest_bytes:
                        raise WuciOSError(f"{label} manifest member mismatch: {manifest_path}")
                for record in records:
                    target = str(record["target_path"])
                    member = members.get(target)
                    if member is None or not member.isfile():
                        raise WuciOSError(f"{label} missing source member: {target}")
                    if member.size != record.get("bytes"):
                        raise WuciOSError(f"{label} member byte count mismatch: {target}")
                    if oct(stat.S_IMODE(member.mode)) != record.get("mode"):
                        raise WuciOSError(f"{label} member mode mismatch: {target}")
                    digest, size = _tar_member_bytes_and_digest(archive, member, label)
                    if size != record.get("bytes"):
                        raise WuciOSError(f"{label} member byte count mismatch: {target}")
                    if digest != record.get("digest_vector"):
                        raise WuciOSError(f"{label} member digest mismatch: {target}")
    except tarfile.TarError as exc:
        raise WuciOSError(f"{label} is not a readable tar archive: {tar_path}") from exc
    return {
        "schema": "wuci-os-source-kit-tar-validation-v1",
        "status": "pass",
        "tar_path": str(tar_path),
        "regular_file_members": len(expected_file_members),
        "manifest_member_paths": expected_manifest_paths,
        "manifest_digest_vector": digest_vector(expected_manifest_bytes),
        "tar_validation": tar_validation,
    }


def _git_source_paths() -> list[Path]:
    root = repo_root()
    try:
        result = subprocess.run(
            ["git", "ls-files", "-co", "--exclude-standard", "-z"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0:
        paths: list[Path] = []
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            text = raw.decode("utf-8", "surrogateescape")
            rel = Path(text)
            if (root / rel).exists() or (root / rel).is_symlink():
                paths.append(rel)
        return sorted(paths, key=lambda path: path.as_posix())

    paths = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in {".git", "build", ".tools", "__pycache__"}:
            continue
        paths.append(rel)
    return paths


def git_missing_source_paths() -> list[dict[str, str]]:
    root = repo_root()
    try:
        result = subprocess.run(
            ["git", "ls-files", "-d", "-z"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
        )
    except OSError:
        return []
    if result.returncode != 0:
        return []
    missing: list[dict[str, str]] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        path = raw.decode("utf-8", "surrogateescape")
        missing.append({"path": path, "status": "tracked-missing-omitted"})
    return sorted(missing, key=lambda item: item["path"])


def _source_kit_output_relative(tar_path: Path) -> Path | None:
    root_resolved = repo_root().resolve(strict=False)
    tar_resolved = tar_path.resolve(strict=False)
    try:
        return tar_resolved.relative_to(root_resolved)
    except ValueError:
        return None


def _reserved_source_kit_output_problem(rel: Path, output_rel: Path | None) -> str:
    if output_rel is None:
        return ""
    if rel == output_rel:
        return f"source-kit output path must not be part of source evidence: {rel.as_posix()}"
    if rel.parent == output_rel.parent and rel.name.startswith(f".{output_rel.name}.") and rel.name.endswith(".tmp"):
        return f"source-kit temporary output artifact must not be part of source evidence: {rel.as_posix()}"
    return ""


def source_kit_records(
    *,
    ticker_mode: str = "auto",
    reserved_output_rel: Path | None = None,
) -> list[dict[str, Any]]:
    root = repo_root()
    paths = _git_source_paths()
    records: list[dict[str, Any]] = []
    ticker = wuci_progress.TriangleTicker(ticker_mode, label="wuci-os source-kit")

    def add_record(path: Path, *, display_path: str, target_path: Path, source_kind: str, strict: bool) -> None:
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise WuciOSError(f"source-kit path disappeared: {display_path}") from exc
        if stat.S_ISDIR(info.st_mode):
            return
        if stat.S_ISLNK(info.st_mode):
            if strict:
                raise WuciOSError(f"source-kit file must not be a symlink: {display_path}")
            return
        if not stat.S_ISREG(info.st_mode):
            if strict:
                raise WuciOSError(f"source-kit contains unsupported file type: {display_path}")
            return
        if info.st_nlink != 1:
            if strict:
                raise WuciOSError(f"source-kit file must not be hardlinked: {display_path}")
            return
        digest, size = wuci_kaiju.file_digest_vector(path, f"Wuci-OS source-kit file {display_path}")
        records.append(
            {
                "path": display_path,
                "source_path": str(path),
                "source_kind": source_kind,
                "target_path": target_path.as_posix(),
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "bytes": size,
                "digest_vector": digest,
            }
        )

    for index, rel in enumerate(paths):
        rel_text = rel.as_posix()
        ticker.tick(index, len(paths), detail=rel_text)
        if rel.is_absolute() or ".." in rel.parts or rel_text.startswith("/"):
            raise WuciOSError(f"unsafe source-kit path: {rel_text}")
        reserved_problem = _reserved_source_kit_output_problem(rel, reserved_output_rel)
        if reserved_problem:
            raise WuciOSError(reserved_problem)
        add_record(root / rel, display_path=rel_text, target_path=SOURCE_KIT_PREFIX / rel, source_kind="wuci-ji", strict=True)

    upstream_root = root / DEFAULT_UPSTREAM_ROOT
    if upstream_root.is_dir():
        upstream_paths = sorted(upstream_root.rglob("*"), key=lambda path: path.relative_to(upstream_root).as_posix())
        for path in upstream_paths:
            rel = path.relative_to(upstream_root)
            rel_text = rel.as_posix()
            if ".git" in rel.parts:
                continue
            if rel.is_absolute() or ".." in rel.parts or rel_text.startswith("/"):
                raise WuciOSError(f"unsafe upstream source-kit path: {rel_text}")
            add_record(
                path,
                display_path=f"{DEFAULT_UPSTREAM_ROOT.as_posix()}/{rel_text}",
                target_path=UPSTREAM_SOURCE_PREFIX / rel,
                source_kind="upstream-build-source",
                strict=False,
            )
    ticker.finish(ok=True)
    return records


def write_deterministic_source_kit_tar(
    tar_path: Path,
    *,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    root = repo_root()
    _prepare_atomic_tar_output_path(tar_path, "Wuci-OS source-kit tar")
    records = source_kit_records(
        ticker_mode=ticker_mode,
        reserved_output_rel=_source_kit_output_relative(tar_path),
    )
    tmp_path = _prepare_atomic_tar_path(tar_path, "Wuci-OS source-kit tar")
    manifest = {
        "schema": SOURCE_KIT_SCHEMA,
        "created_utc": SOURCE_KIT_DETERMINISTIC_CREATED_UTC,
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "source_root": str(root),
        "upstream_source_root": str(root / DEFAULT_UPSTREAM_ROOT),
        "guest_source_root": SOURCE_KIT_PREFIX.as_posix(),
        "guest_upstream_source_root": UPSTREAM_SOURCE_PREFIX.as_posix(),
        "guest_manifest": SOURCE_KIT_GUEST_MANIFEST.as_posix(),
        "omitted_missing_tracked_paths": git_missing_source_paths(),
        "files": records,
        "extraction_policy": tar_extraction_policy(),
        "timestamp_policy": {
            "created_utc": "fixed archive epoch for byte-reproducible source-kit payloads",
            "wall_clock_time": "intentionally omitted from deterministic source-kit tar members",
        },
        "non_claims": list(BOUNDARY_DENIALS),
    }

    def add_data(archive: tarfile.TarFile, rel: Path, data: bytes, mode: int = 0o644) -> None:
        tar_info = tarfile.TarInfo(rel.as_posix())
        tar_info.mtime = 0
        tar_info.uid = 0
        tar_info.gid = 0
        tar_info.uname = "root"
        tar_info.gname = "root"
        tar_info.mode = mode
        tar_info.type = tarfile.REGTYPE
        tar_info.size = len(data)
        with tempfile.SpooledTemporaryFile(max_size=max(1, len(data))) as handle:
            handle.write(data)
            handle.seek(0)
            archive.addfile(tar_info, handle)

    try:
        with tarfile.open(tmp_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for directory in (
                Path("opt"),
                Path("opt/wuci-os"),
                Path("opt/wuci-os/source"),
                SOURCE_KIT_PREFIX,
                UPSTREAM_SOURCE_PREFIX,
                Path("usr"),
                Path("usr/share"),
                Path("usr/share/wuci-os"),
            ):
                tar_info = tarfile.TarInfo(directory.as_posix())
                tar_info.mtime = 0
                tar_info.uid = 0
                tar_info.gid = 0
                tar_info.uname = "root"
                tar_info.gname = "root"
                tar_info.mode = 0o755
                tar_info.type = tarfile.DIRTYPE
                tar_info.size = 0
                archive.addfile(tar_info)

            for record in records:
                path = Path(str(record["source_path"]))
                info = os.lstat(path)
                label = f"Wuci-OS source-kit file {record['path']}"
                if stat.S_ISLNK(info.st_mode):
                    raise WuciOSError(f"{label} must not be a symlink: {path}")
                if not stat.S_ISREG(info.st_mode):
                    raise WuciOSError(f"{label} must be a regular file: {path}")
                if info.st_nlink != 1:
                    raise WuciOSError(f"{label} must not be hardlinked: {path}")
                tar_info = tarfile.TarInfo(str(record["target_path"]))
                tar_info.mtime = 0
                tar_info.uid = 0
                tar_info.gid = 0
                tar_info.uname = "root"
                tar_info.gname = "root"
                tar_info.mode = stat.S_IMODE(info.st_mode)
                tar_info.type = tarfile.REGTYPE
                tar_info.size = info.st_size
                with _open_verified_regular_file(path, label, expected_info=info) as handle:
                    archive.addfile(tar_info, handle)

            manifest_bytes = canonical_json_bytes(manifest) + b"\n"
            add_data(archive, SOURCE_KIT_PREFIX / ".wuci-os-source-kit.json", manifest_bytes)
            add_data(archive, SOURCE_KIT_GUEST_MANIFEST, manifest_bytes)
        validate_source_kit_tar_manifest(tmp_path, manifest, label="Wuci-OS source-kit tar candidate")
        tar_validation = _finish_atomic_tar_path(tmp_path, tar_path, "Wuci-OS source-kit tar")
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise

    source_kit_validation = validate_source_kit_tar_manifest(tar_path, manifest, label="Wuci-OS source-kit tar")
    tar_digest, tar_bytes = wuci_kaiju.file_digest_vector(tar_path, "Wuci-OS source-kit tar")
    return manifest | {
        "tar_path": str(tar_path),
        "tar_bytes": tar_bytes,
        "tar_digest_vector": tar_digest,
        "tar_validation": tar_validation,
        "source_kit_validation": source_kit_validation,
    }


def generate_keyfile(path: Path, *, force: bool = False) -> dict[str, Any]:
    _prepare_exclusive_output_path(path, "Wuci-OS Daylight keyfile", force=force)
    key = base64.b16encode(os.urandom(32)).lower() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | wuci_kaiju._cloexec() | wuci_kaiju._nofollow(), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    _fsync_parent(path)
    try:
        written = os.lstat(path)
    except OSError as exc:
        raise WuciOSError(f"could not inspect Wuci-OS Daylight keyfile after creation: {path}") from exc
    if not stat.S_ISREG(written.st_mode):
        raise WuciOSError(f"Wuci-OS Daylight keyfile changed type after creation: {path}")
    if written.st_nlink != 1:
        raise WuciOSError(f"Wuci-OS Daylight keyfile must not be hardlinked after creation: {path}")
    if stat.S_IMODE(written.st_mode) != 0o600:
        raise WuciOSError(f"Wuci-OS Daylight keyfile mode drift after creation: {path}")
    digest = digest_vector(key)
    return {
        "schema": "wuci-os-daylight-keyfile-v1",
        "path": str(path),
        "bytes": len(key),
        "digest_vector": digest,
        "mode": "0600",
    }


def seal_overlay(
    *,
    overlay_root: Path | None = None,
    out_root: Path | None = None,
    keyfile: Path,
    bin_path: Path | None = None,
    force: bool = False,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    root = DEFAULT_OVERLAY_ROOT if overlay_root is None else overlay_root
    out = DEFAULT_SEAL_ROOT if out_root is None else out_root
    bin_candidate = repo_root() / DEFAULT_WUCI_BIN if bin_path is None else bin_path
    if not root.is_dir():
        raise WuciOSError(f"overlay root is missing: {root}")
    if not os.access(bin_candidate, os.X_OK):
        raise WuciOSError(f"wuci-ji binary is not executable: {bin_candidate}")
    wuci_kaiju.require_regular_local_file(bin_candidate, "wuci-ji binary")
    _reject_symlink_output_parents(out / "manifest.json", "Wuci-OS Daylight seal output")
    key_bytes = _read_regular_bytes(keyfile, "Wuci-OS Daylight keyfile")
    if not re.fullmatch(rb"[0-9a-fA-F]{64}\n?", key_bytes):
        raise WuciOSError("Wuci-OS Daylight keyfile must contain one 32-byte hex key")
    manifest = wuci_kaiju.read_public_json(overlay_manifest_path(root), "Wuci-OS overlay manifest")
    file_records = overlay_file_records(root, ticker_mode=ticker_mode)
    validate_overlay_manifest_current(root, manifest, records=file_records, ticker_mode=ticker_mode)
    _prepare_output_directory(out, "Wuci-OS Daylight seal output")
    sealed_path = out / "wuci-os-overlay.wj"
    manifest_path = out / "manifest.json"
    try:
        wuci_kaiju.prepare_output_path(sealed_path, "Wuci-OS Daylight sealed overlay", force=force)
        wuci_kaiju.prepare_output_path(manifest_path, "Wuci-OS Daylight seal manifest", force=force)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    tar_fd, tar_name = tempfile.mkstemp(prefix=".wuci-os-overlay.", suffix=".tar", dir=str(out))
    key_fd, key_tmp_name = tempfile.mkstemp(prefix=".wuci-os-key.", dir=str(out), text=False)
    seal_tmp_dir = Path(tempfile.mkdtemp(prefix=".wuci-os-seal.", dir=str(out)))
    sealed_tmp_path = seal_tmp_dir / "wuci-os-overlay.wj"
    sealed_backup_name = ""
    manifest_backup_name = ""
    sealed_installed = False
    manifest_write_started = False
    result: subprocess.CompletedProcess[str] | None = None
    try:
        os.close(tar_fd)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_bytes)
            key_handle.flush()
            os.fsync(key_handle.fileno())
        os.chmod(key_tmp_name, 0o600)
        tar_validation = write_deterministic_overlay_tar(root, Path(tar_name), ticker_mode=ticker_mode)
        tar_digest, tar_bytes = wuci_kaiju.file_digest_vector(Path(tar_name), "Wuci-OS deterministic overlay tar")
        bundle = {
            "schema": OVERLAY_SEAL_BUNDLE_SCHEMA,
            "created_utc": utc_now(),
            "product": PRODUCT_NAME,
            "image_id": IMAGE_ID,
            "overlay_manifest_digest_vector": digest_vector(canonical_json_bytes(manifest)),
            "overlay_file_records": file_records,
            "overlay_tar": {
                "bytes": tar_bytes,
                "digest_vector": tar_digest,
                "format": "deterministic tar with mtime=0 and root/root metadata",
                "validation": tar_validation,
            },
            "security_profile": security_profile_manifest(),
            "wrap_scheme": {
                "artifact_envelope": "WJSEAL-v2 via seal-file-keyfile-v2",
                "daylight_binding": "Wuci-OS overlay manifest, file digest records, and security profile",
                "key_source": "operator-supplied local keyfile; key material is not embedded",
                "plaintext_persistence": "deterministic tar is temporary and removed after sealing",
            },
            "non_claims": list(BOUNDARY_DENIALS),
        }
        bundle_digest = digest_vector(canonical_json_bytes(bundle))
        key_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "wuci-os-daylight-overlay-key-id-v1",
                    "bundle_digest_vector": bundle_digest,
                }
            )
        ).hexdigest()[:32]
        with wuci_progress.stage("wuci-os WJSEAL", ticker_mode):
            result = subprocess.run(
                [
                    str(bin_candidate),
                    "seal-file-keyfile-v2",
                    key_tmp_name,
                    key_id,
                    tar_name,
                    str(sealed_tmp_path),
                ],
                cwd=repo_root(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                shell=False,
            )
    finally:
        for name in (tar_name, key_tmp_name):
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
        if result is None or result.returncode != 0:
            try:
                sealed_tmp_path.unlink()
            except FileNotFoundError:
                pass
            try:
                seal_tmp_dir.rmdir()
            except OSError:
                pass
    if result is None or result.returncode != 0:
        stderr = "" if result is None else result.stderr
        raise WuciOSError(stderr.strip() or "seal-file-keyfile-v2 failed")
    if not sealed_tmp_path.is_file():
        try:
            seal_tmp_dir.rmdir()
        except OSError:
            pass
        raise WuciOSError("seal-file-keyfile-v2 did not produce a sealed overlay")
    try:
        wuci_kaiju.file_digest_vector(sealed_tmp_path, "Wuci-OS Daylight sealed overlay")
    except wuci_kaiju.KaijuError as exc:
        try:
            sealed_tmp_path.unlink()
        except FileNotFoundError:
            pass
        try:
            seal_tmp_dir.rmdir()
        except OSError:
            pass
        raise WuciOSError(str(exc)) from exc
    try:
        sealed_backup_name = _backup_existing_regular_file(sealed_path, "Wuci-OS Daylight sealed overlay")
        manifest_backup_name = _backup_existing_regular_file(manifest_path, "Wuci-OS Daylight seal manifest")
        os.replace(sealed_tmp_path, sealed_path)
        sealed_installed = True
        _fsync_parent(sealed_path)
        try:
            seal_tmp_dir.rmdir()
        except OSError:
            pass
        sealed_digest, sealed_bytes = wuci_kaiju.file_digest_vector(sealed_path, "Wuci-OS Daylight sealed overlay")
        seal_manifest = {
            "schema": OVERLAY_SEAL_SCHEMA,
            "status": "sealed",
            "created_utc": utc_now(),
            "product": PRODUCT_NAME,
            "image_id": IMAGE_ID,
            "overlay_root": str(root),
            "key_id": key_id,
            "key_source": "operator-supplied local keyfile; key material is not embedded",
            "sealed_artifact": {
                "path": str(sealed_path),
                "bytes": sealed_bytes,
                "digest_vector": sealed_digest,
            },
            "bundle_digest_vector": bundle_digest,
            "overlay_manifest_digest_vector": digest_vector(canonical_json_bytes(manifest)),
            "security_profile": security_profile_manifest(),
            "wrap_scheme": bundle["wrap_scheme"],
            "non_claims": list(BOUNDARY_DENIALS),
        }
        manifest_write_started = True
        wuci_kaiju.write_json_atomic(manifest_path, seal_manifest)
        _fsync_parent(manifest_path)
        _discard_temporary_path(sealed_backup_name)
        sealed_backup_name = ""
        _discard_temporary_path(manifest_backup_name)
        manifest_backup_name = ""
        return seal_manifest
    except Exception as exc:
        try:
            sealed_tmp_path.unlink()
        except FileNotFoundError:
            pass
        try:
            seal_tmp_dir.rmdir()
        except OSError:
            pass
        rollback_errors = []
        try:
            if sealed_backup_name:
                _restore_backup_file(sealed_path, sealed_backup_name, "Wuci-OS Daylight sealed overlay")
            elif sealed_installed:
                _unlink_existing_path(str(sealed_path))
        except WuciOSError as rollback_exc:
            rollback_errors.append(str(rollback_exc))
        try:
            if manifest_backup_name:
                _restore_backup_file(manifest_path, manifest_backup_name, "Wuci-OS Daylight seal manifest")
            elif manifest_write_started:
                _unlink_existing_path(str(manifest_path))
        except WuciOSError as rollback_exc:
            rollback_errors.append(str(rollback_exc))
        if rollback_errors:
            raise WuciOSError(
                f"seal-overlay failed and rollback failed: {exc}; {'; '.join(rollback_errors)}"
            ) from exc
        raise


def overlay_files() -> dict[str, str]:
    readme = "\n".join(
        [
            "Wuci-OS",
            "",
            "Wuci-OS is the Wuci-Ji/NOXFRAME operating-system image lane.",
            "This live profile is the Wuci-OS operator substrate.",
            "",
            "Commands:",
            "  wuci-status   show the active Wuci-OS live profile",
            "  wuci-attest   run a short local proof marker",
            "  wuci-live-banner show the Wuci-OS activated-console banner",
            "  wuci-enter    enter the WJ>_ operator shell",
            "  wuci-terminal open the preferred terminal: kitty, ghostty, then fallbacks",
            "  wuci-update   update system packages and the onboard Wuci-Ji checkout",
            "  wuci-boot-chime play the original Wuci-OS boot chime",
            "  wuci-network-apply install/enable Wi-Fi and network support",
            "  wuci-media-apply install/enable audio, video, Bluetooth, and portals",
            "  wuci-sdr-apply install/enable SDR/radio software and USB groups",
            "  wuci-guide    guided high-assurance setup",
            "  wuci-auto     mostly automated live workstation setup",
            "  wuci-source-status     show onboard Wuci-Ji source payload status",
            "  wuci-daylight-v14c-plus regenerate/verify the Daylight v14C+ candidate score",
            "  wuci-daylight-meridian verify/score/frontier/gate + the fail-closed Meridian vault (v15)",
            "  wj install <packages>  install Wuci-OS packages",
            "  INSTALL       auto-install Wuci-OS to disk after disk-erasure confirmation",
            "  wuci-install  same as INSTALL",
            "  wuci-install-target-activate  reapply Wuci-OS to an installed target",
            "  /usr/share/wuci-os/OFFLINE-INSTALL.txt  full offline install steps",
            "  wuci-dev-install       install desktop, editor, and developer packages",
            "  wuci-security-apply    apply SELinux-first high-assurance settings",
            "  wuci-security-status   verify SELinux/LUKS/firewall/hardening state",
            "  wuci-ai-setup          print Codex, Copilot, and Grok Build setup plan",
            "",
            "Boundary:",
            "  This profile defaults to high-assurance configuration goals, but claims",
            "  only what wuci-security-status and Daylight/WJSEAL evidence verify.",
            "",
        ]
    )
    status_script = """#!/bin/sh
set -eu
printf 'Wuci-OS live profile\\n'
printf 'base: Wuci-OS x86_64-musl\\n'
printf 'host: '
hostname
printf 'kernel: '
uname -srmo
if [ -r /etc/os-release ]; then
    . /etc/os-release
    printf 'os-release: %s %s\\n' "${NAME:-unknown}" "${VERSION_ID:-unknown}"
fi
printf 'boundary: image evidence and demo substrate; not runtime containment\\n'
wuci-security-status --summary 2>/dev/null || true
wuci-daylight-status --summary 2>/dev/null || true
wuci-source-status --summary 2>/dev/null || true
"""
    live_banner_script = """#!/bin/sh
set -eu
clear 2>/dev/null || true
cat <<'BANNER'
Wuci-OS
WJ>_ high-assurance operator substrate
BANNER
printf '\\n'
if [ -d /opt/wuci-os/source/wuci-ji ]; then
    printf '[PASS] onboard source: /opt/wuci-os/source/wuci-ji\\n'
else
    printf '[WARN] onboard source not extracted yet\\n'
fi
if [ -d /opt/wuci-os/source/upstream ]; then
    printf '[PASS] upstream build source: /opt/wuci-os/source/upstream\\n'
else
    printf '[WARN] upstream build source not extracted yet\\n'
fi
if [ -r /usr/share/wuci-os/source-kit.json ]; then
    printf '[PASS] source-kit manifest: /usr/share/wuci-os/source-kit.json\\n'
else
    printf '[WARN] source-kit manifest not present\\n'
fi
if command -v wuci-terminal >/dev/null 2>&1; then
    printf 'terminal: '
    wuci-terminal --print || true
fi
if command -v wuci-boot-chime >/dev/null 2>&1; then
    wuci-boot-chime --once --quiet 2>/dev/null &
fi
printf 'operator: wuci-enter\\n'
printf 'update:   wuci-update\\n'
printf 'network:  wuci-network-apply\\n'
printf 'media:    wuci-media-apply\\n'
printf 'sdr:      wuci-sdr-apply\\n'
printf 'guide:    wuci-guide\\n'
printf 'attest:   wuci-attest\\n'
"""
    attest_script = """#!/bin/sh
set -eu
clear 2>/dev/null || true
cat <<'BANNER'
Wuci-OS
Wuci-Ji proof lane -> NOXFRAME operator surface -> WJ>_
BANNER
printf '\\n'
wuci-status
printf '\\n'
printf 'proof marker: '
date -u '+%Y-%m-%dT%H:%M:%SZ'
printf 'route: redhat -> wuci-os -> noxframe\\n'
printf 'workspace: /usr/share/wuci-os\\n'
"""
    source_status_script = """#!/bin/sh
set -eu

summary=0
if [ "${1:-}" = "--summary" ]; then
    summary=1
fi

fail=0
say() {
    state=$1
    label=$2
    [ "$summary" -eq 1 ] || printf '[%s] %s\\n' "$state" "$label"
    [ "$state" = "FAIL" ] && fail=1 || true
}

if [ -d /opt/wuci-os/source/wuci-ji ]; then
    say PASS 'Wuci-Ji source tree present at /opt/wuci-os/source/wuci-ji'
else
    say WARN 'Wuci-Ji source tree not extracted; extract all Wuci payload drives'
fi

if [ -d /opt/wuci-os/source/upstream ]; then
    say PASS 'upstream build source present at /opt/wuci-os/source/upstream'
else
    say WARN 'upstream build source not extracted; fetch/build source may still be host-only'
fi

if [ -r /usr/share/wuci-os/source-kit.json ]; then
    say PASS 'source-kit manifest present'
    bytes=$(wc -c < /usr/share/wuci-os/source-kit.json 2>/dev/null | tr -d ' ' || printf 0)
    [ "$summary" -eq 1 ] || printf '[PASS] source-kit manifest bytes: %s\\n' "$bytes"
else
    say WARN 'source-kit manifest missing'
fi

if [ "$summary" -eq 1 ]; then
    if [ -d /opt/wuci-os/source/wuci-ji ]; then
        printf 'source: onboard Wuci-Ji source present'
        if [ -d /opt/wuci-os/source/upstream ]; then
            printf '; upstream build source present\\n'
        else
            printf '; upstream build source missing\\n'
        fi
    else
        printf 'source: onboard source not extracted\\n'
    fi
fi
exit "$fail"
"""
    enter_script = """#!/bin/sh
set -eu

target="${1:-wj}"
entry=$(getent passwd "$target" 2>/dev/null || true)
if [ -z "$entry" ]; then
    printf 'wuci-enter: user not found: %s\\n' "$target" >&2
    printf 'run: wuci-users-apply\\n' >&2
    exit 1
fi

home=$(printf '%s' "$entry" | cut -d: -f6)
shell_path=$(printf '%s' "$entry" | cut -d: -f7)
[ -n "$home" ] || home="/home/$target"
[ -n "$shell_path" ] || shell_path=/bin/sh
[ -x "$shell_path" ] || shell_path=/bin/sh

case "$target" in
    wj) prompt='WJ>_ ' ;;
    wj_low) prompt='WJ-low>_ ' ;;
    *) prompt='Wuci>_ ' ;;
esac

current_user=$(id -un 2>/dev/null || true)
if [ "$(id -u 2>/dev/null || printf 1)" != "0" ]; then
    if [ "$current_user" = "$target" ]; then
        cd "$home" 2>/dev/null || cd /
        exec env -i HOME="$home" USER="$target" LOGNAME="$target" SHELL="$shell_path" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" WUCI_OS=1 PS1="$prompt" "$shell_path" -i
    fi
    printf 'wuci-enter: run as root to switch users: sudo wuci-enter %s\\n' "$target" >&2
    printf 'wuci-enter: from the live console, root fallback is root / voidlinux, then: wuci-enter %s\\n' "$target" >&2
    exit 1
fi

cd "$home" 2>/dev/null || cd /

if command -v chpst >/dev/null 2>&1; then
    exec env -i HOME="$home" USER="$target" LOGNAME="$target" SHELL="$shell_path" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" WUCI_OS=1 PS1="$prompt" chpst -u "$target" "$shell_path" -i
fi
if command -v runuser >/dev/null 2>&1; then
    exec runuser -u "$target" -- "$shell_path" -i
fi
if command -v sudo >/dev/null 2>&1; then
    exec sudo -iu "$target"
fi
if command -v doas >/dev/null 2>&1; then
    exec doas -u "$target" "$shell_path" -i
fi
if command -v su >/dev/null 2>&1; then
    exec su - "$target"
fi

printf 'wuci-enter: no user-switch command found; install runit, util-linux, sudo, doas, or shadow.\\n' >&2
exit 127
"""
    daylight_status_script = """#!/bin/sh
set -eu

summary=0
if [ "${1:-}" = "--summary" ]; then
    summary=1
fi

fail=0
warn=0
report() {
    state=$1
    label=$2
    [ "$summary" -eq 1 ] || printf '[%s] %s\\n' "$state" "$label"
    case "$state" in
        FAIL) fail=1 ;;
        WARN) warn=1 ;;
    esac
}

check_file() {
    path=$1
    label=$2
    if [ -r "$path" ] && [ ! -L "$path" ]; then
        report PASS "$label"
    else
        report FAIL "$label"
    fi
}

check_file /usr/share/wuci-os/overlay-manifest.json 'overlay manifest present'
check_file /usr/share/wuci-os/accounts.json 'account profile present'
check_file /usr/share/wuci-os/security-profile.json 'security profile present'
check_file /usr/share/wuci-os/packages.json 'developer package profile present'
check_file /usr/share/backgrounds/wuci-os/wallpaper1.png 'wallpaper asset present'

if [ -r /usr/share/wuci-os/daylight-seal-manifest.json ]; then
    report PASS 'Daylight/WJSEAL seal manifest present'
else
    report WARN 'release Daylight/WJSEAL seal manifest is not baked into this live preview'
fi

if [ -d /usr/share/wuci-os/daylight/v14c-plus/src ]; then
    report PASS 'Daylight v14C+ candidate package present'
else
    report FAIL 'Daylight v14C+ candidate package missing'
fi

if [ -d /usr/share/wuci-os/daylight/v15-meridian/src ]; then
    report PASS 'Daylight v15 Meridian package present (evidence-derived + fail-closed vault)'
    if command -v wuci-daylight-meridian >/dev/null 2>&1 && wuci-daylight-meridian status >/dev/null 2>&1; then
        report PASS 'Daylight v15 Meridian scorecard verifies'
    else
        report WARN 'Daylight v15 Meridian scorecard did not verify in this environment'
    fi
else
    report FAIL 'Daylight v15 Meridian package missing'
fi

if [ "$summary" -eq 1 ]; then
    if [ "$fail" -eq 0 ]; then
        if [ "$warn" -eq 0 ]; then
            printf 'daylight: required evidence present\\n'
        else
            printf 'daylight: live evidence present; release seal pending\\n'
        fi
    else
        printf 'daylight: required live evidence incomplete\\n'
    fi
fi
exit "$fail"
"""
    daylight_v14c_script = """#!/bin/sh
set -eu

pkg=${WUCI_DAYLIGHT_V14C_PACKAGE:-/usr/share/wuci-os/daylight/v14c-plus}
out=${WUCI_DAYLIGHT_V14C_OUT:-/tmp/wuci-daylight-v14c-plus}
cmd=${1:-status}
py=${PYTHON:-python3}

need_python() {
    if ! command -v "$py" >/dev/null 2>&1; then
        printf 'wuci-daylight-v14c-plus: python3 is required to execute the harness\\n' >&2
        exit 127
    fi
}

need_package() {
    if [ ! -d "$pkg/src" ] || [ ! -r "$pkg/examples/ledger.seed.jsonl" ] || [ ! -r "$pkg/examples/corpus.seed.jsonl" ]; then
        printf 'wuci-daylight-v14c-plus: execution package missing or incomplete: %s\\n' "$pkg" >&2
        exit 1
    fi
}

scorecard_value() {
    "$py" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); print("%sM" % d["final_score_M"])' "$1"
}

verify_packaged() {
    need_python
    need_package
    PYTHONPATH="$pkg" "$py" -m src.cli verify-scorecard "$pkg/examples/expected-scorecard.v14c-plus.json"
}

regenerate() {
    need_python
    need_package
    mkdir -p "$out"
    PYTHONPATH="$pkg" "$py" -m src.cli score \
        --ledger "$pkg/examples/ledger.seed.jsonl" \
        --corpus "$pkg/examples/corpus.seed.jsonl" \
        --out "$out/scorecard.v14c-plus.json" \
        --receipt "$out/reproducibility-receipt.v14c-plus.json" \
        --output-ledger "$out/ledger.with-scorecard.jsonl"
    PYTHONPATH="$pkg" "$py" -m src.cli verify-scorecard "$out/scorecard.v14c-plus.json"
    printf 'candidate: DAYLIGHT v14C+ ASCENDANT CANDIDATE\\n'
    printf 'score: '
    scorecard_value "$out/scorecard.v14c-plus.json"
    printf 'scorecard: %s\\n' "$out/scorecard.v14c-plus.json"
    printf 'receipt: %s\\n' "$out/reproducibility-receipt.v14c-plus.json"
}

case "$cmd" in
    status|--summary)
        if verify_packaged >/dev/null 2>&1; then
            printf 'daylight-v14c-plus: candidate score package verifies; generated release authority is still blocked\\n'
            exit 0
        fi
        printf 'daylight-v14c-plus: candidate package verification failed\\n' >&2
        exit 1
        ;;
    verify)
        verify_packaged
        scorecard_value "$pkg/examples/expected-scorecard.v14c-plus.json"
        ;;
    score|regenerate)
        regenerate
        ;;
    test)
        need_python
        need_package
        PYTHONPATH="$pkg" "$py" -m unittest discover -s "$pkg/tests" -t "$pkg"
        ;;
    path)
        printf '%s\\n' "$pkg"
        ;;
    *)
        cat <<'USAGE'
usage: wuci-daylight-v14c-plus [status|verify|score|test|path]

status  verify the packaged candidate scorecard
verify  verify and print the packaged expected score
score   regenerate the scorecard from frozen package inputs into /tmp
test    run the package unit tests
path    print the packaged harness path
USAGE
        exit 2
        ;;
esac
"""
    daylight_meridian_script = """#!/bin/sh
set -eu

pkg=${WUCI_DAYLIGHT_MERIDIAN_PACKAGE:-/usr/share/wuci-os/daylight/v15-meridian}
out=${WUCI_DAYLIGHT_MERIDIAN_OUT:-/tmp/wuci-daylight-meridian}
cmd=${1:-status}
py=${PYTHON:-python3}

need_python() {
    if ! command -v "$py" >/dev/null 2>&1; then
        printf 'wuci-daylight-meridian: python3 is required to execute the harness\\n' >&2
        exit 127
    fi
}

need_package() {
    if [ ! -d "$pkg/src" ] || [ ! -r "$pkg/examples/ledger.seed.jsonl" ] || [ ! -r "$pkg/examples/corpus.seed.jsonl" ]; then
        printf 'wuci-daylight-meridian: execution package missing or incomplete: %s\\n' "$pkg" >&2
        exit 1
    fi
}

run_cli() {
    PYTHONPATH="$pkg" "$py" -m src.cli "$@"
}

scorecard_value() {
    "$py" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8")); print("%sM" % d["final_score_M"])' "$1"
}

verify_packaged() {
    need_python
    need_package
    run_cli verify-scorecard "$pkg/examples/expected-scorecard.v15-meridian.json"
}

case "$cmd" in
    status)
        if verify_packaged >/dev/null 2>&1; then
            printf 'daylight-meridian: evidence-derived scorecard verifies (v15 Meridian); 1,000,000M still requires external attestation\\n'
            exit 0
        fi
        printf 'daylight-meridian: packaged scorecard verification failed\\n' >&2
        exit 1
        ;;
    verify)
        verify_packaged
        scorecard_value "$pkg/examples/expected-scorecard.v15-meridian.json"
        ;;
    score|regenerate)
        need_python
        need_package
        mkdir -p "$out"
        run_cli score \
            --ledger "$pkg/examples/ledger.seed.jsonl" \
            --corpus "$pkg/examples/corpus.seed.jsonl" \
            --out "$out/scorecard.v15-meridian.json" \
            --receipt "$out/reproducibility-receipt.v15-meridian.json"
        run_cli verify-scorecard "$out/scorecard.v15-meridian.json"
        printf 'model: DAYLIGHT v15 MERIDIAN (evidence-derived, fail-closed)\\n'
        printf 'score: '
        scorecard_value "$out/scorecard.v15-meridian.json"
        ;;
    frontier)
        need_python
        need_package
        run_cli frontier
        ;;
    gate)
        need_python
        need_package
        run_cli gate --scorecard "$pkg/examples/expected-scorecard.v15-meridian.json"
        ;;
    doctor)
        need_python
        need_package
        run_cli doctor
        ;;
    vault)
        need_python
        need_package
        shift
        run_cli vault "$@"
        ;;
    test)
        need_python
        need_package
        PYTHONPATH="$pkg" "$py" -m unittest discover -s "$pkg/tests" -t "$pkg"
        ;;
    path)
        printf '%s\\n' "$pkg"
        ;;
    *)
        cat <<'USAGE'
usage: wuci-daylight-meridian [status|verify|score|frontier|gate|doctor|vault ...|test|path]

status    verify the packaged evidence-derived scorecard
verify    verify and print the packaged score (998900M internal ceiling)
score     regenerate the scorecard from frozen package inputs into /tmp
frontier  print the internal ceiling, residue, and external frontier
gate      run the release/CI gate over the packaged scorecard
doctor    self-check the install (AEAD RFC-8439 KAT + verify)
vault ... evidence-gated, fail-closed vault (init|seal|open|list|status|autoseal)
test      run the package unit tests
path      print the packaged harness path
USAGE
        exit 2
        ;;
esac
"""
    guide_script = """#!/bin/sh
set -eu

ask() {
    prompt=$1
    default=${2:-Y}
    if [ "${WUCI_GUIDE_ASSUME_YES:-0}" = "1" ]; then
        printf '%s [%s] yes\\n' "$prompt" "$default"
        return 0
    fi
    printf '%s [%s] ' "$prompt" "$default"
    IFS= read -r answer || answer=
    case "${answer:-$default}" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

run_step() {
    label=$1
    shift
    printf '\\n==> %s\\n' "$label"
    "$@" || {
        printf 'wuci-guide: step did not complete: %s\\n' "$label" >&2
        return 1
    }
}

run_check() {
    label=$1
    shift
    printf '\\n==> %s\\n' "$label"
    "$@" || true
}

cat <<'TEXT'
Wuci-OS guided setup

This guide configures the live workstation in a high-assurance order:
accounts, prompt, Wi-Fi credential prompt/network support, audio/video support, wallpaper,
Daylight evidence status, developer tools, AI tool hooks, SELinux-first
hardening, and verification.

Use Wuci-OS package commands instead of backend package-manager commands:
  sudo wj install vim emacs kitty
  sudo wj update

Use wuci-update when this live system should fast-forward the onboard repo and
update packages from the configured repository set:
  sudo wuci-update

Destructive disk operations are not automated here.
TEXT

run_step 'apply Wuci-OS users and WJ>_ prompt' wuci-users-apply
run_check 'play Wuci-OS boot chime' wuci-boot-chime --once
run_check 'show preferred terminal resolver' wuci-terminal --print
run_check 'show account status' wuci-users-status
run_check 'show network status before setup' wuci-network-status
run_check 'show media status before setup' wuci-media-status
run_check 'show onboard source payload status' wuci-source-status
run_check 'show Daylight evidence status' wuci-daylight-status
run_check 'verify Daylight v14C+ candidate package' wuci-daylight-v14c-plus
run_check 'show security status before hardening' wuci-security-status

if ask 'Connect and enable Wi-Fi/network support?' Y; then
    run_step 'connect and enable Wi-Fi/network support' wuci-network-apply || true
fi

if ask 'Install and enable audio/video/Bluetooth support?' Y; then
    run_step 'install and enable media support' wuci-media-apply || true
fi

if ask 'Install SDR/radio software and USB SDR helpers?' Y; then
    run_step 'install SDR/radio software' wuci-sdr-apply || true
fi

if ask 'Apply wallpaper now?' Y; then
    run_step 'apply Wuci-OS wallpaper' wuci-wallpaper || true
fi

if ask 'Install developer workstation packages? This can take time.' Y; then
    run_step 'install developer workstation packages' wuci-dev-install || true
fi

if ask 'Print Codex, Copilot, and Grok Build setup plan?' Y; then
    run_step 'prepare AI tool setup plan' wuci-ai-setup || true
fi

if ask 'Apply SELinux-first high-assurance hardening profile?' Y; then
    run_step 'apply high-assurance hardening' wuci-security-apply || true
fi

run_check 'final security status' wuci-security-status
run_check 'network status' wuci-network-status
run_check 'media status' wuci-media-status
run_check 'SDR status' wuci-sdr-status
run_check 'SELinux status' wuci-selinux-status
run_check 'Daylight evidence status' wuci-daylight-status
run_check 'Daylight v14C+ candidate package' wuci-daylight-v14c-plus
run_check 'onboard source payload status' wuci-source-status

cat <<'TEXT'

Next operator shell:
  wuci-enter

Installed high-assurance systems must use LUKS/dm-crypt and rotate the live
empty password. Daylight/WJSEAL evidence must be generated for release artifacts
on the host with:
  tools/wuci-os seal-overlay --force --ticker always
TEXT
"""
    auto_script = """#!/bin/sh
set -eu
export WUCI_GUIDE_ASSUME_YES=1
exec wuci-guide "$@"
"""
    auto_install_script = """#!/bin/sh
set -eu

target=/mnt
disk=${WUCI_INSTALL_DISK:-}
assume_yes=${WUCI_INSTALL_ASSUME_YES:-0}
mode=${WUCI_INSTALL_BOOT_MODE:-auto}
auto_reboot=${WUCI_INSTALL_REBOOT:-0}
empty_passwords=${WUCI_INSTALL_EMPTY_PASSWORDS:-0}
target_password=${WUCI_INSTALL_PASSWORD:-}
hostname=${WUCI_INSTALL_HOSTNAME:-wuci-os}
arch=${WUCI_INSTALL_ARCH:-}

usage() {
    cat <<'TEXT'
Wuci-OS automatic installer

Usage:
  INSTALL [--disk /dev/sdX] [--yes] [--bios|--uefi] [--reboot]
          [--password PW | --empty-passwords] [--hostname NAME] [--arch ARCH]

This command automates partitioning, formatting, package install, GRUB,
Wuci-OS target activation, services, account passwords, and verification.

The installed system gets a real password on root and wj. Supply it with
--password / WUCI_INSTALL_PASSWORD, or you are prompted once. Pass
--empty-passwords only to reproduce the live demo's passwordless accounts.

By default it requires one disk-erasure confirmation. To script it:
  WUCI_INSTALL_DISK=/dev/sda WUCI_INSTALL_PASSWORD=secret \\
    WUCI_INSTALL_ASSUME_YES=1 INSTALL
TEXT
}

die() {
    printf 'INSTALL: %s\\n' "$*" >&2
    exit 1
}

say() {
    printf '\\n==> %s\\n' "$*"
}

run() {
    printf '+'
    for arg in "$@"; do
        printf ' %s' "$arg"
    done
    printf '\\n'
    "$@"
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command missing: $1"
}

cleanup_mounts() {
    umount -R "$target/boot/efi" >/dev/null 2>&1 || true
    umount -R "$target" >/dev/null 2>&1 || true
}

on_exit() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '\\nINSTALL: failed (exit %s); unmounting %s so the disk is left clean.\\n' "$rc" "$target" >&2
        cleanup_mounts
    fi
    return "$rc"
}

if [ "$(id -u)" != "0" ] && [ "${1:-}" != "--help" ] && [ "${1:-}" != "-h" ]; then
    if command -v sudo >/dev/null 2>&1; then
        exec sudo INSTALL "$@"
    fi
    die "run as root: sudo INSTALL"
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --disk)
            [ "$#" -ge 2 ] || die "--disk needs a path"
            disk=$2
            shift 2
            ;;
        --yes|-y)
            assume_yes=1
            shift
            ;;
        --bios)
            mode=bios
            shift
            ;;
        --uefi)
            mode=uefi
            shift
            ;;
        --reboot)
            auto_reboot=1
            shift
            ;;
        --password)
            [ "$#" -ge 2 ] || die "--password needs a value"
            target_password=$2
            shift 2
            ;;
        --empty-passwords)
            empty_passwords=1
            shift
            ;;
        --hostname)
            [ "$#" -ge 2 ] || die "--hostname needs a value"
            hostname=$2
            shift 2
            ;;
        --arch)
            [ "$#" -ge 2 ] || die "--arch needs a value"
            arch=$2
            shift 2
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

need xbps-install

# Match the target package architecture to the live system (e.g. x86_64-musl)
# so xbps-install -r resolves the right repositories instead of guessing.
if [ -z "$arch" ]; then
    arch=$(xbps-uhelper arch 2>/dev/null || true)
fi
[ -n "$arch" ] || arch=$(uname -m)
export XBPS_ARCH="$arch"

detect_disk() {
    count=0
    selected=
    for sysdisk in /sys/block/*; do
        [ -e "$sysdisk" ] || continue
        name=${sysdisk##*/}
        case "$name" in
            loop*|ram*|sr*|fd*) continue ;;
        esac
        [ -b "/dev/$name" ] || continue
        removable=$(cat "$sysdisk/removable" 2>/dev/null || printf 1)
        [ "$removable" = "0" ] || continue
        count=$((count + 1))
        selected=/dev/$name
    done
    if [ "$count" -eq 1 ]; then
        printf '%s\\n' "$selected"
    fi
}

if [ -z "$disk" ]; then
    disk=$(detect_disk || true)
fi

if [ -z "$disk" ]; then
    printf 'INSTALL: could not safely auto-select a target disk. Available disks:\\n' >&2
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL >&2 || true
    printf 'Run: sudo INSTALL --disk /dev/YOUR_DISK\\n' >&2
    exit 2
fi

[ -b "$disk" ] || die "target disk is not a block device: $disk"

if [ "$mode" = "auto" ]; then
    if [ -d /sys/firmware/efi ]; then
        mode=uefi
    else
        mode=bios
    fi
fi

case "$mode" in
    bios|uefi) ;;
    *) die "unsupported boot mode: $mode" ;;
esac

part_path() {
    case "$1" in
        *[0-9]) printf '%sp%s\\n' "$1" "$2" ;;
        *) printf '%s%s\\n' "$1" "$2" ;;
    esac
}

if [ "$mode" = "uefi" ]; then
    esp=$(part_path "$disk" 1)
    rootpart=$(part_path "$disk" 2)
else
    esp=
    rootpart=$(part_path "$disk" 1)
fi

say "Target disk"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL "$disk" || true
printf 'boot mode: %s\\n' "$mode"
printf 'root partition: %s\\n' "$rootpart"
[ -z "$esp" ] || printf 'efi partition: %s\\n' "$esp"

if [ "$assume_yes" != "1" ]; then
    printf '\\nTHIS ERASES %s. Type INSTALL to continue: ' "$disk"
    IFS= read -r answer || answer=
    [ "$answer" = "INSTALL" ] || die "confirmation did not match INSTALL"
fi

say "Install live-side toolchain"
run xbps-install -S || true
run xbps-install -y -Sy xbps parted e2fsprogs dosfstools grub util-linux gawk || true

for tool in parted mkfs.ext4 mount umount chroot blkid grub-install grub-mkconfig; do
    need "$tool"
done
if [ "$mode" = "uefi" ]; then
    need mkfs.vfat
fi

say "Unmount stale target mount"
umount -R "$target" >/dev/null 2>&1 || true
mkdir -p "$target"
trap on_exit EXIT INT TERM

say "Partition disk"
if command -v wipefs >/dev/null 2>&1; then
    run wipefs -a "$disk" || true
fi
if [ "$mode" = "uefi" ]; then
    run parted -s "$disk" mklabel gpt
    run parted -s "$disk" mkpart ESP fat32 1MiB 513MiB
    run parted -s "$disk" set 1 esp on
    run parted -s "$disk" mkpart primary ext4 513MiB 100%
else
    run parted -s "$disk" mklabel msdos
    run parted -s "$disk" mkpart primary ext4 1MiB 100%
    run parted -s "$disk" set 1 boot on
fi
sync
partprobe "$disk" >/dev/null 2>&1 || true
sleep 2

[ -b "$rootpart" ] || die "root partition did not appear: $rootpart"
[ -z "$esp" ] || [ -b "$esp" ] || die "EFI partition did not appear: $esp"

say "Format filesystems"
run mkfs.ext4 -F "$rootpart"
run mount "$rootpart" "$target"
if [ -n "$esp" ]; then
    run mkfs.vfat -F 32 "$esp"
    mkdir -p "$target/boot/efi"
    run mount "$esp" "$target/boot/efi"
fi

say "Seed target package configuration (arch=$arch)"
# A fresh root has no xbps repository config, so copy the live system's and
# pass the live repositories explicitly. Without this, xbps-install -r cannot
# resolve base-system on a musl target.
mkdir -p "$target/usr/share/xbps.d" "$target/etc/xbps.d"
if [ -d /usr/share/xbps.d ]; then
    cp -a /usr/share/xbps.d/. "$target/usr/share/xbps.d/" 2>/dev/null || true
fi
if [ -d /etc/xbps.d ]; then
    cp -a /etc/xbps.d/. "$target/etc/xbps.d/" 2>/dev/null || true
fi
repo_args=""
for repo in $(xbps-query -L 2>/dev/null | awk 'NF >= 2 { print $2 }'); do
    case "$repo" in
        http://*|https://*|/*) repo_args="$repo_args -R $repo" ;;
    esac
done

say "Install required base, kernel, network, and desktop packages"
required_packages="base-system linux6.12 grub sudo opendoas bash shadow util-linux coreutils findutils grep sed gawk less nano vim NetworkManager dbus wpa_supplicant iw rfkill dhcpcd iproute2 wireless-regdb linux-firmware linux-firmware-network linux-firmware-intel pciutils usbutils kmod e2fsprogs python3 git ca-certificates xorg xinit xfce4 xfce4-terminal xterm"
if [ "$mode" = "uefi" ]; then
    required_packages="$required_packages grub-x86_64-efi"
fi
run xbps-install -y -Sy -r "$target" $repo_args $required_packages

say "Install best-effort media and preferred terminal packages"
optional_packages="kitty alsa-utils pipewire wireplumber pulseaudio-utils mesa-dri mesa-vulkan-intel xf86-video-intel"
xbps-install -y -r "$target" $repo_args $optional_packages || printf 'INSTALL: optional package group had unavailable packages; continuing with required desktop.\\n' >&2

say "Prepare chroot mounts"
mkdir -p "$target/proc" "$target/sys" "$target/dev"
mount -t proc proc "$target/proc" 2>/dev/null || true
mount --rbind /sys "$target/sys" 2>/dev/null || true
mount --make-rslave "$target/sys" 2>/dev/null || true
mount --rbind /dev "$target/dev" 2>/dev/null || true
mount --make-rslave "$target/dev" 2>/dev/null || true

say "Write installed system identity and fstab"
root_uuid=$(blkid -s UUID -o value "$rootpart")
[ -n "$root_uuid" ] || die "could not read root UUID"
mkdir -p "$target/etc"
printf 'UUID=%s / ext4 defaults,noatime 0 1\\n' "$root_uuid" > "$target/etc/fstab"
if [ -n "$esp" ]; then
    esp_uuid=$(blkid -s UUID -o value "$esp")
    [ -n "$esp_uuid" ] || die "could not read EFI UUID"
    printf 'UUID=%s /boot/efi vfat defaults 0 2\\n' "$esp_uuid" >> "$target/etc/fstab"
fi
printf '%s\\n' "$hostname" > "$target/etc/hostname"

say "Enable services"
chroot "$target" /bin/sh -c 'mkdir -p /etc/runit/runsvdir/default; for svc in udevd dbus NetworkManager; do [ -d /etc/sv/$svc ] && ln -sfn /etc/sv/$svc /etc/runit/runsvdir/default/$svc; done'

say "Apply Wuci-OS installed-target profile"
if command -v wuci-install-target-activate >/dev/null 2>&1; then
    run wuci-install-target-activate "$target"
else
    die "wuci-install-target-activate is missing from this live image"
fi

say "Reconfigure installed packages (initramfs, kernel hooks)"
# Force reconfiguration in the target so dracut builds an initramfs and the
# kernel/bootloader hooks run; otherwise the disk may not boot.
chroot "$target" xbps-reconfigure -fa || printf 'INSTALL: package reconfigure reported issues; verify boot artifacts before trusting this install.\\n' >&2

say "Set installed-system account passwords"
# wuci-install-target-activate runs wuci-users-apply, which intentionally
# leaves the LIVE accounts passwordless. An installed disk must not ship that
# way, so set a real password on root and wj unless the operator opts out.
if [ "$empty_passwords" = "1" ]; then
    printf 'INSTALL: keeping empty passwords on the installed system (--empty-passwords).\\n'
    printf 'INSTALL: rotate them after first boot with: passwd root; passwd wj\\n'
else
    if [ -z "$target_password" ]; then
        if [ "$assume_yes" = "1" ]; then
            die "no password set: pass --password / WUCI_INSTALL_PASSWORD, or --empty-passwords for an unattended demo install"
        fi
        stty -echo 2>/dev/null || true
        printf 'Set a password for root and wj: '
        IFS= read -r target_password || target_password=
        printf '\\n'
        printf 'Confirm password: '
        IFS= read -r confirm_password || confirm_password=
        printf '\\n'
        stty echo 2>/dev/null || true
        [ -n "$target_password" ] || die "empty password rejected (use --empty-passwords to intentionally keep it empty)"
        [ "$target_password" = "$confirm_password" ] || die "passwords did not match"
        confirm_password=
    fi
    for account in root wj; do
        printf '%s:%s\\n' "$account" "$target_password" | chroot "$target" chpasswd \\
            || die "failed to set password for $account"
    done
    printf 'INSTALL: set password on root and wj.\\n'
fi
target_password=

say "Install bootloader"
if [ "$mode" = "uefi" ]; then
    chroot "$target" grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=Wuci-OS || die "UEFI GRUB install failed"
else
    chroot "$target" grub-install "$disk" || die "BIOS GRUB install failed"
fi
chroot "$target" grub-mkconfig -o /boot/grub/grub.cfg || die "GRUB config generation failed"

say "Write install receipt"
mkdir -p "$target/usr/share/wuci-os"
cat > "$target/usr/share/wuci-os/install-receipt.txt" <<TEXT
Wuci-OS automatic install receipt
disk=$disk
root=$rootpart
mode=$mode
created_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unknown)
TEXT

say "Verify installed target"
chroot "$target" /usr/local/bin/wuci-status || true
chroot "$target" /usr/local/bin/wuci-users-status || true
chroot "$target" /usr/local/bin/wuci-network-status || true
chroot "$target" /usr/local/bin/wuci-daylight-v14c-plus verify || true
chroot "$target" /usr/local/bin/wuci-daylight-meridian verify || true

say "Install complete"
printf 'Installed Wuci-OS to %s.\\n' "$disk"
printf 'Next: sync; umount -R %s; reboot\\n' "$target"
if [ "$auto_reboot" = "1" ]; then
    sync
    umount -R "$target" || true
    reboot
fi
"""
    install_script = """#!/bin/sh
set -eu
exec INSTALL "$@"
"""
    install_target_activate_script = """#!/bin/sh
set -eu

target=${1:-/mnt}

usage() {
    cat <<'TEXT'
Wuci-OS installed-target activation

Usage:
  wuci-install-target-activate [TARGET_ROOT]

Run this from the live ISO after the disk installer finishes and before reboot.
TARGET_ROOT is usually /mnt.
TEXT
}

case "${1:-}" in
    --help|-h)
        usage
        exit 0
        ;;
esac

if [ "$(id -u)" != "0" ]; then
    printf 'wuci-install-target-activate: run as root\\n' >&2
    exit 1
fi

if [ ! -d "$target" ]; then
    printf 'wuci-install-target-activate: target root does not exist: %s\\n' "$target" >&2
    exit 2
fi
if [ ! -d "$target/etc" ] || [ ! -d "$target/usr" ]; then
    printf 'wuci-install-target-activate: %s does not look like an installed root\\n' "$target" >&2
    exit 2
fi

copy_file() {
    src=$1
    dest=$2
    mode=$3
    [ -e "$src" ] || return 0
    install -D -m "$mode" "$src" "$target/$dest"
}

copy_tree() {
    src=$1
    dest=$2
    [ -d "$src" ] || return 0
    mkdir -p "$target/$dest"
    cp -a "$src/." "$target/$dest/"
}

printf 'wuci-install-target-activate: target %s\\n' "$target"

for src in /usr/local/bin/INSTALL /usr/local/bin/wuci-* /usr/local/bin/wj; do
    [ -e "$src" ] || continue
    copy_file "$src" "${src#/}" 0755
done

copy_tree /usr/share/wuci-os usr/share/wuci-os
copy_tree /usr/share/backgrounds/wuci-os usr/share/backgrounds/wuci-os

for src in /etc/profile.d/wuci-*.sh; do
    [ -e "$src" ] || continue
    copy_file "$src" "${src#/}" 0644
done
for src in /etc/xdg/autostart/wuci-*.desktop; do
    [ -e "$src" ] || continue
    copy_file "$src" "${src#/}" 0644
done

copy_file /etc/skel/.xinitrc etc/skel/.xinitrc 0644
copy_file /etc/skel/.ratpoisonrc etc/skel/.ratpoisonrc 0644
copy_file /etc/skel/.config/kitty/kitty.conf etc/skel/.config/kitty/kitty.conf 0644
copy_file /root/.xinitrc root/.xinitrc 0644
copy_file /root/.ratpoisonrc root/.ratpoisonrc 0644
copy_file /root/.config/kitty/kitty.conf root/.config/kitty/kitty.conf 0644

printf 'wuci-os\\n' > "$target/etc/hostname"
rm -f "$target/etc/os-release" "$target/usr/lib/os-release"
copy_file /etc/os-release etc/os-release 0644
copy_file /usr/lib/os-release usr/lib/os-release 0644
copy_file /etc/issue etc/issue 0644
copy_file /etc/motd etc/motd 0644

mkdir -p "$target/etc/sv/agetty-tty1"
cat > "$target/etc/sv/agetty-tty1/conf" <<'TEXT'
GETTY_ARGS="--autologin wj --noclear"
BAUD_RATE=38400
TERM_NAME=linux
TEXT
chmod 0644 "$target/etc/sv/agetty-tty1/conf"

if [ -x "$target/usr/local/bin/wuci-users-apply" ] && command -v chroot >/dev/null 2>&1; then
    chroot "$target" /usr/local/bin/wuci-users-apply || true
fi

for user in wj wj_low; do
    if [ -d "$target/home/$user" ]; then
        mkdir -p "$target/home/$user/.config/kitty"
        copy_file /etc/skel/.xinitrc "home/$user/.xinitrc" 0644
        copy_file /etc/skel/.ratpoisonrc "home/$user/.ratpoisonrc" 0644
        copy_file /etc/skel/.config/kitty/kitty.conf "home/$user/.config/kitty/kitty.conf" 0644
        if command -v chroot >/dev/null 2>&1; then
            chroot "$target" chown -R "$user:$user" "/home/$user" 2>/dev/null || true
        fi
    fi
done

if [ -d /opt/wuci-os/source/wuci-ji ]; then
    mkdir -p "$target/opt/wuci-os/source"
    cp -a /opt/wuci-os/source/wuci-ji "$target/opt/wuci-os/source/"
fi

printf 'wuci-install-target-activate: complete\\n'
printf 'next: chroot %s /usr/local/bin/wuci-status\\n' "$target"
"""
    selfupdate_script = """#!/bin/sh
set -eu

# Update this running system from the repository the machine already carries,
# without flashing a new ISO. It regenerates the Wuci overlay the repo presents
# and syncs it onto / with per-file digest measurement and verification.

src=${WUCI_SOURCE:-/opt/wuci-os/source/wuci-ji}
apply=0
do_pull=0
pass=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --apply) apply=1 ;;
        --pull) do_pull=1 ;;
        --json) pass="$pass --json" ;;
        --root)
            [ "$#" -ge 2 ] || { printf 'wuci-selfupdate: --root needs a value\\n' >&2; exit 2; }
            pass="$pass --root $2"; shift ;;
        --source)
            [ "$#" -ge 2 ] || { printf 'wuci-selfupdate: --source needs a value\\n' >&2; exit 2; }
            src=$2; shift ;;
        --help|-h)
            cat <<'TEXT'
wuci-selfupdate - update this running system from the repo, no reflash

  wuci-selfupdate                 measure what the repo overlay would change (preview)
  wuci-selfupdate --apply         apply changed files atomically, verify each by digest
  wuci-selfupdate --pull          git pull the source repo first, then measure
  wuci-selfupdate --pull --apply  git pull, then apply what changed
  wuci-selfupdate --json          emit the machine-readable receipt

Source repo:  $WUCI_SOURCE or /opt/wuci-os/source/wuci-ji
Scope: the Wuci overlay layer (commands, /usr/share/wuci-os incl. Daylight
packages, os-release, profile.d, autostart, skel). It never removes files and
never touches the kernel or base packages; update those with: xbps-install -Su
TEXT
            exit 0 ;;
        *) printf 'wuci-selfupdate: unknown argument: %s\\n' "$1" >&2; exit 2 ;;
    esac
    shift
done

if [ ! -f "$src/tools/wuci_os.py" ]; then
    printf 'wuci-selfupdate: no repo source at %s\\n' "$src" >&2
    printf 'wuci-selfupdate: clone the repo there, or set WUCI_SOURCE=/path/to/wuci-ji\\n' >&2
    exit 1
fi
command -v python3 >/dev/null 2>&1 || { printf 'wuci-selfupdate: python3 is required\\n' >&2; exit 127; }

# git pull runs as the invoking user (who holds the git credentials), before any
# privilege escalation for --apply.
if [ "$do_pull" = 1 ]; then
    command -v git >/dev/null 2>&1 || { printf 'wuci-selfupdate: git is required for --pull\\n' >&2; exit 127; }
    printf 'wuci-selfupdate: git pull --ff-only in %s\\n' "$src"
    git -C "$src" pull --ff-only
fi

args="live-update $pass"
if [ "$apply" = 1 ]; then
    args="$args --apply"
    if [ "$(id -u)" != 0 ]; then
        # Applying writes into /, which needs root; measurement does not.
        exec sudo WUCI_SOURCE="$src" python3 "$src/tools/wuci_os.py" $args
    fi
fi
# shellcheck disable=SC2086
exec python3 "$src/tools/wuci_os.py" $args
"""
    wait_run_script = """#!/bin/sh
set -eu

if [ "$#" -lt 2 ]; then
    printf 'usage: wuci-wait-run <label> <command> [args...]\\n' >&2
    exit 2
fi

LABEL=$1
shift
TICKER=${WUCI_TICKER:-auto}

show_ticker=0
if [ "$TICKER" = "always" ]; then
    show_ticker=1
elif [ "$TICKER" = "auto" ] && [ -t 2 ]; then
    show_ticker=1
fi

if [ "$show_ticker" -eq 0 ]; then
    "$@"
    exit $?
fi

tmp_out=$(mktemp)
tmp_err=$(mktemp)
frames='▲▶▼◀'
colors='31 33 32 36 34 35'
start=$(date +%s 2>/dev/null || printf 0)
"$@" >"$tmp_out" 2>"$tmp_err" &
pid=$!
i=0
while kill -0 "$pid" 2>/dev/null; do
    frame=$(printf '%s' "$frames" | cut -c $((i % 4 + 1)))
    color=$(printf '%s\\n' $colors | awk -v n=$((i % 6 + 1)) 'NR == n { print; exit }')
    now=$(date +%s 2>/dev/null || printf 0)
    elapsed=$((now - start))
    printf '\\r\\033[%sm%s\\033[0m %s ... %ss' "$color" "$frame" "$LABEL" "$elapsed" >&2
    i=$((i + 1))
    sleep 1
done
rc=0
wait "$pid" || rc=$?
if [ "$rc" -eq 0 ]; then
    printf '\\r\\033[32m▲\\033[0m %s PASS\\n' "$LABEL" >&2
else
    printf '\\r\\033[31m▼\\033[0m %s FAIL\\n' "$LABEL" >&2
fi
cat "$tmp_out"
cat "$tmp_err" >&2
rm -f "$tmp_out" "$tmp_err"
exit "$rc"
"""
    wj_script = """#!/bin/sh
set -eu

usage() {
    cat <<'TEXT'
Wuci-OS operator command

Usage:
  wj install <packages...>        install packages
  wj update                       update package indexes and packages
  wj os-update                    update system packages and onboard Wuci-Ji repo
  wj search <terms...>            search package repository
  wj info <packages...>           show package information
  wj remove <packages...>         remove packages; requires WJ_ALLOW_REMOVE=1
  wj guide                        run guided high-assurance setup
  wj auto                         run mostly automated setup
  wj status                       show Wuci-OS status
  wj security                     show high-assurance security status
  wj daylight                     show Daylight evidence status
  wj daylight-v14c                verify/regenerate Daylight v14C+ candidate score
  wj meridian [cmd]               Daylight v15 Meridian (verify|score|frontier|gate|doctor)
  wj vault [cmd]                  evidence-gated, fail-closed Meridian vault
  wj enter [user]                 enter WJ>_ operator shell
  wj selfupdate [--pull][--apply] update this system live from the repo (no reflash)
  wj attest                       run local proof marker

Examples:
  sudo wj install vim emacs kitty
  sudo wj update
  wj guide
TEXT
}

need_packages() {
    if [ "$#" -eq 0 ]; then
        printf 'wj: package list is empty\\n' >&2
        exit 2
    fi
}

need_xbps() {
    if ! command -v xbps-install >/dev/null 2>&1; then
        printf 'wj: package backend unavailable on this image: xbps-install\\n' >&2
        exit 1
    fi
}

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wj: run as root or use sudo: %s\\n' "$*" >&2
        exit 1
    fi
}

run_root_plain() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wj: run as root or use sudo: %s\\n' "$*" >&2
        exit 1
    fi
}

ensure_network_for_xbps() {
    [ "${WJ_SKIP_NETWORK_PROMPT:-0}" = "1" ] && return 0
    command -v wuci-network-connect >/dev/null 2>&1 || return 0
    if wuci-network-connect --check >/dev/null 2>&1; then
        return 0
    fi
    printf 'wj: network is not connected; starting Wuci network credential prompt before XBPS\\n' >&2
    run_root_plain wuci-network-connect || {
        printf 'wj: network setup did not complete; package repository sync cannot continue\\n' >&2
        printf 'wj: retry after network is up: sudo wuci-network-connect && sudo wj update\\n' >&2
        exit 1
    }
}

run_xbps() {
    label=$1
    shift
    ensure_network_for_xbps
    if run_root_wait "$label" "$@"; then
        return 0
    fi
    printf 'wj: XBPS failed during %s\\n' "$label" >&2
    printf 'wj: check network and repositories, then retry:\\n' >&2
    printf '  sudo wuci-network-connect\\n' >&2
    printf '  xbps-query -L\\n' >&2
    printf '  sudo wj update\\n' >&2
    return 1
}

cmd=${1:-help}
if [ "$#" -gt 0 ]; then
    shift
fi

case "$cmd" in
    install|add)
        need_packages "$@"
        need_xbps
        run_xbps "wj install" xbps-install -Sy "$@"
        ;;
    update|upgrade)
        need_xbps
        run_xbps "wj update" xbps-install -Syu
        ;;
    os-update|live-update)
        exec wuci-update "$@"
        ;;
    search)
        need_packages "$@"
        if command -v xbps-query >/dev/null 2>&1; then
            exec xbps-query -Rs "$@"
        fi
        printf 'wj: package search backend unavailable: xbps-query\\n' >&2
        exit 1
        ;;
    info)
        need_packages "$@"
        if command -v xbps-query >/dev/null 2>&1; then
            exec xbps-query -R "$@"
        fi
        printf 'wj: package info backend unavailable: xbps-query\\n' >&2
        exit 1
        ;;
    remove|delete)
        need_packages "$@"
        if [ "${WJ_ALLOW_REMOVE:-0}" != "1" ]; then
            printf 'wj: refusing package removal without WJ_ALLOW_REMOVE=1\\n' >&2
            exit 2
        fi
        if ! command -v xbps-remove >/dev/null 2>&1; then
            printf 'wj: package removal backend unavailable: xbps-remove\\n' >&2
            exit 1
        fi
        run_root_wait "wj remove" xbps-remove -R "$@"
        ;;
    guide)
        exec wuci-guide "$@"
        ;;
    auto)
        exec wuci-auto "$@"
        ;;
    status)
        exec wuci-status "$@"
        ;;
    security)
        exec wuci-security-status "$@"
        ;;
    daylight)
        exec wuci-daylight-status "$@"
        ;;
    daylight-v14c|daylight-v14c-plus|v14c)
        exec wuci-daylight-v14c-plus "$@"
        ;;
    daylight-meridian|meridian|v15)
        exec wuci-daylight-meridian "$@"
        ;;
    vault)
        exec wuci-daylight-meridian vault "$@"
        ;;
    enter|shell)
        exec wuci-enter "$@"
        ;;
    selfupdate)
        exec wuci-selfupdate "$@"
        ;;
    attest)
        exec wuci-attest "$@"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        printf 'wj: unknown command: %s\\n' "$cmd" >&2
        usage >&2
        exit 2
        ;;
esac
"""
    dev_install_script = """#!/bin/sh
set -eu

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-dev-install: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wuci-dev-install: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

install_group() {
    label=$1
    shift
    [ "$#" -gt 0 ] || return 0
    printf '\\n==> %s\\n' "$label"
    if run_root_wait "xbps $label" xbps-install -Sy "$@"; then
        return 0
    fi
    printf 'wuci-dev-install: group install had misses; trying package-by-package\\n' >&2
    for pkg in "$@"; do
        run_root_wait "xbps $pkg" xbps-install -Sy "$pkg" || printf 'optional package unavailable: %s\\n' "$pkg" >&2
    done
}

if ! command -v xbps-install >/dev/null 2>&1; then
    printf 'wuci-dev-install: xbps-install not found\\n' >&2
    exit 1
fi

run_root_wait "xbps refresh" xbps-install -Sy xbps || as_root xbps-install -u xbps || true
install_group "xfce4 desktop" __DESKTOP_PACKAGES__
install_group "Wi-Fi network firmware and tools" __NETWORK_PACKAGES__ __FIRMWARE_PACKAGES__
install_group "audio media stack" __AUDIO_PACKAGES__
install_group "video graphics stack" __VIDEO_PACKAGES__
install_group "Bluetooth printing scanning portals" __PERIPHERAL_PACKAGES__
install_group "SDR radio stack" __SDR_PACKAGES__ __SDR_OPTIONAL_PACKAGES__
install_group "editors" vim emacs nano
install_group "base developer tools" __BASE_DEV_PACKAGES__
install_group "C C++ systems" __C_CPP_PACKAGES__
install_group "Python" __PYTHON_PACKAGES__
install_group "JavaScript TypeScript" __JS_PACKAGES__
install_group "Rust" __RUST_PACKAGES__
install_group "Go" __GO_PACKAGES__
install_group "JVM" __JVM_PACKAGES__
install_group "Ruby" __RUBY_PACKAGES__
install_group "PHP" __PHP_PACKAGES__
install_group "Perl Lua" __PERL_LUA_PACKAGES__
install_group "data science" __DATA_PACKAGES__
install_group "systems extras" __SYSTEMS_EXTRA_PACKAGES__
install_group "databases" __DATABASE_PACKAGES__
install_group "containers vm" __CONTAINERS_PACKAGES__

mkdir -p /etc/xdg/xfce4 /etc/skel/.config/kitty /root/.config/kitty
cp /usr/share/wuci-os/ratpoisonrc /etc/skel/.ratpoisonrc 2>/dev/null || true
cp /usr/share/wuci-os/ratpoisonrc /root/.ratpoisonrc 2>/dev/null || true
cp /usr/share/wuci-os/kitty.conf /etc/skel/.config/kitty/kitty.conf 2>/dev/null || true
cp /usr/share/wuci-os/kitty.conf /root/.config/kitty/kitty.conf 2>/dev/null || true
printf 'exec startxfce4\\n' >/etc/skel/.xinitrc
printf 'exec startxfce4\\n' >/root/.xinitrc

printf '\\nWuci-OS developer workstation packages requested.\\n'
printf 'Default desktop: XFCE4. Preferred terminal: kitty. Fallback: xfce4-terminal.\\n'
printf 'Network: NetworkManager plus Wi-Fi firmware/tools requested.\\n'
printf 'Media: PipeWire/ALSA/Pulse helpers, Mesa/video, Bluetooth, portals requested.\\n'
printf 'SDR: GNU Radio, Gqrx, RTL-SDR, HackRF, Airspy, SoapySDR helpers requested.\\n'
printf 'Window manager profile: ratpoison config installed. Editors: emacs and vim.\\n'
"""
    security_apply_script = """#!/bin/sh
set -eu

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-security-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wuci-security-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

write_file() {
    path=$1
    mode=$2
    shift 2
    dir=$(dirname "$path")
    as_root mkdir -p "$dir"
    tmp=$(mktemp)
    printf '%s\\n' "$@" >"$tmp"
    as_root install -m "$mode" "$tmp" "$path"
    rm -f "$tmp"
}

if command -v xbps-install >/dev/null 2>&1; then
    run_root_wait "xbps security packages" xbps-install -Sy __SECURITY_PACKAGES__ || true
    run_root_wait "xbps SELinux packages" xbps-install -Sy __SELINUX_PACKAGES__ || true
fi

write_file /etc/selinux/config 0644 \
    '# Wuci-OS SELinux default: Fedora-style enforcing targeted profile' \
    'SELINUX=enforcing' \
    'SELINUXTYPE=targeted' \
    'SETLOCALDEFS=0'

write_file /etc/sysctl.d/50-wuci-high-assurance.conf 0644 __SYSCTL_LINES__
if command -v sysctl >/dev/null 2>&1; then
    as_root sysctl --system || true
fi

write_file /etc/ssh/sshd_config.d/50-wuci-high-assurance.conf 0644 \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'X11Forwarding no' \
    'AllowTcpForwarding no'

write_file /etc/nftables.conf 0600 \
    'flush ruleset' \
    'table inet filter {' \
    '  chain input {' \
    '    type filter hook input priority 0; policy drop;' \
    '    iif lo accept' \
    '    ct state established,related accept' \
    '    ip protocol icmp accept' \
    '    ip6 nexthdr ipv6-icmp accept' \
    '  }' \
    '  chain forward { type filter hook forward priority 0; policy drop; }' \
    '  chain output { type filter hook output priority 0; policy accept; }' \
    '}'
if command -v nft >/dev/null 2>&1; then
    as_root nft -f /etc/nftables.conf || true
fi
if [ -d /etc/sv/nftables ] && [ -d /var/service ]; then
    as_root ln -s /etc/sv/nftables /var/service/nftables 2>/dev/null || true
fi

as_root chmod 700 /root 2>/dev/null || true
as_root touch /.autorelabel 2>/dev/null || true
if command -v setenforce >/dev/null 2>&1; then
    as_root setenforce 1 || true
fi
if command -v restorecon >/dev/null 2>&1; then
    as_root restorecon -RF /etc /usr/local/bin /usr/share/wuci-os 2>/dev/null || true
fi

mkdir -p /etc/default/grub.d
write_file /etc/default/grub.d/50-wuci-selinux.cfg 0644 \
    '# Wuci-OS requires SELinux enforcing by default.' \
    'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT __SELINUX_GRUB_FLAGS__"'

cat <<'TEXT'
Wuci-OS high-assurance profile applied.

Required next verification:
  wuci-security-status

If SELinux policy tools are missing, that is a hard blocker for this profile.
Reboot after installing on disk so SELinux kernel flags and relabeling take effect.
TEXT
"""
    security_status_script = """#!/bin/sh
set -eu

summary=0
if [ "${1:-}" = "--summary" ]; then
    summary=1
fi

fail=0
check() {
    label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        [ "$summary" -eq 1 ] || printf '[PASS] %s\\n' "$label"
    else
        fail=1
        [ "$summary" -eq 1 ] || printf '[FAIL] %s\\n' "$label"
    fi
}

selinux_enforcing() {
    [ -d /sys/fs/selinux ] || return 1
    if command -v getenforce >/dev/null 2>&1; then
        [ "$(getenforce 2>/dev/null)" = "Enforcing" ]
    elif [ -r /sys/fs/selinux/enforce ]; then
        [ "$(cat /sys/fs/selinux/enforce)" = "1" ]
    else
        return 1
    fi
}

selinux_configured() {
    [ -r /etc/selinux/config ] || return 1
    grep -q '^SELINUX=enforcing' /etc/selinux/config
    grep -q '^SELINUXTYPE=targeted' /etc/selinux/config
}

luks_root() {
    findmnt -no SOURCE / 2>/dev/null | grep -Eq '/dev/mapper/|^/dev/dm-'
}

firewall_loaded() {
    command -v nft >/dev/null 2>&1 || return 1
    nft list ruleset 2>/dev/null | grep -q 'policy drop'
}

sysctl_hardened() {
    sysctl -n kernel.kptr_restrict 2>/dev/null | grep -qx '2'
    sysctl -n kernel.dmesg_restrict 2>/dev/null | grep -qx '1'
    sysctl -n fs.protected_symlinks 2>/dev/null | grep -qx '1'
}

check 'SELinux configured enforcing targeted' selinux_configured
check 'SELinux currently enforcing' selinux_enforcing
check 'root filesystem is dm-crypt/LUKS mapped' luks_root
check 'nftables default-deny inbound policy loaded' firewall_loaded
check 'kernel/sysctl hardening active' sysctl_hardened

if [ "$summary" -eq 1 ]; then
    if [ "$fail" -eq 0 ]; then
        printf 'security: high-assurance checks pass\\n'
    else
        printf 'security: high-assurance checks blocked\\n'
    fi
fi
exit "$fail"
"""
    selinux_status_script = """#!/bin/sh
set -eu
printf 'Wuci-OS SELinux status\\n'
if [ -r /etc/selinux/config ]; then
    grep -E '^(SELINUX|SELINUXTYPE)=' /etc/selinux/config || true
else
    printf 'config: missing /etc/selinux/config\\n'
fi
if command -v getenforce >/dev/null 2>&1; then
    printf 'getenforce: %s\\n' "$(getenforce 2>/dev/null || printf unknown)"
elif [ -r /sys/fs/selinux/enforce ]; then
    printf 'enforce: %s\\n' "$(cat /sys/fs/selinux/enforce)"
else
    printf 'runtime: SELinux filesystem not mounted\\n'
fi
if command -v sestatus >/dev/null 2>&1; then
    sestatus || true
fi
"""
    users_apply_script = """#!/bin/sh
set -eu

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-users-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

ensure_group() {
    group=$1
    getent group "$group" >/dev/null 2>&1 || as_root groupadd "$group" 2>/dev/null || true
}

ensure_user() {
    user=$1
    shell_path=$2
    groups=$3
    if ! getent passwd "$user" >/dev/null 2>&1; then
        as_root useradd -m -s "$shell_path" -G "$groups" "$user"
    fi
}

for group in wheel audio video input kvm network storage; do
    ensure_group "$group"
done

shell_path=/bin/bash
[ -x "$shell_path" ] || shell_path=/bin/sh
ensure_user wj "$shell_path" wheel,audio,video,input,kvm,network,storage
ensure_user wj_low "$shell_path" audio,video

as_root passwd -d wj >/dev/null 2>&1 || true
as_root passwd -d wj_low >/dev/null 2>&1 || true

as_root mkdir -p /etc/sudoers.d /etc/doas.d /home/wj/.config/kitty /home/wj_low/.config/kitty
if [ -d /etc/sudoers.d ]; then
    tmp=$(mktemp)
    printf 'wj ALL=(ALL:ALL) NOPASSWD: ALL\\n' >"$tmp"
    as_root install -m 0440 "$tmp" /etc/sudoers.d/90-wuci-os-wj
    rm -f "$tmp"
fi
if [ -d /etc/doas.d ]; then
    tmp=$(mktemp)
    printf 'permit nopass wj as root\\n' >"$tmp"
    as_root install -m 0440 "$tmp" /etc/doas.d/90-wuci-os-wj.conf
    rm -f "$tmp"
fi

for user in wj wj_low; do
    home=$(getent passwd "$user" | cut -d: -f6)
    [ -n "$home" ] || continue
    as_root mkdir -p "$home/.config/kitty"
    as_root cp /usr/share/wuci-os/kitty.conf "$home/.config/kitty/kitty.conf" 2>/dev/null || true
    as_root cp /usr/share/wuci-os/ratpoisonrc "$home/.ratpoisonrc" 2>/dev/null || true
    printf 'exec startxfce4\\n' | as_root tee "$home/.xinitrc" >/dev/null
    as_root chown -R "$user:$user" "$home/.config" "$home/.ratpoisonrc" "$home/.xinitrc" 2>/dev/null || true
done

cat <<'TEXT'
Wuci-OS users applied.

Login:
  wj       password: press Enter   admin live/demo account, prompt WJ>_
  wj_low   password: press Enter   lower-privilege account

High-assurance installed systems must rotate the live empty password.
TEXT
"""
    users_status_script = """#!/bin/sh
set -eu

fail=0
for user in wj wj_low; do
    if getent passwd "$user" >/dev/null 2>&1; then
        printf '[PASS] user exists: %s\\n' "$user"
    else
        printf '[FAIL] user missing: %s\\n' "$user"
        fail=1
    fi
done

if id -nG wj 2>/dev/null | tr ' ' '\\n' | grep -qx wheel; then
    printf '[PASS] wj has wheel admin membership\\n'
else
    printf '[FAIL] wj missing wheel admin membership\\n'
    fail=1
fi

if id -nG wj_low 2>/dev/null | tr ' ' '\\n' | grep -qx wheel; then
    printf '[FAIL] wj_low unexpectedly has wheel membership\\n'
    fail=1
else
    printf '[PASS] wj_low has no wheel membership\\n'
fi

shadow_line=$(getent shadow wj 2>/dev/null || true)
if [ -z "$shadow_line" ] && [ -r /etc/shadow ]; then
    shadow_line=$(awk -F: '$1 == "wj" { print; exit }' /etc/shadow 2>/dev/null || true)
fi
case "$shadow_line" in
    wj::*) printf '[WARN] wj has empty live-demo password; rotate after install\\n' ;;
    wj:!*) printf '[FAIL] wj account is locked\\n'; fail=1 ;;
    wj:*) printf '[PASS] wj password is not empty\\n' ;;
    *) printf '[WARN] cannot inspect wj shadow entry in this live shell\\n' ;;
esac

exit "$fail"
"""
    prompt_script = """# Wuci-OS prompt identity
if [ "${USER:-}" = "wj" ]; then
    PS1='WJ>_ '
elif [ "${USER:-}" = "wj_low" ]; then
    PS1='WJ-low>_ '
elif [ "$(id -u 2>/dev/null || printf 1)" = "0" ]; then
    PS1='WJ#_ '
fi
"""
    account_profile_json = json.dumps(
        {
            "schema": "wuci-os-account-profile-v1",
            "operator_login": "wj",
            "operator_prompt": "WJ>_",
            "operator_live_password": "press Enter",
            "operator_groups": ["wheel", "audio", "video", "input", "kvm", "network", "storage"],
            "operator_admin": "passwordless sudo/doas in live profile",
            "lower_privilege_login": "wj_low",
            "lower_privilege_prompt": "WJ-low>_",
            "lower_privilege_live_password": "press Enter",
            "installed_security_requirement": "rotate empty live passwords before installed high-assurance status",
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    def sh_words(values: tuple[str, ...] | list[str]) -> str:
        return " ".join(shlex.quote(value) for value in values)

    dev_install_script = (
        dev_install_script.replace("__DESKTOP_PACKAGES__", sh_words(DESKTOP_PACKAGES))
        .replace("__NETWORK_PACKAGES__", sh_words(NETWORK_PACKAGES))
        .replace("__FIRMWARE_PACKAGES__", sh_words(FIRMWARE_PACKAGES))
        .replace("__AUDIO_PACKAGES__", sh_words(AUDIO_PACKAGES))
        .replace("__VIDEO_PACKAGES__", sh_words(VIDEO_PACKAGES))
        .replace("__PERIPHERAL_PACKAGES__", sh_words(PERIPHERAL_PACKAGES))
        .replace("__SDR_PACKAGES__", sh_words(SDR_PACKAGES))
        .replace("__SDR_OPTIONAL_PACKAGES__", sh_words(SDR_OPTIONAL_PACKAGES))
        .replace("__BASE_DEV_PACKAGES__", sh_words(BASE_DEV_PACKAGES))
        .replace("__C_CPP_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["c_cpp"]))
        .replace("__PYTHON_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["python"]))
        .replace("__JS_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["javascript_typescript"]))
        .replace("__RUST_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["rust"]))
        .replace("__GO_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["go"]))
        .replace("__JVM_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["java_jvm"]))
        .replace("__RUBY_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["ruby"]))
        .replace("__PHP_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["php"]))
        .replace("__PERL_LUA_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["perl_lua"]))
        .replace("__DATA_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["data_science"]))
        .replace("__SYSTEMS_EXTRA_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["systems_extras"]))
        .replace("__DATABASE_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["databases"]))
        .replace("__CONTAINERS_PACKAGES__", sh_words(LANGUAGE_PACKAGE_GROUPS["containers_vm"]))
    )
    security_apply_script = (
        security_apply_script.replace("__SECURITY_PACKAGES__", sh_words(SECURITY_PACKAGES))
        .replace("__SELINUX_PACKAGES__", sh_words(SELINUX_CANDIDATE_PACKAGES))
        .replace("__SYSCTL_LINES__", sh_words(list(KICKSECURE_INSPIRED_HARDENING)))
        .replace("__SELINUX_GRUB_FLAGS__", " ".join(SELINUX_GRUB_FLAGS))
    )
    wallpaper_script = """#!/bin/sh
set -eu

SRC="${WUCI_WALLPAPER_SRC:-/usr/share/backgrounds/wuci-os/wallpaper1.png}"
if [ ! -f "$SRC" ]; then
    printf 'wuci-wallpaper: missing wallpaper: %s\\n' "$SRC" >&2
    exit 1
fi

detect_geometry() {
    if [ -n "${WUCI_WALLPAPER_GEOMETRY:-}" ]; then
        printf '%s\\n' "$WUCI_WALLPAPER_GEOMETRY"
        return 0
    fi
    if command -v xrandr >/dev/null 2>&1; then
        xrandr --current 2>/dev/null | awk '
            / connected/ {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^[0-9]+x[0-9]+[+][0-9]+[+][0-9]+/) {
                        split($i, a, "+");
                        print a[1];
                        exit;
                    }
                }
            }'
        return 0
    fi
    if command -v xdpyinfo >/dev/null 2>&1; then
        xdpyinfo 2>/dev/null | awk '/dimensions:/ { print $2; exit }'
        return 0
    fi
    printf '1672x941\\n'
}

GEOM="$(detect_geometry | head -n 1)"
case "$GEOM" in
    *x*) ;;
    *) GEOM="1672x941" ;;
esac

CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/wuci-os/wallpaper"
mkdir -p "$CACHE"
OUT="$CACHE/wuci-os-${GEOM}.png"

if command -v magick >/dev/null 2>&1; then
    magick "$SRC" -resize "${GEOM}^" -gravity center -extent "$GEOM" "$OUT"
elif command -v convert >/dev/null 2>&1; then
    convert "$SRC" -resize "${GEOM}^" -gravity center -extent "$GEOM" "$OUT"
elif command -v gm >/dev/null 2>&1; then
    gm convert "$SRC" -resize "${GEOM}^" -gravity center -extent "$GEOM" "$OUT"
else
    OUT="$SRC"
fi

URI="file://$OUT"
SET=0

if command -v xfconf-query >/dev/null 2>&1; then
    for prop in $(xfconf-query -c xfce4-desktop -l 2>/dev/null | grep '/last-image$' || true); do
        xfconf-query -c xfce4-desktop -p "$prop" -s "$OUT" 2>/dev/null || true
        style="${prop%/last-image}/image-style"
        xfconf-query -c xfce4-desktop -p "$style" -s 5 2>/dev/null || true
        SET=1
    done
fi

if command -v gsettings >/dev/null 2>&1; then
    gsettings set org.gnome.desktop.background picture-uri "$URI" 2>/dev/null && SET=1 || true
    gsettings set org.gnome.desktop.background picture-options "'zoom'" 2>/dev/null || true
fi

if command -v feh >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
    feh --bg-fill "$OUT" && SET=1 || true
fi

if command -v xwallpaper >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
    xwallpaper --zoom "$OUT" && SET=1 || true
fi

if command -v swaybg >/dev/null 2>&1 && [ -n "${WAYLAND_DISPLAY:-}" ]; then
    pkill -x swaybg 2>/dev/null || true
    swaybg -m fill -i "$OUT" >/tmp/wuci-swaybg.log 2>&1 &
    SET=1
fi

printf 'wuci-wallpaper: %s (%s)\\n' "$OUT" "$GEOM"
if [ "$SET" -eq 0 ]; then
    printf 'wuci-wallpaper: no graphical setter detected; install feh, xwallpaper, xfconf-query, gsettings, or swaybg.\\n' >&2
fi
"""
    terminal_script = """#!/bin/sh
set -eu

candidates="${WUCI_TERMINAL:-} __TERMINAL_CANDIDATES__"

find_terminal() {
    for term in $candidates; do
        [ -n "$term" ] || continue
        if command -v "$term" >/dev/null 2>&1; then
            command -v "$term"
            return 0
        fi
    done
    return 1
}

terminal=$(find_terminal || true)

if [ "${1:-}" = "--print" ]; then
    if [ -n "$terminal" ]; then
        printf '%s\\n' "$terminal"
    else
        printf 'no graphical terminal found; falling back to %s\\n' "${SHELL:-/bin/sh}"
    fi
    exit 0
fi

if [ -z "$terminal" ]; then
    exec "${SHELL:-/bin/sh}" -i
fi

if [ "$#" -eq 0 ]; then
    exec "$terminal"
fi

base=$(basename "$terminal")
case "$base" in
    xfce4-terminal)
        command_text=$(printf '%s ' "$@")
        exec "$terminal" --command "$command_text"
        ;;
    *)
        exec "$terminal" -e "$@"
        ;;
esac
"""
    boot_chime_script = """#!/bin/sh
set -eu

once=0
quiet=0
print_path=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --once) once=1; shift ;;
        --quiet) quiet=1; shift ;;
        --print-path) print_path=1; shift ;;
        --help|-h)
            cat <<'TEXT'
Wuci-OS boot chime

Usage:
  wuci-boot-chime [--once] [--quiet] [--print-path]

Generates and plays the original Wuci-OS boot chime. No external sound asset is
required; the WAV is generated deterministically with Python stdlib when needed.
TEXT
            exit 0
            ;;
        *) printf 'wuci-boot-chime: unknown argument: %s\\n' "$1" >&2; exit 2 ;;
    esac
done

cache="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/wuci-os"
mkdir -p "$cache" 2>/dev/null || cache=/tmp
wav="$cache/wuci-boot-chime.wav"
stamp="/tmp/wuci-boot-chime.${USER:-user}.${DISPLAY:-tty}.${WAYLAND_DISPLAY:-none}.played"

if [ "$print_path" -eq 1 ]; then
    printf '%s\\n' "$wav"
    exit 0
fi

if [ "$once" -eq 1 ] && [ -e "$stamp" ]; then
    exit 0
fi

if [ ! -s "$wav" ] || [ "${WUCI_BOOT_CHIME_REBUILD:-0}" = "1" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$wav" <<'PY'
import math
import struct
import sys
import wave

path = sys.argv[1]
rate = 44100
notes = [
    (523.25, 0.060, 0.28),
    (659.25, 0.070, 0.34),
    (783.99, 0.075, 0.36),
    (1046.50, 0.105, 0.42),
]
tail = 0.060
samples = []
for freq, duration, gain in notes:
    count = int(rate * duration)
    for i in range(count):
        t = i / rate
        attack = min(1.0, i / max(1, int(rate * 0.006)))
        decay = math.exp(-5.8 * t / max(duration, 0.001))
        tone = math.sin(2 * math.pi * freq * t)
        overtone = 0.36 * math.sin(2 * math.pi * freq * 2.01 * t)
        click = 0.14 * math.sin(2 * math.pi * 1760.0 * t) * math.exp(-32.0 * t)
        value = (tone + overtone + click) * gain * attack * decay
        samples.append(max(-1.0, min(1.0, value)))
for i in range(int(rate * tail)):
    t = i / rate
    value = math.sin(2 * math.pi * 1318.51 * t) * 0.20 * math.exp(-12.0 * t)
    samples.append(value)
with wave.open(path, "wb") as wav:
    wav.setnchannels(1)
    wav.setsampwidth(2)
    wav.setframerate(rate)
    frames = bytearray()
    for value in samples:
        frames.extend(struct.pack("<h", int(max(-0.95, min(0.95, value)) * 32767)))
    wav.writeframes(bytes(frames))
PY
    fi
fi

played=0
if [ -s "$wav" ]; then
    for player in ${WUCI_CHIME_PLAYER:-} pw-play aplay paplay ffplay mpv play; do
        [ -n "$player" ] || continue
        command -v "$player" >/dev/null 2>&1 || continue
        case "$player" in
            pw-play) "$player" "$wav" >/dev/null 2>&1 && played=1 && break ;;
            aplay) "$player" -q "$wav" >/dev/null 2>&1 && played=1 && break ;;
            paplay) "$player" "$wav" >/dev/null 2>&1 && played=1 && break ;;
            ffplay) "$player" -nodisp -autoexit -loglevel quiet "$wav" >/dev/null 2>&1 && played=1 && break ;;
            mpv) "$player" --no-video --really-quiet "$wav" >/dev/null 2>&1 && played=1 && break ;;
            play) "$player" -q "$wav" >/dev/null 2>&1 && played=1 && break ;;
        esac
    done
fi

if [ "$played" -eq 0 ]; then
    if [ "$quiet" -eq 0 ]; then
        printf '\\a' >/dev/tty 2>/dev/null || printf '\\a'
    fi
fi
if [ "$once" -eq 1 ]; then
    : > "$stamp" 2>/dev/null || true
fi
exit 0
"""
    network_connect_script = """#!/bin/sh
set -eu

mode="${1:-connect}"
case "$mode" in
    --help|-h)
        cat <<'TEXT'
Wuci-OS network connection prompt

Usage:
  wuci-network-connect
  wuci-network-connect --check

No Wi-Fi IDs or passwords are baked into Wuci-OS. The prompt asks locally at
first boot. Optional noninteractive inputs:
  WUCI_WIFI_SSID='network name' wuci-network-connect
  WUCI_WIFI_PASSWORD='password' WUCI_WIFI_SSID='network name' wuci-network-connect
TEXT
        exit 0
        ;;
esac

online() {
    if command -v ip >/dev/null 2>&1 && ip route get 1.1.1.1 >/dev/null 2>&1; then
        return 0
    fi
    if command -v ping >/dev/null 2>&1 && ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

auth_tool_ready() {
    tool_path=$1
    [ -n "$tool_path" ] || return 1
    [ -x "$tool_path" ] || return 1
    uid=$(ls -ln "$tool_path" 2>/dev/null | awk '{ print $3; exit }')
    [ "$uid" = "0" ] || return 1
    [ -u "$tool_path" ] || return 1
}

try_escalate() {
    tool=$1
    shift
    tool_path=$(command -v "$tool" 2>/dev/null || true)
    [ -n "$tool_path" ] || return 1
    if auth_tool_ready "$tool_path"; then
        exec "$tool_path" "$0" "$@"
    fi
    printf 'wuci-network-connect: %s exists but is not root-owned setuid: %s\\n' "$tool" "$tool_path" >&2
    printf 'wuci-network-connect: the live image privilege profile is broken; expected root:root mode 4755 for sudo/su/doas.\\n' >&2
    return 1
}

if [ "$mode" = "--check" ]; then
    online
    exit $?
fi

if [ "$(id -u)" != "0" ]; then
    try_escalate sudo "$@" || true
    try_escalate doas "$@" || true
    printf 'wuci-network-connect: root is required and no usable sudo/doas path is available.\\n' >&2
    printf 'wuci-network-connect: rebuild/remaster this ISO or repair auth setuid bits from a root shell, then rerun wuci-network-connect.\\n' >&2
    exit 1
fi

printf 'Wuci-OS network setup\\n'
printf '  user: root\\n'
printf '  tools:'
for tool in ip dhcpcd iw rfkill wpa_supplicant wpa_passphrase nmcli; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf ' %s=ok' "$tool"
    else
        printf ' %s=missing' "$tool"
    fi
done
printf '\\n'

enable_service() {
    service=$1
    if [ -d "/etc/sv/$service" ]; then
        mkdir -p /etc/runit/runsvdir/default
        if [ ! -e "/etc/runit/runsvdir/default/$service" ]; then
            ln -s "/etc/sv/$service" "/etc/runit/runsvdir/default/$service" 2>/dev/null || true
        fi
        command -v sv >/dev/null 2>&1 && sv up "$service" >/dev/null 2>&1 || true
    fi
}

enable_service dbus
enable_service NetworkManager
enable_service udevd

if command -v rfkill >/dev/null 2>&1; then
    rfkill unblock wifi 2>/dev/null || true
    rfkill unblock all 2>/dev/null || true
fi

try_load_kernel_modules() {
    command -v modprobe >/dev/null 2>&1 || return 0
    for module in cfg80211 mac80211 iwlwifi iwldvm mt7921u mt76_usb mt76 rtw88_pci rtw89_pci ath10k_pci ath11k_pci brcmfmac xhci_pci xhci_hcd ehci_pci ehci_hcd uhci_hcd; do
        modprobe "$module" >/dev/null 2>&1 || true
    done
}

print_wireless_snapshot() {
    printf 'wuci-network-connect: hardware snapshot follows\\n' >&2
    uname -r 2>/dev/null | sed 's/^/  kernel: /' >&2 || true
    if command -v rfkill >/dev/null 2>&1; then
        rfkill list all 2>/dev/null | sed 's/^/  rfkill: /' >&2 || true
    fi
    if command -v iw >/dev/null 2>&1; then
        iw dev 2>/dev/null | sed 's/^/  iw: /' >&2 || true
    fi
    if command -v ip >/dev/null 2>&1; then
        ip -br link 2>/dev/null | sed 's/^/  link: /' >&2 || true
    fi
    if command -v lspci >/dev/null 2>&1; then
        lspci -nnk 2>/dev/null | grep -A4 -iE 'network|wireless|wifi' | sed 's/^/  pci: /' >&2 || true
    fi
    if command -v lsusb >/dev/null 2>&1; then
        lsusb 2>/dev/null | sed 's/^/  usb: /' >&2 || true
    fi
}

check_wireless_kernel_stack() {
    kernel_release=$(uname -r 2>/dev/null || printf unknown)
    missing=""
    for module in cfg80211 mac80211; do
        if [ -d "/sys/module/$module" ]; then
            continue
        fi
        found=0
        for base in /lib/modules /usr/lib/modules; do
            if find "$base/$kernel_release" -iname "$module.ko*" -print -quit 2>/dev/null | grep -q .; then
                found=1
                break
            fi
        done
        if [ "$found" -eq 0 ]; then
            missing="$missing $module"
            continue
        fi
        if command -v modprobe >/dev/null 2>&1; then
            modprobe "$module" >/dev/null 2>&1 || true
        fi
        if [ ! -d "/sys/module/$module" ]; then
            missing="$missing $module-unloaded"
        fi
    done
    if [ -n "$missing" ]; then
        printf 'wuci-network-connect: kernel wireless stack missing for %s:%s\\n' "$kernel_release" "$missing" >&2
        printf 'wuci-network-connect: nl80211 cannot work until the ISO includes matching cfg80211/mac80211 modules and firmware.\\n' >&2
        printf 'wuci-network-connect: use Ethernet, then rebuild or install the matching linux package and run depmod -a %s.\\n' "$kernel_release" >&2
        print_wireless_snapshot
        return 1
    fi
    return 0
}

try_dhcp() {
    iface=$1
    [ -n "$iface" ] || return 1
    printf 'wuci-network-connect: DHCP probe on %s\\n' "$iface"
    if command -v dhcpcd >/dev/null 2>&1; then
        if command -v timeout >/dev/null 2>&1; then
            timeout 12s dhcpcd -n "$iface" >/dev/null 2>&1 || timeout 12s dhcpcd -4 "$iface" >/dev/null 2>&1 || true
        else
            dhcpcd -n "$iface" >/dev/null 2>&1 || dhcpcd -4 "$iface" >/dev/null 2>&1 || true
        fi
    elif command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$iface" -q -t 3 >/dev/null 2>&1 || true
    else
        return 1
    fi
    online
}

if command -v ip >/dev/null 2>&1; then
    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '$2 != "lo" { print $2 }' | cut -d@ -f1); do
        case "$iface" in
            wl*|wifi*|wlan*) continue ;;
        esac
        ip link set "$iface" up >/dev/null 2>&1 || true
        carrier=$(cat "/sys/class/net/$iface/carrier" 2>/dev/null || printf unknown)
        if [ "$carrier" = "0" ]; then
            printf 'wuci-network-connect: skipping %s, no carrier\\n' "$iface"
            continue
        fi
        try_dhcp "$iface" && {
            printf 'wuci-network-connect: online through %s\\n' "$iface"
            exit 0
        }
    done
fi

if online; then
    printf 'wuci-network-connect: network route already available\\n'
    exit 0
fi

try_load_kernel_modules
if ! check_wireless_kernel_stack; then
    printf 'wuci-network-connect: refusing Wi-Fi scan because the kernel cannot provide nl80211.\\n' >&2
    exit 1
fi

if command -v nmcli >/dev/null 2>&1; then

    nmcli networking on 2>/dev/null || true
    nmcli radio wifi on 2>/dev/null || true

    printf 'Wuci-OS network credential prompt\\n'
    nmcli -f DEVICE,TYPE,STATE device status 2>/dev/null || true

    has_wifi=0
    if nmcli -t -f DEVICE,TYPE device status 2>/dev/null | grep -q ':wifi$'; then
        has_wifi=1
    fi

    if [ "$has_wifi" -eq 0 ]; then
        printf 'wuci-network-connect: no Wi-Fi device reported by NetworkManager. Trying wpa_supplicant fallback.\\n' >&2
    else
        nmcli_may_connect=1
        unavailable_wifi=0
        if nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null | awk -F: '$2 == "wifi" && $3 == "unavailable" { found=1 } END { exit found ? 0 : 1 }'; then
            unavailable_wifi=1
        fi
        if [ "$unavailable_wifi" -eq 1 ]; then
            printf 'wuci-network-connect: NetworkManager reports Wi-Fi unavailable; trying wpa_supplicant fallback.\\n' >&2
            print_wireless_snapshot
            nmcli_may_connect=0
        fi

        if [ "$nmcli_may_connect" -eq 1 ] && ! rescan_output=$(nmcli device wifi rescan 2>&1); then
            printf 'wuci-network-connect: Wi-Fi rescan failed: %s\\n' "$rescan_output" >&2
            case "$rescan_output" in
                *unavailable*|*Unavailable*)
                    printf 'wuci-network-connect: NetworkManager scan unavailable; trying wpa_supplicant fallback.\\n' >&2
                    print_wireless_snapshot
                    nmcli_may_connect=0
                    ;;
            esac
        fi
        if [ "$nmcli_may_connect" -eq 1 ]; then
            nmcli -f SSID,SECURITY,SIGNAL device wifi list 2>/dev/null || true

            ssid="${WUCI_WIFI_SSID:-}"
            if [ -z "$ssid" ]; then
                if [ -r /dev/tty ]; then
                    printf 'Wi-Fi SSID: ' >/dev/tty
                    IFS= read -r ssid </dev/tty || true
                elif [ -t 0 ]; then
                    printf 'Wi-Fi SSID: '
                    IFS= read -r ssid || true
                else
                    printf 'wuci-network-connect: no interactive terminal and WUCI_WIFI_SSID is not set\\n' >&2
                    exit 1
                fi
            fi

            if [ -z "$ssid" ]; then
                printf 'wuci-network-connect: SSID is empty; network not configured\\n' >&2
                exit 1
            fi

            if [ -n "${WUCI_WIFI_PASSWORD:-}" ]; then
                if [ "${WUCI_WIFI_HIDDEN:-0}" = "1" ]; then
                    nmcli device wifi connect "$ssid" password "$WUCI_WIFI_PASSWORD" hidden yes
                else
                    nmcli device wifi connect "$ssid" password "$WUCI_WIFI_PASSWORD"
                fi
            else
                if [ "${WUCI_WIFI_HIDDEN:-0}" = "1" ]; then
                    nmcli --ask device wifi connect "$ssid" hidden yes
                else
                    nmcli --ask device wifi connect "$ssid"
                fi
            fi

            if online; then
                printf 'wuci-network-connect: online\\n'
                ip -br addr 2>/dev/null || true
                exit 0
            fi
        fi
    fi
fi

if ! command -v nmcli >/dev/null 2>&1; then
    check_wireless_kernel_stack || true
fi

if command -v wpa_supplicant >/dev/null 2>&1; then
    printf 'wuci-network-connect: using wpa_supplicant fallback\\n'
    wifi_iface="${WUCI_WIFI_IFACE:-}"
    if [ -z "$wifi_iface" ] && command -v iw >/dev/null 2>&1; then
        wifi_iface=$(iw dev 2>/dev/null | awk '$1 == "Interface" { print $2; exit }')
    fi
    if [ -z "$wifi_iface" ] && command -v ip >/dev/null 2>&1; then
        wifi_iface=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(wl|wlan|wifi)/ { print $2; exit }' | cut -d@ -f1)
    fi
    if [ -z "$wifi_iface" ]; then
        printf 'wuci-network-connect: no Wi-Fi interface found for wpa_supplicant\\n' >&2
    else
        ip link set "$wifi_iface" up >/dev/null 2>&1 || true
        if command -v rfkill >/dev/null 2>&1 && rfkill list all 2>/dev/null | grep -qi 'Hard blocked: yes'; then
            printf 'wuci-network-connect: Wi-Fi is hard-blocked; not asking for SSID until the hardware switch/BIOS block is cleared.\\n' >&2
            print_wireless_snapshot
            exit 1
        fi
        ssid="${WUCI_WIFI_SSID:-}"
        if [ -z "$ssid" ]; then
            if [ -r /dev/tty ]; then
                printf 'Wi-Fi SSID: ' >/dev/tty
                IFS= read -r ssid </dev/tty || true
            else
                printf 'Wi-Fi SSID: '
                IFS= read -r ssid || true
            fi
        fi
        if [ -z "$ssid" ]; then
            printf 'wuci-network-connect: SSID is empty; network not configured\\n' >&2
            exit 1
        fi
        pass="${WUCI_WIFI_PASSWORD:-}"
        if [ -z "$pass" ]; then
            if [ -r /dev/tty ]; then
                stty -echo < /dev/tty 2>/dev/null || true
                printf 'Wi-Fi password, blank for open network: ' >/dev/tty
                IFS= read -r pass </dev/tty || true
                printf '\\n' >/dev/tty
                stty echo < /dev/tty 2>/dev/null || true
            else
                stty -echo 2>/dev/null || true
                printf 'Wi-Fi password, blank for open network: '
                IFS= read -r pass || true
                printf '\\n'
                stty echo 2>/dev/null || true
            fi
        fi
        conf_dir=/run/wuci-network
        mkdir -p "$conf_dir"
        chmod 0700 "$conf_dir"
        conf="$conf_dir/wpa_supplicant.conf"
        if [ -n "$pass" ]; then
            if command -v wpa_passphrase >/dev/null 2>&1; then
                wpa_passphrase "$ssid" "$pass" > "$conf"
            else
                {
                    printf 'network={\\n'
                    printf '    ssid="%s"\\n' "$ssid"
                    printf '    psk="%s"\\n' "$pass"
                    printf '}\\n'
                } > "$conf"
            fi
        else
            {
                printf 'network={\\n'
                printf '    ssid="%s"\\n' "$ssid"
                printf '    key_mgmt=NONE\\n'
                printf '}\\n'
            } > "$conf"
        fi
        chmod 0600 "$conf"
        pkill -f "wpa_supplicant.*-i $wifi_iface" >/dev/null 2>&1 || true
        wpa_supplicant -B -i "$wifi_iface" -c "$conf" || true
        try_dhcp "$wifi_iface" && {
            printf 'wuci-network-connect: online through %s\\n' "$wifi_iface"
            exit 0
        }
    fi
fi

printf 'wuci-network-connect: no network route. Use Ethernet, or ensure NetworkManager/wpa_supplicant and Wi-Fi firmware are installed.\\n' >&2
exit 1
"""
    network_apply_script = """#!/bin/sh
set -eu

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wuci-network-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

enable_service() {
    service=$1
    if [ -d "/etc/sv/$service" ]; then
        mkdir -p /etc/runit/runsvdir/default
        if [ ! -e "/etc/runit/runsvdir/default/$service" ]; then
            ln -s "/etc/sv/$service" "/etc/runit/runsvdir/default/$service" 2>/dev/null || true
        fi
        command -v sv >/dev/null 2>&1 && sv up "$service" >/dev/null 2>&1 || true
    fi
}

enable_service dbus
enable_service NetworkManager
enable_service udevd
if command -v rfkill >/dev/null 2>&1; then
    rfkill unblock wifi 2>/dev/null || true
    rfkill unblock all 2>/dev/null || true
fi
if command -v nmcli >/dev/null 2>&1; then
    nmcli networking on 2>/dev/null || true
    nmcli radio wifi on 2>/dev/null || true
fi

wuci-network-connect || true

if command -v xbps-install >/dev/null 2>&1; then
    if wuci-network-connect --check >/dev/null 2>&1; then
        run_root_wait "network and Wi-Fi packages" xbps-install -Sy __NETWORK_PACKAGES__ __FIRMWARE_PACKAGES__ || true
    else
        printf 'wuci-network-apply: skipping package install until network is connected\\n' >&2
    fi
else
    printf 'wuci-network-apply: xbps-install not found; cannot add missing network packages\\n' >&2
fi

cat <<'TEXT'
Wuci-OS network suite requested.

Wi-Fi defaults:
  service: NetworkManager
  connect:  sudo wuci-network-connect
  manual:   nmcli device wifi list
            nmcli --ask device wifi connect SSID
TEXT
wuci-network-status || true
"""
    network_status_script = """#!/bin/sh
set -eu

printf 'Wuci-OS network status\\n'
for cmd in NetworkManager nmcli wpa_supplicant iwd iw rfkill ip; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  %-18s %s\\n' "$cmd" "$(command -v "$cmd")"
    else
        printf '  %-18s missing\\n' "$cmd"
    fi
done
if command -v rfkill >/dev/null 2>&1; then
    rfkill list 2>/dev/null | sed 's/^/  rfkill: /' || true
fi
if command -v nmcli >/dev/null 2>&1; then
    nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null | sed 's/^/  nm: /' || true
fi
if command -v ip >/dev/null 2>&1; then
    ip -br link 2>/dev/null | sed 's/^/  link: /' || true
fi
"""
    media_session_script = """#!/bin/sh
set -eu

uid=$(id -u)
runtime_fallback="/tmp/wuci-runtime-$uid"

runtime_owner_matches() {
    candidate=$1
    if [ -O "$candidate" ] 2>/dev/null; then
        return 0
    fi
    if command -v stat >/dev/null 2>&1; then
        owner=$(stat -c %u "$candidate" 2>/dev/null || printf '?')
        [ "$owner" = "$uid" ]
        return
    fi
    return 1
}

prepare_runtime() {
    candidate=$1
    [ -n "$candidate" ] || return 1
    [ ! -L "$candidate" ] || return 1
    if [ ! -e "$candidate" ]; then
        mkdir -p "$candidate" 2>/dev/null || return 1
    fi
    [ -d "$candidate" ] || return 1
    [ ! -L "$candidate" ] || return 1
    runtime_owner_matches "$candidate" || return 1
    chmod 700 "$candidate" 2>/dev/null || return 1
    [ -w "$candidate" ] && [ -x "$candidate" ] || return 1
    printf '%s\\n' "$candidate"
}

runtime=""
if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    runtime=$(prepare_runtime "$XDG_RUNTIME_DIR" 2>/dev/null || true)
fi
if [ -z "$runtime" ]; then
    runtime=$(prepare_runtime "$runtime_fallback" 2>/dev/null || true)
fi
if [ -z "$runtime" ]; then
    printf 'wuci-media-session: cannot prepare a private runtime directory\\n' >&2
    exit 1
fi
export XDG_RUNTIME_DIR="$runtime"

pipewire_ready() {
    command -v pw-cli >/dev/null 2>&1 && pw-cli info 0 >/dev/null 2>&1
}

pulse_ready() {
    command -v pactl >/dev/null 2>&1 && pactl info >/dev/null 2>&1
}

start_daemon() {
    name=$1
    shift
    command -v "$name" >/dev/null 2>&1 || return 0
    "$@" >>/tmp/wuci-"$name".log 2>&1 &
}

wait_for() {
    check=$1
    attempts=0
    while [ "$attempts" -lt 5 ]; do
        if "$check"; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 1
    done
    return 1
}

started_pipewire=0
if ! pipewire_ready; then
    start_daemon pipewire pipewire
    started_pipewire=1
    wait_for pipewire_ready || true
fi

if [ "$started_pipewire" = "1" ] || ! pgrep -x wireplumber >/dev/null 2>&1; then
    start_daemon wireplumber wireplumber
fi

if ! pulse_ready; then
    start_daemon pipewire-pulse pipewire-pulse
    wait_for pulse_ready || true
fi
"""
    media_apply_script = """#!/bin/sh
set -eu

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wuci-media-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

enable_service() {
    service=$1
    if [ -d "/etc/sv/$service" ]; then
        mkdir -p /etc/runit/runsvdir/default
        if [ ! -e "/etc/runit/runsvdir/default/$service" ]; then
            ln -s "/etc/sv/$service" "/etc/runit/runsvdir/default/$service" 2>/dev/null || true
        fi
        command -v sv >/dev/null 2>&1 && sv up "$service" >/dev/null 2>&1 || true
    fi
}

if command -v xbps-install >/dev/null 2>&1; then
    run_root_wait "audio video Bluetooth portal packages" xbps-install -Sy __AUDIO_PACKAGES__ __VIDEO_PACKAGES__ __PERIPHERAL_PACKAGES__ || true
else
    printf 'wuci-media-apply: xbps-install not found; cannot add missing media packages\\n' >&2
fi

enable_service dbus
enable_service bluetoothd
enable_service bluetooth
enable_service cupsd
enable_service cups
wuci-media-session || true
wuci-boot-chime --once || true

cat <<'TEXT'
Wuci-OS media suite requested.

Audio: PipeWire/WirePlumber with ALSA and Pulse helpers.
Video: Mesa, Vulkan loader/tools, VAAPI/VDPAU helpers, common Xorg drivers.
Peripherals: Bluetooth, printing, scanning, desktop portals, removable media.
TEXT
wuci-media-status || true
"""
    media_status_script = """#!/bin/sh
set -eu

printf 'Wuci-OS media status\\n'
for cmd in pipewire wireplumber pipewire-pulse pw-play aplay paplay pactl mpv vlc bluetoothctl lpstat scanimage; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  %-18s %s\\n' "$cmd" "$(command -v "$cmd")"
    else
        printf '  %-18s missing\\n' "$cmd"
    fi
done
if [ -d /dev/snd ]; then
    printf '  audio-devices: present\\n'
else
    printf '  audio-devices: missing /dev/snd\\n'
fi
if [ -d /dev/dri ]; then
    ls /dev/dri 2>/dev/null | sed 's/^/  dri: /' || true
else
    printf '  dri: missing /dev/dri\\n'
fi
if command -v pactl >/dev/null 2>&1; then
    pactl info 2>/dev/null | sed 's/^/  pulse: /' || true
fi
"""
    sdr_apply_script = """#!/bin/sh
set -eu

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "$label" sudo "$@"
    else
        printf 'wuci-sdr-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-sdr-apply: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

install_group() {
    label=$1
    shift
    [ "$#" -gt 0 ] || return 0
    printf '\\n==> %s\\n' "$label"
    if run_root_wait "$label" xbps-install -Sy "$@"; then
        return 0
    fi
    printf 'wuci-sdr-apply: group install had misses; trying package-by-package\\n' >&2
    for pkg in "$@"; do
        run_root_wait "sdr $pkg" xbps-install -Sy "$pkg" || printf 'optional SDR package unavailable: %s\\n' "$pkg" >&2
    done
}

ensure_group() {
    group=$1
    getent group "$group" >/dev/null 2>&1 || as_root groupadd "$group" 2>/dev/null || true
}

if command -v xbps-install >/dev/null 2>&1; then
    install_group "SDR radio stack" __SDR_PACKAGES__ __SDR_OPTIONAL_PACKAGES__
else
    printf 'wuci-sdr-apply: xbps-install not found; cannot add missing SDR packages\\n' >&2
fi

for group in plugdev usb dialout uucp; do
    ensure_group "$group"
done
for user in wj wj_low; do
    if getent passwd "$user" >/dev/null 2>&1; then
        as_root usermod -aG plugdev,usb,dialout,uucp "$user" 2>/dev/null || true
    fi
done

tmp=$(mktemp)
cat >"$tmp" <<'RULES'
# Wuci-OS SDR USB access helpers. Verify hardware-specific rules after install.
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", MODE="0660", GROUP="plugdev", TAG+="uaccess"
SUBSYSTEM=="usb", ATTRS{idVendor}=="04b4", MODE="0660", GROUP="plugdev", TAG+="uaccess"
RULES
as_root mkdir -p /etc/udev/rules.d
as_root install -m 0644 "$tmp" /etc/udev/rules.d/60-wuci-sdr.rules
rm -f "$tmp"
if command -v udevadm >/dev/null 2>&1; then
    as_root udevadm control --reload-rules 2>/dev/null || true
    as_root udevadm trigger 2>/dev/null || true
fi

cat <<'TEXT'
Wuci-OS SDR suite requested.

Included lanes: GNU Radio, Gqrx, RTL-SDR, HackRF, Airspy, SoapySDR, UHD, RF
inspection helpers, USB device tools, and user/group access for SDR hardware.
Use only lawful radio workflows and verify hardware-specific udev behavior on
the installed target.
TEXT
wuci-sdr-status || true
"""
    sdr_status_script = """#!/bin/sh
set -eu

printf 'Wuci-OS SDR status\\n'
for cmd in gnuradio-companion gnuradio-config-info gqrx rtl_test rtl_eeprom hackrf_info airspy_info airspyhf_info SoapySDRUtil uhd_find_devices inspectrum qspectrumanalyzer dump1090 multimon-ng fldigi lsusb; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  %-24s %s\\n' "$cmd" "$(command -v "$cmd")"
    else
        printf '  %-24s missing\\n' "$cmd"
    fi
done
for group in plugdev usb dialout uucp; do
    if getent group "$group" >/dev/null 2>&1; then
        printf '  group %-17s present\\n' "$group"
    else
        printf '  group %-17s missing\\n' "$group"
    fi
done
if [ -r /etc/udev/rules.d/60-wuci-sdr.rules ]; then
    printf '  udev rules: /etc/udev/rules.d/60-wuci-sdr.rules\\n'
else
    printf '  udev rules: missing\\n'
fi
if command -v lsusb >/dev/null 2>&1; then
    lsusb 2>/dev/null | sed 's/^/  usb: /' || true
fi
"""
    network_apply_script = (
        network_apply_script.replace("__NETWORK_PACKAGES__", sh_words(NETWORK_PACKAGES))
        .replace("__FIRMWARE_PACKAGES__", sh_words(FIRMWARE_PACKAGES))
    )
    media_apply_script = (
        media_apply_script.replace("__AUDIO_PACKAGES__", sh_words(AUDIO_PACKAGES))
        .replace("__VIDEO_PACKAGES__", sh_words(VIDEO_PACKAGES))
        .replace("__PERIPHERAL_PACKAGES__", sh_words(PERIPHERAL_PACKAGES))
    )
    sdr_apply_script = (
        sdr_apply_script.replace("__SDR_PACKAGES__", sh_words(SDR_PACKAGES))
        .replace("__SDR_OPTIONAL_PACKAGES__", sh_words(SDR_OPTIONAL_PACKAGES))
    )
    update_script = """#!/bin/sh
set -eu

usage() {
    cat <<'TEXT'
Wuci-OS live update

Usage:
  wuci-update [--check] [--packages-only] [--source-only] [--no-packages]
              [--repo PATH] [--live-repo PATH] [--repo-url URL]
              [--branch NAME] [--allow-dirty]

Default behavior:
  1. report the active Wuci-OS identity, architecture, and configured repositories
  2. update packages with the configured xbps repository set
  3. fast-forward the onboard Wuci-Ji checkout, or clone a live checkout when
     the embedded source payload is a deterministic snapshot
  4. rebuild and reactivate the local Wuci-OS overlay when possible

No credentials are baked into Wuci-OS. Git remotes and xbps repositories must be
configured by the operator or the installed image.
TEXT
}

repo="${WUCI_SOURCE_ROOT:-/opt/wuci-os/source/wuci-ji}"
live_repo="${WUCI_LIVE_SOURCE_ROOT:-${HOME:-/tmp}/wuci-ji-live}"
repo_url="${WUCI_REPO_URL:-https://github.com/chasebryan/-wuci-ji.git}"
branch="${WUCI_UPDATE_BRANCH:-}"
allow_dirty=0
check_only=0
packages=1
source=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --repo)
            [ "$#" -ge 2 ] || { printf 'wuci-update: --repo needs a path\\n' >&2; exit 2; }
            repo=$2
            shift 2
            ;;
        --live-repo)
            [ "$#" -ge 2 ] || { printf 'wuci-update: --live-repo needs a path\\n' >&2; exit 2; }
            live_repo=$2
            shift 2
            ;;
        --repo-url)
            [ "$#" -ge 2 ] || { printf 'wuci-update: --repo-url needs a URL\\n' >&2; exit 2; }
            repo_url=$2
            shift 2
            ;;
        --branch)
            [ "$#" -ge 2 ] || { printf 'wuci-update: --branch needs a name\\n' >&2; exit 2; }
            branch=$2
            shift 2
            ;;
        --allow-dirty)
            allow_dirty=1
            shift
            ;;
        --check|--dry-run)
            check_only=1
            shift
            ;;
        --packages-only)
            packages=1
            source=0
            shift
            ;;
        --source-only|--repo-only)
            packages=0
            source=1
            shift
            ;;
        --no-packages)
            packages=0
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            printf 'wuci-update: unknown argument: %s\\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-update: run as root or install sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

run_wait() {
    label=$1
    shift
    if command -v wuci-wait-run >/dev/null 2>&1; then
        wuci-wait-run "$label" "$@"
    else
        "$@"
    fi
}

run_root_wait() {
    label=$1
    shift
    if [ "$(id -u)" = "0" ]; then
        run_wait "$label" "$@"
    elif command -v sudo >/dev/null 2>&1; then
        run_wait "$label" sudo "$@"
    else
        printf 'wuci-update: run as root or install sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

ensure_network_for_updates() {
    [ "${WUCI_SKIP_NETWORK_PROMPT:-0}" = "1" ] && return 0
    command -v wuci-network-connect >/dev/null 2>&1 || return 0
    if wuci-network-connect --check >/dev/null 2>&1; then
        return 0
    fi
    printf 'wuci-update: network is not connected; starting Wuci network credential prompt\\n' >&2
    as_root wuci-network-connect
}

os_id=unknown
os_like=
os_name=unknown
os_version=rolling
if [ -r /etc/os-release ]; then
    os_id=$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release)
    os_like=$(awk -F= '$1 == "ID_LIKE" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release)
    os_name=$(awk -F= '$1 == "NAME" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release)
    found_version=$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2; exit }' /etc/os-release)
    [ -n "$found_version" ] && os_version=$found_version || true
fi
arch=unknown
if command -v xbps-uhelper >/dev/null 2>&1; then
    arch=$(xbps-uhelper arch 2>/dev/null || printf unknown)
elif command -v uname >/dev/null 2>&1; then
    arch=$(uname -m)
fi

printf 'Wuci-OS update context\\n'
printf '  os:      %s (%s)\\n' "$os_name" "$os_id"
[ -n "$os_like" ] && printf '  like:    %s\\n' "$os_like"
printf '  version: %s\\n' "$os_version"
printf '  arch:    %s\\n' "$arch"
printf '  repo:    %s\\n' "$repo"
printf '  live:    %s\\n' "$live_repo"
printf '  remote:  %s\\n' "$repo_url"

if ! command -v xbps-install >/dev/null 2>&1; then
    printf 'wuci-update: warning: xbps-install is unavailable; package updates will be skipped\\n' >&2
fi

if command -v xbps-query >/dev/null 2>&1; then
    base_pkg=$(xbps-query -p pkgver base-system 2>/dev/null || true)
    [ -n "$base_pkg" ] && printf '  base:    %s\\n' "$base_pkg"
fi
if command -v xbps-query >/dev/null 2>&1; then
    repos=$(xbps-query -L 2>/dev/null || true)
    if [ -n "$repos" ]; then
        printf '  xbps repositories:\\n'
        printf '%s\\n' "$repos" | sed 's/^/    /'
    fi
fi

if [ "$check_only" -eq 1 ]; then
    if [ "$source" -eq 1 ] && [ -d "$repo/.git" ]; then
        git -C "$repo" status --short --branch || true
    elif [ "$source" -eq 1 ] && [ -d "$live_repo/.git" ]; then
        git -C "$live_repo" status --short --branch || true
    elif [ "$source" -eq 1 ]; then
        printf 'wuci-update: embedded source is not a git checkout; live clone target: %s\\n' "$live_repo"
    fi
    exit 0
fi

if [ "$packages" -eq 1 ]; then
    if command -v xbps-install >/dev/null 2>&1; then
        if ensure_network_for_updates; then
            run_root_wait "system package update" xbps-install -Syu
        else
            printf 'wuci-update: package update skipped because network setup did not complete\\n' >&2
        fi
    else
        printf 'wuci-update: xbps-install unavailable; skipping package update\\n' >&2
    fi
fi

if [ "$source" -eq 1 ]; then
    if ! ensure_network_for_updates; then
        printf 'wuci-update: source repo sync skipped because network setup did not complete\\n' >&2
        exit 1
    fi
    if ! command -v git >/dev/null 2>&1; then
        printf 'wuci-update: git unavailable; cannot update source repo\\n' >&2
        exit 1
    fi
    if [ ! -d "$repo/.git" ]; then
        if [ -d "$live_repo/.git" ]; then
            printf 'wuci-update: using existing live checkout: %s\\n' "$live_repo"
            repo=$live_repo
        else
            clone_target=$repo
            if [ -d "$repo" ]; then
                if find "$repo" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .; then
                    clone_target=$live_repo
                fi
            fi
            mkdir -p "$(dirname "$clone_target")"
            if [ -n "$branch" ]; then
                run_wait "repo clone" git clone --branch "$branch" "$repo_url" "$clone_target"
            else
                run_wait "repo clone" git clone "$repo_url" "$clone_target"
            fi
            repo=$clone_target
        fi
    fi
    dirty=$(git -C "$repo" status --porcelain)
    if [ -n "$dirty" ] && [ "$allow_dirty" -ne 1 ]; then
        printf 'wuci-update: refusing to update dirty checkout; use --allow-dirty after review\\n' >&2
        git -C "$repo" status --short
        exit 2
    fi
    current_branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD)
    if [ "$current_branch" = "HEAD" ] && [ -z "$branch" ]; then
        printf 'wuci-update: detached HEAD; pass --branch NAME for fast-forward update\\n' >&2
        exit 2
    fi
    [ -n "$branch" ] || branch=$current_branch
    before=$(git -C "$repo" rev-parse HEAD)
    run_wait "repo fetch" git -C "$repo" fetch --prune origin
    run_wait "repo fast-forward" git -C "$repo" pull --ff-only origin "$branch"
    after=$(git -C "$repo" rev-parse HEAD)
    printf 'wuci-update: repo %s -> %s on %s\\n' "$before" "$after" "$branch"

    if command -v wuci-selfupdate >/dev/null 2>&1; then
        # Preferred: measured, digest-verified overlay sync onto the running root.
        run_wait "measured overlay update" wuci-selfupdate --apply --source "$repo"
    elif [ -x "$repo/tools/wuci-os" ]; then
        run_wait "wuci-os overlay refresh" "$repo/tools/wuci-os" overlay --force
        if [ "$(id -u)" = "0" ] && [ -x "$repo/tools/wuci-os-live-activate" ]; then
            WUCI_OS_OVERLAY="$repo/build/wuci-os/overlay" "$repo/tools/wuci-os-live-activate" || true
        else
            printf 'wuci-update: overlay refreshed; run as root to reactivate live overlay:\\n'
            printf '  WUCI_OS_OVERLAY=%s %s/tools/wuci-os-live-activate\\n' "$repo/build/wuci-os/overlay" "$repo"
        fi
    fi
fi

printf 'wuci-update: complete\\n'
"""
    ai_status_script = """#!/bin/sh
set -eu

printf 'Wuci-OS AI toolchain status\\n'
for cmd in curl git codex copilot wuci-grok-build; do
    if command -v "$cmd" >/dev/null 2>&1; then
        printf '  %-16s %s\\n' "$cmd" "$(command -v "$cmd")"
    else
        printf '  %-16s missing\\n' "$cmd"
    fi
done

if [ -n "${OPENAI_API_KEY:-}" ]; then
    printf '  %-16s set\\n' "OPENAI_API_KEY"
else
    printf '  %-16s not set; Codex can still use ChatGPT login if supported\\n' "OPENAI_API_KEY"
fi

if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    printf '  %-16s set\\n' "GH_TOKEN"
else
    printf '  %-16s not set; Copilot CLI will ask you to log in\\n' "GH_TOKEN"
fi

if [ -n "${XAI_API_KEY:-}" ]; then
    printf '  %-16s set\\n' "XAI_API_KEY"
else
    printf '  %-16s not set; wuci-grok-build will not call xAI\\n' "XAI_API_KEY"
fi
"""
    ai_setup_script = """#!/bin/sh
set -eu

cat <<'TEXT'
Wuci-OS AI setup plan

This command is plan-only. It does not download installer scripts, run remote
code, install global npm packages, or write credentials.

Review current upstream installation instructions from the tool vendors, then
install through a local package, pinned package manager transaction, or manually
reviewed installer:

  sudo wj install ca-certificates curl git bash tar gzip xz unzip nodejs npm
  codex        # after operator-reviewed Codex CLI installation or login setup
  copilot      # after operator-reviewed GitHub Copilot CLI installation
  export XAI_API_KEY=...
  wuci-grok-build "write a defensive Wuci-OS task checklist"

Credentials remain operator-supplied. Do not bake API keys into the image.
TEXT

wuci-ai-status || true
"""
    grok_build_script = """#!/bin/sh
set -eu

MODEL="${GROK_BUILD_MODEL:-grok-build-0.1}"
API="${XAI_API_BASE:-https://api.x.ai/v1/responses}"

if [ -z "${XAI_API_KEY:-}" ]; then
    printf 'wuci-grok-build: set XAI_API_KEY first\\n' >&2
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    printf 'wuci-grok-build: curl is required\\n' >&2
    exit 2
fi

PROMPT="${*:-Build inside Wuci-OS: inspect this system and suggest the next clean repo task.}"
ESCAPED=$(printf '%s' "$PROMPT" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')
SYSTEM='You are Grok Build running in Wuci-OS. Stay defensive, concise, and implementation-focused.'
SYSTEM_ESCAPED=$(printf '%s' "$SYSTEM" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g')

curl -fsS "$API" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $XAI_API_KEY" \
  -d "{
    \\"model\\": \\"$MODEL\\",
    \\"input\\": [
      {\\"role\\": \\"system\\", \\"content\\": \\"$SYSTEM_ESCAPED\\"},
      {\\"role\\": \\"user\\", \\"content\\": \\"$ESCAPED\\"}
    ]
  }"
printf '\\n'
"""
    profile = """# Wuci-OS live profile
export WUCI_OS=1
export WUCI_OS_NAME="Wuci-OS"
export WUCI_OS_BASE="Wuci-OS x86_64-musl"
if [ -t 1 ] && [ "${WUCI_OS_QUIET:-0}" != "1" ]; then
    printf '\\nWuci-OS live profile active. Run: wuci-status | wuci-attest | wuci-enter\\n\\n'
fi
"""
    xfce_autostart_profile = """# Wuci-OS tty1 XFCE autostart
if [ -z "${DISPLAY:-}" ] && [ "${WUCI_XFCE_AUTOSTART:-1}" = "1" ] && [ -t 0 ]; then
    current_tty=$(tty 2>/dev/null || true)
    current_user=$(id -un 2>/dev/null || true)
    if [ "$current_tty" = "/dev/tty1" ] && [ "$current_user" = "wj" ] && command -v startx >/dev/null 2>&1; then
        if command -v wuci-live-banner >/dev/null 2>&1; then
            wuci-live-banner || true
        fi
        exec startx >/tmp/wuci-xfce.log 2>&1
    fi
fi
"""
    issue = """Wuci-OS live profile
Wuci-OS x86_64-musl base
login: wj / press Enter  or  wj_low / press Enter
admin: wj shows prompt WJ>_
"""
    os_release = """NAME="Wuci-OS"
ID=wuci-os
ID_LIKE=linux
PRETTY_NAME="Wuci-OS x86_64-musl"
VERSION_ID="0"
HOME_URL="https://github.com/chasebryan/-wuci-ji"
BUG_REPORT_URL="https://github.com/chasebryan/-wuci-ji/issues"
"""
    motd = """Wuci-OS live profile

Run:
  wuci-status
  wuci-attest
  wuci-live-banner
  wuci-enter
  wuci-guide
  wuci-auto
  wuci-source-status
  INSTALL
  wuci-install
  wuci-install-target-activate
  wuci-wallpaper
  wuci-terminal
  wuci-boot-chime
  wuci-network-connect
  wuci-network-apply
  wuci-network-status
  wuci-media-apply
  wuci-media-status
  wuci-media-session
  wuci-sdr-apply
  wuci-sdr-status
  wuci-update
  wuci-users-apply
  wuci-users-status
  wuci-dev-install
  wuci-security-apply
  wuci-security-status
  wuci-selinux-status
  wuci-daylight-status
  wuci-daylight-v14c-plus
  wuci-daylight-meridian
  wuci-ai-status
  wuci-ai-setup
  wuci-grok-build

This is a Wuci-Ji/NOXFRAME image lane on a Wuci-OS musl base. It defaults to
SELinux-first high-assurance settings, XFCE4, kitty, ratpoison, emacs, vim, and
developer toolchains. It is not a runtime sandbox or production trust authority.
"""
    desktop_entry = """[Desktop Entry]
Type=Application
Name=Wuci-OS Wallpaper
Exec=/usr/local/bin/wuci-wallpaper
OnlyShowIn=XFCE;GNOME;LXDE;LXQt;MATE;
X-GNOME-Autostart-enabled=true
"""
    terminal_desktop_entry = """[Desktop Entry]
Type=Application
Name=Wuci-OS Terminal
Exec=/usr/local/bin/wuci-terminal
OnlyShowIn=XFCE;GNOME;LXDE;LXQt;MATE;
X-GNOME-Autostart-enabled=true
"""
    chime_desktop_entry = """[Desktop Entry]
Type=Application
Name=Wuci-OS Boot Chime
Exec=/usr/local/bin/wuci-boot-chime --once --quiet
OnlyShowIn=XFCE;GNOME;LXDE;LXQt;MATE;
X-GNOME-Autostart-enabled=true
"""
    media_desktop_entry = """[Desktop Entry]
Type=Application
Name=Wuci-OS Media Session
Exec=/usr/local/bin/wuci-media-session
OnlyShowIn=XFCE;GNOME;LXDE;LXQt;MATE;
X-GNOME-Autostart-enabled=true
"""
    ratpoisonrc = """# Wuci-OS ratpoison profile
set prefix C-t
set border 1
set barpadding 4 4
set font fixed
set winname class
set startupmessage 0
set historysize 2000
set wingravity center
set msgwait 4
set framefmt %n:%t
bind c exec wuci-terminal
bind C exec wuci-terminal
bind e exec emacs
bind v exec wuci-terminal vim
bind b exec firefox
bind p exec dmenu_run
bind s exec wuci-security-status
bind w exec wuci-wallpaper
bind P exec wuci-attest
bind r restart
bind q only
bind Q quit
startup_message off
echo Wuci-OS ratpoison profile active: C-t c opens preferred terminal, C-t s checks security.
"""
    kitty_conf = """# Wuci-OS kitty profile
font_family monospace
font_size 11.0
cursor_shape block
scrollback_lines 20000
enable_audio_bell no
confirm_os_window_close 0
copy_on_select yes
background #050505
foreground #d7d7d7
selection_background #7a1111
selection_foreground #ffffff
color0 #050505
color1 #cc1414
color2 #3f8f46
color3 #c09a35
color4 #6177a8
color5 #8c4d8f
color6 #4f9a9a
color7 #d7d7d7
color8 #555555
color9 #ff3030
color10 #57b863
color11 #d6b85b
color12 #849bd8
color13 #ad68b0
color14 #66c4c4
color15 #ffffff
"""
    xinitrc = """#!/bin/sh
if command -v wuci-boot-chime >/dev/null 2>&1; then
    wuci-boot-chime --once --quiet &
fi
if command -v wuci-media-session >/dev/null 2>&1; then
    wuci-media-session &
fi
if command -v wuci-terminal >/dev/null 2>&1; then
    wuci-terminal &
fi
exec startxfce4
"""
    def command_wrapper(command: str) -> str:
        return (
            "#!/bin/sh\n"
            f"for candidate in /usr/bin/{command} /bin/{command} /usr/sbin/{command} /sbin/{command}; do\n"
            "    if [ -x \"$candidate\" ]; then\n"
            "        exec \"$candidate\" \"$@\"\n"
            "    fi\n"
            "done\n"
            f"printf '{command}: required Wuci-OS command is missing from this image\\n' >&2\n"
            "exit 127\n"
        )

    boot_chime_runit = """#!/bin/sh
if [ -x /usr/local/bin/wuci-boot-chime ]; then
    /usr/local/bin/wuci-boot-chime --once --quiet >/dev/null 2>&1 || true
fi
while :; do
    sleep 3600
done
"""
    package_profile_json = json.dumps(package_manifest(), indent=2, sort_keys=True) + "\n"
    return {
        "etc/hostname": "wuci-os-live\n",
        "etc/issue": issue,
        "etc/motd": motd,
        "etc/os-release": os_release,
        "usr/lib/os-release": os_release,
        "etc/profile.d/wuci-os.sh": profile,
        "etc/profile.d/wuci-xfce-autostart.sh": xfce_autostart_profile,
        "etc/profile.d/wuci-prompt.sh": prompt_script,
        "etc/xdg/autostart/wuci-wallpaper.desktop": desktop_entry,
        "etc/xdg/autostart/wuci-terminal.desktop": terminal_desktop_entry,
        "etc/xdg/autostart/wuci-boot-chime.desktop": chime_desktop_entry,
        "etc/xdg/autostart/wuci-media-session.desktop": media_desktop_entry,
        "etc/runit/runsvdir/default/wuci-boot-chime/run": boot_chime_runit,
        "etc/skel/.xinitrc": xinitrc,
        "etc/skel/.ratpoisonrc": ratpoisonrc,
        "etc/skel/.config/kitty/kitty.conf": kitty_conf,
        "root/.xinitrc": xinitrc,
        "root/.ratpoisonrc": ratpoisonrc,
        "root/.config/kitty/kitty.conf": kitty_conf,
        "usr/local/bin/wuci-status": status_script,
        "usr/local/bin/wuci-attest": attest_script,
        "usr/local/bin/wuci-live-banner": live_banner_script,
        "usr/local/bin/sudo": command_wrapper("sudo"),
        "usr/local/bin/su": command_wrapper("su"),
        "usr/local/bin/ip": command_wrapper("ip"),
        "usr/local/bin/dhcpcd": command_wrapper("dhcpcd"),
        "usr/local/bin/iw": command_wrapper("iw"),
        "usr/local/bin/rfkill": command_wrapper("rfkill"),
        "usr/local/bin/wpa_supplicant": command_wrapper("wpa_supplicant"),
        "usr/local/bin/wpa_passphrase": command_wrapper("wpa_passphrase"),
        "usr/local/bin/xbps-install": command_wrapper("xbps-install"),
        "usr/local/bin/wuci-source-status": source_status_script,
        "usr/local/bin/wuci-enter": enter_script,
        "usr/local/bin/wuci-guide": guide_script,
        "usr/local/bin/wuci-auto": auto_script,
        "usr/local/bin/INSTALL": auto_install_script,
        "usr/local/bin/wuci-install": install_script,
        "usr/local/bin/wuci-install-target-activate": install_target_activate_script,
        "usr/local/bin/wuci-selfupdate": selfupdate_script,
        "usr/local/bin/wuci-wallpaper": wallpaper_script,
        "usr/local/bin/wuci-terminal": terminal_script.replace("__TERMINAL_CANDIDATES__", sh_words(TERMINAL_CANDIDATES)),
        "usr/local/bin/wuci-boot-chime": boot_chime_script,
        "usr/local/bin/wuci-network-connect": network_connect_script,
        "usr/local/bin/wuci-network-apply": network_apply_script,
        "usr/local/bin/wuci-network-status": network_status_script,
        "usr/local/bin/wuci-media-apply": media_apply_script,
        "usr/local/bin/wuci-media-status": media_status_script,
        "usr/local/bin/wuci-media-session": media_session_script,
        "usr/local/bin/wuci-sdr-apply": sdr_apply_script,
        "usr/local/bin/wuci-sdr-status": sdr_status_script,
        "usr/local/bin/wuci-update": update_script,
        "usr/local/bin/wuci-wait-run": wait_run_script,
        "usr/local/bin/wj": wj_script,
        "usr/local/bin/wuci-users-apply": users_apply_script,
        "usr/local/bin/wuci-users-status": users_status_script,
        "usr/local/bin/wuci-dev-install": dev_install_script,
        "usr/local/bin/wuci-security-apply": security_apply_script,
        "usr/local/bin/wuci-security-status": security_status_script,
        "usr/local/bin/wuci-selinux-status": selinux_status_script,
        "usr/local/bin/wuci-daylight-status": daylight_status_script,
        "usr/local/bin/wuci-daylight-v14c-plus": daylight_v14c_script,
        "usr/local/bin/wuci-daylight-meridian": daylight_meridian_script,
        "usr/local/bin/wuci-ai-status": ai_status_script,
        "usr/local/bin/wuci-ai-setup": ai_setup_script,
        "usr/local/bin/wuci-grok-build": grok_build_script,
        "usr/share/wuci-os/accounts.json": account_profile_json,
        "usr/share/wuci-os/packages.json": package_profile_json,
        "usr/share/wuci-os/security-profile.json": json.dumps(security_profile_manifest(), indent=2, sort_keys=True) + "\n",
        "usr/share/wuci-os/full-suite-packages.txt": "\n".join(full_suite_packages()) + "\n",
        "usr/share/wuci-os/ratpoisonrc": ratpoisonrc,
        "usr/share/wuci-os/kitty.conf": kitty_conf,
        "usr/share/wuci-os/README": readme,
        "usr/share/wuci-os/OFFLINE-INSTALL.txt": offline_install_guide_text(),
        "usr/share/wuci-os/WUCI_DAYLIGHT_V8.md": _read_regular_bytes(
            repo_root() / DAYLIGHT_V8_MODEL_DOC,
            "Wuci-OS Daylight v8 model doc",
        ).decode("utf-8"),
        "usr/share/wuci-os/WUCI_DAYLIGHT_V9.md": _read_regular_bytes(
            repo_root() / DAYLIGHT_V9_MODEL_DOC,
            "Wuci-OS Daylight v9 model doc",
        ).decode("utf-8"),
        "usr/share/wuci-os/WUCI_DAYLIGHT_V10.md": _read_regular_bytes(
            repo_root() / DAYLIGHT_V10_MODEL_DOC,
            "Wuci-OS Daylight v10 model doc",
        ).decode("utf-8"),
        "usr/share/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md": _read_regular_bytes(
            repo_root() / DAYLIGHT_V13_MODEL_DOC,
            "Wuci-OS Daylight v13 Sovereign model doc",
        ).decode("utf-8"),
        "usr/share/wuci-os/boundary.txt": "\n".join(BOUNDARY_DENIALS) + "\n",
        "usr/share/wuci-os/selinux.txt": "\n".join(
            [
                "Wuci-OS SELinux default",
                "",
                "Required mode: enforcing",
                "Required policy type: targeted",
                "Fedora-style operator experience: configure once, verify automatically, and avoid manual interaction unless policy blocks a real workflow.",
                "If SELinux packages or policy are unavailable, Wuci-OS reports a blocker instead of treating AppArmor as a substitute.",
                "",
            ]
        ),
        "usr/share/wuci-os/kicksecure-inspired-hardening.txt": "\n".join(KICKSECURE_INSPIRED_HARDENING) + "\n",
        "usr/share/wuci-os/ai-tools.txt": "\n".join(
            [
                "Wuci-OS AI tools",
                "",
                "Codex CLI: install only through an operator-reviewed official flow or local package.",
                "GitHub Copilot CLI: install only through an operator-reviewed GitHub flow or local package.",
                "Grok Build: call xAI Responses API with model grok-build-0.1 and XAI_API_KEY.",
                "",
                "wuci-ai-setup is plan-only: it does not download or execute remote installers.",
                "No credentials are baked into Wuci-OS. Use environment variables or each tool's login flow.",
                "",
            ]
        ),
    }


def create_overlay(
    overlay_root: Path | None = None,
    *,
    wallpaper_source: Path | None = None,
    force: bool = False,
) -> dict[str, Any]:
    root = DEFAULT_OVERLAY_ROOT if overlay_root is None else overlay_root
    _reject_symlink_output_parents(root / ".wuci-output-check", "Wuci-OS overlay root")
    wallpaper = DEFAULT_WALLPAPER_SOURCE if wallpaper_source is None else wallpaper_source
    wallpaper_info = _verified_regular_file_info(wallpaper, "Wuci-OS wallpaper")
    model_diagram = repo_root() / DEFAULT_MODEL_DIAGRAM_SOURCE
    model_diagram_info = _verified_regular_file_info(model_diagram, "Wuci-OS Daylight wire model diagram")
    _validate_png_bytes(
        _read_regular_bytes(model_diagram, "Wuci-OS Daylight wire model diagram"),
        "Wuci-OS Daylight wire model diagram",
    )
    daylight_v8_diagram = repo_root() / DEFAULT_DAYLIGHT_V8_DIAGRAM_SOURCE
    daylight_v8_diagram_info = _verified_regular_file_info(daylight_v8_diagram, "Wuci-OS Daylight v8 sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v8_diagram, "Wuci-OS Daylight v8 sheet"),
        "Wuci-OS Daylight v8 sheet",
    )
    daylight_v9_sheet = repo_root() / DEFAULT_DAYLIGHT_V9_SHEET_SOURCE
    daylight_v9_sheet_info = _verified_regular_file_info(daylight_v9_sheet, "Wuci-OS Daylight v9 sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v9_sheet, "Wuci-OS Daylight v9 sheet"),
        "Wuci-OS Daylight v9 sheet",
    )
    daylight_v9_diagram = repo_root() / DEFAULT_DAYLIGHT_V9_DIAGRAM_SOURCE
    daylight_v9_diagram_info = _verified_regular_file_info(daylight_v9_diagram, "Wuci-OS Daylight v9 formal spine")
    daylight_v9_diagram_data = _read_regular_bytes(daylight_v9_diagram, "Wuci-OS Daylight v9 formal spine")
    if b"<svg" not in daylight_v9_diagram_data[:256]:
        raise WuciOSError(f"Wuci-OS Daylight v9 formal spine is not an SVG document: {daylight_v9_diagram}")
    daylight_v10_scoreboard = repo_root() / DEFAULT_DAYLIGHT_V10_SCOREBOARD_SOURCE
    daylight_v10_scoreboard_info = _verified_regular_file_info(daylight_v10_scoreboard, "Wuci-OS Daylight v10 scoreboard")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v10_scoreboard, "Wuci-OS Daylight v10 scoreboard"),
        "Wuci-OS Daylight v10 scoreboard",
    )
    daylight_v13_math = repo_root() / DEFAULT_DAYLIGHT_V13_MATH_SOURCE
    daylight_v13_math_info = _verified_regular_file_info(daylight_v13_math, "Wuci-OS Daylight v13 Sovereign math sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v13_math, "Wuci-OS Daylight v13 Sovereign math sheet"),
        "Wuci-OS Daylight v13 Sovereign math sheet",
    )
    daylight_v14c_image = repo_root() / DEFAULT_DAYLIGHT_V14C_IMAGE_SOURCE
    daylight_v14c_image_info = _verified_regular_file_info(daylight_v14c_image, "Wuci-OS Daylight v14C+ Ascendant candidate sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v14c_image, "Wuci-OS Daylight v14C+ Ascendant candidate sheet"),
        "Wuci-OS Daylight v14C+ Ascendant candidate sheet",
    )
    daylight_v14c_math = repo_root() / DEFAULT_DAYLIGHT_V14C_MATH_SOURCE
    daylight_v14c_math_info = _verified_regular_file_info(daylight_v14c_math, "Wuci-OS Daylight v14C+ Ascendant math sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v14c_math, "Wuci-OS Daylight v14C+ Ascendant math sheet"),
        "Wuci-OS Daylight v14C+ Ascendant math sheet",
    )
    daylight_v14c_wide = repo_root() / DEFAULT_DAYLIGHT_V14C_WIDE_SOURCE
    daylight_v14c_wide_info = _verified_regular_file_info(daylight_v14c_wide, "Wuci-OS Daylight v14C+ Ascendant wide sheet")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v14c_wide, "Wuci-OS Daylight v14C+ Ascendant wide sheet"),
        "Wuci-OS Daylight v14C+ Ascendant wide sheet",
    )
    daylight_v15_solstice = repo_root() / DEFAULT_DAYLIGHT_V15_SOLSTICE_SOURCE
    daylight_v15_solstice_info = _verified_regular_file_info(daylight_v15_solstice, "Wuci-OS Daylight v15+ Solstice notice")
    _validate_png_bytes(
        _read_regular_bytes(daylight_v15_solstice, "Wuci-OS Daylight v15+ Solstice notice"),
        "Wuci-OS Daylight v15+ Solstice notice",
    )
    daylight_v14c_package = repo_root() / DEFAULT_DAYLIGHT_V14C_PACKAGE_SOURCE
    try:
        daylight_v14c_package_info = os.lstat(daylight_v14c_package)
    except OSError as exc:
        raise WuciOSError(f"missing Wuci-OS Daylight v14C+ execution package: {daylight_v14c_package}") from exc
    if stat.S_ISLNK(daylight_v14c_package_info.st_mode):
        raise WuciOSError(f"Wuci-OS Daylight v14C+ execution package must not be a symlink: {daylight_v14c_package}")
    if not stat.S_ISDIR(daylight_v14c_package_info.st_mode):
        raise WuciOSError(f"Wuci-OS Daylight v14C+ execution package must be a directory: {daylight_v14c_package}")
    daylight_v15_package = repo_root() / DEFAULT_DAYLIGHT_V15_PACKAGE_SOURCE
    try:
        daylight_v15_package_info = os.lstat(daylight_v15_package)
    except OSError as exc:
        raise WuciOSError(f"missing Wuci-OS Daylight v15 Meridian execution package: {daylight_v15_package}") from exc
    if stat.S_ISLNK(daylight_v15_package_info.st_mode):
        raise WuciOSError(f"Wuci-OS Daylight v15 Meridian execution package must not be a symlink: {daylight_v15_package}")
    if not stat.S_ISDIR(daylight_v15_package_info.st_mode):
        raise WuciOSError(f"Wuci-OS Daylight v15 Meridian execution package must be a directory: {daylight_v15_package}")
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        root_info = None
    except OSError as exc:
        raise WuciOSError(f"could not inspect overlay root: {root}") from exc
    if root_info is not None:
        if stat.S_ISLNK(root_info.st_mode):
            raise WuciOSError(f"overlay root must not be a symlink: {root}")
        if not stat.S_ISDIR(root_info.st_mode):
            raise WuciOSError(f"overlay root must be a directory: {root}")
        if any(root.iterdir()) and not force:
            raise WuciOSError(f"overlay root already exists and is not empty: {root}")
        if force:
            clear_overlay_root_for_rebuild(root)
    root.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(root / ".wuci-output-check", "Wuci-OS overlay root")
    _fsync_parent(root)
    written: list[str] = []
    for relative, text in overlay_files().items():
        path = root / relative
        mode = 0o755 if relative.startswith("usr/local/bin/") else 0o644
        _write_verified_new_file(
            path,
            text.encode("utf-8"),
            f"Wuci-OS overlay generated file {relative}",
            mode=mode,
        )
        written.append(relative)
    wallpaper_dest = root / OVERLAY_WALLPAPER_PATH
    wallpaper_digest, wallpaper_bytes = _copy_verified_regular_file(
        wallpaper,
        wallpaper_dest,
        "Wuci-OS overlay wallpaper",
        expected_info=wallpaper_info,
        mode=0o644,
    )
    written.append(str(OVERLAY_WALLPAPER_PATH))
    model_diagram_overlay_path = Path("usr/share/wuci-os/wuci-daylight-wire-model.png")
    model_diagram_digest, model_diagram_bytes = _copy_verified_regular_file(
        model_diagram,
        root / model_diagram_overlay_path,
        "Wuci-OS overlay Daylight wire model diagram",
        expected_info=model_diagram_info,
        mode=0o644,
    )
    written.append(str(model_diagram_overlay_path))
    daylight_v8_diagram_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v8-sheet.png")
    daylight_v8_diagram_digest, daylight_v8_diagram_bytes = _copy_verified_regular_file(
        daylight_v8_diagram,
        root / daylight_v8_diagram_overlay_path,
        "Wuci-OS overlay Daylight v8 sheet",
        expected_info=daylight_v8_diagram_info,
        mode=0o644,
    )
    written.append(str(daylight_v8_diagram_overlay_path))
    daylight_v9_sheet_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v9-sheet.png")
    daylight_v9_sheet_digest, daylight_v9_sheet_bytes = _copy_verified_regular_file(
        daylight_v9_sheet,
        root / daylight_v9_sheet_overlay_path,
        "Wuci-OS overlay Daylight v9 sheet",
        expected_info=daylight_v9_sheet_info,
        mode=0o644,
    )
    written.append(str(daylight_v9_sheet_overlay_path))
    daylight_v9_diagram_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v9-spine.svg")
    daylight_v9_diagram_digest, daylight_v9_diagram_bytes = _copy_verified_regular_file(
        daylight_v9_diagram,
        root / daylight_v9_diagram_overlay_path,
        "Wuci-OS overlay Daylight v9 formal spine",
        expected_info=daylight_v9_diagram_info,
        mode=0o644,
    )
    written.append(str(daylight_v9_diagram_overlay_path))
    daylight_v10_scoreboard_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v10-scoreboard.png")
    daylight_v10_scoreboard_digest, daylight_v10_scoreboard_bytes = _copy_verified_regular_file(
        daylight_v10_scoreboard,
        root / daylight_v10_scoreboard_overlay_path,
        "Wuci-OS overlay Daylight v10 scoreboard",
        expected_info=daylight_v10_scoreboard_info,
        mode=0o644,
    )
    written.append(str(daylight_v10_scoreboard_overlay_path))
    daylight_v13_math_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v13-sovereign-math.png")
    daylight_v13_math_digest, daylight_v13_math_bytes = _copy_verified_regular_file(
        daylight_v13_math,
        root / daylight_v13_math_overlay_path,
        "Wuci-OS overlay Daylight v13 Sovereign math sheet",
        expected_info=daylight_v13_math_info,
        mode=0o644,
    )
    written.append(str(daylight_v13_math_overlay_path))
    daylight_v14c_image_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant.png")
    daylight_v14c_image_digest, daylight_v14c_image_bytes = _copy_verified_regular_file(
        daylight_v14c_image,
        root / daylight_v14c_image_overlay_path,
        "Wuci-OS overlay Daylight v14C+ Ascendant candidate sheet",
        expected_info=daylight_v14c_image_info,
        mode=0o644,
    )
    written.append(str(daylight_v14c_image_overlay_path))
    daylight_v14c_math_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png")
    daylight_v14c_math_digest, daylight_v14c_math_bytes = _copy_verified_regular_file(
        daylight_v14c_math,
        root / daylight_v14c_math_overlay_path,
        "Wuci-OS overlay Daylight v14C+ Ascendant math sheet",
        expected_info=daylight_v14c_math_info,
        mode=0o644,
    )
    written.append(str(daylight_v14c_math_overlay_path))
    daylight_v14c_wide_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png")
    daylight_v14c_wide_digest, daylight_v14c_wide_bytes = _copy_verified_regular_file(
        daylight_v14c_wide,
        root / daylight_v14c_wide_overlay_path,
        "Wuci-OS overlay Daylight v14C+ Ascendant wide sheet",
        expected_info=daylight_v14c_wide_info,
        mode=0o644,
    )
    written.append(str(daylight_v14c_wide_overlay_path))
    daylight_v15_solstice_overlay_path = Path("usr/share/wuci-os/wuci-daylight-v15-plus-solstice.png")
    daylight_v15_solstice_digest, daylight_v15_solstice_bytes = _copy_verified_regular_file(
        daylight_v15_solstice,
        root / daylight_v15_solstice_overlay_path,
        "Wuci-OS overlay Daylight v15+ Solstice notice",
        expected_info=daylight_v15_solstice_info,
        mode=0o644,
    )
    written.append(str(daylight_v15_solstice_overlay_path))
    daylight_v14c_package_overlay_path = Path("usr/share/wuci-os/daylight/v14c-plus")
    daylight_v14c_package_records: list[dict[str, Any]] = []
    for source_path in sorted(daylight_v14c_package.rglob("*"), key=lambda item: item.relative_to(daylight_v14c_package).as_posix()):
        rel = source_path.relative_to(daylight_v14c_package)
        rel_text = rel.as_posix()
        if "__pycache__" in rel.parts or rel_text.endswith(".pyc"):
            continue
        if rel.is_absolute() or ".." in rel.parts or rel_text.startswith("/"):
            raise WuciOSError(f"unsafe Daylight v14C+ package path: {rel_text}")
        info = os.lstat(source_path)
        if stat.S_ISDIR(info.st_mode):
            continue
        target = daylight_v14c_package_overlay_path / rel
        digest, size = _copy_verified_regular_file(
            source_path,
            root / target,
            f"Wuci-OS overlay Daylight v14C+ execution package file {rel_text}",
            expected_info=info,
            mode=0o755 if rel.parts and rel.parts[0] == "src" and source_path.suffix == ".py" else 0o644,
        )
        written.append(str(target))
        daylight_v14c_package_records.append(
            {
                "path": target.as_posix(),
                "source_path": str(source_path),
                "bytes": size,
                "digest_vector": digest,
            }
        )
    daylight_v15_package_overlay_path = Path("usr/share/wuci-os/daylight/v15-meridian")
    daylight_v15_package_records: list[dict[str, Any]] = []
    for source_path in sorted(daylight_v15_package.rglob("*"), key=lambda item: item.relative_to(daylight_v15_package).as_posix()):
        rel = source_path.relative_to(daylight_v15_package)
        rel_text = rel.as_posix()
        if "__pycache__" in rel.parts or rel_text.endswith(".pyc"):
            continue
        if ".egg-info" in rel_text or rel.parts and rel.parts[0] == "build":
            continue
        if rel.is_absolute() or ".." in rel.parts or rel_text.startswith("/"):
            raise WuciOSError(f"unsafe Daylight v15 Meridian package path: {rel_text}")
        info = os.lstat(source_path)
        if stat.S_ISLNK(info.st_mode):
            raise WuciOSError(f"Wuci-OS Daylight v15 Meridian package must not contain symlinks: {rel_text}")
        if stat.S_ISDIR(info.st_mode):
            continue
        target = daylight_v15_package_overlay_path / rel
        digest, size = _copy_verified_regular_file(
            source_path,
            root / target,
            f"Wuci-OS overlay Daylight v15 Meridian execution package file {rel_text}",
            expected_info=info,
            mode=0o755 if rel.parts and rel.parts[0] == "src" and source_path.suffix == ".py" else 0o644,
        )
        written.append(str(target))
        daylight_v15_package_records.append(
            {
                "path": target.as_posix(),
                "source_path": str(source_path),
                "bytes": size,
                "digest_vector": digest,
            }
        )
    manifest_relative = "usr/share/wuci-os/overlay-manifest.json"
    manifest_files = written + [manifest_relative]
    manifest = {
        "schema": OVERLAY_SCHEMA,
        "created_utc": utc_now(),
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "overlay_root": str(root),
        "files": manifest_files,
        "manifest_path": manifest_relative,
        "recorded_paths": [],
        "content_records": [],
        "wallpaper": {
            "path": str(OVERLAY_WALLPAPER_PATH),
            "source_path": str(wallpaper),
            "bytes": wallpaper_bytes,
            "digest_vector": wallpaper_digest,
            "resize_policy": "wuci-wallpaper detects screen geometry and creates an exact-size cache when ImageMagick or GraphicsMagick is present; otherwise it uses desktop fill/zoom setters",
        },
        "substract_model_diagram": {
            "path": str(model_diagram_overlay_path),
            "source_path": str(model_diagram),
            "bytes": model_diagram_bytes,
            "digest_vector": model_diagram_digest,
        },
        "daylight_v8_diagram": {
            "path": str(daylight_v8_diagram_overlay_path),
            "source_path": str(daylight_v8_diagram),
            "bytes": daylight_v8_diagram_bytes,
            "digest_vector": daylight_v8_diagram_digest,
        },
        "daylight_v9_sheet": {
            "path": str(daylight_v9_sheet_overlay_path),
            "source_path": str(daylight_v9_sheet),
            "bytes": daylight_v9_sheet_bytes,
            "digest_vector": daylight_v9_sheet_digest,
        },
        "daylight_v9_diagram": {
            "path": str(daylight_v9_diagram_overlay_path),
            "source_path": str(daylight_v9_diagram),
            "bytes": daylight_v9_diagram_bytes,
            "digest_vector": daylight_v9_diagram_digest,
        },
        "daylight_v10_scoreboard": {
            "path": str(daylight_v10_scoreboard_overlay_path),
            "source_path": str(daylight_v10_scoreboard),
            "bytes": daylight_v10_scoreboard_bytes,
            "digest_vector": daylight_v10_scoreboard_digest,
        },
        "daylight_v13_math": {
            "path": str(daylight_v13_math_overlay_path),
            "source_path": str(daylight_v13_math),
            "bytes": daylight_v13_math_bytes,
            "digest_vector": daylight_v13_math_digest,
        },
        "daylight_v14c_image": {
            "path": str(daylight_v14c_image_overlay_path),
            "source_path": str(daylight_v14c_image),
            "bytes": daylight_v14c_image_bytes,
            "digest_vector": daylight_v14c_image_digest,
        },
        "daylight_v14c_math": {
            "path": str(daylight_v14c_math_overlay_path),
            "source_path": str(daylight_v14c_math),
            "bytes": daylight_v14c_math_bytes,
            "digest_vector": daylight_v14c_math_digest,
        },
        "daylight_v14c_wide": {
            "path": str(daylight_v14c_wide_overlay_path),
            "source_path": str(daylight_v14c_wide),
            "bytes": daylight_v14c_wide_bytes,
            "digest_vector": daylight_v14c_wide_digest,
        },
        "daylight_v15_solstice": {
            "path": str(daylight_v15_solstice_overlay_path),
            "source_path": str(daylight_v15_solstice),
            "bytes": daylight_v15_solstice_bytes,
            "digest_vector": daylight_v15_solstice_digest,
        },
        "daylight_v14c_execution_package": {
            "path": str(daylight_v14c_package_overlay_path),
            "source_path": str(daylight_v14c_package),
            "file_count": len(daylight_v14c_package_records),
            "files": daylight_v14c_package_records,
            "command": "wuci-daylight-v14c-plus",
            "claim": "candidate score package only; not release authority",
        },
        "daylight_v15_meridian_execution_package": {
            "path": str(daylight_v15_package_overlay_path),
            "source_path": str(daylight_v15_package),
            "file_count": len(daylight_v15_package_records),
            "files": daylight_v15_package_records,
            "command": "wuci-daylight-meridian",
            "claim": "evidence-derived scorecard + fail-closed Meridian vault; 1,000,000M still requires external attestation",
        },
        "boundary_denials": list(BOUNDARY_DENIALS),
    }
    wuci_kaiju.write_json_atomic(root / manifest_relative, manifest)
    _fsync_parent(root / manifest_relative)
    records = overlay_file_records(root, ticker_mode="never")
    manifest["recorded_paths"] = [record["path"] for record in records]
    manifest["content_records"] = _overlay_content_records(records, manifest_relative)
    wuci_kaiju.write_json_atomic(root / manifest_relative, manifest)
    _fsync_parent(root / manifest_relative)
    validate_overlay_manifest_current(root, manifest, ticker_mode="never")
    return manifest


def _build_qemu_argv(
    qemu: str,
    *,
    image_path: str,
    kernel_path: str,
    initrd_path: str,
    append: str,
    memory_mib: int,
    cpus: int,
    network: bool,
    share_path: str | Path | None = None,
    share_mode: str = "9p",
    share_tag: str = "wuci-src",
    extra_drive_paths: list[str | Path] | None = None,
) -> list[str]:
    argv = [
        qemu,
        "-m",
        str(memory_mib),
        "-smp",
        str(cpus),
        "-machine",
        "pc,accel=kvm:tcg",
        "-cpu",
        "max",
        "-kernel",
        kernel_path,
        "-initrd",
        initrd_path,
        "-append",
        append,
        "-drive",
        f"file={image_path},if=ide,media=cdrom,readonly=on",
        "-nographic",
        "-serial",
        "mon:stdio",
        "-no-reboot",
    ]
    if network:
        argv.extend(["-nic", "user,model=virtio-net-pci"])
    else:
        argv.extend(["-net", "none"])
    if share_path:
        sp = str(share_path)
        if share_mode == "9p":
            argv.extend(["-fsdev", f"local,id=wucisrc,path={sp},readonly=on,security_model=mapped"])
            argv.extend(["-device", f"virtio-9p-pci,fsdev=wucisrc,mount_tag={share_tag}"])
        elif share_mode == "tar-drive":
            argv.extend(["-drive", f"file={sp},format=raw,if=virtio,readonly=on"])
        else:
            raise WuciOSError(f"unsupported share mode: {share_mode}")
    for drive_path in extra_drive_paths or []:
        argv.extend(["-drive", f"file={drive_path},format=raw,if=virtio,readonly=on"])
    return argv


def boot_plan(
    *,
    source_root: Path | None = None,
    boot_root: Path | None = None,
    qemu_bin: str = DEFAULT_QEMU_BIN,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    cpus: int = DEFAULT_CPUS,
    network: bool = False,
    share_repo: Path | None = None,
    share_tag: str = "wuci-src",
) -> dict[str, Any]:
    if memory_mib < 512 or memory_mib > 262144:
        raise WuciOSError("memory must be between 512 and 262144 MiB")
    if cpus < 1 or cpus > 256:
        raise WuciOSError("cpus must be between 1 and 256")
    source = verify_source(source_root, require_layout=True)
    qemu_path = discover_qemu(qemu_bin)
    root = DEFAULT_BOOT_ROOT if boot_root is None else boot_root
    problems: list[str] = []
    if source["status"] != "pass":
        problems.extend(str(problem) for problem in source.get("problems", []))
    if not qemu_path:
        problems.append(f"QEMU executable not found: {qemu_bin}")
    share_path = share_repo
    share_mode = "9p"
    share_note = ""
    overlay_root = repo_root() / DEFAULT_OVERLAY_ROOT
    if share_repo and not wuci_kaiju.qemu_supports_virtio_9p(qemu_path or qemu_bin):
        share_mode = "tar-drive"
        share_path = root / "wuci-os-overlay.tar"
        share_note = "QEMU does not advertise virtio-9p-pci; using read-only overlay tar drive fallback"
    source_kit_path = root / SOURCE_KIT_TAR_NAME if share_repo else None
    image_path = str(source.get("image_path", ""))
    layout = source.get("layout", {})
    append = serial_append_from_void(str(layout.get("append", ""))) if layout.get("append") else ""
    kernel_path = str(root / "vmlinuz")
    initrd_path = str(root / "initrd")
    argv = []
    if not problems:
        argv = _build_qemu_argv(
            qemu_path or qemu_bin,
            image_path=image_path,
            kernel_path=kernel_path,
            initrd_path=initrd_path,
            append=append,
            memory_mib=memory_mib,
            cpus=cpus,
            network=network,
            share_path=share_path,
            share_mode=share_mode,
            share_tag=share_tag,
            extra_drive_paths=[source_kit_path] if source_kit_path else None,
        )
    result: dict[str, Any] = {
        "schema": BOOT_SCHEMA,
        "status": "ready" if not problems else "blocked",
        "product": PRODUCT_NAME,
        "source": source,
        "boot_root": str(root),
        "qemu_bin": qemu_bin,
        "qemu_discovered": qemu_path or "not found on PATH",
        "qemu_candidates": list(DEFAULT_QEMU_CANDIDATES) if qemu_bin == DEFAULT_QEMU_BIN else [qemu_bin],
        "memory_mib": memory_mib,
        "cpus": cpus,
        "network": "user" if network else "none",
        "kernel_iso_path": "boot/vmlinuz",
        "initrd_iso_path": "boot/initrd",
        "append": append,
        "boot_profile": {
            "mode": "fast-live",
            "qemu_acceleration": "kvm:tcg",
            "kernel_args": list(FAST_BOOT_KERNEL_ARGS),
            "module_blacklist": list(FAST_BOOT_MODPROBE_BLACKLIST),
            "purpose": "reduce live-boot hardware/storage probing for the Wuci-OS workstation path",
        },
        "argv": argv,
        "overlay_root": str(overlay_root),
        "source_kit_path": str(source_kit_path) if source_kit_path else "",
        "problems": problems,
        "exit_hint": "Ctrl-a x to quit QEMU from the nographic serial monitor",
        "non_claims": list(BOUNDARY_DENIALS),
    }
    if share_repo:
        result["share_requested"] = True
        result["share_status"] = "ready"
        result["share_mode"] = share_mode
        result["share_requested_path"] = str(share_repo)
        result["share_tag"] = share_tag
        if share_note:
            result["share_note"] = share_note
        result["share_path"] = str(share_path)
        if share_mode == "9p":
            result["guest_mount_hint"] = (
                f"mkdir -p /mnt/wuci && mount -t 9p -o trans=virtio,version=9p2000.L "
                f"{share_tag} /mnt/wuci"
            )
            result["guest_activate_hint"] = "sh /mnt/wuci/tools/wuci-os-live-activate"
            result["guest_source_extract_hint"] = (
                "for dev in /dev/vd? /dev/sd?; do "
                "tar -tf \"$dev\" >/dev/null 2>&1 && tar -xf \"$dev\" -C /; "
                "done"
            )
        else:
            result["guest_extract_hint"] = (
                "for dev in /dev/vd? /dev/sd?; do "
                "tar -tf \"$dev\" >/dev/null 2>&1 && tar -xf \"$dev\" -C /; "
                "done"
            )
            result["guest_activate_hint"] = "wuci-live-banner && wuci-users-apply && wuci-status"
    return result


def _write_transient(path: Path, data: bytes) -> None:
    _reject_symlink_output_parents(path, "Wuci-OS transient boot artifact")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_output_parents(path, "Wuci-OS transient boot artifact")
    try:
        wuci_kaiju._write_transient_file(path, data)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc


def _regular_artifact_evidence(path: Path, label: str) -> dict[str, Any]:
    try:
        digest, size = wuci_kaiju.file_digest_vector(path, label)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    return {
        "path": str(path),
        "bytes": size,
        "digest_vector": digest,
    }


def _direct_boot_artifact_path(boot_root: Path, path: Path, label: str) -> Path:
    root_resolved = boot_root.resolve(strict=False)
    path_resolved = path.resolve(strict=False)
    try:
        relative = path_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise WuciOSError(f"{label} must stay under boot_root") from exc
    if len(relative.parts) != 1:
        raise WuciOSError(f"{label} must be a direct boot_root artifact")
    return path


def _remove_boot_artifact_file(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WuciOSError(f"could not inspect {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise WuciOSError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise WuciOSError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise WuciOSError(f"{label} must not be hardlinked: {path}")
    try:
        path.unlink()
    except OSError as exc:
        raise WuciOSError(f"could not remove {label}: {path}") from exc


def build_live_boot_argv(plan: dict[str, Any]) -> list[str]:
    if not isinstance(plan, dict) or plan.get("schema") != BOOT_SCHEMA:
        raise WuciOSError("invalid Wuci-OS boot plan")
    if plan.get("status") != "ready":
        raise WuciOSError("Wuci-OS boot plan is blocked")
    plan.pop("generated_artifacts", None)
    image_path = Path(str(plan["source"]["image_path"]))
    boot_root = Path(str(plan["boot_root"]))
    created_paths: list[Path] = []

    def cleanup_created_paths(exc: BaseException) -> None:
        cleanup_errors: list[str] = []
        for path in reversed(created_paths):
            try:
                _remove_boot_artifact_file(path, "Wuci-OS boot cleanup artifact")
            except WuciOSError as cleanup_exc:
                cleanup_errors.append(str(cleanup_exc))
        try:
            boot_root.rmdir()
        except OSError:
            pass
        if cleanup_errors:
            raise WuciOSError(
                f"Wuci-OS boot payload build failed and cleanup failed: {exc}; {'; '.join(cleanup_errors)}"
            ) from exc

    overlay_root: Path | None = None
    try:
        if plan.get("share_mode") == "tar-drive":
            overlay_root = Path(str(plan.get("overlay_root", repo_root() / DEFAULT_OVERLAY_ROOT)))
            if not overlay_manifest_path(overlay_root).is_file():
                create_overlay(overlay_root, wallpaper_source=repo_root() / DEFAULT_WALLPAPER_SOURCE, force=True)
            else:
                try:
                    manifest = wuci_kaiju.read_public_json(overlay_manifest_path(overlay_root), "Wuci-OS overlay manifest")
                except wuci_kaiju.KaijuError as exc:
                    raise WuciOSError(str(exc)) from exc
                validate_overlay_manifest_current(overlay_root, manifest, ticker_mode="auto")
        kernel_data = wuci_kaiju._extract_iso_file_content(image_path, "boot/vmlinuz")
        initrd_data = wuci_kaiju._extract_iso_file_content(image_path, "boot/initrd")
        if not kernel_data or not initrd_data:
            raise WuciOSError("could not extract live source kernel/initrd")
        kernel_path = boot_root / "vmlinuz"
        initrd_path = boot_root / "initrd"
        _write_transient(kernel_path, kernel_data)
        created_paths.append(kernel_path)
        _write_transient(initrd_path, initrd_data)
        created_paths.append(initrd_path)
        generated_artifacts: dict[str, Any] = {
            "schema": "wuci-os-live-boot-generated-artifacts-v1",
            "kernel": _regular_artifact_evidence(kernel_path, "Wuci-OS transient kernel"),
            "initrd": _regular_artifact_evidence(initrd_path, "Wuci-OS transient initrd"),
        }
        if plan.get("share_mode") == "tar-drive":
            if overlay_root is None:
                raise WuciOSError("overlay root was not prepared for tar-drive share mode")
            overlay_tar_path = boot_root / "wuci-os-overlay.tar"
            overlay_validation = write_deterministic_overlay_tar(overlay_root, overlay_tar_path, ticker_mode="auto")
            created_paths.append(overlay_tar_path)
            generated_artifacts["overlay_tar"] = _regular_artifact_evidence(
                overlay_tar_path,
                "Wuci-OS transient overlay tar",
            ) | {"validation": overlay_validation}
        source_kit_path = str(plan.get("source_kit_path", ""))
        if source_kit_path:
            source_kit_target = _direct_boot_artifact_path(
                boot_root,
                Path(source_kit_path),
                "Wuci-OS source-kit boot payload",
            )
            source_kit_result = write_deterministic_source_kit_tar(source_kit_target, ticker_mode="auto")
            created_paths.append(source_kit_target)
            generated_artifacts["source_kit_tar"] = {
                "path": source_kit_result["tar_path"],
                "bytes": source_kit_result["tar_bytes"],
                "digest_vector": source_kit_result["tar_digest_vector"],
                "validation": source_kit_result["source_kit_validation"],
            }
        plan["generated_artifacts"] = generated_artifacts
    except Exception as exc:
        plan.pop("generated_artifacts", None)
        cleanup_created_paths(exc)
        raise
    argv = list(plan["argv"])
    return argv


def cleanup_boot_artifacts(boot_root: Path | str) -> None:
    root = Path(boot_root)
    try:
        root_info = os.lstat(root)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WuciOSError(f"could not inspect Wuci-OS boot cleanup root: {root}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise WuciOSError(f"Wuci-OS boot cleanup root must not be a symlink: {root}")
    if not stat.S_ISDIR(root_info.st_mode):
        raise WuciOSError(f"Wuci-OS boot cleanup root must be a directory: {root}")
    for name in ("vmlinuz", "initrd", "wuci-os-overlay.tar", SOURCE_KIT_TAR_NAME):
        _remove_boot_artifact_file(root / name, "Wuci-OS boot cleanup artifact")
    try:
        root.rmdir()
    except OSError:
        pass


def _iso_remove_if_present(iso: Any, iso_path: str) -> None:
    try:
        iso.get_record(iso_path=iso_path)
    except Exception:
        return
    iso.rm_file(iso_path=iso_path)


def _iso_path_exists(iso: Any, iso_path: str) -> bool:
    try:
        iso.get_record(iso_path=iso_path)
        return True
    except Exception:
        return False


def _iso_first_existing_path(iso: Any, candidates: tuple[str, ...], label: str) -> str:
    for candidate in candidates:
        if _iso_path_exists(iso, candidate):
            return candidate
    raise WuciOSError(f"could not find ISO path for {label}: {', '.join(candidates)}")


def _iso_child_path_for_parent(iso: Any, candidates: tuple[tuple[str, str], ...]) -> str:
    for parent, child in candidates:
        if _iso_path_exists(iso, parent):
            return child
    return candidates[0][1]


def _iso_get_record_any(iso: Any, candidates: tuple[str, ...], label: str) -> None:
    _iso_first_existing_path(iso, candidates, label)


ISO9660_FILE_ALIASES = {
    "isolinux.cfg": "ISOLINUX.CFG;1",
    "wuci-splash.png": "WUCISPL.PNG;1",
    "boot-splash.svg": "SPLASH.SVG;1",
    "grub.cfg": "GRUB.CFG;1",
    "grub_void.cfg": "GRUBVOID.CFG;1",
    "loopback.cfg": "LOOPBACK.CFG;1",
    "squashfs.img": "SQUASHFS.IMG;1",
    "vmlinuz": "VMLINUX.;1",
    "initrd": "INITRD.;1",
}


def _iso_add_path_for_rr_name(iso_path: str, rr_name: str) -> str:
    parent, _, name = iso_path.rpartition("/")
    if not parent:
        return iso_path
    if re.fullmatch(r"[A-Z0-9_]+(?:\.[A-Z0-9_]+)?(?:;[0-9]+)?", name):
        return iso_path
    alias = ISO9660_FILE_ALIASES.get(rr_name)
    if alias is None:
        base, dot, ext = rr_name.partition(".")
        safe_base = re.sub(r"[^A-Z0-9_]", "", base.upper())[:8] or "FILE"
        safe_ext = re.sub(r"[^A-Z0-9_]", "", ext.upper())[:3]
        alias = f"{safe_base}.{safe_ext};1" if dot and safe_ext else f"{safe_base};1"
    return f"{parent}/{alias}"


def _iso_replace_bytes(
    iso: Any,
    data: bytes,
    *,
    iso_path: str,
    rr_name: str,
    joliet_path: str,
    mode: int = 0o644,
) -> dict[str, Any]:
    _iso_remove_if_present(iso, iso_path)
    return _iso_add_bytes(
        iso,
        data,
        iso_path=_iso_add_path_for_rr_name(iso_path, rr_name),
        rr_name=rr_name,
        joliet_path=joliet_path,
        mode=mode,
    )


def _iso_replace_local_file(
    iso: Any,
    source: Path,
    *,
    iso_path: str,
    rr_name: str,
    joliet_path: str,
    label: str,
) -> dict[str, Any]:
    _iso_remove_if_present(iso, iso_path)
    return _iso_add_local_file(
        iso,
        source,
        iso_path=_iso_add_path_for_rr_name(iso_path, rr_name),
        rr_name=rr_name,
        joliet_path=joliet_path,
        label=label,
    )


GRUB_CONFIG_ISO_PATHS: dict[str, tuple[str, str, str]] = {
    "boot/grub/grub.cfg": ("/boot/grub/grub.cfg", "grub.cfg", "/boot/grub/grub.cfg"),
    "boot/grub/grub_void.cfg": ("/boot/grub/grub_void.cfg", "grub_void.cfg", "/boot/grub/grub_void.cfg"),
    "boot/grub/loopback.cfg": ("/boot/grub/loopback.cfg", "loopback.cfg", "/boot/grub/loopback.cfg"),
    "EFI/BOOT/grub.cfg": ("/EFI/BOOT/grub.cfg", "grub.cfg", "/EFI/BOOT/grub.cfg"),
}


def _require_host_tool(tools: dict[str, dict[str, Any]], name: str) -> str:
    item = tools.get(name, {})
    path = str(item.get("path", ""))
    if item.get("status") != "available" or not path:
        raise WuciOSError(f"Wuci-OS remaster requires host tool: {name}")
    return path


def _safe_rootfs_relative_path(relative: str | Path) -> Path:
    rel = Path(relative)
    text = rel.as_posix()
    if rel.is_absolute() or ".." in rel.parts or text in {"", "."} or text.startswith("/"):
        raise WuciOSError(f"unsafe rootfs path: {text}")
    return rel


def _write_rootfs_file(rootfs: Path, relative: str | Path, data: bytes, *, mode: int) -> dict[str, Any]:
    rel = _safe_rootfs_relative_path(relative)
    path = rootfs / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        info = None
    if info is not None:
        if stat.S_ISDIR(info.st_mode):
            raise WuciOSError(f"rootfs target is a directory: {rel.as_posix()}")
        if not stat.S_ISLNK(info.st_mode) and not stat.S_ISREG(info.st_mode):
            raise WuciOSError(f"rootfs target has unsupported type: {rel.as_posix()}")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise WuciOSError(f"rootfs target must not be hardlinked: {rel.as_posix()}")
        path.unlink()
    digest, size = _write_verified_new_file(
        path,
        data,
        f"Wuci-OS remaster rootfs file {rel.as_posix()}",
        mode=mode,
    )
    return {
        "path": rel.as_posix(),
        "bytes": size,
        "mode": oct(mode),
        "digest_vector": digest,
    }


def _patch_rootfs_text_file(rootfs: Path, relative: str | Path, replacements: dict[str, str]) -> dict[str, Any] | None:
    rel = _safe_rootfs_relative_path(relative)
    path = rootfs / rel
    if not path.exists() or path.is_symlink():
        return None
    info = _verified_regular_file_info(path, f"Wuci-OS remaster text file {rel.as_posix()}")
    data = _read_regular_bytes(path, f"Wuci-OS remaster text file {rel.as_posix()}").decode("utf-8", "replace")
    patched = data
    for old, new in replacements.items():
        patched = patched.replace(old, new)
    if patched == data:
        return {
            "path": rel.as_posix(),
            "changed": False,
            "bytes": info.st_size,
        }
    return _write_rootfs_file(
        rootfs,
        rel,
        patched.encode("utf-8"),
        mode=stat.S_IMODE(info.st_mode),
    ) | {"changed": True}


def _rootfs_text(rootfs: Path, relative: str | Path, *, default: str = "") -> str:
    rel = _safe_rootfs_relative_path(relative)
    path = rootfs / rel
    if not path.exists():
        return default
    return _read_regular_bytes(path, f"Wuci-OS rootfs text {rel.as_posix()}").decode("utf-8", "replace")


def _write_rootfs_text(rootfs: Path, relative: str | Path, text: str, *, mode: int = 0o644) -> dict[str, Any]:
    return _write_rootfs_file(rootfs, relative, text.encode("utf-8"), mode=mode)


def _debugfs_remote_path(relative: str | Path) -> str:
    rel = _safe_rootfs_relative_path(relative)
    return "/" + rel.as_posix()


def _debugfs_inode_mode_text(file_type: int, mode: int) -> str:
    return f"{file_type | (mode & 0o7777):07o}"


def _debugfs_run(image: Path, commands: list[str], label: str, *, cwd: Path) -> subprocess.CompletedProcess[str]:
    command_file = cwd / f".debugfs-{hashlib.sha256(label.encode('utf-8')).hexdigest()[:16]}.cmd"
    _prepare_exclusive_output_path(command_file, f"{label} debugfs command file", force=True)
    _write_verified_new_file(command_file, ("\n".join(commands) + "\n").encode("utf-8"), f"{label} debugfs command file", mode=0o600)
    try:
        result = subprocess.run(
            ["debugfs", "-w", "-f", str(command_file), str(image)],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
    finally:
        try:
            command_file.unlink()
        except FileNotFoundError:
            pass
    if result.returncode != 0:
        raise WuciOSError(f"{label} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result


def _debugfs_mkdir_commands(relative: str | Path) -> list[str]:
    rel = _safe_rootfs_relative_path(relative)
    commands: list[str] = []
    parts: list[str] = []
    for part in rel.parts:
        parts.append(part)
        remote = "/" + "/".join(parts)
        commands.append(f"mkdir {remote}")
        commands.append(f"set_inode_field {remote} mode 040755")
    return commands


def _debugfs_write_file_commands(local: Path, relative: str | Path, mode: int) -> list[str]:
    remote = _debugfs_remote_path(relative)
    return [
        f"rm {remote}",
        f"write {local} {remote}",
        f"set_inode_field {remote} mode {_debugfs_inode_mode_text(0o100000, mode)}",
        "dirty",
    ]


def _debugfs_write_text_file(
    image: Path,
    relative: str | Path,
    text: str,
    *,
    mode: int,
    work_root: Path,
    label: str,
) -> dict[str, Any]:
    rel = _safe_rootfs_relative_path(relative)
    local = work_root / "debugfs-files" / rel
    _prepare_exclusive_output_path(local, f"{label} local staging file", force=True)
    digest, size = _write_verified_new_file(local, text.encode("utf-8"), f"{label} local staging file", mode=0o644)
    commands = _debugfs_mkdir_commands(rel.parent) if rel.parent.as_posix() != "." else []
    commands.extend(_debugfs_write_file_commands(local, rel, mode))
    _debugfs_run(image, commands, label, cwd=work_root)
    return {
        "path": rel.as_posix(),
        "bytes": size,
        "mode": oct(mode),
        "digest_vector": digest,
    }


def _debugfs_write_bytes_file(
    image: Path,
    relative: str | Path,
    data: bytes,
    *,
    mode: int,
    work_root: Path,
    label: str,
) -> dict[str, Any]:
    rel = _safe_rootfs_relative_path(relative)
    local = work_root / "debugfs-files" / rel
    _prepare_exclusive_output_path(local, f"{label} local staging file", force=True)
    digest, size = _write_verified_new_file(local, data, f"{label} local staging file", mode=0o644)
    commands = _debugfs_mkdir_commands(rel.parent) if rel.parent.as_posix() != "." else []
    commands.extend(_debugfs_write_file_commands(local, rel, mode))
    _debugfs_run(image, commands, label, cwd=work_root)
    return {
        "path": rel.as_posix(),
        "bytes": size,
        "mode": oct(mode),
        "digest_vector": digest,
    }


def _debugfs_dump_file(image: Path, relative: str | Path, dest: Path, *, work_root: Path, label: str) -> bool:
    rel = _safe_rootfs_relative_path(relative)
    _prepare_exclusive_output_path(dest, f"{label} dump", force=True)
    result = _debugfs_run(image, [f"dump {_debugfs_remote_path(rel)} {dest}"], label, cwd=work_root)
    if dest.is_file():
        return True
    stderr = (result.stderr or "") + (result.stdout or "")
    if "File not found" in stderr or "not found" in stderr:
        return False
    return False


def _debugfs_read_text_file(image: Path, relative: str | Path, *, work_root: Path, default: str = "") -> str:
    rel = _safe_rootfs_relative_path(relative)
    dest = work_root / "debugfs-dumps" / rel
    if not _debugfs_dump_file(image, rel, dest, work_root=work_root, label=f"Wuci-OS ext image dump {rel.as_posix()}"):
        return default
    return _read_regular_bytes(dest, f"Wuci-OS ext image text {rel.as_posix()}").decode("utf-8", "replace")


def _patch_ext_image_text_file(
    image: Path,
    relative: str | Path,
    replacements: dict[str, str],
    *,
    work_root: Path,
) -> dict[str, Any] | None:
    rel = _safe_rootfs_relative_path(relative)
    original = _debugfs_read_text_file(image, rel, work_root=work_root, default="")
    if not original:
        return None
    patched = original
    for old, new in replacements.items():
        patched = patched.replace(old, new)
    if patched == original:
        return {
            "path": rel.as_posix(),
            "changed": False,
            "bytes": len(original.encode("utf-8")),
        }
    return _debugfs_write_text_file(
        image,
        rel,
        patched,
        mode=0o644,
        work_root=work_root,
        label=f"Wuci-OS ext image patched text {rel.as_posix()}",
    ) | {"changed": True}


def _debugfs_path_exists(image: Path, relative: str | Path, *, work_root: Path) -> bool:
    rel = _safe_rootfs_relative_path(relative)
    result = _debugfs_run(image, [f"stat {_debugfs_remote_path(rel)}"], f"Wuci-OS ext image stat {rel.as_posix()}", cwd=work_root)
    combined = (result.stdout or "") + (result.stderr or "")
    return "Inode:" in combined and "File not found" not in combined


def _debugfs_path_stat(image: Path, relative: str | Path, *, work_root: Path) -> dict[str, Any]:
    rel = _safe_rootfs_relative_path(relative)
    result = _debugfs_run(image, [f"stat {_debugfs_remote_path(rel)}"], f"Wuci-OS ext image stat {rel.as_posix()}", cwd=work_root)
    combined = (result.stdout or "") + (result.stderr or "")
    exists = "Inode:" in combined and "File not found" not in combined
    mode_match = re.search(r"\bMode:\s+([0-7]+)\b", combined)
    type_match = re.search(r"\bType:\s+([A-Za-z0-9_-]+)\b", combined)
    mode_value = int(mode_match.group(1), 8) if mode_match else None
    return {
        "path": rel.as_posix(),
        "exists": exists,
        "type": type_match.group(1) if type_match else None,
        "mode": f"0{mode_value:o}" if mode_value is not None else None,
        "executable": bool(exists and mode_value is not None and (mode_value & 0o111)),
    }


def _next_rootfs_id(lines: list[str], field_index: int, *, start: int) -> int:
    used: set[int] = set()
    for line in lines:
        parts = line.split(":")
        if len(parts) > field_index:
            try:
                used.add(int(parts[field_index]))
            except ValueError:
                pass
    candidate = start
    while candidate in used:
        candidate += 1
    return candidate


def _ensure_group_line(lines: list[str], name: str, gid: int, members: list[str]) -> list[str]:
    updated: list[str] = []
    found = False
    for line in lines:
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] == name:
            existing = [member for member in parts[3].split(",") if member]
            for member in members:
                if member not in existing:
                    existing.append(member)
            parts[3] = ",".join(existing)
            updated.append(":".join(parts))
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(f"{name}:x:{gid}:{','.join(members)}")
    return updated


def _ensure_shadow_line(lines: list[str], name: str, *, secret: str = "!", last_change: str = "20121") -> list[str]:
    normalized = f"{name}:{secret}:{last_change}:0:99999:7:::"
    updated: list[str] = []
    found = False
    for line in lines:
        if line.split(":", 1)[0] == name:
            updated.append(normalized)
            found = True
        else:
            updated.append(line)
    if not found:
        updated.append(normalized)
    return updated


def restore_rootfs_auth_setuid(rootfs: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing_required: list[str] = []
    for rel in (*AUTH_SETUID_REQUIRED_PATHS, *AUTH_SETUID_OPTIONAL_PATHS):
        path = rootfs / rel
        required = rel in AUTH_SETUID_REQUIRED_PATHS
        if not path.exists():
            records.append({"path": rel, "status": "missing", "required": required})
            if required:
                missing_required.append(rel)
            continue
        try:
            owner_repair = "not-root"
            if os.geteuid() == 0:
                os.chown(path, 0, 0)
                owner_repair = "root:root"
            os.chmod(path, 0o4755)
            info = os.stat(path)
        except OSError as exc:
            records.append({"path": rel, "status": "fail", "required": required, "problem": str(exc)})
            if required:
                missing_required.append(rel)
            continue
        records.append(
            {
                "path": rel,
                "status": "pass",
                "required": required,
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "uid": info.st_uid,
                "gid": info.st_gid,
                "owner_repair": owner_repair,
            }
        )
    if missing_required:
        raise WuciOSError("Wuci-OS rootfs missing required auth setuid tools: " + ", ".join(missing_required))
    return {
        "schema": "wuci-os-rootfs-auth-setuid-repair-v1",
        "status": "pass",
        "records": records,
    }


def restore_ext_image_auth_setuid(ext_image: Path, work_root: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing_required: list[str] = []
    commands: list[str] = []
    for rel in (*AUTH_SETUID_REQUIRED_PATHS, *AUTH_SETUID_OPTIONAL_PATHS):
        required = rel in AUTH_SETUID_REQUIRED_PATHS
        if not _debugfs_path_exists(ext_image, rel, work_root=work_root):
            records.append({"path": rel, "status": "missing", "required": required})
            if required:
                missing_required.append(rel)
            continue
        remote = _debugfs_safe_path(rel)
        commands.extend(
            [
                f"set_inode_field {remote} uid 0",
                f"set_inode_field {remote} gid 0",
                f"set_inode_field {remote} mode 0104755",
            ]
        )
        records.append({"path": rel, "status": "pass", "required": required, "mode": "0o4755", "uid": 0, "gid": 0})
    if missing_required:
        raise WuciOSError("Wuci-OS ext image missing required auth setuid tools: " + ", ".join(missing_required))
    if commands:
        _debugfs_run(ext_image, commands, "Wuci-OS ext image auth setuid repair", cwd=work_root)
    return {
        "schema": "wuci-os-ext-image-auth-setuid-repair-v1",
        "status": "pass",
        "records": records,
    }


def apply_rootfs_account_profile(rootfs: Path) -> dict[str, Any]:
    passwd_lines = [line for line in _rootfs_text(rootfs, "etc/passwd").splitlines() if line]
    group_lines = [line for line in _rootfs_text(rootfs, "etc/group").splitlines() if line]
    shadow_lines = [line for line in _rootfs_text(rootfs, "etc/shadow").splitlines() if line]
    gid_wj = _next_rootfs_id(group_lines, 2, start=1000)
    gid_low = gid_wj + 1 if gid_wj + 1 not in {int(line.split(":")[2]) for line in group_lines if len(line.split(":")) > 2 and line.split(":")[2].isdigit()} else _next_rootfs_id(group_lines, 2, start=gid_wj + 1)
    uid_wj = _next_rootfs_id(passwd_lines, 2, start=1000)
    uid_low = uid_wj + 1 if uid_wj + 1 not in {int(line.split(":")[2]) for line in passwd_lines if len(line.split(":")) > 2 and line.split(":")[2].isdigit()} else _next_rootfs_id(passwd_lines, 2, start=uid_wj + 1)
    shell_path = "/bin/bash" if (rootfs / "bin/bash").exists() else "/bin/sh"
    if not any(line.split(":", 1)[0] == "wj" for line in passwd_lines):
        passwd_lines.append(f"wj:x:{uid_wj}:{gid_wj}:Wuci-OS Operator:/home/wj:{shell_path}")
    if not any(line.split(":", 1)[0] == "wj_low" for line in passwd_lines):
        passwd_lines.append(f"wj_low:x:{uid_low}:{gid_low}:Wuci-OS Low Privilege:/home/wj_low:{shell_path}")
    if (rootfs / "usr/bin/dbus-daemon").is_file() and not any(line.split(":", 1)[0] == "dbus" for line in passwd_lines):
        passwd_lines.append("dbus:x:22:22:System Message Bus:/var/run/dbus:/sbin/nologin")
    group_lines = _ensure_group_line(group_lines, "wj", gid_wj, ["wj"])
    group_lines = _ensure_group_line(group_lines, "wj_low", gid_low, ["wj_low"])
    if (rootfs / "usr/bin/dbus-daemon").is_file():
        group_lines = _ensure_group_line(group_lines, "dbus", 22, [])
    for group in ("wheel", "audio", "video", "input", "kvm", "network", "storage", "plugdev", "usb", "dialout", "uucp"):
        group_lines = _ensure_group_line(group_lines, group, _next_rootfs_id(group_lines, 2, start=100), ["wj"])
    for group in ("audio", "video", "plugdev", "usb", "dialout", "uucp"):
        group_lines = _ensure_group_line(group_lines, group, _next_rootfs_id(group_lines, 2, start=100), ["wj_low"])
    shadow_lines = _ensure_shadow_line(shadow_lines, "wj", secret="")
    shadow_lines = _ensure_shadow_line(shadow_lines, "wj_low", secret="")
    if (rootfs / "usr/bin/dbus-daemon").is_file():
        shadow_lines = _ensure_shadow_line(shadow_lines, "dbus", secret="!")
    written = [
        _write_rootfs_text(rootfs, "etc/passwd", "\n".join(passwd_lines) + "\n", mode=0o644),
        _write_rootfs_text(rootfs, "etc/group", "\n".join(group_lines) + "\n", mode=0o644),
        _write_rootfs_text(rootfs, "etc/shadow", "\n".join(shadow_lines) + "\n", mode=0o600),
        _write_rootfs_text(rootfs, "etc/sudoers.d/90-wuci-os-wj", "wj ALL=(ALL:ALL) NOPASSWD: ALL\n", mode=0o440),
        _write_rootfs_text(rootfs, "etc/doas.d/90-wuci-os-wj.conf", "permit nopass wj as root\n", mode=0o440),
    ]
    written.append(
        _write_rootfs_text(
            rootfs,
            "etc/sv/agetty-tty1/conf",
            'GETTY_ARGS="--autologin wj --noclear"\nBAUD_RATE=38400\nTERM_NAME=linux\n',
            mode=0o644,
        )
    )
    written.append(
        _write_rootfs_text(
            rootfs,
            "etc/sv/agetty-ttyS0/conf",
            'GETTY_ARGS="--autologin wj --noclear -L -8"\nBAUD_RATE=115200\nTERM_NAME=vt100\n',
            mode=0o644,
        )
    )
    homes: list[dict[str, Any]] = []
    for user in ("wj", "wj_low"):
        home = rootfs / "home" / user
        (home / ".config/kitty").mkdir(parents=True, exist_ok=True)
        homes.append(_write_rootfs_text(rootfs, Path("home") / user / ".xinitrc", "exec startxfce4\n", mode=0o644))
        kitty = rootfs / "usr/share/wuci-os/kitty.conf"
        ratpoison = rootfs / "usr/share/wuci-os/ratpoisonrc"
        if kitty.is_file():
            homes.append(
                _write_rootfs_file(
                    rootfs,
                    Path("home") / user / ".config/kitty/kitty.conf",
                    _read_regular_bytes(kitty, "Wuci-OS rootfs kitty profile"),
                    mode=0o644,
                )
            )
        if ratpoison.is_file():
            homes.append(
                _write_rootfs_file(
                    rootfs,
                    Path("home") / user / ".ratpoisonrc",
                    _read_regular_bytes(ratpoison, "Wuci-OS rootfs ratpoison profile"),
                    mode=0o644,
                )
            )
        if os.geteuid() == 0:
            target_uid = uid_wj if user == "wj" else uid_low
            target_gid = gid_wj if user == "wj" else gid_low
            for path in [home, *home.rglob("*")]:
                try:
                    os.chown(path, target_uid, target_gid)
                except OSError:
                    pass
    auth_setuid = restore_rootfs_auth_setuid(rootfs)
    return {
        "schema": "wuci-os-rootfs-account-profile-v1",
        "status": "pass",
        "users": ["wj", "wj_low"],
        "operator_prompt": "WJ>_",
        "live_password": "empty password for live/demo only",
        "written": written,
        "home_files": homes,
        "auth_setuid": auth_setuid,
    }


def apply_ext_image_account_profile(ext_image: Path, overlay_root: Path, work_root: Path) -> dict[str, Any]:
    passwd_lines = [line for line in _debugfs_read_text_file(ext_image, "etc/passwd", work_root=work_root).splitlines() if line]
    group_lines = [line for line in _debugfs_read_text_file(ext_image, "etc/group", work_root=work_root).splitlines() if line]
    shadow_lines = [line for line in _debugfs_read_text_file(ext_image, "etc/shadow", work_root=work_root).splitlines() if line]
    gid_wj = _next_rootfs_id(group_lines, 2, start=1000)
    used_gids = {int(line.split(":")[2]) for line in group_lines if len(line.split(":")) > 2 and line.split(":")[2].isdigit()}
    gid_low = gid_wj + 1 if gid_wj + 1 not in used_gids else _next_rootfs_id(group_lines, 2, start=gid_wj + 1)
    uid_wj = _next_rootfs_id(passwd_lines, 2, start=1000)
    used_uids = {int(line.split(":")[2]) for line in passwd_lines if len(line.split(":")) > 2 and line.split(":")[2].isdigit()}
    uid_low = uid_wj + 1 if uid_wj + 1 not in used_uids else _next_rootfs_id(passwd_lines, 2, start=uid_wj + 1)
    shell_path = "/bin/bash" if _debugfs_path_exists(ext_image, "bin/bash", work_root=work_root) else "/bin/sh"
    if not any(line.split(":", 1)[0] == "wj" for line in passwd_lines):
        passwd_lines.append(f"wj:x:{uid_wj}:{gid_wj}:Wuci-OS Operator:/home/wj:{shell_path}")
    if not any(line.split(":", 1)[0] == "wj_low" for line in passwd_lines):
        passwd_lines.append(f"wj_low:x:{uid_low}:{gid_low}:Wuci-OS Low Privilege:/home/wj_low:{shell_path}")
    group_lines = _ensure_group_line(group_lines, "wj", gid_wj, ["wj"])
    group_lines = _ensure_group_line(group_lines, "wj_low", gid_low, ["wj_low"])
    for group in ("wheel", "audio", "video", "input", "kvm", "network", "storage", "plugdev", "usb", "dialout", "uucp"):
        group_lines = _ensure_group_line(group_lines, group, _next_rootfs_id(group_lines, 2, start=100), ["wj"])
    for group in ("audio", "video", "plugdev", "usb", "dialout", "uucp"):
        group_lines = _ensure_group_line(group_lines, group, _next_rootfs_id(group_lines, 2, start=100), ["wj_low"])
    shadow_lines = _ensure_shadow_line(shadow_lines, "wj", secret="")
    shadow_lines = _ensure_shadow_line(shadow_lines, "wj_low", secret="")
    written = [
        _debugfs_write_text_file(
            ext_image,
            "etc/passwd",
            "\n".join(passwd_lines) + "\n",
            mode=0o644,
            work_root=work_root,
            label="Wuci-OS ext image passwd",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/group",
            "\n".join(group_lines) + "\n",
            mode=0o644,
            work_root=work_root,
            label="Wuci-OS ext image group",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/shadow",
            "\n".join(shadow_lines) + "\n",
            mode=0o600,
            work_root=work_root,
            label="Wuci-OS ext image shadow",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/sudoers.d/90-wuci-os-wj",
            "wj ALL=(ALL:ALL) NOPASSWD: ALL\n",
            mode=0o440,
            work_root=work_root,
            label="Wuci-OS ext image sudoers",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/doas.d/90-wuci-os-wj.conf",
            "permit nopass wj as root\n",
            mode=0o440,
            work_root=work_root,
            label="Wuci-OS ext image doas",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/sv/agetty-tty1/conf",
            'GETTY_ARGS="--autologin wj --noclear"\nBAUD_RATE=38400\nTERM_NAME=linux\n',
            mode=0o644,
            work_root=work_root,
            label="Wuci-OS ext image tty1 autologin",
        ),
        _debugfs_write_text_file(
            ext_image,
            "etc/sv/agetty-ttyS0/conf",
            'GETTY_ARGS="--autologin wj --noclear -L -8"\nBAUD_RATE=115200\nTERM_NAME=vt100\n',
            mode=0o644,
            work_root=work_root,
            label="Wuci-OS ext image ttyS0 autologin",
        ),
    ]
    homes: list[dict[str, Any]] = []
    skeletons = {
        ".xinitrc": overlay_root / "etc/skel/.xinitrc",
        ".ratpoisonrc": overlay_root / "usr/share/wuci-os/ratpoisonrc",
        ".config/kitty/kitty.conf": overlay_root / "usr/share/wuci-os/kitty.conf",
    }
    for user, uid, gid in (("wj", uid_wj, gid_wj), ("wj_low", uid_low, gid_low)):
        dir_commands: list[str] = []
        for rel in (Path("home") / user, Path("home") / user / ".config", Path("home") / user / ".config/kitty"):
            remote = _debugfs_remote_path(rel)
            dir_commands.extend(_debugfs_mkdir_commands(rel))
            dir_commands.extend(
                [
                    f"set_inode_field {remote} uid {uid}",
                    f"set_inode_field {remote} gid {gid}",
                    f"set_inode_field {remote} mode 040755",
                ]
            )
        _debugfs_run(ext_image, dir_commands, f"Wuci-OS ext image home directories {user}", cwd=work_root)
        for dest_name, source in skeletons.items():
            if source.is_file():
                data = _read_regular_bytes(source, f"Wuci-OS ext image skeleton {dest_name}")
            elif dest_name == ".xinitrc":
                data = b"exec startxfce4\n"
            else:
                continue
            rel = Path("home") / user / dest_name
            record = _debugfs_write_bytes_file(
                ext_image,
                rel,
                data,
                mode=0o644,
                work_root=work_root,
                label=f"Wuci-OS ext image home file {user}/{dest_name}",
            )
            remote = _debugfs_remote_path(rel)
            _debugfs_run(
                ext_image,
                [
                    f"set_inode_field {remote} uid {uid}",
                    f"set_inode_field {remote} gid {gid}",
                ],
                f"Wuci-OS ext image chown {user}/{dest_name}",
                cwd=work_root,
            )
            homes.append(record)
    auth_setuid = restore_ext_image_auth_setuid(ext_image, work_root)
    return {
        "schema": "wuci-os-ext-image-account-profile-v1",
        "status": "pass",
        "users": ["wj", "wj_low"],
        "operator_prompt": "WJ>_",
        "live_password": "empty password for live/demo only",
        "written": written,
        "home_files": homes,
        "auth_setuid": auth_setuid,
    }


def enable_rootfs_runit_services(rootfs: Path, services: Sequence[str]) -> dict[str, Any]:
    default_dir = rootfs / "etc/runit/runsvdir/default"
    default_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, str]] = []
    for service in services:
        if "/" in service or service in {"", ".", ".."}:
            raise WuciOSError(f"invalid runit service name: {service!r}")
        service_dir = rootfs / "etc/sv" / service
        target = default_dir / service
        if not service_dir.is_dir():
            records.append({"service": service, "status": "missing-service-dir"})
            continue
        if target.is_symlink() or target.exists():
            records.append({"service": service, "status": "already-enabled", "target": str(target)})
            continue
        target.symlink_to(Path("../../../sv") / service)
        records.append({"service": service, "status": "enabled", "target": str(target)})
    return {
        "schema": "wuci-os-rootfs-runit-service-enable-v1",
        "status": "pass",
        "services": records,
    }


def apply_wuci_overlay_to_rootfs(overlay_root: Path, rootfs: Path) -> dict[str, Any]:
    manifest_path = overlay_manifest_path(overlay_root)
    if manifest_path.is_file():
        try:
            manifest = wuci_kaiju.read_public_json(manifest_path, "Wuci-OS overlay manifest")
        except wuci_kaiju.KaijuError as exc:
            raise WuciOSError(str(exc)) from exc
        records = validate_overlay_manifest_current(overlay_root, manifest, ticker_mode="never")
    else:
        records = overlay_file_records(overlay_root, ticker_mode="never")
    written: list[dict[str, Any]] = []
    directories = 0
    for record in records:
        rel = _safe_rootfs_relative_path(str(record["path"]))
        dest = rootfs / rel
        if record["type"] in {"dir", "directory"}:
            dest.mkdir(parents=True, exist_ok=True)
            directories += 1
            continue
        if record["type"] != "file":
            raise WuciOSError(f"unsupported overlay record type: {record['type']}")
        source = overlay_root / rel
        data = _read_regular_bytes(source, f"Wuci-OS overlay remaster file {rel.as_posix()}")
        mode_text = str(record.get("mode", "0o644"))
        mode = int(mode_text, 8)
        written.append(_write_rootfs_file(rootfs, rel, data, mode=mode))
    patches = [
        result
        for result in (
            _patch_rootfs_text_file(
                rootfs,
                "etc/runit/1",
                {
                    "Welcome to Void!": "Welcome to Wuci-OS!",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "voidlinux": "press Enter",
                },
            ),
            _patch_rootfs_text_file(
                rootfs,
                "etc/issue",
                {
                    "Welcome to the Void Linux Live system": "Welcome to the Wuci-OS live system",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "anon:voidlinux": "wj_low:press Enter",
                    "root:voidlinux": "wj:press Enter",
                    "voidlinux": "press Enter",
                },
            ),
            _patch_rootfs_text_file(
                rootfs,
                "etc/motd",
                {
                    "Welcome to the Void Linux Live system": "Welcome to the Wuci-OS live system",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "anon:voidlinux": "wj_low:press Enter",
                    "root:voidlinux": "wj:press Enter",
                    "voidlinux": "press Enter",
                },
            ),
        )
        if result is not None
    ]
    hostname_service = _write_rootfs_file(
        rootfs,
        "etc/runit/core-services/04-wuci-hostname.sh",
        (
            "#!/bin/sh\n"
            "# Restore Wuci hostname after the inherited live initramfs writes its default.\n"
            "printf 'wuci-os-live\\n' > /etc/hostname\n"
        ).encode("utf-8"),
        mode=0o755,
    )
    written.append(hostname_service)
    live_access_service = _write_rootfs_file(
        rootfs,
        "etc/runit/core-services/04-wuci-live-access.sh",
        (
            "#!/bin/sh\n"
            "# Restore Wuci live access after inherited live-init account hooks run.\n"
            "mkdir -p /etc/sudoers.d /etc/doas.d\n"
            "printf 'wj ALL=(ALL:ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/90-wuci-os-wj\n"
            "chmod 0440 /etc/sudoers.d/90-wuci-os-wj\n"
            "printf 'permit nopass wj as root\\n' > /etc/doas.d/90-wuci-os-wj.conf\n"
            "chmod 0440 /etc/doas.d/90-wuci-os-wj.conf\n"
            "for tool in /usr/bin/sudo /usr/bin/su /usr/bin/doas; do\n"
            "    [ -e \"$tool\" ] || continue\n"
            "    chown root:root \"$tool\" 2>/dev/null || true\n"
            "    chmod 4755 \"$tool\" 2>/dev/null || true\n"
            "done\n"
            "if command -v usermod >/dev/null 2>&1 && id wj >/dev/null 2>&1; then\n"
            "    for group in wheel audio video input kvm network storage; do\n"
            "        getent group \"$group\" >/dev/null 2>&1 && usermod -aG \"$group\" wj >/dev/null 2>&1 || true\n"
            "    done\n"
            "fi\n"
        ).encode("utf-8"),
        mode=0o755,
    )
    written.append(live_access_service)
    accounts = apply_rootfs_account_profile(rootfs)
    services = enable_rootfs_runit_services(rootfs, ("dbus", "NetworkManager", "udevd", "agetty-ttyS0"))
    return {
        "schema": "wuci-os-rootfs-overlay-application-v1",
        "status": "pass",
        "overlay_root": str(overlay_root),
        "rootfs": str(rootfs),
        "directories": directories,
        "files": written,
        "identity_patches": patches,
        "account_profile": accounts,
        "service_enablement": services,
    }


def validate_live_command_surface(rootfs: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in LIVE_COMMAND_SURFACE_REQUIRED:
        rel = Path(relative)
        path = rootfs / rel
        exists = path.exists() or path.is_symlink()
        executable = exists and os.access(path, os.X_OK)
        record = {
            "path": relative,
            "exists": exists,
            "executable": executable,
        }
        records.append(record)
        if not executable:
            missing.append(relative)
    result = {
        "schema": "wuci-os-live-command-surface-v1",
        "status": "pass" if not missing else "fail",
        "required": list(LIVE_COMMAND_SURFACE_REQUIRED),
        "records": records,
        "missing_or_not_executable": missing,
    }
    if missing:
        raise WuciOSError("Wuci-OS live command surface incomplete: " + ", ".join(missing))
    return result


def validate_ext_image_live_command_surface(ext_image: Path, *, work_root: Path) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in LIVE_COMMAND_SURFACE_REQUIRED:
        record = _debugfs_path_stat(ext_image, relative, work_root=work_root)
        records.append(record)
        if not record["executable"]:
            missing.append(relative)
    result = {
        "schema": "wuci-os-live-command-surface-v1",
        "status": "pass" if not missing else "fail",
        "required": list(LIVE_COMMAND_SURFACE_REQUIRED),
        "records": records,
        "missing_or_not_executable": missing,
        "image_layout": "nested-ext-image",
    }
    if missing:
        raise WuciOSError("Wuci-OS nested live command surface incomplete: " + ", ".join(missing))
    return result


def detect_kernel_release_from_bytes(data: bytes) -> str | None:
    text = data.decode("latin-1", "ignore")
    patterns = (
        r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?_[0-9]+)\s+\([^)]*\)\s+#\d+",
        r"Linux version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?_[0-9]+)",
        r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?-[A-Za-z0-9_.+-]+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def detect_boot_kernel_release(source_iso: Path) -> str | None:
    kernel = _extract_iso_bytes(source_iso, "boot/vmlinuz", "boot kernel")
    return detect_kernel_release_from_bytes(kernel)


def kernel_package_from_release(kernel_release: str | None) -> str | None:
    if not kernel_release:
        return None
    match = re.match(r"^([0-9]+)\.([0-9]+)\.", kernel_release)
    if not match:
        return None
    return f"linux{match.group(1)}.{match.group(2)}"


def kernel_module_releases(rootfs: Path) -> list[str]:
    releases: set[str] = set()
    for base in (rootfs / "lib/modules", rootfs / "usr/lib/modules"):
        if not base.is_dir():
            continue
        for child in base.iterdir():
            if child.is_dir():
                releases.add(child.name)
    return sorted(releases)


def kernel_module_root(rootfs: Path, kernel_release: str) -> Path | None:
    for base in (rootfs / "lib/modules", rootfs / "usr/lib/modules"):
        candidate = base / kernel_release
        if candidate.is_dir():
            return candidate
    return None


def _kernel_release_sort_key(release: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for part in re.split(r"([0-9]+)", release):
        if not part:
            continue
        parts.append(int(part) if part.isdigit() else part)
    return tuple(parts)


def _first_existing_rootfs_file(rootfs: Path, candidates: tuple[str, ...]) -> Path | None:
    for candidate in candidates:
        path = rootfs / candidate
        if path.is_file():
            return path
    return None


def rootfs_boot_artifacts_for_release(rootfs: Path, kernel_release: str) -> dict[str, Any]:
    kernel = _first_existing_rootfs_file(
        rootfs,
        (
            f"boot/vmlinuz-{kernel_release}",
            f"boot/kernel-{kernel_release}",
            "boot/vmlinuz",
        ),
    )
    initrd = _first_existing_rootfs_file(
        rootfs,
        (
            f"boot/initrd-{kernel_release}.img",
            f"boot/initramfs-{kernel_release}.img",
            f"boot/initrd.img-{kernel_release}",
            f"boot/initrd-{kernel_release}",
            f"boot/initramfs-{kernel_release}",
            "boot/initrd",
        ),
    )
    result: dict[str, Any] = {
        "schema": "wuci-os-rootfs-boot-artifacts-v1",
        "kernel_release": kernel_release,
        "kernel_path": str(kernel) if kernel else None,
        "initrd_path": str(initrd) if initrd else None,
        "status": "pass" if kernel and initrd else "fail",
        "problems": [],
    }
    if kernel is None:
        result["problems"].append(f"missing rootfs boot kernel for {kernel_release}")
    if initrd is None:
        result["problems"].append(f"missing rootfs initramfs for {kernel_release}")
    if kernel and initrd:
        _verified_regular_file_info(kernel, f"Wuci-OS rootfs boot kernel {kernel_release}")
        _verified_regular_file_info(initrd, f"Wuci-OS rootfs initramfs {kernel_release}")
        result["kernel"] = _regular_artifact_evidence(kernel, f"Wuci-OS rootfs boot kernel {kernel_release}")
        result["initrd"] = _regular_artifact_evidence(initrd, f"Wuci-OS rootfs initramfs {kernel_release}")
    return result


def select_live_boot_kernel_surface(rootfs: Path, source_kernel_release: str | None) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []
    if source_kernel_release:
        source_surface = inspect_live_kernel_hardware_surface(rootfs, source_kernel_release)
        checked.append({"kernel_release": source_kernel_release, "surface": source_surface, "boot_artifacts": None})
        if source_surface["status"] == "pass":
            return {
                "schema": "wuci-os-live-boot-kernel-selection-v1",
                "status": "source-iso-kernel",
                "source_kernel_release": source_kernel_release,
                "effective_kernel_release": source_kernel_release,
                "kernel_package": kernel_package_from_release(source_kernel_release),
                "replacement_required": False,
                "kernel_hardware_surface": source_surface,
                "boot_artifacts": {
                    "schema": "wuci-os-rootfs-boot-artifacts-v1",
                    "status": "not-needed",
                    "reason": "source ISO boot kernel already matches a passing rootfs module tree",
                },
                "checked": checked,
            }
    artifact_blockers: list[str] = []
    for release in sorted(kernel_module_releases(rootfs), key=_kernel_release_sort_key, reverse=True):
        if release == source_kernel_release:
            continue
        surface = inspect_live_kernel_hardware_surface(rootfs, release)
        artifacts = rootfs_boot_artifacts_for_release(rootfs, release)
        checked.append({"kernel_release": release, "surface": surface, "boot_artifacts": artifacts})
        if surface["status"] == "pass" and artifacts["status"] == "pass":
            return {
                "schema": "wuci-os-live-boot-kernel-selection-v1",
                "status": "rootfs-kernel-replacement",
                "source_kernel_release": source_kernel_release or "unknown",
                "effective_kernel_release": release,
                "kernel_package": kernel_package_from_release(release),
                "replacement_required": True,
                "kernel_hardware_surface": surface,
                "boot_artifacts": artifacts,
                "checked": checked,
            }
        if surface["status"] == "pass" and artifacts["status"] != "pass":
            artifact_blockers.extend(str(problem) for problem in artifacts["problems"])
    source_label = source_kernel_release or "unknown"
    problems = [f"no passing kernel hardware surface for source ISO boot kernel: {source_label}"]
    if artifact_blockers:
        problems.extend(artifact_blockers)
    raise WuciOSError("Wuci-OS boot kernel/rootfs module closure incomplete: " + "; ".join(problems))


def _rootfs_path_record(rootfs: Path, relative: str) -> dict[str, Any]:
    rel = Path(relative)
    path = rootfs / rel
    exists = path.exists() or path.is_symlink()
    executable = exists and os.access(path, os.X_OK)
    return {
        "path": relative,
        "exists": exists,
        "executable": executable,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "is_symlink": path.is_symlink(),
    }


def inspect_live_kernel_hardware_surface(rootfs: Path, kernel_release: str | None) -> dict[str, Any]:
    problems: list[str] = []
    module_records: list[dict[str, Any]] = []
    available_releases = kernel_module_releases(rootfs)
    module_root = kernel_module_root(rootfs, kernel_release) if kernel_release else None
    if not kernel_release:
        problems.append("boot kernel release could not be detected")
    elif module_root is None:
        problems.append(f"missing module tree for boot kernel: {kernel_release}")
    else:
        for name, patterns in LIVE_KERNEL_MODULE_REQUIREMENTS.items():
            pattern_records: list[dict[str, Any]] = []
            missing_patterns: list[str] = []
            for pattern in patterns:
                matches = sorted(path.relative_to(module_root).as_posix() for path in module_root.glob(pattern))
                pattern_records.append({"pattern": pattern, "matches": matches})
                if not matches:
                    missing_patterns.append(pattern)
            module_records.append(
                {
                    "requirement": name,
                    "patterns": pattern_records,
                    "status": "pass" if not missing_patterns else "fail",
                    "missing_patterns": missing_patterns,
                }
            )
            if missing_patterns:
                problems.append(f"{name} missing: " + ", ".join(missing_patterns))
        for required in ("modules.dep", "modules.alias"):
            if not (module_root / required).is_file():
                problems.append(f"missing module metadata: {kernel_release}/{required}")
    path_records = [
        _rootfs_path_record(rootfs, path)
        for path in (*MINIMUM_LIVE_NETWORK_REQUIRED_PATHS, *LIVE_USB_HOTPLUG_REQUIRED_PATHS)
    ]
    for record in path_records:
        path = str(record["path"])
        if path.endswith("/") and not record["is_dir"]:
            problems.append(f"missing required directory: {path}")
        elif path.startswith("usr/bin/") and not record["executable"]:
            problems.append(f"missing executable: {path}")
        elif not record["exists"]:
            problems.append(f"missing required path: {path}")
    return {
        "schema": "wuci-os-live-kernel-hardware-surface-v1",
        "status": "pass" if not problems else "fail",
        "kernel_release": kernel_release or "unknown",
        "kernel_package": kernel_package_from_release(kernel_release),
        "module_root": str(module_root) if module_root else None,
        "available_module_releases": available_releases,
        "module_requirements": module_records,
        "path_requirements": path_records,
        "problems": problems,
    }


def validate_live_kernel_hardware_surface(rootfs: Path, kernel_release: str | None) -> dict[str, Any]:
    result = inspect_live_kernel_hardware_surface(rootfs, kernel_release)
    if result["status"] != "pass":
        raise WuciOSError("Wuci-OS kernel hardware surface incomplete: " + "; ".join(result["problems"]))
    return result


def any_live_kernel_hardware_surface_passes(rootfs: Path, preferred_release: str | None) -> bool:
    releases: list[str] = []
    if preferred_release:
        releases.append(preferred_release)
    for release in kernel_module_releases(rootfs):
        if release not in releases:
            releases.append(release)
    return any(inspect_live_kernel_hardware_surface(rootfs, release)["status"] == "pass" for release in releases)


def _rootfs_musl_command(rootfs: Path, program: str) -> list[str]:
    loader = rootfs / "usr/lib64/libc.so"
    binary = rootfs / program.lstrip("/")
    if not loader.is_file() or not os.access(loader, os.X_OK):
        raise WuciOSError(f"rootfs musl loader is unavailable: {loader}")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise WuciOSError(f"rootfs executable is unavailable: {binary}")
    library_path = ":".join(
        str(path)
        for path in (
            rootfs / "usr/lib",
            rootfs / "usr/lib64",
            rootfs / "lib",
            rootfs / "lib64",
        )
    )
    return [str(loader), "--library-path", library_path, str(binary)]


def refresh_rootfs_depmod(rootfs: Path, kernel_release: str | None, *, ticker_mode: str = "auto") -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": "wuci-os-rootfs-depmod-refresh-v1",
        "kernel_release": kernel_release or "unknown",
        "status": "skipped",
        "method": "depmod -b",
        "problems": [],
    }
    if not kernel_release:
        result["reason"] = "kernel release unknown"
        return result
    module_root = kernel_module_root(rootfs, kernel_release)
    if module_root is None:
        result["reason"] = f"module tree not present for {kernel_release}"
        return result
    depmod = rootfs / "usr/bin/depmod"
    if not depmod.is_file() or not os.access(depmod, os.X_OK):
        result["status"] = "fail"
        result["problems"] = [f"depmod missing or not executable: {depmod.relative_to(rootfs).as_posix()}"]
        return result
    try:
        command = _rootfs_musl_command(rootfs, "usr/bin/depmod") + ["-b", str(rootfs), kernel_release]
    except WuciOSError as exc:
        metadata = all((module_root / item).is_file() for item in ("modules.dep", "modules.alias"))
        result["status"] = "simulated-pass" if metadata else "fail"
        result["reason"] = str(exc)
        if not metadata:
            result["problems"] = [f"depmod could not run and module metadata is incomplete for {kernel_release}"]
        return result
    with wuci_progress.stage(f"wuci-os depmod {kernel_release}", ticker_mode):
        proc = subprocess.run(
            command,
            cwd=repo_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
    result["returncode"] = proc.returncode
    result["stdout_tail"] = "\n".join((proc.stdout or "").splitlines()[-8:])
    result["stderr_tail"] = "\n".join((proc.stderr or "").splitlines()[-8:])
    if proc.returncode != 0:
        result["status"] = "fail"
        result["problems"] = [proc.stderr.strip() or proc.stdout.strip() or f"depmod failed for {kernel_release}"]
        return result
    result["status"] = "pass"
    return result


def refresh_rootfs_depmod_for_releases(
    rootfs: Path,
    preferred_release: str | None,
    *,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    releases: list[str] = []
    if preferred_release:
        releases.append(preferred_release)
    for release in kernel_module_releases(rootfs):
        if release not in releases:
            releases.append(release)
    records = [refresh_rootfs_depmod(rootfs, release, ticker_mode=ticker_mode) for release in releases]
    failures = [problem for record in records if record["status"] == "fail" for problem in record.get("problems", [])]
    if failures:
        raise WuciOSError("Wuci-OS depmod refresh failed: " + "; ".join(str(problem) for problem in failures))
    return {
        "schema": "wuci-os-rootfs-depmod-refresh-set-v1",
        "status": "pass",
        "preferred_kernel_release": preferred_release or "unknown",
        "records": records,
    }


def _run_rootfs_xbps(rootfs: Path, args: list[str], *, label: str, ticker_mode: str) -> subprocess.CompletedProcess[str]:
    command = _rootfs_musl_command(rootfs, "usr/bin/xbps-install") + ["-r", str(rootfs), *args]
    with wuci_progress.stage(label, ticker_mode):
        return subprocess.run(
            command,
            cwd=repo_root(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )


def ensure_minimum_live_network_packages(
    rootfs: Path,
    *,
    boot_kernel_release: str | None = None,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    packages = list(MINIMUM_LIVE_NETWORK_PACKAGES)
    kernel_package = kernel_package_from_release(boot_kernel_release)
    if kernel_package and kernel_package not in packages:
        packages.append(kernel_package)
    missing_before = [path for path in MINIMUM_LIVE_NETWORK_REQUIRED_PATHS if not (rootfs / path).exists()]
    kernel_surface_before = inspect_live_kernel_hardware_surface(rootfs, boot_kernel_release)
    if not any_live_kernel_hardware_surface_passes(rootfs, boot_kernel_release):
        missing_before.extend(f"kernel:{problem}" for problem in kernel_surface_before["problems"])
    if not missing_before:
        return {
            "schema": "wuci-os-minimum-live-network-package-bootstrap-v1",
            "status": "already-present",
            "packages": packages,
            "kernel_package": kernel_package,
            "required_paths": list(MINIMUM_LIVE_NETWORK_REQUIRED_PATHS),
            "missing_before": [],
            "missing_after": [],
            "kernel_hardware_surface_before": kernel_surface_before,
        }
    _rootfs_musl_command(rootfs, "usr/bin/xbps-install")
    install = _run_rootfs_xbps(
        rootfs,
        ["-y", "-Sy", *packages],
        label="wuci-os minimum Wi-Fi packages",
        ticker_mode=ticker_mode,
    )
    install_output = (install.stdout or "") + (install.stderr or "")
    xbps_update: dict[str, Any] | None = None
    if install.returncode != 0 and "xbps' package must be updated" in install_output:
        update = _run_rootfs_xbps(
            rootfs,
            ["-y", "-u", "xbps"],
            label="wuci-os rootfs xbps self-update",
            ticker_mode=ticker_mode,
        )
        xbps_update = {
            "returncode": update.returncode,
            "stdout_tail": "\n".join((update.stdout or "").splitlines()[-12:]),
            "stderr_tail": "\n".join((update.stderr or "").splitlines()[-12:]),
        }
        if update.returncode != 0:
            raise WuciOSError("rootfs xbps self-update failed: " + (update.stderr.strip() or update.stdout.strip()))
        install = _run_rootfs_xbps(
            rootfs,
            ["-y", "-Sy", *packages],
            label="wuci-os minimum Wi-Fi packages",
            ticker_mode=ticker_mode,
        )
        install_output = (install.stdout or "") + (install.stderr or "")
    if install.returncode != 0:
        raise WuciOSError("minimum live Wi-Fi package install failed: " + (install.stderr.strip() or install.stdout.strip()))
    missing_after = [path for path in MINIMUM_LIVE_NETWORK_REQUIRED_PATHS if not (rootfs / path).exists()]
    kernel_surface_after = inspect_live_kernel_hardware_surface(rootfs, boot_kernel_release)
    if not any_live_kernel_hardware_surface_passes(rootfs, boot_kernel_release):
        missing_after.extend(f"kernel:{problem}" for problem in kernel_surface_after["problems"])
    if missing_after:
        raise WuciOSError("minimum live Wi-Fi package install did not provide: " + ", ".join(missing_after))
    return {
        "schema": "wuci-os-minimum-live-network-package-bootstrap-v1",
        "status": "pass",
        "packages": packages,
        "kernel_package": kernel_package,
        "required_paths": list(MINIMUM_LIVE_NETWORK_REQUIRED_PATHS),
        "missing_before": missing_before,
        "missing_after": missing_after,
        "kernel_hardware_surface_before": kernel_surface_before,
        "kernel_hardware_surface_after": kernel_surface_after,
        "xbps_update": xbps_update,
        "install_returncode": install.returncode,
        "install_stdout_tail": "\n".join((install.stdout or "").splitlines()[-16:]),
        "install_stderr_tail": "\n".join((install.stderr or "").splitlines()[-16:]),
    }


def run_e2fsck(image: Path, *, work_root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["e2fsck", "-fy", str(image)],
        cwd=work_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    status = "pass" if result.returncode in {0, 1} else "fail"
    if status != "pass":
        raise WuciOSError(f"e2fsck failed for Wuci-OS ext image: {result.stderr.strip() or result.stdout.strip()}")
    digest, size = wuci_kaiju.file_digest_vector(image, "Wuci-OS ext image after e2fsck")
    return {
        "schema": "wuci-os-ext-image-fsck-v1",
        "status": status,
        "returncode": result.returncode,
        "bytes": size,
        "digest_vector": digest,
    }


def apply_wuci_overlay_to_ext_image(overlay_root: Path, ext_image: Path, work_root: Path) -> dict[str, Any]:
    manifest_path = overlay_manifest_path(overlay_root)
    if manifest_path.is_file():
        try:
            manifest = wuci_kaiju.read_public_json(manifest_path, "Wuci-OS overlay manifest")
        except wuci_kaiju.KaijuError as exc:
            raise WuciOSError(str(exc)) from exc
        records = validate_overlay_manifest_current(overlay_root, manifest, ticker_mode="never")
    else:
        records = overlay_file_records(overlay_root, ticker_mode="never")
    directory_commands: list[str] = []
    directories = 0
    for record in records:
        rel = _safe_rootfs_relative_path(str(record["path"]))
        if record["type"] in {"dir", "directory"}:
            directory_commands.extend(_debugfs_mkdir_commands(rel))
            directories += 1
    if directory_commands:
        _debugfs_run(ext_image, directory_commands, "Wuci-OS ext image overlay directories", cwd=work_root)

    written: list[dict[str, Any]] = []
    for record in records:
        rel = _safe_rootfs_relative_path(str(record["path"]))
        if record["type"] in {"dir", "directory"}:
            continue
        if record["type"] != "file":
            raise WuciOSError(f"unsupported overlay record type: {record['type']}")
        source = overlay_root / rel
        data = _read_regular_bytes(source, f"Wuci-OS ext image overlay file {rel.as_posix()}")
        mode_text = str(record.get("mode", "0o644"))
        mode = int(mode_text, 8)
        written.append(
            _debugfs_write_bytes_file(
                ext_image,
                rel,
                data,
                mode=mode,
                work_root=work_root,
                label=f"Wuci-OS ext image overlay file {rel.as_posix()}",
            )
        )
    patches = [
        result
        for result in (
            _patch_ext_image_text_file(
                ext_image,
                "etc/runit/1",
                {
                    "Welcome to Void!": "Welcome to Wuci-OS!",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "voidlinux": "press Enter",
                },
                work_root=work_root,
            ),
            _patch_ext_image_text_file(
                ext_image,
                "etc/issue",
                {
                    "Welcome to the Void Linux Live system": "Welcome to the Wuci-OS live system",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "anon:voidlinux": "wj_low:press Enter",
                    "root:voidlinux": "wj:press Enter",
                    "voidlinux": "press Enter",
                },
                work_root=work_root,
            ),
            _patch_ext_image_text_file(
                ext_image,
                "etc/motd",
                {
                    "Welcome to the Void Linux Live system": "Welcome to the Wuci-OS live system",
                    "Void Linux": "Wuci-OS",
                    "void-live": "wuci-os-live",
                    "void-installer": "wuci-install",
                    "anon:voidlinux": "wj_low:press Enter",
                    "root:voidlinux": "wj:press Enter",
                    "voidlinux": "press Enter",
                },
                work_root=work_root,
            ),
        )
        if result is not None
    ]
    written.append(
        _debugfs_write_text_file(
            ext_image,
            "etc/runit/core-services/04-wuci-hostname.sh",
            "#!/bin/sh\n"
            "# Restore Wuci hostname after the inherited live initramfs writes its default.\n"
            "printf 'wuci-os-live\\n' > /etc/hostname\n",
            mode=0o755,
            work_root=work_root,
            label="Wuci-OS ext image hostname core service",
        )
    )
    written.append(
        _debugfs_write_text_file(
            ext_image,
            "etc/runit/core-services/04-wuci-live-access.sh",
            "#!/bin/sh\n"
            "# Restore Wuci live access after inherited live-init account hooks run.\n"
            "mkdir -p /etc/sudoers.d /etc/doas.d\n"
            "printf 'wj ALL=(ALL:ALL) NOPASSWD: ALL\\n' > /etc/sudoers.d/90-wuci-os-wj\n"
            "chmod 0440 /etc/sudoers.d/90-wuci-os-wj\n"
            "printf 'permit nopass wj as root\\n' > /etc/doas.d/90-wuci-os-wj.conf\n"
            "chmod 0440 /etc/doas.d/90-wuci-os-wj.conf\n"
            "for tool in /usr/bin/sudo /usr/bin/su /usr/bin/doas; do\n"
            "    [ -e \"$tool\" ] || continue\n"
            "    chown root:root \"$tool\" 2>/dev/null || true\n"
            "    chmod 4755 \"$tool\" 2>/dev/null || true\n"
            "done\n"
            "if command -v usermod >/dev/null 2>&1 && id wj >/dev/null 2>&1; then\n"
            "    for group in wheel audio video input kvm network storage; do\n"
            "        getent group \"$group\" >/dev/null 2>&1 && usermod -aG \"$group\" wj >/dev/null 2>&1 || true\n"
            "    done\n"
            "fi\n",
            mode=0o755,
            work_root=work_root,
            label="Wuci-OS ext image live access core service",
        )
    )
    accounts = apply_ext_image_account_profile(ext_image, overlay_root, work_root)
    fsck = run_e2fsck(ext_image, work_root=work_root)
    return {
        "schema": "wuci-os-ext-image-overlay-application-v1",
        "status": "pass",
        "overlay_root": str(overlay_root),
        "ext_image": str(ext_image),
        "directories": directories,
        "files": written,
        "identity_patches": patches,
        "account_profile": accounts,
        "fsck": fsck,
    }


def install_suite_packages_into_rootfs(rootfs: Path, *, ticker_mode: str = "auto") -> dict[str, Any]:
    packages = list(full_suite_packages())
    host_xbps = shutil.which("xbps-install")
    rootfs_xbps = rootfs / "usr/bin/xbps-install"
    if host_xbps:
        base_cmd = [host_xbps, "-r", str(rootfs), "-Sy"]
        method = "host-xbps-install-root"
    elif os.geteuid() == 0 and rootfs_xbps.is_file():
        base_cmd = ["chroot", str(rootfs), "/usr/bin/xbps-install", "-Sy"]
        method = "rootfs-chroot-xbps-install"
    else:
        raise WuciOSError(
            "Wuci-OS suite package baking requires host xbps-install, or root chroot access "
            "to a rootfs that already contains /usr/bin/xbps-install"
        )

    def run_install(items: list[str], label: str) -> subprocess.CompletedProcess[str]:
        with wuci_progress.stage(label, ticker_mode):
            return subprocess.run(
                base_cmd + items,
                cwd=repo_root(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                check=False,
            )

    result = run_install(packages, "wuci-os suite packages")
    installed = packages
    failed: list[dict[str, str]] = []
    if result.returncode != 0:
        installed = []
        for package in packages:
            package_result = run_install([package], f"wuci-os package {package}")
            if package_result.returncode == 0:
                installed.append(package)
            else:
                reason = "\n".join((package_result.stderr or package_result.stdout).splitlines()[-8:])
                failed.append({"package": package, "reason": reason})
    status = "pass" if not failed else "partial"
    return {
        "schema": "wuci-os-rootfs-suite-package-install-v1",
        "status": status,
        "method": method,
        "package_count": len(packages),
        "installed_count": len(installed),
        "failed_count": len(failed),
        "packages": packages,
        "installed_packages": installed,
        "failed_packages": failed,
    }


def _looks_like_void_rootfs(rootfs: Path) -> bool:
    required = (
        "etc/passwd",
        "etc/group",
        "etc/shadow",
        "etc/runit/1",
        "etc/runit/2",
        "usr/bin/xbps-install",
        "sbin/init",
    )
    return rootfs.is_dir() and not rootfs.is_symlink() and all((rootfs / item).exists() for item in required)


def resolve_rootfs_source(rootfs_source: Path | None) -> Path | None:
    if rootfs_source is None:
        return None
    root = rootfs_source
    if _looks_like_void_rootfs(root):
        return root
    if root.is_dir() and not root.is_symlink():
        candidates = sorted(child for child in root.iterdir() if _looks_like_void_rootfs(child))
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            names = ", ".join(candidate.name for candidate in candidates)
            raise WuciOSError(f"multiple extracted Void rootfs candidates under {root}: {names}")
    raise WuciOSError(
        "rootfs source must be an extracted Void rootfs tree containing "
        "etc/passwd, etc/runit/1, usr/bin/xbps-install, and sbin/init"
    )


def auto_rootfs_source(default_root: Path) -> Path | None:
    if not default_root.exists():
        return None
    return resolve_rootfs_source(default_root)


def rootfs_source_manifest(rootfs: Path) -> dict[str, Any]:
    release = ""
    os_release = rootfs / "usr/lib/os-release"
    if not os_release.is_file():
        os_release = rootfs / "etc/os-release"
    if os_release.is_file() and not os_release.is_symlink():
        release = _read_regular_bytes(os_release, "Void extracted rootfs os-release").decode("utf-8", "replace")
    return {
        "schema": "wuci-os-extracted-rootfs-source-v1",
        "path": str(rootfs),
        "layout": "direct-rootfs-tree",
        "has_proc_dir": (rootfs / "proc").is_dir(),
        "has_xbps_install": (rootfs / "usr/bin/xbps-install").is_file(),
        "os_release": release,
    }


def rootfs_source_tarball(rootfs: Path) -> Path | None:
    for suffix in (".tar.xz", ".tar.zst", ".tar.gz", ".tar"):
        candidate = rootfs.with_name(rootfs.name + suffix)
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _parse_tar_owner_spec(owner_spec: str) -> tuple[int, int] | None:
    user, slash, group = owner_spec.partition("/")
    if not slash:
        return None
    try:
        return int(user), int(group)
    except ValueError:
        return None


def _rootfs_owner_map_from_tarball(rootfs: Path, tarball: Path, tools: dict[str, dict[str, Any]], work_root: Path) -> dict[str, tuple[int, int]]:
    tar = _require_host_tool(tools, "tar")
    listing = subprocess.run(
        [tar, "--numeric-owner", "-tvf", str(tarball)],
        cwd=work_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    if listing.returncode != 0:
        raise WuciOSError(f"could not inspect rootfs tarball ownership: {listing.stderr.strip() or listing.stdout.strip()}")
    owner_map: dict[str, tuple[int, int]] = {}
    for line in listing.stdout.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 6:
            continue
        owner = _parse_tar_owner_spec(parts[1])
        if owner is None:
            continue
        name = parts[5].split(" -> ", 1)[0].strip()
        while name.startswith("./"):
            name = name[2:]
        name = name.strip("/")
        owner_map[name] = owner
    if not owner_map:
        raise WuciOSError(f"rootfs tarball ownership listing was empty: {tarball}")
    return owner_map


def _debugfs_safe_path(relative: str) -> str:
    if relative in {"", "."}:
        return "/"
    if "\\" in relative or '"' in relative or any(ch in relative for ch in "\r\n\t"):
        raise WuciOSError(f"rootfs path cannot be safely normalized with debugfs: {relative}")
    path = "/" + relative.strip("/")
    if any(ch.isspace() for ch in relative):
        return f'"{path}"'
    return path


def normalize_generated_rootfs_image_ownership(
    image: Path,
    rootfs: Path,
    *,
    tools: dict[str, dict[str, Any]],
    work_root: Path,
    owner_tarball: Path | None = None,
) -> dict[str, Any]:
    _require_host_tool(tools, "debugfs")
    tarball = owner_tarball or rootfs_source_tarball(rootfs)
    owner_map: dict[str, tuple[int, int]] = {}
    source = "all-root-fallback"
    if tarball is not None:
        owner_map = _rootfs_owner_map_from_tarball(rootfs, tarball, tools, work_root)
        source = str(tarball)
    commands = ["set_inode_field / uid 0", "set_inode_field / gid 0"]
    path_count = 1
    setuid_fixed = 0
    auth_setuid_root_paths: list[str] = []
    missing_required_auth: list[str] = []
    for path in sorted(rootfs.rglob("*"), key=lambda item: item.relative_to(rootfs).as_posix()):
        rel = path.relative_to(rootfs).as_posix()
        uid, gid = owner_map.get(rel, (0, 0))
        remote = _debugfs_safe_path(rel)
        commands.append(f"set_inode_field {remote} uid {uid}")
        commands.append(f"set_inode_field {remote} gid {gid}")
        path_count += 1
        try:
            if os.lstat(path).st_mode & 0o6000 and (uid, gid) == (0, 0):
                setuid_fixed += 1
        except FileNotFoundError:
            pass
    for rel in (*AUTH_SETUID_REQUIRED_PATHS, *AUTH_SETUID_OPTIONAL_PATHS):
        path = rootfs / rel
        if not path.exists():
            if rel in AUTH_SETUID_REQUIRED_PATHS:
                missing_required_auth.append(rel)
            continue
        remote = _debugfs_safe_path(rel)
        commands.append(f"set_inode_field {remote} uid 0")
        commands.append(f"set_inode_field {remote} gid 0")
        commands.append(f"set_inode_field {remote} mode 0104755")
        auth_setuid_root_paths.append(rel)
    if missing_required_auth:
        raise WuciOSError("generated rootfs image is missing required auth tools: " + ", ".join(missing_required_auth))
    _debugfs_run(image, commands, "Wuci-OS generated rootfs ownership normalization", cwd=work_root)
    return {
        "schema": "wuci-os-rootfs-ownership-normalization-v1",
        "status": "pass",
        "source": source,
        "paths": path_count,
        "setuid_or_setgid_root_paths": setuid_fixed,
        "auth_setuid_root_paths": auth_setuid_root_paths,
        "auth_setuid_required_missing": missing_required_auth,
    }


def _rootfs_tree_payload_bytes(rootfs: Path) -> int:
    total = 0
    for path in rootfs.rglob("*"):
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
        elif stat.S_ISLNK(info.st_mode):
            try:
                total += len(os.readlink(path).encode("utf-8"))
            except OSError:
                total += 128
    return total


def build_rootfs_image_from_tree(
    rootfs: Path,
    image: Path,
    *,
    tools: dict[str, dict[str, Any]],
    work_root: Path,
    owner_tarball: Path | None = None,
) -> dict[str, Any]:
    mke2fs = _require_host_tool(tools, "mke2fs")
    payload_bytes = _rootfs_tree_payload_bytes(rootfs)
    image_bytes = max(512 * 1024 * 1024, int(payload_bytes * 2.4) + 128 * 1024 * 1024)
    image_bytes = ((image_bytes + 4095) // 4096) * 4096
    _prepare_exclusive_output_path(image, "Wuci-OS generated rootfs image", force=True)
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("wb") as handle:
        handle.truncate(image_bytes)
    build = subprocess.run(
        [
            mke2fs,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-L",
            "wuci-rootfs",
            "-d",
            str(rootfs),
            str(image),
        ],
        cwd=work_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    if build.returncode != 0:
        raise WuciOSError(f"mke2fs generated rootfs image failed: {build.stderr.strip() or build.stdout.strip()}")
    ownership = normalize_generated_rootfs_image_ownership(
        image,
        rootfs,
        tools=tools,
        work_root=work_root,
        owner_tarball=owner_tarball,
    )
    digest, size = wuci_kaiju.file_digest_vector(image, "Wuci-OS generated rootfs image")
    return {
        "schema": "wuci-os-generated-rootfs-image-v1",
        "status": "pass",
        "path": str(image),
        "filesystem": "ext4",
        "label": "wuci-rootfs",
        "payload_bytes": payload_bytes,
        "bytes": size,
        "digest_vector": digest,
        "ownership_normalization": ownership,
    }


def remaster_live_rootfs(
    *,
    source_iso: Path,
    overlay_root: Path,
    work_root: Path,
    rootfs_source: Path | None = None,
    install_suite_packages: bool = False,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    tools = discover_host_image_tools()
    unsquashfs = _require_host_tool(tools, "unsquashfs")
    mksquashfs = _require_host_tool(tools, "mksquashfs")
    _prepare_output_directory(work_root, "Wuci-OS remaster workspace")
    old_squashfs = work_root / "source-squashfs.img"
    new_squashfs = work_root / "wuci-os-squashfs.img"
    rootfs = work_root / "rootfs"
    squashfs_source = rootfs
    generated_rootfs_image: dict[str, Any] | None = None
    for path in (old_squashfs, new_squashfs):
        _prepare_exclusive_output_path(path, f"Wuci-OS remaster artifact {path.name}", force=True)
    if rootfs.exists():
        shutil.rmtree(rootfs)
    rootfs_source_root = resolve_rootfs_source(rootfs_source)
    if rootfs_source_root is None:
        rootfs.mkdir(parents=True)
    squashfs_data = _extract_iso_bytes(source_iso, "LiveOS/squashfs.img", "LiveOS squashfs")
    _write_verified_new_file(old_squashfs, squashfs_data, "Wuci-OS source squashfs", mode=0o644)
    rootfs_source_info: dict[str, Any] | None = None
    if rootfs_source_root is not None:
        rootfs_source_info = rootfs_source_manifest(rootfs_source_root)
        shutil.copytree(rootfs_source_root, rootfs, symlinks=True)
    else:
        extract = subprocess.run(
            [unsquashfs, "-d", str(rootfs), str(old_squashfs)],
            cwd=work_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
        if extract.returncode != 0:
            raise WuciOSError(f"unsquashfs failed: {extract.stderr.strip() or extract.stdout.strip()}")
    nested_ext_image = rootfs / "LiveOS/ext3fs.img"
    rootfs_image_layout = "wrapped-rootfs-img" if rootfs_source_root is not None else ("nested-ext3fs" if nested_ext_image.is_file() else "direct-squashfs-root")
    source_boot_kernel_release = detect_boot_kernel_release(source_iso)
    minimum_network_bootstrap = (
        ensure_minimum_live_network_packages(rootfs, boot_kernel_release=source_boot_kernel_release, ticker_mode=ticker_mode)
        if not nested_ext_image.is_file()
        else {
            "schema": "wuci-os-minimum-live-network-package-bootstrap-v1",
            "status": "not-checked",
            "reason": "nested ext image package bootstrap requires mounted root access",
            "packages": list(MINIMUM_LIVE_NETWORK_PACKAGES),
            "kernel_release": source_boot_kernel_release or "unknown",
        }
    )
    depmod_refresh = (
        refresh_rootfs_depmod_for_releases(rootfs, source_boot_kernel_release, ticker_mode=ticker_mode)
        if not nested_ext_image.is_file()
        else {
            "schema": "wuci-os-rootfs-depmod-refresh-set-v1",
            "status": "not-checked",
            "reason": "nested ext image depmod refresh requires mounted root access",
            "preferred_kernel_release": source_boot_kernel_release or "unknown",
            "records": [],
        }
    )
    boot_kernel_selection = (
        select_live_boot_kernel_surface(rootfs, source_boot_kernel_release)
        if not nested_ext_image.is_file()
        else {
            "schema": "wuci-os-live-boot-kernel-selection-v1",
            "status": "not-checked",
            "reason": "nested ext image boot kernel selection requires mounted root access",
            "source_kernel_release": source_boot_kernel_release or "unknown",
            "effective_kernel_release": source_boot_kernel_release or "unknown",
            "replacement_required": False,
        }
    )
    if nested_ext_image.is_file():
        _require_host_tool(tools, "e2fsck")
        if not install_suite_packages or os.geteuid() != 0:
            _require_host_tool(tools, "debugfs")
    if nested_ext_image.is_file() and install_suite_packages:
        if os.geteuid() != 0:
            raise WuciOSError(
                "Wuci-OS suite package baking for this nested ext3 live image requires root chroot access; "
                "rerun final-iso with sudo/root, or omit --install-suite-packages for identity-only remaster"
            )
        mount_root = work_root / "mounted-rootfs"
        mount_root.mkdir(parents=True, exist_ok=True)
        mounted = False
        mount = subprocess.run(
            ["mount", "-o", "loop,rw", str(nested_ext_image), str(mount_root)],
            cwd=work_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
        if mount.returncode != 0:
            raise WuciOSError(f"mount nested Wuci-OS ext image failed: {mount.stderr.strip() or mount.stdout.strip()}")
        mounted = True
        try:
            package_install = install_suite_packages_into_rootfs(mount_root, ticker_mode=ticker_mode)
            overlay_application = apply_wuci_overlay_to_rootfs(overlay_root, mount_root)
        finally:
            if mounted:
                umount = subprocess.run(
                    ["umount", str(mount_root)],
                    cwd=work_root,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=False,
                    check=False,
                )
                if umount.returncode != 0:
                    raise WuciOSError(f"umount nested Wuci-OS ext image failed: {umount.stderr.strip() or umount.stdout.strip()}")
        fsck = run_e2fsck(nested_ext_image, work_root=work_root)
        overlay_application = overlay_application | {"nested_ext_image_fsck": fsck}
    elif install_suite_packages:
        package_install = install_suite_packages_into_rootfs(rootfs, ticker_mode=ticker_mode)
        overlay_application = apply_wuci_overlay_to_rootfs(overlay_root, rootfs)
    else:
        package_install = {
            "schema": "wuci-os-rootfs-suite-package-install-v1",
            "status": "not-requested",
            "reason": "pass --install-suite-packages with --remaster-rootfs to bake Wi-Fi/audio/video/developer packages",
            "package_count": len(full_suite_packages()),
            "packages": list(full_suite_packages()),
        }
        if nested_ext_image.is_file():
            overlay_application = apply_wuci_overlay_to_ext_image(overlay_root, nested_ext_image, work_root)
        else:
            overlay_application = apply_wuci_overlay_to_rootfs(overlay_root, rootfs)
    command_surface = (
        validate_live_command_surface(rootfs)
        if not nested_ext_image.is_file()
        else validate_ext_image_live_command_surface(nested_ext_image, work_root=work_root)
    )
    kernel_hardware_surface = (
        boot_kernel_selection["kernel_hardware_surface"]
        if not nested_ext_image.is_file()
        else {
            "schema": "wuci-os-live-kernel-hardware-surface-v1",
            "status": "not-checked",
            "reason": "nested ext image hardware surface is validated after image extraction in integration checks",
            "kernel_release": source_boot_kernel_release or "unknown",
        }
    )
    if rootfs_source_root is not None:
        squashfs_source = work_root / "squashfs-wrapper"
        if squashfs_source.exists():
            shutil.rmtree(squashfs_source)
        (squashfs_source / "LiveOS").mkdir(parents=True)
        generated_rootfs_image = build_rootfs_image_from_tree(
            rootfs,
            squashfs_source / "LiveOS/rootfs.img",
            tools=tools,
            work_root=work_root,
            owner_tarball=rootfs_source_tarball(rootfs_source_root),
        )
    build = subprocess.run(
        [
            mksquashfs,
            str(squashfs_source),
            str(new_squashfs),
            "-noappend",
            "-all-root",
            "-comp",
            "xz",
            "-no-xattrs",
            "-no-progress",
        ],
        cwd=work_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
    )
    if build.returncode != 0:
        raise WuciOSError(f"mksquashfs failed: {build.stderr.strip() or build.stdout.strip()}")
    old_digest, old_bytes = wuci_kaiju.file_digest_vector(old_squashfs, "Wuci-OS source squashfs")
    new_digest, new_bytes = wuci_kaiju.file_digest_vector(new_squashfs, "Wuci-OS remastered squashfs")
    return {
        "schema": "wuci-os-rootfs-remaster-v1",
        "status": "pass",
        "source_squashfs": {
            "path": str(old_squashfs),
            "bytes": old_bytes,
            "digest_vector": old_digest,
        },
        "remastered_squashfs": {
            "path": str(new_squashfs),
            "bytes": new_bytes,
            "digest_vector": new_digest,
        },
        "rootfs_image_layout": rootfs_image_layout,
        "generated_rootfs_image": generated_rootfs_image
        or {
            "schema": "wuci-os-generated-rootfs-image-v1",
            "status": "not-used",
            "reason": "remaster preserved source live rootfs image layout",
        },
        "rootfs_source": rootfs_source_info
        or {
            "schema": "wuci-os-extracted-rootfs-source-v1",
            "status": "not-used",
            "reason": "remaster used source ISO LiveOS/squashfs.img",
        },
        "minimum_network_package_bootstrap": minimum_network_bootstrap,
        "depmod_refresh": depmod_refresh,
        "boot_kernel_selection": boot_kernel_selection,
        "suite_package_install": package_install,
        "overlay_application": overlay_application,
        "live_command_surface": command_surface,
        "kernel_hardware_surface": kernel_hardware_surface,
        "host_tool_status": tools,
        "non_claims": list(BOUNDARY_DENIALS),
    }


def build_final_iso(
    *,
    source_root: Path | None = None,
    overlay_root: Path | None = None,
    seal_root: Path | None = None,
    final_root: Path | None = None,
    rootfs_source: Path | None = None,
    keyfile: Path | None = None,
    bin_path: Path | None = None,
    remaster_rootfs: bool = False,
    install_suite_packages: bool = False,
    force: bool = False,
    ticker_mode: str = "auto",
) -> dict[str, Any]:
    try:
        import pycdlib  # type: ignore[import-not-found]
    except ImportError as exc:
        raise WuciOSError(
            "pycdlib is required for payload ISO assembly; run: python3 -m ensurepip --user && "
            "python3 -m pip install --user pycdlib"
        ) from exc

    source = verify_source(source_root, require_layout=True)
    if source.get("status") != "pass":
        raise WuciOSError("Wuci-OS source verification failed: " + "; ".join(map(str, source.get("problems", []))))
    if install_suite_packages and not remaster_rootfs:
        raise WuciOSError("--install-suite-packages requires --remaster-rootfs")

    overlay = DEFAULT_OVERLAY_ROOT if overlay_root is None else overlay_root
    seal = DEFAULT_SEAL_ROOT if seal_root is None else seal_root
    final = DEFAULT_FINAL_ROOT if final_root is None else final_root
    key = seal / "wuci-os-overlay.key" if keyfile is None else keyfile
    binary = repo_root() / DEFAULT_WUCI_BIN if bin_path is None else bin_path
    final_iso = final / FINAL_ISO_NAME
    sha_path = final / f"{FINAL_ISO_NAME}.sha256"
    manifest_path = final / "manifest.json"
    daylight_manifest_path = final / "daylight-manifest.json"
    rootfs_manifest_path = final / "rootfs-manifest.json"
    source_kit_path = final / SOURCE_KIT_TAR_NAME
    overlay_tar_path = final / "wuci-os-overlay.tar"
    boot_splash_png_path = final / BOOT_SPLASH_PNG_NAME

    _prepare_output_directory(final, "Wuci-OS final ISO output")
    for path, label in (
        (final_iso, "Wuci-OS final ISO"),
        (sha_path, "Wuci-OS final ISO sha256"),
        (manifest_path, "Wuci-OS final ISO manifest"),
        (daylight_manifest_path, "Wuci-OS final Daylight manifest"),
        (rootfs_manifest_path, "Wuci-OS final rootfs manifest"),
        (source_kit_path, "Wuci-OS final source-kit tar"),
        (overlay_tar_path, "Wuci-OS final overlay tar"),
        (boot_splash_png_path, "Wuci-OS rendered boot splash PNG"),
    ):
        _prepare_exclusive_output_path(path, label, force=force)

    if not key.is_file():
        generate_keyfile(key, force=False)

    overlay_manifest = create_overlay(
        overlay,
        wallpaper_source=repo_root() / DEFAULT_WALLPAPER_SOURCE,
        force=True,
    )
    seal_manifest = seal_overlay(
        overlay_root=overlay,
        out_root=seal,
        keyfile=key,
        bin_path=binary,
        force=True,
        ticker_mode=ticker_mode,
    )
    source_kit = write_deterministic_source_kit_tar(source_kit_path, ticker_mode=ticker_mode)
    overlay_tar_validation = write_deterministic_overlay_tar(overlay, overlay_tar_path, ticker_mode=ticker_mode)
    overlay_tar_digest, overlay_tar_bytes = wuci_kaiju.file_digest_vector(overlay_tar_path, "Wuci-OS final overlay tar")
    source_manifest = read_source_manifest(Path(str(source.get("source_root", DEFAULT_SOURCE_ROOT))))
    tools = discover_host_image_tools()
    bootable_base = bool(source.get("layout", {}).get("status") == "pass")
    source_iso = Path(str(source["image_path"]))
    boot_splash_source = repo_root() / DEFAULT_BOOT_SPLASH_SOURCE
    if not boot_splash_source.is_file():
        boot_splash_source = repo_root() / DEFAULT_WALLPAPER_SOURCE
    boot_splash_render = render_boot_splash_png(boot_splash_source, boot_splash_png_path, force=True)
    boot_splash = Path(str(boot_splash_render["rendered_path"]))
    boot_splash_digest = dict(boot_splash_render["digest_vector"])
    boot_splash_bytes = int(boot_splash_render["bytes"])
    model_doc_source = repo_root() / SUBSTRACT_MODEL_DOC
    model_doc_digest, model_doc_bytes = wuci_kaiju.file_digest_vector(model_doc_source, "Wuci-OS Substract Substrate model doc")
    daylight_v8_model_source = repo_root() / DAYLIGHT_V8_MODEL_DOC
    daylight_v8_model_data = _read_regular_bytes(daylight_v8_model_source, "Wuci-OS Daylight v8 model doc")
    daylight_v8_model_digest = digest_vector(daylight_v8_model_data)
    daylight_v8_model_bytes = len(daylight_v8_model_data)
    daylight_v9_model_source = repo_root() / DAYLIGHT_V9_MODEL_DOC
    daylight_v9_model_data = _read_regular_bytes(daylight_v9_model_source, "Wuci-OS Daylight v9 model doc")
    daylight_v9_model_digest = digest_vector(daylight_v9_model_data)
    daylight_v9_model_bytes = len(daylight_v9_model_data)
    daylight_v10_model_source = repo_root() / DAYLIGHT_V10_MODEL_DOC
    daylight_v10_model_data = _read_regular_bytes(daylight_v10_model_source, "Wuci-OS Daylight v10 model doc")
    daylight_v10_model_digest = digest_vector(daylight_v10_model_data)
    daylight_v10_model_bytes = len(daylight_v10_model_data)
    daylight_v13_model_source = repo_root() / DAYLIGHT_V13_MODEL_DOC
    daylight_v13_model_data = _read_regular_bytes(daylight_v13_model_source, "Wuci-OS Daylight v13 Sovereign model doc")
    daylight_v13_model_digest = digest_vector(daylight_v13_model_data)
    daylight_v13_model_bytes = len(daylight_v13_model_data)
    model_diagram_source = repo_root() / DEFAULT_MODEL_DIAGRAM_SOURCE
    model_diagram_data = _read_regular_bytes(model_diagram_source, "Wuci-OS Daylight wire model diagram")
    _validate_png_bytes(model_diagram_data, "Wuci-OS Daylight wire model diagram")
    model_diagram_digest, model_diagram_bytes = digest_vector(model_diagram_data), len(model_diagram_data)
    daylight_v8_diagram_source = repo_root() / DEFAULT_DAYLIGHT_V8_DIAGRAM_SOURCE
    daylight_v8_diagram_data = _read_regular_bytes(daylight_v8_diagram_source, "Wuci-OS Daylight v8 sheet")
    _validate_png_bytes(daylight_v8_diagram_data, "Wuci-OS Daylight v8 sheet")
    daylight_v8_diagram_digest, daylight_v8_diagram_bytes = digest_vector(daylight_v8_diagram_data), len(daylight_v8_diagram_data)
    daylight_v9_sheet_source = repo_root() / DEFAULT_DAYLIGHT_V9_SHEET_SOURCE
    daylight_v9_sheet_data = _read_regular_bytes(daylight_v9_sheet_source, "Wuci-OS Daylight v9 sheet")
    _validate_png_bytes(daylight_v9_sheet_data, "Wuci-OS Daylight v9 sheet")
    daylight_v9_sheet_digest, daylight_v9_sheet_bytes = digest_vector(daylight_v9_sheet_data), len(daylight_v9_sheet_data)
    daylight_v9_diagram_source = repo_root() / DEFAULT_DAYLIGHT_V9_DIAGRAM_SOURCE
    daylight_v9_diagram_data = _read_regular_bytes(daylight_v9_diagram_source, "Wuci-OS Daylight v9 formal spine")
    if b"<svg" not in daylight_v9_diagram_data[:256]:
        raise WuciOSError(f"Wuci-OS Daylight v9 formal spine is not an SVG document: {daylight_v9_diagram_source}")
    daylight_v9_diagram_digest, daylight_v9_diagram_bytes = digest_vector(daylight_v9_diagram_data), len(daylight_v9_diagram_data)
    daylight_v10_scoreboard_source = repo_root() / DEFAULT_DAYLIGHT_V10_SCOREBOARD_SOURCE
    daylight_v10_scoreboard_data = _read_regular_bytes(daylight_v10_scoreboard_source, "Wuci-OS Daylight v10 scoreboard")
    _validate_png_bytes(daylight_v10_scoreboard_data, "Wuci-OS Daylight v10 scoreboard")
    daylight_v10_scoreboard_digest = digest_vector(daylight_v10_scoreboard_data)
    daylight_v10_scoreboard_bytes = len(daylight_v10_scoreboard_data)
    daylight_v13_math_source = repo_root() / DEFAULT_DAYLIGHT_V13_MATH_SOURCE
    daylight_v13_math_data = _read_regular_bytes(daylight_v13_math_source, "Wuci-OS Daylight v13 Sovereign math sheet")
    _validate_png_bytes(daylight_v13_math_data, "Wuci-OS Daylight v13 Sovereign math sheet")
    daylight_v13_math_digest = digest_vector(daylight_v13_math_data)
    daylight_v13_math_bytes = len(daylight_v13_math_data)
    daylight_v14c_image_source = repo_root() / DEFAULT_DAYLIGHT_V14C_IMAGE_SOURCE
    daylight_v14c_image_data = _read_regular_bytes(daylight_v14c_image_source, "Wuci-OS Daylight v14C+ Ascendant candidate sheet")
    _validate_png_bytes(daylight_v14c_image_data, "Wuci-OS Daylight v14C+ Ascendant candidate sheet")
    daylight_v14c_image_digest = digest_vector(daylight_v14c_image_data)
    daylight_v14c_image_bytes = len(daylight_v14c_image_data)
    daylight_v14c_math_source = repo_root() / DEFAULT_DAYLIGHT_V14C_MATH_SOURCE
    daylight_v14c_math_data = _read_regular_bytes(daylight_v14c_math_source, "Wuci-OS Daylight v14C+ Ascendant math sheet")
    _validate_png_bytes(daylight_v14c_math_data, "Wuci-OS Daylight v14C+ Ascendant math sheet")
    daylight_v14c_math_digest = digest_vector(daylight_v14c_math_data)
    daylight_v14c_math_bytes = len(daylight_v14c_math_data)
    daylight_v14c_wide_source = repo_root() / DEFAULT_DAYLIGHT_V14C_WIDE_SOURCE
    daylight_v14c_wide_data = _read_regular_bytes(daylight_v14c_wide_source, "Wuci-OS Daylight v14C+ Ascendant wide sheet")
    _validate_png_bytes(daylight_v14c_wide_data, "Wuci-OS Daylight v14C+ Ascendant wide sheet")
    daylight_v14c_wide_digest = digest_vector(daylight_v14c_wide_data)
    daylight_v14c_wide_bytes = len(daylight_v14c_wide_data)
    daylight_v15_solstice_source = repo_root() / DEFAULT_DAYLIGHT_V15_SOLSTICE_SOURCE
    daylight_v15_solstice_data = _read_regular_bytes(daylight_v15_solstice_source, "Wuci-OS Daylight v15+ Solstice notice")
    _validate_png_bytes(daylight_v15_solstice_data, "Wuci-OS Daylight v15+ Solstice notice")
    daylight_v15_solstice_digest = digest_vector(daylight_v15_solstice_data)
    daylight_v15_solstice_bytes = len(daylight_v15_solstice_data)
    original_boot_menu = _extract_iso_text(source_iso, "boot/isolinux/isolinux.cfg")
    wuci_boot_menu = rewrite_isolinux_config_for_wuci(original_boot_menu) if original_boot_menu else ""
    grub_rewrites: dict[str, str] = {}
    for grub_path in GRUB_CONFIG_ISO_PATHS:
        grub_text = _extract_iso_text(source_iso, grub_path)
        if grub_text:
            grub_rewrites[grub_path] = rewrite_grub_config_for_wuci(grub_text)
    remaster_result: dict[str, Any] = {
        "schema": "wuci-os-rootfs-remaster-v1",
        "status": "not-requested",
        "reason": "payload-preview mode; pass --remaster-rootfs for the Wuci-OS first-boot identity image",
        "host_tool_status": tools,
    }
    remaster_tmp_ctx: tempfile.TemporaryDirectory[str] | None = None
    if remaster_rootfs:
        remaster_tmp_ctx = tempfile.TemporaryDirectory(prefix=".wuci-os-remaster.", dir=str(final))
        remaster_result = remaster_live_rootfs(
            source_iso=source_iso,
            overlay_root=overlay,
            work_root=Path(remaster_tmp_ctx.name),
            rootfs_source=rootfs_source,
            install_suite_packages=install_suite_packages,
            ticker_mode=ticker_mode,
        )
    boot_kernel_selection = remaster_result.get("boot_kernel_selection", {})
    replacement_kernel_path: Path | None = None
    replacement_initrd_path: Path | None = None
    if remaster_rootfs and bool(boot_kernel_selection.get("replacement_required")):
        boot_artifacts = boot_kernel_selection.get("boot_artifacts", {})
        replacement_kernel_text = str(boot_artifacts.get("kernel_path") or "")
        replacement_initrd_text = str(boot_artifacts.get("initrd_path") or "")
        if not replacement_kernel_text or not replacement_initrd_text:
            raise WuciOSError("Wuci-OS boot kernel replacement selected without kernel/initrd paths")
        replacement_kernel_path = Path(replacement_kernel_text)
        replacement_initrd_path = Path(replacement_initrd_text)
        _verified_regular_file_info(replacement_kernel_path, "Wuci-OS replacement boot kernel")
        _verified_regular_file_info(replacement_initrd_path, "Wuci-OS replacement initramfs")

    suite_packages_baked = bool(
        remaster_rootfs
        and isinstance(remaster_result.get("suite_package_install"), dict)
        and remaster_result["suite_package_install"].get("status") == "pass"
    )
    release_blockers = []
    if not remaster_rootfs:
        release_blockers.append("deterministic-rootfs-not-remastered")
    if not suite_packages_baked:
        release_blockers.append("package-closure-fixed-point-missing")
    release_blockers.extend(
        [
            "qemu-boot-trace-not-bound-to-final-manifest",
            "hardware-boot-trace-missing",
            "final-iso-manifest-signature-missing",
            "witness-ledger-entry-missing",
        ]
    )
    # Each blocker is fail-closed: absent evidence keeps it active. This map is
    # informational only -- it documents the exact evidence and verification that
    # retires a blocker, turning the gate into an actionable release checklist. It
    # never flips release_allowed; only real, verified evidence (most of it from
    # outside this build host: reference hardware, the release authority key, and
    # the operated witness ledger) can do that. See docs/WUCI_OS_RELEASE_RUNBOOK.md.
    blocker_requirements = {
        "deterministic-rootfs-not-remastered":
            "Rebuild with --remaster-rootfs so the live rootfs is deterministically "
            "remastered with the Wuci-OS overlay (not payload-preview mode).",
        "package-closure-fixed-point-missing":
            "Bake the full install suite into the remaster (suite_package_install must "
            "report status=pass) so the package dependency graph reaches a sealed fixed point.",
        "qemu-boot-trace-not-bound-to-final-manifest":
            "Capture a QEMU boot trace of THIS final ISO reaching the WJ>_ prompt and bind "
            "it to the final-ISO manifest by recording the manifest sha256 inside the trace.",
        "hardware-boot-trace-missing":
            "Boot the final ISO on the reference hardware (ThinkPad X200s) and record a boot "
            "trace reaching WJ>_ with the live Wi-Fi/admin surface present.",
        "final-iso-manifest-signature-missing":
            "Sign the final-ISO manifest digest with the Wuci-OS release authority key and "
            "publish the detached signature alongside the ISO.",
        "witness-ledger-entry-missing":
            "Append the signed final-ISO manifest digest to the WUCI-WITNESS ledger and record "
            "its inclusion proof so the release is publicly transparent.",
    }
    release_gate = {
        "schema": "wuci-os-substract-release-gate-v1",
        "status": "blocked" if release_blockers else "pass",
        "release_allowed": not release_blockers,
        "blockers": release_blockers,
        "blocker_requirements": {
            blocker: blocker_requirements[blocker]
            for blocker in release_blockers
            if blocker in blocker_requirements
        },
        "release_runbook": "docs/WUCI_OS_RELEASE_RUNBOOK.md",
        "subtracted_claims": [
            "release-ready",
            "package-closure-fixed-point",
            "manifest-signed",
            "boot-bisimulation-complete",
        ]
        if release_blockers
        else [],
        "model": "docs/WUCI_OS_SUBSTRACT_SUBSTRATE.md",
    }

    onboard_manifest = {
        "schema": FINAL_ISO_SCHEMA,
        "status": "remastered-iso-built" if remaster_rootfs else "payload-preview-built",
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "created_utc": utc_now(),
        "mode": "bootable remastered Wuci-OS ISO" if remaster_rootfs else "bootable payload-preview ISO",
        "base_source_iso": {
            "path": str(source["image_path"]),
            "digest_vector": source.get("digest_vector", {}),
            "bytes": source.get("image_bytes", 0),
            "layout": source.get("layout", {}),
        },
        "payload_policy": {
            "rootfs_squashfs_rebuilt": remaster_rootfs,
            "rootfs_image_layout": remaster_result.get("rootfs_image_layout"),
            "suite_packages_baked": suite_packages_baked,
            "boot_catalog_preserved_from_source": bootable_base,
            "boot_menu_rewritten": bool(wuci_boot_menu),
            "boot_kernel_rewritten": bool(replacement_kernel_path and replacement_initrd_path),
            "boot_kernel_selection": boot_kernel_selection,
            "grub_entries_rewritten": sorted(grub_rewrites),
            "boot_splash_embedded": True,
            "legacy_bios_live_profile": list(LEGACY_BIOS_LIVE_KERNEL_ARGS),
            "direct_kernel_fast_boot_profile": list(FAST_BOOT_KERNEL_ARGS),
            "activation": "Wuci-OS rootfs boots directly" if remaster_rootfs else "boot the live base, then extract /wuci-os/*.tar payloads or run tools/wuci-os-live-activate from mounted source",
            "reason": "rootfs remastered with Wuci-OS overlay" if remaster_rootfs else "payload-preview mode embeds Wuci-OS overlay/source evidence as onboard payloads",
        },
        "self_host_payloads": {
            "wuci_source": "wuci-os/wuci-os-source-kit.tar includes the Wuci-Ji checkout under /opt/wuci-os/source/wuci-ji",
            "upstream_build_source": "source-kit includes build/wuci-os/upstream under /opt/wuci-os/source/upstream when present",
            "activation_helper": "wuci-os/wuci-os-live-activate",
            "offline_install_guide": "wuci-os/OFFLINE-INSTALL.txt gives beginning-to-end install and first-boot steps without internet",
            "update_command": "wuci-update updates system packages from configured repositories and fast-forwards the onboard repo",
            "terminal_resolver": "wuci-terminal prefers kitty, then ghostty, then safe fallbacks",
            "boot_chime": "wuci-boot-chime generates the original Wuci-OS chime locally and falls back to terminal bell",
            "network_suite": "NetworkManager, Wi-Fi supplicants, firmware, VPN/mobile helpers, and nftables are listed for baked suite installs",
            "media_suite": "PipeWire/WirePlumber, ALSA/Pulse helpers, Mesa/video drivers, Bluetooth, printing, scanning, and portals are listed for baked suite installs",
            "ai_tooling": "wuci-ai-setup is plan-only; credentials are operator-supplied and not baked into the ISO",
        },
        "boot_splash": {
            "source_path": str(boot_splash_source),
            "source_bytes": boot_splash_render["source_bytes"],
            "source_digest_vector": boot_splash_render["source_digest_vector"],
            "rendered_path": str(boot_splash),
            "render_method": boot_splash_render["render_method"],
            "iso_paths": [
                "/boot/isolinux/wuci-splash.png",
                "/boot/grub/wuci-splash.png",
                "/wuci-os/boot-splash.svg",
            ],
            "bytes": boot_splash_bytes,
            "digest_vector": boot_splash_digest,
            "menu_names": [
                "Wuci-Ji Systems / Wuci-OS live",
                "Wuci-Ji Systems recovery and tools",
            ],
        },
        "substract_substrate_model": {
            "schema": "wuci-os-substract-substrate-model-binding-v1",
            "formal_model_path": str(SUBSTRACT_MODEL_DOC),
            "formal_model_bytes": model_doc_bytes,
            "formal_model_digest_vector": model_doc_digest,
            "daylight_v8_model_path": str(DAYLIGHT_V8_MODEL_DOC),
            "daylight_v8_model_bytes": daylight_v8_model_bytes,
            "daylight_v8_model_digest_vector": daylight_v8_model_digest,
            "daylight_v9_model_path": str(DAYLIGHT_V9_MODEL_DOC),
            "daylight_v9_model_bytes": daylight_v9_model_bytes,
            "daylight_v9_model_digest_vector": daylight_v9_model_digest,
            "daylight_v10_model_path": str(DAYLIGHT_V10_MODEL_DOC),
            "daylight_v10_model_bytes": daylight_v10_model_bytes,
            "daylight_v10_model_digest_vector": daylight_v10_model_digest,
            "daylight_v13_model_path": str(DAYLIGHT_V13_MODEL_DOC),
            "daylight_v13_model_bytes": daylight_v13_model_bytes,
            "daylight_v13_model_digest_vector": daylight_v13_model_digest,
            "diagram_path": str(DEFAULT_MODEL_DIAGRAM_SOURCE),
            "diagram_bytes": model_diagram_bytes,
            "diagram_digest_vector": model_diagram_digest,
            "daylight_v8_diagram_path": str(DEFAULT_DAYLIGHT_V8_DIAGRAM_SOURCE),
            "daylight_v8_diagram_bytes": daylight_v8_diagram_bytes,
            "daylight_v8_diagram_digest_vector": daylight_v8_diagram_digest,
            "daylight_v9_sheet_path": str(DEFAULT_DAYLIGHT_V9_SHEET_SOURCE),
            "daylight_v9_sheet_bytes": daylight_v9_sheet_bytes,
            "daylight_v9_sheet_digest_vector": daylight_v9_sheet_digest,
            "daylight_v9_diagram_path": str(DEFAULT_DAYLIGHT_V9_DIAGRAM_SOURCE),
            "daylight_v9_diagram_bytes": daylight_v9_diagram_bytes,
            "daylight_v9_diagram_digest_vector": daylight_v9_diagram_digest,
            "daylight_v10_scoreboard_path": str(DEFAULT_DAYLIGHT_V10_SCOREBOARD_SOURCE),
            "daylight_v10_scoreboard_bytes": daylight_v10_scoreboard_bytes,
            "daylight_v10_scoreboard_digest_vector": daylight_v10_scoreboard_digest,
            "daylight_v13_math_path": str(DEFAULT_DAYLIGHT_V13_MATH_SOURCE),
            "daylight_v13_math_bytes": daylight_v13_math_bytes,
            "daylight_v13_math_digest_vector": daylight_v13_math_digest,
            "daylight_v14c_image_path": str(DEFAULT_DAYLIGHT_V14C_IMAGE_SOURCE),
            "daylight_v14c_image_bytes": daylight_v14c_image_bytes,
            "daylight_v14c_image_digest_vector": daylight_v14c_image_digest,
            "daylight_v14c_math_path": str(DEFAULT_DAYLIGHT_V14C_MATH_SOURCE),
            "daylight_v14c_math_bytes": daylight_v14c_math_bytes,
            "daylight_v14c_math_digest_vector": daylight_v14c_math_digest,
            "daylight_v14c_wide_path": str(DEFAULT_DAYLIGHT_V14C_WIDE_SOURCE),
            "daylight_v14c_wide_bytes": daylight_v14c_wide_bytes,
            "daylight_v14c_wide_digest_vector": daylight_v14c_wide_digest,
            "daylight_v15_solstice_path": str(DEFAULT_DAYLIGHT_V15_SOLSTICE_SOURCE),
            "daylight_v15_solstice_bytes": daylight_v15_solstice_bytes,
            "daylight_v15_solstice_digest_vector": daylight_v15_solstice_digest,
            "iso_paths": [
                "/wuci-os/WUCI_DAYLIGHT_V8.md",
                "/wuci-os/WUCI_DAYLIGHT_V9.md",
                "/wuci-os/WUCI_DAYLIGHT_V10.md",
                "/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
                "/wuci-os/wuci-daylight-v8-sheet.png",
                "/wuci-os/wuci-daylight-v9-sheet.png",
                "/wuci-os/wuci-daylight-v9-spine.svg",
                "/wuci-os/wuci-daylight-v10-scoreboard.png",
                "/wuci-os/wuci-daylight-v13-sovereign-math.png",
                "/wuci-os/wuci-daylight-v14c-plus-ascendant.png",
                "/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png",
                "/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png",
                "/wuci-os/wuci-daylight-v15-plus-solstice.png",
                "/wuci-os/wuci-daylight-wire-model.png",
                f"/opt/wuci-os/source/wuci-ji/{SUBSTRACT_MODEL_DOC.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DAYLIGHT_V8_MODEL_DOC.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DAYLIGHT_V9_MODEL_DOC.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DAYLIGHT_V10_MODEL_DOC.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DAYLIGHT_V13_MODEL_DOC.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_MODEL_DIAGRAM_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V8_DIAGRAM_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V9_SHEET_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V9_DIAGRAM_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V10_SCOREBOARD_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V13_MATH_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V14C_IMAGE_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V14C_MATH_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V14C_WIDE_SOURCE.as_posix()}",
                f"/opt/wuci-os/source/wuci-ji/{DEFAULT_DAYLIGHT_V15_SOLSTICE_SOURCE.as_posix()}",
            ],
        },
        "payloads": {
            "overlay_tar": {
                "path": "wuci-os/wuci-os-overlay.tar",
                "bytes": overlay_tar_bytes,
                "digest_vector": overlay_tar_digest,
                "validation": overlay_tar_validation,
            },
            "source_kit_tar": {
                "path": "wuci-os/wuci-os-source-kit.tar",
                "bytes": source_kit["tar_bytes"],
                "digest_vector": source_kit["tar_digest_vector"],
                "validation": source_kit["source_kit_validation"],
            },
            "daylight_overlay": seal_manifest["sealed_artifact"],
        },
        "rootfs_remaster": remaster_result,
        "release_gate": release_gate,
        "overlay_manifest_digest_vector": digest_vector(canonical_json_bytes(overlay_manifest)),
        "daylight_manifest_digest_vector": digest_vector(canonical_json_bytes(seal_manifest)),
        "host_tool_status": tools,
        "next_remaster_requirements": [
            "install squashfs-tools for mksquashfs and unsquashfs",
            "install or expose xbps-install/chroot for --install-suite-packages",
            "rebuild LiveOS/squashfs.img with the Wuci-OS overlay applied",
            "reassemble and boot-smoke-test the remastered ISO",
        ],
        "non_claims": list(BOUNDARY_DENIALS),
    }
    onboard_manifest_bytes = canonical_json_bytes(onboard_manifest) + b"\n"
    source_manifest_bytes = canonical_json_bytes(wuci_public_source_manifest(source_manifest)) + b"\n"
    seal_manifest_bytes = canonical_json_bytes(seal_manifest) + b"\n"
    remaster_manifest_bytes = canonical_json_bytes(remaster_result) + b"\n"
    offline_install_bytes = offline_install_guide_text().encode("utf-8")
    remaster_readme_note = (
        "LiveOS/squashfs.img was remastered with Wuci-OS identity and overlay files.\n\n"
        if remaster_rootfs
        else "This payload-preview ISO has not remastered LiveOS/squashfs.img; pass --remaster-rootfs for the first-boot Wuci identity image.\n\n"
    )
    readme_bytes = (
        "Wuci-OS boot ISO\n\n"
        "This ISO includes Wuci-OS payloads under /wuci-os and preserves upstream attribution in evidence.\n"
        + remaster_readme_note
        +
        "Payloads:\n"
        "  /wuci-os/wuci-os-overlay.tar\n"
        "  /wuci-os/wuci-os-source-kit.tar\n"
        "  /wuci-os/wuci-os-overlay.wj\n"
        "  /wuci-os/manifest.json\n"
        "  /wuci-os/daylight-manifest.json\n"
        "  /wuci-os/rootfs-manifest.json\n"
        "  /wuci-os/WUCI_DAYLIGHT_V8.md\n"
        "  /wuci-os/WUCI_DAYLIGHT_V9.md\n"
        "  /wuci-os/WUCI_DAYLIGHT_V10.md\n"
        "  /wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md\n"
        "  /wuci-os/wuci-daylight-v8-sheet.png\n"
        "  /wuci-os/wuci-daylight-v9-sheet.png\n"
        "  /wuci-os/wuci-daylight-v9-spine.svg\n"
        "  /wuci-os/wuci-daylight-v10-scoreboard.png\n"
        "  /wuci-os/wuci-daylight-v13-sovereign-math.png\n"
        "  /wuci-os/wuci-daylight-v14c-plus-ascendant.png\n"
        "  /wuci-os/wuci-daylight-v14c-plus-ascendant-math.png\n"
        "  /wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png\n"
        "  /wuci-os/wuci-daylight-v15-plus-solstice.png\n"
        "  /wuci-os/wuci-daylight-wire-model.png\n"
        "  /wuci-os/OFFLINE-INSTALL.txt\n"
    ).encode("utf-8")
    activate_path = repo_root() / "tools/wuci-os-live-activate"

    payload_records: list[dict[str, Any]] = []
    iso_assembly: dict[str, Any] = {
        "schema": "wuci-os-iso-assembly-v1",
        "status": "pass",
        "tool": "pycdlib",
        "reason": "xorriso was not available; used Python ISO writer fallback",
    }
    iso = pycdlib.PyCdlib()
    try:
        iso.open(str(source_iso))
        isolinux_cfg_iso_path = _iso_first_existing_path(
            iso,
            ("/boot/isolinux/isolinux.cfg", "/BOOT/ISOLINUX/ISOLINUX.CFG;1"),
            "ISOLINUX config",
        )
        isolinux_splash_iso_path = _iso_child_path_for_parent(
            iso,
            (
                ("/boot/isolinux", "/boot/isolinux/wuci-splash.png"),
                ("/BOOT/ISOLINUX", "/BOOT/ISOLINUX/WUCISPL.PNG;1"),
            ),
        )
        grub_dir_iso_path = "/boot/grub" if _iso_path_exists(iso, "/boot/grub") else "/BOOT/GRUB"
        grub_splash_iso_path = _iso_child_path_for_parent(
            iso,
            (
                ("/boot/grub", "/boot/grub/wuci-splash.png"),
                ("/BOOT/GRUB", "/BOOT/GRUB/WUCISPL.PNG;1"),
            ),
        )
        if wuci_boot_menu:
            payload_records.append(
                _iso_replace_bytes(
                    iso,
                    wuci_boot_menu.encode("utf-8"),
                    iso_path=isolinux_cfg_iso_path,
                    rr_name="isolinux.cfg",
                    joliet_path="/boot/isolinux/isolinux.cfg",
                )
            )
        _iso_add_directory_once(iso, grub_dir_iso_path, rr_name="grub", joliet_path="/boot/grub")
        payload_records.append(
            _iso_replace_local_file(
                iso,
                boot_splash,
                iso_path=isolinux_splash_iso_path,
                rr_name="wuci-splash.png",
                joliet_path="/boot/isolinux/wuci-splash.png",
                label="Wuci-OS ISOLINUX boot splash",
            )
        )
        payload_records.append(
            _iso_replace_local_file(
                iso,
                boot_splash,
                iso_path=grub_splash_iso_path,
                rr_name="wuci-splash.png",
                joliet_path="/boot/grub/wuci-splash.png",
                label="Wuci-OS GRUB boot splash",
            )
        )
        for grub_path, grub_text in grub_rewrites.items():
            iso_path, rr_name, joliet_path = GRUB_CONFIG_ISO_PATHS[grub_path]
            iso_path_candidates = (iso_path,)
            if grub_path == "boot/grub/grub.cfg":
                iso_path_candidates = (iso_path, "/BOOT/GRUB/GRUB.CFG;1")
            elif grub_path == "boot/grub/grub_void.cfg":
                iso_path_candidates = (iso_path, "/BOOT/GRUB/GRUBVOID.CFG;1")
            elif grub_path == "boot/grub/loopback.cfg":
                iso_path_candidates = (iso_path, "/BOOT/GRUB/LOOPBACK.CFG;1")
            elif grub_path == "EFI/BOOT/grub.cfg":
                iso_path_candidates = (iso_path, "/EFI/BOOT/GRUB.CFG;1")
            payload_records.append(
                _iso_replace_bytes(
                    iso,
                    grub_text.encode("utf-8"),
                    iso_path=_iso_first_existing_path(iso, iso_path_candidates, f"GRUB config {grub_path}"),
                    rr_name=rr_name,
                    joliet_path=joliet_path,
                )
            )
        if remaster_rootfs:
            payload_records.append(
                _iso_replace_local_file(
                    iso,
                    Path(str(remaster_result["remastered_squashfs"]["path"])),
                    iso_path=_iso_first_existing_path(
                        iso,
                        ("/LiveOS/squashfs.img", "/LIVEOS/SQUASHFS.IMG;1"),
                        "LiveOS squashfs",
                    ),
                    rr_name="squashfs.img",
                    joliet_path="/LiveOS/squashfs.img",
                    label="Wuci-OS remastered squashfs",
                )
            )
            if replacement_kernel_path is not None:
                payload_records.append(
                    _iso_replace_local_file(
                        iso,
                        replacement_kernel_path,
                        iso_path=_iso_first_existing_path(iso, ("/boot/vmlinuz", "/BOOT/VMLINUZ.;1", "/BOOT/VMLINUZ;1"), "boot kernel"),
                        rr_name="vmlinuz",
                        joliet_path="/boot/vmlinuz",
                        label="Wuci-OS replacement boot kernel",
                    )
                )
            if replacement_initrd_path is not None:
                payload_records.append(
                    _iso_replace_local_file(
                        iso,
                        replacement_initrd_path,
                        iso_path=_iso_first_existing_path(iso, ("/boot/initrd", "/BOOT/INITRD.;1", "/BOOT/INITRD;1"), "boot initramfs"),
                        rr_name="initrd",
                        joliet_path="/boot/initrd",
                        label="Wuci-OS replacement initramfs",
                    )
                )
        _iso_add_directory_once(iso, "/WUCI_OS", rr_name="wuci-os", joliet_path="/wuci-os")
        payload_records.append(
            _iso_add_local_file(
                iso,
                boot_splash_source,
                iso_path="/WUCI_OS/SPLASH.SVG;1",
                rr_name="boot-splash.svg",
                joliet_path="/wuci-os/boot-splash.svg",
                label="Wuci-OS boot splash source SVG",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                model_diagram_source,
                iso_path="/WUCI_OS/WIRE.PNG;1",
                rr_name="wuci-daylight-wire-model.png",
                joliet_path="/wuci-os/wuci-daylight-wire-model.png",
                label="Wuci-OS Daylight wire model diagram",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v8_diagram_source,
                iso_path="/WUCI_OS/DLV8.PNG;1",
                rr_name="wuci-daylight-v8-sheet.png",
                joliet_path="/wuci-os/wuci-daylight-v8-sheet.png",
                label="Wuci-OS Daylight v8 sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v9_sheet_source,
                iso_path="/WUCI_OS/D9SHEET.PNG;1",
                rr_name="wuci-daylight-v9-sheet.png",
                joliet_path="/wuci-os/wuci-daylight-v9-sheet.png",
                label="Wuci-OS Daylight v9 sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v9_diagram_source,
                iso_path="/WUCI_OS/DLV9.SVG;1",
                rr_name="wuci-daylight-v9-spine.svg",
                joliet_path="/wuci-os/wuci-daylight-v9-spine.svg",
                label="Wuci-OS Daylight v9 formal spine",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v10_scoreboard_source,
                iso_path="/WUCI_OS/D10SCORE.PNG;1",
                rr_name="wuci-daylight-v10-scoreboard.png",
                joliet_path="/wuci-os/wuci-daylight-v10-scoreboard.png",
                label="Wuci-OS Daylight v10 scoreboard",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v13_math_source,
                iso_path="/WUCI_OS/D13MATH.PNG;1",
                rr_name="wuci-daylight-v13-sovereign-math.png",
                joliet_path="/wuci-os/wuci-daylight-v13-sovereign-math.png",
                label="Wuci-OS Daylight v13 Sovereign math sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v14c_image_source,
                iso_path="/WUCI_OS/D14CPLUS.PNG;1",
                rr_name="wuci-daylight-v14c-plus-ascendant.png",
                joliet_path="/wuci-os/wuci-daylight-v14c-plus-ascendant.png",
                label="Wuci-OS Daylight v14C+ Ascendant candidate sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v14c_math_source,
                iso_path="/WUCI_OS/D14MATH.PNG;1",
                rr_name="wuci-daylight-v14c-plus-ascendant-math.png",
                joliet_path="/wuci-os/wuci-daylight-v14c-plus-ascendant-math.png",
                label="Wuci-OS Daylight v14C+ Ascendant math sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v14c_wide_source,
                iso_path="/WUCI_OS/D14WIDE.PNG;1",
                rr_name="wuci-daylight-v14c-plus-ascendant-wide.png",
                joliet_path="/wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png",
                label="Wuci-OS Daylight v14C+ Ascendant wide sheet",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                daylight_v15_solstice_source,
                iso_path="/WUCI_OS/D15SOLST.PNG;1",
                rr_name="wuci-daylight-v15-plus-solstice.png",
                joliet_path="/wuci-os/wuci-daylight-v15-plus-solstice.png",
                label="Wuci-OS Daylight v15+ Solstice notice",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                readme_bytes,
                iso_path="/WUCI_OS/README.TXT;1",
                rr_name="README.txt",
                joliet_path="/wuci-os/README.txt",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                offline_install_bytes,
                iso_path="/WUCI_OS/INSTALL.TXT;1",
                rr_name="OFFLINE-INSTALL.txt",
                joliet_path="/wuci-os/OFFLINE-INSTALL.txt",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                daylight_v8_model_data,
                iso_path="/WUCI_OS/DLV8.MD;1",
                rr_name="WUCI_DAYLIGHT_V8.md",
                joliet_path="/wuci-os/WUCI_DAYLIGHT_V8.md",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                daylight_v9_model_data,
                iso_path="/WUCI_OS/DLV9.MD;1",
                rr_name="WUCI_DAYLIGHT_V9.md",
                joliet_path="/wuci-os/WUCI_DAYLIGHT_V9.md",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                daylight_v10_model_data,
                iso_path="/WUCI_OS/DL10.MD;1",
                rr_name="WUCI_DAYLIGHT_V10.md",
                joliet_path="/wuci-os/WUCI_DAYLIGHT_V10.md",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                daylight_v13_model_data,
                iso_path="/WUCI_OS/DL13SOV.MD;1",
                rr_name="WUCI_DAYLIGHT_V13_SOVEREIGN.md",
                joliet_path="/wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                onboard_manifest_bytes,
                iso_path="/WUCI_OS/MANIFEST.JSON;1",
                rr_name="manifest.json",
                joliet_path="/wuci-os/manifest.json",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                source_manifest_bytes,
                iso_path="/WUCI_OS/SOURCE.JSON;1",
                rr_name="source.json",
                joliet_path="/wuci-os/source.json",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                seal_manifest_bytes,
                iso_path="/WUCI_OS/DAYLIGHT.JSON;1",
                rr_name="daylight-manifest.json",
                joliet_path="/wuci-os/daylight-manifest.json",
            )
        )
        payload_records.append(
            _iso_add_bytes(
                iso,
                remaster_manifest_bytes,
                iso_path="/WUCI_OS/ROOTFS.JSON;1",
                rr_name="rootfs-manifest.json",
                joliet_path="/wuci-os/rootfs-manifest.json",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                overlay_tar_path,
                iso_path="/WUCI_OS/OVERLAY.TAR;1",
                rr_name="wuci-os-overlay.tar",
                joliet_path="/wuci-os/wuci-os-overlay.tar",
                label="Wuci-OS final overlay tar",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                source_kit_path,
                iso_path="/WUCI_OS/SOURCEKT.TAR;1",
                rr_name=SOURCE_KIT_TAR_NAME,
                joliet_path=f"/wuci-os/{SOURCE_KIT_TAR_NAME}",
                label="Wuci-OS final source-kit tar",
            )
        )
        payload_records.append(
            _iso_add_local_file(
                iso,
                Path(str(seal_manifest["sealed_artifact"]["path"])),
                iso_path="/WUCI_OS/OVERLAY.WJ;1",
                rr_name="wuci-os-overlay.wj",
                joliet_path="/wuci-os/wuci-os-overlay.wj",
                label="Wuci-OS Daylight sealed overlay",
            )
        )
        if activate_path.is_file():
            payload_records.append(
                _iso_add_local_file(
                    iso,
                    activate_path,
                    iso_path="/WUCI_OS/ACTIVATE.SH;1",
                    rr_name="wuci-os-live-activate",
                    joliet_path="/wuci-os/wuci-os-live-activate",
                    label="Wuci-OS live activate helper",
                )
            )
        iso.write(str(final_iso))
        xorriso_path = str(tools.get("xorriso", {}).get("path") or "")
        if tools.get("xorriso", {}).get("status") == "available" and xorriso_path:
            with tempfile.TemporaryDirectory(prefix=".wuci-os-xorriso.", dir=str(final)) as xorriso_tmp:
                iso_assembly = _xorriso_replay_final_iso(
                    xorriso=xorriso_path,
                    source_iso=source_iso,
                    final_iso=final_iso,
                    staging_root=Path(xorriso_tmp),
                    wuci_boot_menu=wuci_boot_menu,
                    grub_rewrites=grub_rewrites,
                    boot_splash=boot_splash,
                    boot_splash_source=boot_splash_source,
                    model_diagram_source=model_diagram_source,
                    daylight_v8_diagram_source=daylight_v8_diagram_source,
                    daylight_v9_sheet_source=daylight_v9_sheet_source,
                    daylight_v9_diagram_source=daylight_v9_diagram_source,
                    daylight_v10_scoreboard_source=daylight_v10_scoreboard_source,
                    daylight_v13_math_source=daylight_v13_math_source,
                    daylight_v14c_image_source=daylight_v14c_image_source,
                    daylight_v14c_math_source=daylight_v14c_math_source,
                    daylight_v14c_wide_source=daylight_v14c_wide_source,
                    daylight_v15_solstice_source=daylight_v15_solstice_source,
                    readme_bytes=readme_bytes,
                    offline_install_bytes=offline_install_bytes,
                    daylight_v8_model_bytes=daylight_v8_model_data,
                    daylight_v9_model_bytes=daylight_v9_model_data,
                    daylight_v10_model_bytes=daylight_v10_model_data,
                    daylight_v13_model_bytes=daylight_v13_model_data,
                    replacement_kernel_path=replacement_kernel_path,
                    replacement_initrd_path=replacement_initrd_path,
                    onboard_manifest_bytes=onboard_manifest_bytes,
                    source_manifest_bytes=source_manifest_bytes,
                    seal_manifest_bytes=seal_manifest_bytes,
                    remaster_manifest_bytes=remaster_manifest_bytes,
                    overlay_tar_path=overlay_tar_path,
                    source_kit_path=source_kit_path,
                    sealed_overlay_path=Path(str(seal_manifest["sealed_artifact"]["path"])),
                    activate_path=activate_path,
                    remaster_result=remaster_result,
                    remaster_rootfs=remaster_rootfs,
                )
    except Exception:
        try:
            final_iso.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        iso.close()
        if remaster_tmp_ctx is not None:
            remaster_tmp_ctx.cleanup()

    final_digest, final_bytes = wuci_kaiju.file_digest_vector(final_iso, "Wuci-OS final ISO")
    validation_iso = pycdlib.PyCdlib()
    try:
        validation_iso.open(str(final_iso))
        has_boot_catalog = validation_iso.eltorito_boot_catalog is not None
    finally:
        validation_iso.close()
    for subpath, label in (
        ("wuci-os/manifest.json", "Wuci-OS manifest"),
        ("wuci-os/wuci-os-overlay.tar", "Wuci-OS overlay tar"),
        (f"wuci-os/{SOURCE_KIT_TAR_NAME}", "Wuci-OS source kit"),
        ("wuci-os/wuci-os-overlay.wj", "Wuci-OS sealed overlay"),
        ("wuci-os/rootfs-manifest.json", "Wuci-OS rootfs manifest"),
        ("wuci-os/OFFLINE-INSTALL.txt", "Wuci-OS offline install guide"),
        ("wuci-os/WUCI_DAYLIGHT_V8.md", "Wuci-OS Daylight v8 model"),
        ("wuci-os/WUCI_DAYLIGHT_V9.md", "Wuci-OS Daylight v9 model"),
        ("wuci-os/WUCI_DAYLIGHT_V10.md", "Wuci-OS Daylight v10 model"),
        ("wuci-os/WUCI_DAYLIGHT_V13_SOVEREIGN.md", "Wuci-OS Daylight v13 Sovereign model"),
        ("wuci-os/wuci-daylight-v8-sheet.png", "Wuci-OS Daylight v8 sheet"),
        ("wuci-os/wuci-daylight-v9-sheet.png", "Wuci-OS Daylight v9 sheet"),
        ("wuci-os/wuci-daylight-v9-spine.svg", "Wuci-OS Daylight v9 formal spine"),
        ("wuci-os/wuci-daylight-v10-scoreboard.png", "Wuci-OS Daylight v10 scoreboard"),
        ("wuci-os/wuci-daylight-v13-sovereign-math.png", "Wuci-OS Daylight v13 Sovereign math sheet"),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant.png", "Wuci-OS Daylight v14C+ Ascendant candidate sheet"),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant-math.png", "Wuci-OS Daylight v14C+ Ascendant math sheet"),
        ("wuci-os/wuci-daylight-v14c-plus-ascendant-wide.png", "Wuci-OS Daylight v14C+ Ascendant wide sheet"),
        ("wuci-os/wuci-daylight-v15-plus-solstice.png", "Wuci-OS Daylight v15+ Solstice notice"),
        ("wuci-os/wuci-daylight-wire-model.png", "Wuci-OS Daylight wire model diagram"),
        ("boot/isolinux/wuci-splash.png", "Wuci-OS ISOLINUX boot splash"),
        ("boot/grub/wuci-splash.png", "Wuci-OS GRUB boot splash"),
    ):
        _extract_iso_bytes(final_iso, subpath, label)
    layout = inspect_void_iso(final_iso)
    result = onboard_manifest | {
        "status": "built",
        "iso": {
            "path": str(final_iso),
            "bytes": final_bytes,
            "digest_vector": final_digest,
            "sha256_path": str(sha_path),
        },
        "manifest_path": str(manifest_path),
        "daylight_manifest_path": str(daylight_manifest_path),
        "rootfs_manifest_path": str(rootfs_manifest_path),
        "payload_records": payload_records,
        "iso_assembly": iso_assembly,
        "validation": {
            "schema": "wuci-os-final-iso-validation-v1",
            "status": "pass" if has_boot_catalog and layout.get("status") == "pass" else "blocked",
            "eltorito_boot_catalog": "present" if has_boot_catalog else "missing",
            "void_live_layout": layout,
            "payload_directory": "/wuci-os",
            "rootfs_remastered": remaster_rootfs,
        },
    }
    sha_text = f"{final_digest['sha256']}  {FINAL_ISO_NAME}\n".encode("ascii")
    _write_verified_new_file(sha_path, sha_text, "Wuci-OS final ISO sha256", mode=0o644)
    wuci_kaiju.write_json_atomic(manifest_path, result)
    wuci_kaiju.write_json_atomic(daylight_manifest_path, seal_manifest)
    wuci_kaiju.write_json_atomic(rootfs_manifest_path, remaster_result)
    _fsync_parent(final_iso)
    _fsync_parent(manifest_path)
    return result


def _read_failure_notes(notes_path: Path) -> tuple[dict[str, Any], dict[str, str], int]:
    data = _read_regular_bytes(notes_path, "Wuci-OS failure notes")
    try:
        notes = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise WuciOSError(f"failure notes must be JSON: {notes_path}: {exc}") from exc
    if not isinstance(notes, dict):
        raise WuciOSError("failure notes must be a JSON object")
    required = ("observed_failure", "boot_log", "qemu_plan", "target_hardware")
    missing = [key for key in required if not notes.get(key)]
    if missing:
        raise WuciOSError("failure notes missing required fields: " + ", ".join(missing))
    return notes, digest_vector(data), len(data)


def _failure_evidence_file_records(notes: dict[str, Any], notes_path: Path) -> list[dict[str, Any]]:
    raw = notes.get("evidence_files", {})
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise WuciOSError("failure notes evidence_files must be an object when present")
    records: list[dict[str, Any]] = []
    for label, raw_path in sorted(raw.items()):
        if not isinstance(label, str) or not label:
            raise WuciOSError("failure evidence file labels must be non-empty strings")
        if not isinstance(raw_path, str) or not raw_path:
            raise WuciOSError(f"failure evidence path for {label!r} must be a non-empty string")
        path = Path(raw_path)
        if not path.is_absolute():
            path = notes_path.parent / path
        digest, size = wuci_kaiju.file_digest_vector(path, f"Wuci-OS failure evidence file {label}")
        records.append(
            {
                "label": label,
                "path": str(path),
                "bytes": size,
                "digest_vector": digest,
            }
        )
    return records


def ingest_failure_specimen(iso_path: Path, notes_path: Path, *, failure_root: Path | None = None) -> dict[str, Any]:
    failure_root = DEFAULT_FAILURE_ROOT if failure_root is None else failure_root
    iso_digest, iso_bytes = wuci_kaiju.file_digest_vector(iso_path, "Wuci-OS failed ISO specimen")
    notes, notes_digest, notes_bytes = _read_failure_notes(notes_path)
    evidence_files = _failure_evidence_file_records(notes, notes_path)
    specimen_id = iso_digest["sha256"]
    out_dir = failure_root / specimen_id
    manifest_path = out_dir / "failure.json"
    _prepare_output_directory(failure_root, "Wuci-OS failure specimen root")
    if out_dir.exists():
        raise WuciOSError(f"failure specimen already exists and will not be overwritten: {out_dir}")
    _prepare_output_directory(out_dir, "Wuci-OS failure specimen directory")
    manifest = {
        "schema": FAILURE_SPECIMEN_SCHEMA,
        "status": "negative-evidence",
        "created_utc": utc_now(),
        "specimen_id": specimen_id,
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "failed_iso": {
            "path": str(iso_path),
            "bytes": iso_bytes,
            "digest_vector": iso_digest,
        },
        "notes": notes,
        "notes_file": {
            "path": str(notes_path),
            "bytes": notes_bytes,
            "digest_vector": notes_digest,
        },
        "evidence_files": evidence_files,
        "claim_effect": {
            "release_allowed": False,
            "reason": "failed ISO specimen is negative evidence; it cannot be promoted as a release base",
            "subtracted_claims": [
                "working-iso",
                "boot-trace-qemu-pass",
                "boot-trace-hardware-pass",
            ],
        },
        "non_claims": list(BOUNDARY_DENIALS),
    }
    wuci_kaiju.write_json_atomic(manifest_path, manifest)
    _fsync_parent(manifest_path)
    return manifest | {"manifest_path": str(manifest_path)}


def command_source(args: argparse.Namespace) -> int:
    source_root = resolve_repo_path(args.source_root, DEFAULT_SOURCE_ROOT)
    subcommand = args.source_command or "status"
    if subcommand == "status":
        print(source_status_text(source_root), end="")
        return 0
    if subcommand == "install":
        result = install_source(
            Path(args.source),
            source_root=source_root,
            name=args.name,
            force=args.force,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-os source: installed {result['image_path']}")
            print(f"bytes: {result['image_bytes']}")
            print(f"sha256: {result['digest_vector']['sha256']}")
            print(f"layout: {result['layout']['status']}")
        return 0
    if subcommand == "verify":
        result = verify_source(source_root, require_layout=True)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-os source verify: {result['status']}")
            for problem in result.get("problems", []):
                print(f"problem: {problem}")
        return 0 if result["status"] == "pass" else 1
    raise WuciOSError(f"unsupported source command: {subcommand}")


def command_plan(args: argparse.Namespace) -> int:
    source_root = resolve_repo_path(args.source_root, DEFAULT_SOURCE_ROOT)
    result = build_plan(source_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "ready" else 1


def command_iso_plan(args: argparse.Namespace) -> int:
    source_root = resolve_repo_path(args.source_root, DEFAULT_SOURCE_ROOT)
    result = finished_iso_plan(source_root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "ready-for-build-lane" else 1


def command_demo_commands(args: argparse.Namespace) -> int:
    print(demo_command_text(), end="")
    return 0


def command_source_kit(args: argparse.Namespace) -> int:
    out = resolve_repo_path(args.out, DEFAULT_BOOT_ROOT / SOURCE_KIT_TAR_NAME)
    result = write_deterministic_source_kit_tar(out, ticker_mode=args.ticker)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"wuci-os source-kit: {result['tar_path']}")
        print(f"files: {len(result['files'])}")
        print(f"bytes: {result['tar_bytes']}")
        print(f"sha256: {result['tar_digest_vector']['sha256']}")
        print(f"guest-root: /{result['guest_source_root']}")
        print(f"guest-upstream-root: /{result['guest_upstream_source_root']}")
    return 0


def command_overlay(args: argparse.Namespace) -> int:
    overlay_root = resolve_repo_path(args.overlay_root, DEFAULT_OVERLAY_ROOT)
    wallpaper = resolve_repo_path(args.wallpaper, DEFAULT_WALLPAPER_SOURCE) if args.wallpaper else repo_root() / DEFAULT_WALLPAPER_SOURCE
    result = create_overlay(overlay_root, wallpaper_source=wallpaper, force=args.force)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"wuci-os overlay: {result['overlay_root']}")
        print(f"files: {len(result['files'])}")
        print(f"wallpaper: {result['wallpaper']['path']}")
        print(f"wallpaper-sha256: {result['wallpaper']['digest_vector']['sha256']}")
    return 0


def command_live_update(args: argparse.Namespace) -> int:
    receipt = live_update_system(
        target_root=Path(args.root),
        apply=args.apply,
        ticker_mode=getattr(args, "ticker", "auto"),
    )
    if args.json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    counts = receipt["counts"]
    print(f"wuci-os live-update: {receipt['mode']} (target {receipt['target_root']})")
    print(f"source: {receipt['source_root']}")
    print(f"overlay-fingerprint-sha256: {receipt['overlay_fingerprint_sha256']}")
    print(
        f"files: {counts['files']} | add: {counts['add']} | update: {counts['update']} | "
        f"unchanged: {counts['unchanged']}"
    )
    for change in receipt["changes"]:
        marker = "+" if change["status"] == "add" else "~"
        print(f"  {marker} {change['path']} ({change['status']})")
    if receipt["mode"] == "applied":
        print(f"applied: {counts['applied']} | verified-by-digest: {counts['verified']}")
    elif receipt["changes"]:
        print("preview only; re-run with --apply (as root) to write these changes")
    else:
        print("system already matches the repo-presented overlay")
    return 0


def command_keygen(args: argparse.Namespace) -> int:
    key_path = resolve_repo_path(args.out, DEFAULT_SEAL_ROOT / "wuci-os-overlay.key")
    result = generate_keyfile(key_path, force=args.force)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"wuci-os daylight keyfile: {result['path']}")
        print(f"sha256: {result['digest_vector']['sha256']}")
    return 0


def command_seal(args: argparse.Namespace) -> int:
    overlay_root = resolve_repo_path(args.overlay_root, DEFAULT_OVERLAY_ROOT)
    out_root = resolve_repo_path(args.out_root, DEFAULT_SEAL_ROOT)
    keyfile = resolve_repo_path(args.keyfile, DEFAULT_SEAL_ROOT / "wuci-os-overlay.key")
    bin_path = resolve_repo_path(args.bin, DEFAULT_WUCI_BIN)
    result = seal_overlay(
        overlay_root=overlay_root,
        out_root=out_root,
        keyfile=keyfile,
        bin_path=bin_path,
        force=args.force,
        ticker_mode=args.ticker,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("wuci-os daylight overlay: sealed")
        print(f"artifact: {result['sealed_artifact']['path']}")
        print(f"manifest: {out_root / 'manifest.json'}")
        print(f"key-id: {result['key_id']}")
        print(f"sha256: {result['sealed_artifact']['digest_vector']['sha256']}")
    return 0


def command_failure(args: argparse.Namespace) -> int:
    subcommand = args.failure_command or ""
    if subcommand == "ingest":
        iso_path = resolve_repo_path(args.iso, Path(args.iso))
        notes_path = resolve_repo_path(args.notes, Path(args.notes))
        failure_root = resolve_repo_path(args.failure_root, DEFAULT_FAILURE_ROOT)
        result = ingest_failure_specimen(iso_path, notes_path, failure_root=failure_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("wuci-os failure specimen: ingested")
            print(f"manifest: {result['manifest_path']}")
            print(f"specimen-id: {result['specimen_id']}")
            print(f"sha256: {result['failed_iso']['digest_vector']['sha256']}")
            print("release: blocked-negative-evidence")
        return 0
    raise WuciOSError(f"unsupported failure command: {subcommand}")


def command_final_iso(args: argparse.Namespace) -> int:
    source_root = resolve_repo_path(args.source_root, DEFAULT_SOURCE_ROOT)
    overlay_root = resolve_repo_path(args.overlay_root, DEFAULT_OVERLAY_ROOT)
    seal_root = resolve_repo_path(args.seal_root, DEFAULT_SEAL_ROOT)
    final_root = resolve_repo_path(args.final_root, DEFAULT_FINAL_ROOT)
    rootfs_source = (
        resolve_repo_path(args.rootfs_source, DEFAULT_ROOTFS_SOURCE_ROOT)
        if args.rootfs_source
        else auto_rootfs_source(resolve_repo_path(None, DEFAULT_ROOTFS_SOURCE_ROOT))
        if args.remaster_rootfs
        else None
    )
    keyfile = resolve_repo_path(args.keyfile, DEFAULT_SEAL_ROOT / "wuci-os-overlay.key")
    bin_path = resolve_repo_path(args.bin, DEFAULT_WUCI_BIN)
    result = build_final_iso(
        source_root=source_root,
        overlay_root=overlay_root,
        seal_root=seal_root,
        final_root=final_root,
        rootfs_source=rootfs_source,
        keyfile=keyfile,
        bin_path=bin_path,
        remaster_rootfs=args.remaster_rootfs,
        install_suite_packages=args.install_suite_packages,
        force=args.force,
        ticker_mode=args.ticker,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("wuci-os final ISO: built")
        print(f"artifact: {result['iso']['path']}")
        print(f"manifest: {result['manifest_path']}")
        print(f"daylight-manifest: {result['daylight_manifest_path']}")
        print(f"rootfs-manifest: {result['rootfs_manifest_path']}")
        print(f"sha256: {result['iso']['digest_vector']['sha256']}")
        print(f"mode: {result['mode']}")
        if rootfs_source is not None:
            print(f"rootfs-source: {rootfs_source}")
        if not result["payload_policy"]["rootfs_squashfs_rebuilt"]:
            print("warning: payload-preview ISO; pass --remaster-rootfs for Wuci-OS first-boot identity")
        elif not result["payload_policy"].get("suite_packages_baked") and rootfs_source is None:
            print("warning: suite packages were not baked; pass --install-suite-packages with host xbps/chroot support")
    return 0 if result.get("validation", {}).get("status") == "pass" else 1


def command_boot(args: argparse.Namespace) -> int:
    source_root = resolve_repo_path(args.source_root, DEFAULT_SOURCE_ROOT)
    boot_root = resolve_repo_path(args.boot_root, DEFAULT_BOOT_ROOT)
    share = repo_root() if getattr(args, "share_repo", False) else None
    plan = boot_plan(
        source_root=source_root,
        boot_root=boot_root,
        qemu_bin=args.qemu_bin,
        memory_mib=args.memory_mib,
        cpus=args.cpus,
        network=args.allow_network,
        share_repo=share,
    )
    if args.json or not args.run:
        print(json.dumps(plan, indent=2, sort_keys=True))
    if not args.run:
        return 0 if plan["status"] == "ready" else 1
    if plan["status"] != "ready":
        print(f"wuci-os boot: {plan['status']}", file=sys.stderr)
        for problem in plan.get("problems", []):
            print(f"wuci-os: {problem}", file=sys.stderr)
        return 1
    argv = build_live_boot_argv(plan)
    print("wuci-os boot: launching Wuci-OS live source base")
    print("argv: " + shlex.join(argv))
    print("exit: Ctrl-a x")
    result = subprocess.run(argv, check=False, shell=False)
    cleanup_boot_artifacts(plan["boot_root"])
    return result.returncode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wuci-OS musl source evidence and boot planning")
    subparsers = parser.add_subparsers(dest="command")

    source_parser = subparsers.add_parser("source", help="install and verify the operator-supplied musl source ISO")
    source_parser.add_argument("--source-root", help="Wuci-OS source workspace")
    source_subparsers = source_parser.add_subparsers(dest="source_command")
    source_subparsers.add_parser("status", help="show Wuci-OS source status")
    install_parser = source_subparsers.add_parser("install", help="copy a local musl source ISO into Wuci-OS evidence")
    install_parser.add_argument("source", help="local musl live ISO path")
    install_parser.add_argument("--name", help="installed ISO filename; defaults to source basename")
    install_parser.add_argument("--force", action="store_true", help="replace an existing installed ISO")
    install_parser.add_argument("--json", action="store_true", help="emit JSON source manifest")
    verify_parser = source_subparsers.add_parser("verify", help="verify the installed source digest and live layout")
    verify_parser.add_argument("--json", action="store_true", help="emit JSON verification result")

    plan_parser = subparsers.add_parser("plan", help="emit the Wuci-OS first-phase build plan")
    plan_parser.add_argument("--source-root", help="Wuci-OS source workspace")

    iso_plan_parser = subparsers.add_parser("iso-plan", help="emit the finished bootable Wuci-OS ISO build plan")
    iso_plan_parser.add_argument("--source-root", help="Wuci-OS source workspace")

    subparsers.add_parser("demo-commands", help="print a numbered guided demo command list")

    source_kit_parser = subparsers.add_parser("source-kit", help="create the onboard Wuci-Ji source payload tar")
    source_kit_parser.add_argument("--out", help="source-kit tar path")
    source_kit_parser.add_argument("--json", action="store_true", help="emit JSON source-kit manifest")
    wuci_progress.add_ticker_arg(source_kit_parser)

    overlay_parser = subparsers.add_parser("overlay", help="create the Wuci-OS rootfs overlay")
    overlay_parser.add_argument("--overlay-root", help="Wuci-OS overlay output directory")
    overlay_parser.add_argument("--wallpaper", help="Wuci-OS wallpaper PNG source")
    overlay_parser.add_argument("--force", action="store_true", help="replace files in an existing overlay directory")
    overlay_parser.add_argument("--json", action="store_true", help="emit JSON overlay manifest")

    live_update_parser = subparsers.add_parser(
        "live-update",
        help="measure/apply the repo-presented overlay onto a live system root (no reflash)",
    )
    live_update_parser.add_argument("--root", default="/", help="system root to update (default: /)")
    live_update_parser.add_argument("--apply", action="store_true", help="write changed files atomically and verify each by digest")
    live_update_parser.add_argument("--json", action="store_true", help="emit the JSON update receipt")
    wuci_progress.add_ticker_arg(live_update_parser)

    keygen_parser = subparsers.add_parser("keygen", help="create a local Wuci-OS Daylight/WJSEAL overlay keyfile")
    keygen_parser.add_argument("--out", help="keyfile path")
    keygen_parser.add_argument("--force", action="store_true", help="replace an existing keyfile")
    keygen_parser.add_argument("--json", action="store_true", help="emit JSON keyfile metadata")

    seal_parser = subparsers.add_parser("seal-overlay", help="seal the generated Wuci-OS overlay with WJSEAL evidence")
    seal_parser.add_argument("--overlay-root", help="Wuci-OS overlay directory")
    seal_parser.add_argument("--out-root", help="Daylight seal output directory")
    seal_parser.add_argument("--keyfile", help="local 32-byte hex WJSEAL keyfile")
    seal_parser.add_argument("--bin", help="wuci-ji binary path")
    seal_parser.add_argument("--force", action="store_true", help="replace existing sealed artifact and manifest")
    seal_parser.add_argument("--json", action="store_true", help="emit JSON seal manifest")
    wuci_progress.add_ticker_arg(seal_parser)

    failure_parser = subparsers.add_parser("failure", help="ingest failed Wuci-OS ISO specimens as negative evidence")
    failure_subparsers = failure_parser.add_subparsers(dest="failure_command")
    failure_ingest_parser = failure_subparsers.add_parser("ingest", help="record a failed ISO digest and boot notes")
    failure_ingest_parser.add_argument("iso", help="failed ISO specimen path")
    failure_ingest_parser.add_argument("notes", help="JSON notes with observed_failure, boot_log, qemu_plan, and target_hardware")
    failure_ingest_parser.add_argument("--failure-root", help="failure evidence output directory")
    failure_ingest_parser.add_argument("--json", action="store_true", help="emit JSON failure specimen manifest")

    final_parser = subparsers.add_parser("final-iso", help="build the bootable Wuci-OS payload ISO")
    final_parser.add_argument("--source-root", help="Wuci-OS source workspace")
    final_parser.add_argument("--overlay-root", help="Wuci-OS overlay directory")
    final_parser.add_argument("--seal-root", help="Daylight seal output directory")
    final_parser.add_argument("--final-root", help="final ISO output directory")
    final_parser.add_argument("--rootfs-source", help="extracted Void rootfs directory to pack directly into LiveOS/squashfs.img")
    final_parser.add_argument("--keyfile", help="local 32-byte hex WJSEAL keyfile")
    final_parser.add_argument("--bin", help="wuci-ji binary path")
    final_parser.add_argument("--remaster-rootfs", action="store_true", help="rebuild LiveOS/squashfs.img with Wuci-OS identity and overlay")
    final_parser.add_argument("--install-suite-packages", action="store_true", help="bake Wi-Fi/audio/video/developer package suite into the remastered rootfs")
    final_parser.add_argument("--force", action="store_true", help="replace existing final ISO outputs")
    final_parser.add_argument("--json", action="store_true", help="emit JSON final ISO manifest")
    wuci_progress.add_ticker_arg(final_parser)

    boot_parser = subparsers.add_parser("boot", help="build or run a serial QEMU boot plan for the Wuci-OS musl source")
    boot_parser.add_argument("--source-root", help="Wuci-OS source workspace")
    boot_parser.add_argument("--boot-root", help="transient Wuci-OS boot artifact workspace")
    boot_parser.add_argument("--qemu-bin", default=DEFAULT_QEMU_BIN, help="QEMU executable")
    boot_parser.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB, help="VM memory in MiB")
    boot_parser.add_argument("--cpus", type=int, default=DEFAULT_CPUS, help="VM CPU count")
    boot_parser.add_argument("--allow-network", action="store_true", help="enable QEMU user networking")
    boot_parser.add_argument("--share-repo", action="store_true", help="expose this checkout read-only to the guest via 9p")
    boot_parser.add_argument("--run", action="store_true", help="launch QEMU instead of printing the plan")
    boot_parser.add_argument("--json", action="store_true", help="emit JSON boot plan")

    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "source"
        args.source_command = "status"
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "source":
            return command_source(args)
        if args.command == "plan":
            return command_plan(args)
        if args.command == "iso-plan":
            return command_iso_plan(args)
        if args.command == "demo-commands":
            return command_demo_commands(args)
        if args.command == "source-kit":
            return command_source_kit(args)
        if args.command == "overlay":
            return command_overlay(args)
        if args.command == "live-update":
            return command_live_update(args)
        if args.command == "keygen":
            return command_keygen(args)
        if args.command == "seal-overlay":
            return command_seal(args)
        if args.command == "failure":
            return command_failure(args)
        if args.command == "final-iso":
            return command_final_iso(args)
        if args.command == "boot":
            return command_boot(args)
    except (WuciOSError, wuci_kaiju.KaijuError) as exc:
        print(f"wuci-os: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
