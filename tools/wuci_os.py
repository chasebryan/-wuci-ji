#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
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
from pathlib import Path
from typing import Any

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
DEFAULT_SOURCE_ROOT = Path("build/wuci-os/source")
DEFAULT_BOOT_ROOT = Path("build/wuci-os/boot")
DEFAULT_OVERLAY_ROOT = Path("build/wuci-os/overlay")
DEFAULT_SEAL_ROOT = Path("build/wuci-os/daylight")
DEFAULT_WALLPAPER_SOURCE = Path("docs/wuci-os/assets/wallpaper1.png")
OVERLAY_WALLPAPER_PATH = Path("usr/share/backgrounds/wuci-os/wallpaper1.png")
DEFAULT_WUCI_BIN = Path("build/wuci-ji")
SOURCE_KIT_PREFIX = Path("opt/wuci-os/source/wuci-ji")
UPSTREAM_SOURCE_PREFIX = Path("opt/wuci-os/source/upstream")
SOURCE_KIT_GUEST_MANIFEST = Path("usr/share/wuci-os/source-kit.json")
SOURCE_KIT_TAR_NAME = "wuci-os-source-kit.tar"
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


DESKTOP_PACKAGES = (
    "xorg",
    "xinit",
    "xfce4",
    "xfce4-terminal",
    "kitty",
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
    "doas",
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


def release_stamp_from_name(name: str) -> str:
    match = VOID_RELEASE_RE.search(name)
    return match.group(1) if match else "unknown"


def _extract_iso_text(image_path: Path, subpath: str) -> str:
    data = wuci_kaiju._extract_iso_file_content(image_path, subpath)
    if data is None:
        return ""
    return data.decode("utf-8", "replace")


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
        problems.append("missing required Void live paths: " + ", ".join(missing))
    if append and f"root=live:CDLABEL={VOID_LIVE_LABEL}" not in append:
        problems.append("isolinux APPEND line does not target VOID_LIVE")
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


def serial_append_from_void(append: str) -> str:
    parts = [part for part in append.split() if not part.startswith("initrd=")]
    for required in ("console=ttyS0,115200n8", "nomodeset"):
        if required not in parts:
            parts.append(required)
    return " ".join(parts)


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
    root.mkdir(parents=True, exist_ok=True)
    try:
        source_info = wuci_kaiju.require_regular_local_file(source, "Void musl ISO source")
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    iso_name = safe_iso_name(name or source.name)
    dest = root / iso_name
    if source.resolve() == dest.resolve():
        raise WuciOSError("Void ISO source and destination must differ")
    try:
        wuci_kaiju.prepare_output_path(dest, "Wuci-OS source ISO", force=force)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc

    tmp_fd = -1
    tmp_name = ""
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
            if opened.st_ino != source_info.st_ino or opened.st_dev != source_info.st_dev:
                raise WuciOSError(f"Void ISO source changed while opening: {source}")
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
            raise WuciOSError("Void ISO source is empty")
        os.replace(tmp_name, dest)
        layout = inspect_void_iso(dest)
        if layout.get("status") != "pass":
            try:
                dest.unlink()
            except OSError:
                pass
            problems = "; ".join(str(problem) for problem in layout.get("problems", []))
            raise WuciOSError(f"Void musl ISO layout verification failed: {problems}")
        manifest: dict[str, Any] = {
            "schema": SOURCE_SCHEMA,
            "created_utc": utc_now(),
            "product": PRODUCT_NAME,
            "image_id": IMAGE_ID,
            "base": {
                "distribution": "Void Linux",
                "libc": "musl",
                "image_kind": "live base ISO",
                "upstream_label": VOID_LIVE_LABEL,
                "release_stamp": release_stamp_from_name(iso_name),
            },
            "operator_supplied": True,
            "source_path": str(source),
            "image_name": iso_name,
            "image_path": str(dest),
            "image_bytes": total,
            "digest_vector": {name: digest.hexdigest() for name, digest in digests.items()},
            "layout": layout,
            "boundary_denials": list(BOUNDARY_DENIALS),
        }
        wuci_kaiju.write_json_atomic(source_manifest_path(root), manifest)
        return manifest
    except Exception:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def verify_source(source_root: Path | None = None, *, require_layout: bool = True) -> dict[str, Any]:
    root = DEFAULT_SOURCE_ROOT if source_root is None else source_root
    problems: list[str] = []
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
    image_path_value = manifest.get("image_path")
    image_path = Path(str(image_path_value)) if isinstance(image_path_value, str) else root / "missing.iso"
    try:
        digest_vector, size = wuci_kaiju.file_digest_vector(image_path, "Wuci-OS source ISO")
    except wuci_kaiju.KaijuError as exc:
        digest_vector, size = {}, -1
        problems.append(str(exc))
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
            "build/wuci-os/final/wuci-os.iso.wj",
            "build/wuci-os/final/daylight-manifest.json",
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
                "automation": "future Rust wuci-os-image-builder around reviewed live-image tooling",
                "status": "planned",
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
                "name": "boot ISO rebuild",
                "automation": "future Rust ISO assembler using xorriso/libisoburn or reviewed external argv",
                "status": "planned",
                "requirements": [
                    "replace boot menu branding with Wuci-OS",
                    "preserve required license/source attribution in docs/evidence",
                    "emit serial and graphical boot entries",
                    "include Daylight-sealed manifest for the final ISO",
                ],
            },
            {
                "phase": 6,
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
        "6. tools/wuci-os boot --qemu-bin /usr/libexec/qemu-kvm --allow-network --share-repo --run",
        "7. login: root",
        "8. password: voidlinux",
        '9. for dev in /dev/vd? /dev/sd?; do tar -tf "$dev" >/dev/null 2>&1 && tar -xf "$dev" -C /; done',
        "10. wuci-live-banner",
        "11. wuci-users-apply",
        "12. wuci-source-status",
        "13. wuci-guide",
        "14. sudo wj install vim emacs kitty",
        "15. wuci-enter",
        "16. wuci-attest",
        "17. wuci-security-status",
        "18. wuci-daylight-status",
        "19. exit QEMU with Ctrl-a x",
    ]
    return "\n".join(rows) + "\n"


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest_vector(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": hashlib.sha384(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def developer_package_manifest() -> dict[str, Any]:
    language_groups = {name: list(packages) for name, packages in LANGUAGE_PACKAGE_GROUPS.items()}
    all_dev_packages: list[str] = []
    for packages in language_groups.values():
        all_dev_packages.extend(packages)
    return {
        "schema": "wuci-os-developer-package-profile-v1",
        "desktop": {
            "default": "xfce4",
            "window_manager": "ratpoison",
            "preferred_terminal": "kitty",
            "fallback_terminal": "xfce4-terminal",
            "packages": list(DESKTOP_PACKAGES),
        },
        "editors": {
            "default_terminal_editors": ["vim", "emacs"],
            "packages": ["vim", "emacs", "nano"],
        },
        "base_developer_packages": list(BASE_DEV_PACKAGES),
        "language_package_groups": language_groups,
        "all_developer_packages": sorted(set(BASE_DEV_PACKAGES + tuple(all_dev_packages))),
        "ai_tools": {
            "codex": {
                "installer": "https://chatgpt.com/codex/install.sh",
                "npm_fallback": "@openai/codex",
                "credential": "OPENAI_API_KEY or interactive login",
            },
            "github_copilot": {
                "installer": "https://gh.io/copilot-install",
                "npm_fallback": "@github/copilot",
                "credential": "GH_TOKEN, GITHUB_TOKEN, or interactive login",
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
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise WuciOSError(f"{label} changed while opening: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, wuci_kaiju.READ_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def overlay_manifest_path(overlay_root: Path) -> Path:
    return overlay_root / "usr/share/wuci-os/overlay-manifest.json"


def overlay_file_records(overlay_root: Path, *, ticker_mode: str = "auto") -> list[dict[str, Any]]:
    if not overlay_root.is_dir():
        raise WuciOSError(f"overlay root is missing: {overlay_root}")
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


def write_deterministic_overlay_tar(
    overlay_root: Path,
    tar_path: Path,
    *,
    ticker_mode: str = "auto",
) -> None:
    paths = sorted(overlay_root.rglob("*"), key=lambda path: path.relative_to(overlay_root).as_posix())
    ticker = wuci_progress.TriangleTicker(ticker_mode, label="wuci-os tar")
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
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
                with path.open("rb") as handle:
                    archive.addfile(tar_info, handle)
            else:
                raise WuciOSError(f"overlay contains unsupported file type: {rel}")
    ticker.finish(ok=True)


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
            paths.append(Path(text))
        return sorted(paths, key=lambda path: path.as_posix())

    paths = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in {".git", "build", ".tools", "__pycache__"}:
            continue
        paths.append(rel)
    return paths


def source_kit_records(*, ticker_mode: str = "auto") -> list[dict[str, Any]]:
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
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    if tar_path.exists():
        wuci_kaiju.reject_unsafe_existing_path(tar_path, "Wuci-OS source-kit tar")
        tar_path.unlink()
    records = source_kit_records(ticker_mode=ticker_mode)
    manifest = {
        "schema": SOURCE_KIT_SCHEMA,
        "created_utc": utc_now(),
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "source_root": str(root),
        "upstream_source_root": str(root / DEFAULT_UPSTREAM_ROOT),
        "guest_source_root": SOURCE_KIT_PREFIX.as_posix(),
        "guest_upstream_source_root": UPSTREAM_SOURCE_PREFIX.as_posix(),
        "guest_manifest": SOURCE_KIT_GUEST_MANIFEST.as_posix(),
        "files": records,
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

    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as archive:
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
            tar_info = tarfile.TarInfo(str(record["target_path"]))
            tar_info.mtime = 0
            tar_info.uid = 0
            tar_info.gid = 0
            tar_info.uname = "root"
            tar_info.gname = "root"
            tar_info.mode = stat.S_IMODE(info.st_mode)
            tar_info.type = tarfile.REGTYPE
            tar_info.size = info.st_size
            with path.open("rb") as handle:
                archive.addfile(tar_info, handle)

        manifest_bytes = canonical_json_bytes(manifest) + b"\n"
        add_data(archive, SOURCE_KIT_PREFIX / ".wuci-os-source-kit.json", manifest_bytes)
        add_data(archive, SOURCE_KIT_GUEST_MANIFEST, manifest_bytes)

    tar_digest, tar_bytes = wuci_kaiju.file_digest_vector(tar_path, "Wuci-OS source-kit tar")
    return manifest | {
        "tar_path": str(tar_path),
        "tar_bytes": tar_bytes,
        "tar_digest_vector": tar_digest,
    }


def generate_keyfile(path: Path, *, force: bool = False) -> dict[str, Any]:
    if path.exists() and force:
        wuci_kaiju.reject_unsafe_existing_path(path, "Wuci-OS Daylight keyfile")
        path.unlink()
    else:
        wuci_kaiju.prepare_output_path(path, "Wuci-OS Daylight keyfile", force=force)
    path.parent.mkdir(parents=True, exist_ok=True)
    key = base64.b16encode(os.urandom(32)).lower() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | wuci_kaiju._cloexec(), 0o600)
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
    key_bytes = _read_regular_bytes(keyfile, "Wuci-OS Daylight keyfile")
    if not re.fullmatch(rb"[0-9a-fA-F]{64}\n?", key_bytes):
        raise WuciOSError("Wuci-OS Daylight keyfile must contain one 32-byte hex key")
    manifest = wuci_kaiju.read_public_json(overlay_manifest_path(root), "Wuci-OS overlay manifest")
    if manifest.get("schema") != OVERLAY_SCHEMA:
        raise WuciOSError("Wuci-OS overlay manifest schema mismatch")
    out.mkdir(parents=True, exist_ok=True)
    sealed_path = out / "wuci-os-overlay.wj"
    manifest_path = out / "manifest.json"
    wuci_kaiju.prepare_output_path(sealed_path, "Wuci-OS Daylight sealed overlay", force=force)
    wuci_kaiju.prepare_output_path(manifest_path, "Wuci-OS Daylight seal manifest", force=force)
    if force and sealed_path.exists():
        sealed_path.unlink()
    file_records = overlay_file_records(root, ticker_mode=ticker_mode)
    tar_fd, tar_name = tempfile.mkstemp(prefix=".wuci-os-overlay.", suffix=".tar", dir=str(out))
    key_fd, key_tmp_name = tempfile.mkstemp(prefix=".wuci-os-key.", dir=str(out), text=False)
    result: subprocess.CompletedProcess[str] | None = None
    try:
        os.close(tar_fd)
        with os.fdopen(key_fd, "wb") as key_handle:
            key_handle.write(key_bytes)
            key_handle.flush()
            os.fsync(key_handle.fileno())
        os.chmod(key_tmp_name, 0o600)
        write_deterministic_overlay_tar(root, Path(tar_name), ticker_mode=ticker_mode)
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
                    str(sealed_path),
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
            sealed_path.unlink()
        except FileNotFoundError:
            pass
        stderr = "" if result is None else result.stderr
        raise WuciOSError(stderr.strip() or "seal-file-keyfile-v2 failed")
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
    wuci_kaiju.write_json_atomic(manifest_path, seal_manifest)
    return seal_manifest


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
            "  wuci-guide    guided high-assurance setup",
            "  wuci-auto     mostly automated live workstation setup",
            "  wuci-source-status     show onboard Wuci-Ji source payload status",
            "  wj install <packages>  install Wuci-OS packages",
            "  wuci-install  start the Wuci-OS installer context",
            "  wuci-dev-install       install desktop, editor, and developer packages",
            "  wuci-security-apply    apply SELinux-first high-assurance settings",
            "  wuci-security-status   verify SELinux/LUKS/firewall/hardening state",
            "  wuci-ai-setup          install Codex, Copilot, and Grok Build helpers",
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
printf 'operator: wuci-enter\\n'
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
accounts, prompt, wallpaper, Daylight evidence status, developer tools,
AI tool hooks, SELinux-first hardening, and verification.

Use Wuci-OS package commands instead of backend package-manager commands:
  sudo wj install vim emacs kitty
  sudo wj update

Destructive disk operations are not automated here.
TEXT

run_step 'apply Wuci-OS users and WJ>_ prompt' wuci-users-apply
run_check 'show account status' wuci-users-status
run_check 'show onboard source payload status' wuci-source-status
run_check 'show Daylight evidence status' wuci-daylight-status
run_check 'show security status before hardening' wuci-security-status

if ask 'Apply wallpaper now?' Y; then
    run_step 'apply Wuci-OS wallpaper' wuci-wallpaper || true
fi

if ask 'Install developer workstation packages? This can take time.' Y; then
    run_step 'install developer workstation packages' wuci-dev-install || true
fi

if ask 'Prepare Codex, Copilot, and Grok Build tool hooks? This can take time.' Y; then
    run_step 'prepare AI tool hooks' wuci-ai-setup || true
fi

if ask 'Apply SELinux-first high-assurance hardening profile?' Y; then
    run_step 'apply high-assurance hardening' wuci-security-apply || true
fi

run_check 'final security status' wuci-security-status
run_check 'SELinux status' wuci-selinux-status
run_check 'Daylight evidence status' wuci-daylight-status
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
    install_script = """#!/bin/sh
set -eu
cat <<'TEXT'
Wuci-OS install lane

This starts the Wuci-OS installer context. For now, install the base system,
then apply Wuci-OS packages/overlay after first boot. For high-assurance installs,
use LUKS/dm-crypt during disk setup, then run:

  wuci-dev-install
  wuci-security-apply
  wuci-security-status

Future Wuci-OS images should be generated with the Wuci-OS profile baked in.
TEXT
exec void-installer "$@"
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
  wj search <terms...>            search package repository
  wj info <packages...>           show package information
  wj remove <packages...>         remove packages; requires WJ_ALLOW_REMOVE=1
  wj guide                        run guided high-assurance setup
  wj auto                         run mostly automated setup
  wj status                       show Wuci-OS status
  wj security                     show high-assurance security status
  wj daylight                     show Daylight evidence status
  wj enter [user]                 enter WJ>_ operator shell
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

cmd=${1:-help}
if [ "$#" -gt 0 ]; then
    shift
fi

case "$cmd" in
    install|add)
        need_packages "$@"
        need_xbps
        run_root_wait "wj install" xbps-install -Sy "$@"
        ;;
    update|upgrade)
        need_xbps
        run_root_wait "wj update" xbps-install -Syu
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
    enter|shell)
        exec wuci-enter "$@"
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

as_root() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        printf 'wuci-ai-setup: need root or sudo for: %s\\n' "$*" >&2
        return 1
    fi
}

install_xbps_baseline() {
    if ! command -v xbps-install >/dev/null 2>&1; then
        printf 'wuci-ai-setup: xbps-install not found; skipping Wuci-OS package setup\\n' >&2
        return 0
    fi
    if [ "$(id -u)" = "0" ]; then
        wuci-wait-run "xbps ai refresh" xbps-install -Sy xbps || xbps-install -u xbps || true
        wuci-wait-run "xbps ai base" xbps-install -Sy ca-certificates curl git bash tar gzip xz unzip || true
        wuci-wait-run "xbps nodejs" xbps-install -Sy nodejs || true
        wuci-wait-run "xbps npm" xbps-install -Sy npm || true
    elif command -v sudo >/dev/null 2>&1; then
        wuci-wait-run "xbps ai refresh" sudo xbps-install -Sy xbps || sudo xbps-install -u xbps || true
        wuci-wait-run "xbps ai base" sudo xbps-install -Sy ca-certificates curl git bash tar gzip xz unzip || true
        wuci-wait-run "xbps nodejs" sudo xbps-install -Sy nodejs || true
        wuci-wait-run "xbps npm" sudo xbps-install -Sy npm || true
    fi
}

install_codex() {
    if command -v codex >/dev/null 2>&1; then
        printf 'codex already installed: %s\\n' "$(command -v codex)"
        return 0
    fi
    if command -v curl >/dev/null 2>&1; then
        printf 'installing Codex CLI with OpenAI standalone installer\\n'
        tmp=$(mktemp)
        wuci-wait-run "download Codex CLI" curl -fsSL https://chatgpt.com/codex/install.sh -o "$tmp" || true
        if [ -s "$tmp" ]; then
            CODEX_NON_INTERACTIVE=1 wuci-wait-run "install Codex CLI" sh "$tmp" || true
        fi
        rm -f "$tmp"
    fi
    if ! command -v codex >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        printf 'Codex standalone install unavailable; trying npm package\\n'
        npm install -g @openai/codex || true
    fi
}

install_copilot() {
    if command -v copilot >/dev/null 2>&1; then
        printf 'copilot already installed: %s\\n' "$(command -v copilot)"
        return 0
    fi
    if command -v curl >/dev/null 2>&1 && command -v bash >/dev/null 2>&1; then
        printf 'installing GitHub Copilot CLI with GitHub installer\\n'
        tmp=$(mktemp)
        wuci-wait-run "download Copilot CLI" curl -fsSL https://gh.io/copilot-install -o "$tmp" || true
        if [ -s "$tmp" ]; then
            PREFIX="${PREFIX:-/usr/local}" wuci-wait-run "install Copilot CLI" bash "$tmp" || true
        fi
        rm -f "$tmp"
    fi
    if ! command -v copilot >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
        printf 'Copilot installer unavailable; trying npm package\\n'
        npm install -g @github/copilot || true
    fi
}

install_xbps_baseline
install_codex
install_copilot

cat <<'TEXT'

Wuci-OS AI tool setup complete.

Next:
  codex
  copilot
  export XAI_API_KEY=...
  wuci-grok-build "write a small C hello world"

No credentials were written by this script.
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
    issue = """Wuci-OS live profile
Wuci-OS x86_64-musl base
login: wj / press Enter  or  wj_low / press Enter
admin: wj shows prompt WJ>_
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
  wuci-install
  wuci-wallpaper
  wuci-users-apply
  wuci-users-status
  wuci-dev-install
  wuci-security-apply
  wuci-security-status
  wuci-selinux-status
  wuci-daylight-status
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
bind c exec kitty
bind C exec xfce4-terminal
bind e exec emacs
bind v exec kitty -e vim
bind b exec firefox
bind p exec dmenu_run
bind s exec wuci-security-status
bind w exec wuci-wallpaper
bind P exec wuci-attest
bind r restart
bind q only
bind Q quit
startup_message off
echo Wuci-OS ratpoison profile active: C-t c opens kitty, C-t s checks security.
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
exec startxfce4
"""
    package_profile_json = json.dumps(package_manifest(), indent=2, sort_keys=True) + "\n"
    return {
        "etc/hostname": "wuci-os-live\n",
        "etc/issue": issue,
        "etc/motd": motd,
        "etc/profile.d/wuci-os.sh": profile,
        "etc/profile.d/wuci-prompt.sh": prompt_script,
        "etc/xdg/autostart/wuci-wallpaper.desktop": desktop_entry,
        "etc/skel/.xinitrc": xinitrc,
        "etc/skel/.ratpoisonrc": ratpoisonrc,
        "etc/skel/.config/kitty/kitty.conf": kitty_conf,
        "root/.xinitrc": xinitrc,
        "root/.ratpoisonrc": ratpoisonrc,
        "root/.config/kitty/kitty.conf": kitty_conf,
        "usr/local/bin/wuci-status": status_script,
        "usr/local/bin/wuci-attest": attest_script,
        "usr/local/bin/wuci-live-banner": live_banner_script,
        "usr/local/bin/wuci-source-status": source_status_script,
        "usr/local/bin/wuci-enter": enter_script,
        "usr/local/bin/wuci-guide": guide_script,
        "usr/local/bin/wuci-auto": auto_script,
        "usr/local/bin/wuci-install": install_script,
        "usr/local/bin/wuci-wallpaper": wallpaper_script,
        "usr/local/bin/wuci-wait-run": wait_run_script,
        "usr/local/bin/wj": wj_script,
        "usr/local/bin/wuci-users-apply": users_apply_script,
        "usr/local/bin/wuci-users-status": users_status_script,
        "usr/local/bin/wuci-dev-install": dev_install_script,
        "usr/local/bin/wuci-security-apply": security_apply_script,
        "usr/local/bin/wuci-security-status": security_status_script,
        "usr/local/bin/wuci-selinux-status": selinux_status_script,
        "usr/local/bin/wuci-daylight-status": daylight_status_script,
        "usr/local/bin/wuci-ai-status": ai_status_script,
        "usr/local/bin/wuci-ai-setup": ai_setup_script,
        "usr/local/bin/wuci-grok-build": grok_build_script,
        "usr/share/wuci-os/accounts.json": account_profile_json,
        "usr/share/wuci-os/packages.json": package_profile_json,
        "usr/share/wuci-os/security-profile.json": json.dumps(security_profile_manifest(), indent=2, sort_keys=True) + "\n",
        "usr/share/wuci-os/ratpoisonrc": ratpoisonrc,
        "usr/share/wuci-os/kitty.conf": kitty_conf,
        "usr/share/wuci-os/README": readme,
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
                "Codex CLI: install with https://chatgpt.com/codex/install.sh or npm @openai/codex.",
                "GitHub Copilot CLI: install with https://gh.io/copilot-install or npm @github/copilot.",
                "Grok Build: call xAI Responses API with model grok-build-0.1 and XAI_API_KEY.",
                "",
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
    if root.exists() and any(root.iterdir()) and not force:
        raise WuciOSError(f"overlay root already exists and is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for relative, text in overlay_files().items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if relative.startswith("usr/local/bin/"):
            path.chmod(0o755)
        else:
            path.chmod(0o644)
        written.append(relative)
    wallpaper = DEFAULT_WALLPAPER_SOURCE if wallpaper_source is None else wallpaper_source
    wallpaper_dest = root / OVERLAY_WALLPAPER_PATH
    wallpaper_dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        wuci_kaiju.require_regular_local_file(wallpaper, "Wuci-OS wallpaper")
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc
    shutil.copy2(wallpaper, wallpaper_dest)
    wallpaper_dest.chmod(0o644)
    wallpaper_digest, wallpaper_bytes = wuci_kaiju.file_digest_vector(wallpaper_dest, "Wuci-OS overlay wallpaper")
    written.append(str(OVERLAY_WALLPAPER_PATH))
    manifest = {
        "schema": OVERLAY_SCHEMA,
        "created_utc": utc_now(),
        "product": PRODUCT_NAME,
        "image_id": IMAGE_ID,
        "overlay_root": str(root),
        "files": written,
        "wallpaper": {
            "path": str(OVERLAY_WALLPAPER_PATH),
            "source_path": str(wallpaper),
            "bytes": wallpaper_bytes,
            "digest_vector": wallpaper_digest,
            "resize_policy": "wuci-wallpaper detects screen geometry and creates an exact-size cache when ImageMagick or GraphicsMagick is present; otherwise it uses desktop fill/zoom setters",
        },
        "boundary_denials": list(BOUNDARY_DENIALS),
    }
    wuci_kaiju.write_json_atomic(root / "usr/share/wuci-os/overlay-manifest.json", manifest)
    written.append("usr/share/wuci-os/overlay-manifest.json")
    return manifest | {"files": written}


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
        "pc,accel=tcg",
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
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        wuci_kaiju._write_transient_file(path, data)
    except wuci_kaiju.KaijuError as exc:
        raise WuciOSError(str(exc)) from exc


def build_live_boot_argv(plan: dict[str, Any]) -> list[str]:
    if not isinstance(plan, dict) or plan.get("schema") != BOOT_SCHEMA:
        raise WuciOSError("invalid Wuci-OS boot plan")
    if plan.get("status") != "ready":
        raise WuciOSError("Wuci-OS boot plan is blocked")
    image_path = Path(str(plan["source"]["image_path"]))
    boot_root = Path(str(plan["boot_root"]))
    kernel_data = wuci_kaiju._extract_iso_file_content(image_path, "boot/vmlinuz")
    initrd_data = wuci_kaiju._extract_iso_file_content(image_path, "boot/initrd")
    if not kernel_data or not initrd_data:
        raise WuciOSError("could not extract live source kernel/initrd")
    _write_transient(boot_root / "vmlinuz", kernel_data)
    _write_transient(boot_root / "initrd", initrd_data)
    if plan.get("share_mode") == "tar-drive":
        overlay_root = Path(str(plan.get("overlay_root", repo_root() / DEFAULT_OVERLAY_ROOT)))
        if not overlay_manifest_path(overlay_root).is_file():
            create_overlay(overlay_root, wallpaper_source=repo_root() / DEFAULT_WALLPAPER_SOURCE, force=True)
        write_deterministic_overlay_tar(overlay_root, boot_root / "wuci-os-overlay.tar", ticker_mode="auto")
    source_kit_path = str(plan.get("source_kit_path", ""))
    if source_kit_path:
        write_deterministic_source_kit_tar(Path(source_kit_path), ticker_mode="auto")
    argv = list(plan["argv"])
    return argv


def cleanup_boot_artifacts(boot_root: Path | str) -> None:
    root = Path(boot_root)
    for name in ("vmlinuz", "initrd", "wuci-os-overlay.tar", SOURCE_KIT_TAR_NAME):
        path = root / name
        try:
            if path.exists() and path.is_file():
                path.unlink()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


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
        if args.command == "keygen":
            return command_keygen(args)
        if args.command == "seal-overlay":
            return command_seal(args)
        if args.command == "boot":
            return command_boot(args)
    except (WuciOSError, wuci_kaiju.KaijuError) as exc:
        print(f"wuci-os: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
