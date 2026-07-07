#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import termios
from pathlib import Path
from typing import Any

import wuci_progress

ISO_SECTOR_SIZE = 2048
READ_CHUNK = 1024 * 1024
MAX_PUBLIC_JSON_BYTES = 4 * 1024 * 1024
DISK_SECTOR_SIZE = 512
EXT_SUPERBLOCK_OFFSET = 1024
EXT_SUPER_MAGIC = 0xEF53
EXT_EXTENTS_FL = 0x80000
EXTENT_HEADER_MAGIC = 0xF30A
INSTALLED_BOOT_MAX_BYTES = 300 * 1024 * 1024
INSTALLED_BOOT_ROOT = ".kaiju-boot-disk"
MBR_LINUX_TYPES = {0x83, 0x8E}
MBR_EXTENDED_TYPES = {0x05, 0x0F, 0x85}
MBR_SWAP_TYPES = {0x82}
INITRD_TAIL_MAGICS = (
    b"\x1f\x8b",  # gzip
    b"BZh",  # bzip2
    b"\x5d\x00\x00",  # lzma
    b"\xfd7zXZ\x00",  # xz
    b"\x89LZO",  # lzo
    b"\x02\x21\x4c\x18",  # legacy lz4
    b"\x04\x22\x4d\x18",  # lz4
    b"\x28\xb5\x2f\xfd",  # zstd
)


SCHEMA = "wuci-kaiju-catalog-v1"
DEFAULT_MANIFEST = Path("docs/noxframe/wuci_kaiju_manifest.json")
DEFAULT_ISO_ROOT = Path("build/noxframe/kaiju/iso")
DEFAULT_DISK_ROOT = Path("build/noxframe/kaiju/disk")
ISO_MANIFEST_NAME = "manifest.json"
DISK_MANIFEST_NAME = "disk.json"
ISO_SCHEMA = "wuci-kaiju-iso-install-v1"
DISK_SCHEMA = "wuci-kaiju-disk-v1"
BOOT_SCHEMA = "wuci-kaiju-boot-plan-v1"
DEFAULT_QEMU_BIN = "qemu-system-x86_64"
DEFAULT_QEMU_CANDIDATES = (
    "qemu-system-x86_64",
    "qemu-kvm",
    "/usr/libexec/qemu-kvm",
)
QEMU_INSTALL_HINT = (
    "install qemu-kvm-core on RHEL, or pass --kaiju-qemu-bin /path/to/qemu"
)
DEFAULT_MEMORY_MIB = 2048
DEFAULT_CPUS = 2
REQUIRED_PURPOSES = (
    "top10-anchor",
    "information-gathering",
    "vulnerability-analysis",
    "web-applications",
    "database-assessment",
    "password-audit",
    "wireless-analysis",
    "reverse-engineering",
    "exploitation-frameworks",
    "social-engineering-awareness",
    "sniffing-spoofing",
    "post-exploitation-review",
    "forensics",
    "reporting",
    "802-11",
    "bluetooth",
    "rfid",
    "sdr",
    "voip",
    "windows-resources",
    "gpu",
    "crypto-stego",
    "fuzzing",
    "hardware",
    "labs",
)
REQUIRED_TOOL_KEYS = {
    "name",
    "package",
    "kali_url",
    "role",
    "disposition",
    "host_execution",
    "notes",
}
ALLOWED_DISPOSITIONS = {
    "catalog-only",
    "offline-evidence-catalog",
    "blocked-catalog",
}
FORBIDDEN_KEYS = {
    "argv",
    "command",
    "commands",
    "pipeline",
    "shell_pipeline",
    "target_args",
    "scan_args",
    "exploit_args",
    "module_path",
    "operator_steps",
}
ISO_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\.iso")


class KaijuError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_manifest_path(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_MANIFEST


def default_iso_root(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_ISO_ROOT


def default_disk_root(root: Path | None = None) -> Path:
    base = repo_root() if root is None else root
    return base / DEFAULT_DISK_ROOT


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _nofollow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KaijuError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def read_public_json(
    path: Path,
    label: str = "WUCI-KAIJU manifest",
    *,
    max_bytes: int = MAX_PUBLIC_JSON_BYTES,
) -> dict[str, Any]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise KaijuError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")

    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KaijuError(f"could not open {label}: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise KaijuError(f"{label} changed type while opening: {path}")
        if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            raise KaijuError(f"{label} changed while opening: {path}")
        if opened.st_nlink != 1:
            raise KaijuError(f"{label} must not be hardlinked: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise KaijuError(f"{label} exceeds maximum size: {path}")
            chunks.append(chunk)
    finally:
        os.close(fd)

    try:
        value = json.loads(
            b"".join(chunks).decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KaijuError(f"{label} is not valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise KaijuError(f"{label} must be a JSON object: {path}")
    return value


def reject_symlink_ancestors(path: Path, label: str) -> None:
    parent = path.parent
    current = Path(parent.anchor) if parent.is_absolute() else Path(".")
    parts = parent.parts[1:] if parent.is_absolute() else parent.parts
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise KaijuError(f"could not stat {label} parent: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise KaijuError(f"{label} parent must not be a symlink: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise KaijuError(f"{label} parent must be a directory: {current}")


def ensure_output_directory_root(path: Path, label: str) -> None:
    reject_symlink_ancestors(path, label)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise KaijuError(f"could not stat {label}: {path}") from exc
    else:
        if stat.S_ISLNK(info.st_mode):
            raise KaijuError(f"{label} must not be a symlink: {path}")
        if not stat.S_ISDIR(info.st_mode):
            raise KaijuError(f"{label} must be a directory: {path}")
    reject_symlink_ancestors(path, label)


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    ensure_output_directory_root(path.parent, f"{path.name} JSON parent")
    reject_unsafe_existing_path(path, f"{path.name} JSON")
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def require_regular_local_file(path: Path, label: str) -> os.stat_result:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise KaijuError(f"missing {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")
    return info


def reject_unsafe_existing_path(path: Path, label: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise KaijuError(f"could not stat {label}: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"{label} must not be a symlink: {path}")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise KaijuError(f"{label} must not be hardlinked: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise KaijuError(f"{label} must be a regular file: {path}")


def prepare_output_path(path: Path, label: str, *, force: bool) -> None:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    reject_unsafe_existing_path(path, label)
    if not force:
        raise KaijuError(f"refusing to overwrite {label}: {path}")


def safe_iso_name(name: str) -> str:
    candidate = Path(name).name
    if candidate != name or not ISO_NAME_RE.fullmatch(candidate):
        raise KaijuError("ISO name must be a plain .iso filename")
    return candidate


def iso_manifest_path(iso_root: Path) -> Path:
    return iso_root / ISO_MANIFEST_NAME


def disk_manifest_path(disk_root: Path) -> Path:
    return disk_root / DISK_MANIFEST_NAME


def read_iso_manifest(iso_root: Path) -> dict[str, Any]:
    return read_public_json(iso_manifest_path(iso_root), "WUCI-KAIJU ISO manifest")


def read_disk_manifest(disk_root: Path) -> dict[str, Any]:
    return read_public_json(disk_manifest_path(disk_root), "WUCI-KAIJU disk manifest")


def file_digest_vector(path: Path, label: str) -> tuple[dict[str, str], int]:
    require_regular_local_file(path, label)
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    ticker = _make_kaiju_ticker("wuci-kaiju verify")
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise KaijuError(f"could not open {label}: {path}") from exc
    total = 0
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise KaijuError(f"{label} changed type while opening: {path}")
        if opened.st_nlink != 1:
            raise KaijuError(f"{label} must not be hardlinked: {path}")
        ticker.tick(0, opened.st_size, detail=f"{label} 0MiB")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
            ticker.tick(total, opened.st_size, detail=f"{label} {total // (1024*1024)}MiB")
    finally:
        os.close(fd)
    ticker.finish(ok=True)
    return {name: digest.hexdigest() for name, digest in digests.items()}, total


def _make_kaiju_ticker(label: str = "wuci-kaiju") -> Any:
    """Return a ticker or no-op shim for progress during kaiju ops."""
    try:
        return wuci_progress.TriangleTicker("auto", label=label)
    except Exception:
        class _NoopTicker:
            def tick(self, *a: Any, **k: Any) -> None: pass
            def pulse(self, *a: Any, **k: Any) -> None: pass
            def finish(self, *a: Any, **k: Any) -> None: pass
        return _NoopTicker()


def _locate_iso_file(iso_path: Path, subpath: str) -> tuple[int, int] | None:
    """Pure-stdlib ISO9660 locator for a file by path (e.g. install.amd/vmlinuz).
    Returns (lba, size) or None. Rejects symlinks/hardlinks via open flags.
    """
    if not isinstance(subpath, str):
        return None
    target = subpath.replace("\\", "/").lower().strip("/")
    want = [p.upper() for p in target.split("/") if p]
    if not want:
        return None
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(str(iso_path), flags)
    except OSError:
        return None
    try:
        os.lseek(fd, 16 * ISO_SECTOR_SIZE, os.SEEK_SET)
        pvd = os.read(fd, ISO_SECTOR_SIZE)
        if len(pvd) < ISO_SECTOR_SIZE or pvd[0] != 1 or pvd[1:6] != b"CD001":
            return None
        root_rec = pvd[156:190]
        if root_rec[0] < 34:
            return None
        root_lba = int.from_bytes(root_rec[2:6], "little")
        root_sz = int.from_bytes(root_rec[10:14], "little")

        def _read_at(lba: int, nbytes: int) -> bytes:
            os.lseek(fd, lba * ISO_SECTOR_SIZE, os.SEEK_SET)
            return os.read(fd, nbytes)

        def _scan_dir(dir_bytes: bytes, want_name: str) -> tuple[int, int, bool] | None:
            off = 0
            wname = want_name.upper().encode("ascii", errors="ignore").split(b";")[0].rstrip(b".")
            while off < len(dir_bytes):
                rlen = dir_bytes[off] if off < len(dir_bytes) else 0
                if rlen == 0:
                    off = ((off // ISO_SECTOR_SIZE) + 1) * ISO_SECTOR_SIZE
                    continue
                if off + rlen > len(dir_bytes):
                    break
                flagsb = dir_bytes[off + 25]
                is_dir = bool(flagsb & 2)
                nlen = dir_bytes[off + 32]
                nameb = dir_bytes[off + 33 : off + 33 + nlen]
                lba = int.from_bytes(dir_bytes[off + 2 : off + 6], "little")
                size = int.from_bytes(dir_bytes[off + 10 : off + 14], "little")
                nstrip = nameb.split(b";")[0].rstrip(b".")
                if nstrip == wname or wname in nameb or nstrip.lower() == wname.lower():
                    return (lba, size, is_dir)
                off += rlen
            return None

        cur_lba = root_lba
        cur_size = root_sz
        for idx, part in enumerate(want):
            dirdata = _read_at(cur_lba, cur_size)
            hit = _scan_dir(dirdata, part)
            if hit is None:
                return None
            lba, sz, isd = hit
            if idx == len(want) - 1:
                if isd:
                    return None
                return lba, sz
            cur_lba = lba
            cur_size = sz
        return None
    finally:
        os.close(fd)


def _extract_iso_file_content(iso_path: Path, subpath: str, *, ticker: Any | None = None) -> bytes | None:
    """Extract file bytes from ISO using locate + direct read, with optional ticker."""
    loc = _locate_iso_file(iso_path, subpath)
    if not loc:
        return None
    lba, size = loc
    if size <= 0 or size > 300 * 1024 * 1024:
        return None
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    try:
        fd = os.open(str(iso_path), flags)
    except OSError:
        return None
    try:
        os.lseek(fd, lba * ISO_SECTOR_SIZE, os.SEEK_SET)
        if ticker:
            ticker.pulse(detail=f"extract {subpath}")
        data = os.read(fd, size)
        if ticker:
            ticker.tick(len(data), size, detail=f"{subpath} {len(data)//(1024*1024)}MiB")
        if len(data) != size:
            return None
        return data
    finally:
        os.close(fd)


def _extract_boot_kernel_pair(iso_path: Path, dest_dir: Path, *, ticker: Any | None = None) -> tuple[Path | None, Path | None]:
    """Extract vmlinuz + initrd.gz for direct kernel boot. Returns paths or (None,None)."""
    v_data = _extract_iso_file_content(iso_path, "install.amd/vmlinuz", ticker=ticker)
    i_data = _extract_iso_file_content(iso_path, "install.amd/initrd.gz", ticker=ticker)
    if not v_data or not i_data:
        return None, None
    dest_dir.mkdir(parents=True, exist_ok=True)
    kdest = dest_dir / "vmlinuz"
    idest = dest_dir / "initrd.gz"
    for dpath, data, nm in ((kdest, v_data, "vmlinuz"), (idest, i_data, "initrd.gz")):
        try:
            if dpath.exists():
                if dpath.is_symlink() or (dpath.is_file() and os.stat(dpath).st_nlink != 1):
                    # refuse weird; remove if regular
                    pass
                if dpath.is_file():
                    dpath.unlink()
        except OSError:
            pass
        # write atomically
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".kaiju-boot-{nm}.", dir=str(dest_dir))
        try:
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, dpath)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            return None, None
    return kdest, idest


def _boot_log(message: str) -> None:
    if sys.stdout.isatty():
        print(message)


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_at(fd: int, offset: int, size: int) -> bytes:
    os.lseek(fd, offset, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = os.read(fd, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _has_ext_superblock(fd: int, base_offset: int) -> bool:
    try:
        magic = _read_at(fd, base_offset + EXT_SUPERBLOCK_OFFSET + 56, 2)
    except OSError:
        return False
    return len(magic) == 2 and _u16(magic, 0) == EXT_SUPER_MAGIC


def _mbr_partitions(fd: int, disk_size: int) -> list[dict[str, Any]]:
    sector = _read_at(fd, 0, DISK_SECTOR_SIZE)
    if len(sector) < DISK_SECTOR_SIZE or sector[510:512] != b"\x55\xaa":
        return []
    rows: list[dict[str, Any]] = []
    for idx in range(4):
        entry = sector[446 + idx * 16 : 446 + (idx + 1) * 16]
        part_type = entry[4]
        start = _u32(entry, 8)
        size = _u32(entry, 12)
        if part_type == 0 or start == 0 or size == 0:
            continue
        offset = start * DISK_SECTOR_SIZE
        byte_size = size * DISK_SECTOR_SIZE
        if offset <= 0 or offset >= disk_size or offset + byte_size > disk_size:
            continue
        rows.append(
            {
                "number": idx + 1,
                "bootable": entry[0] == 0x80,
                "type": part_type,
                "start_sector": start,
                "sectors": size,
                "offset": offset,
                "root_device": f"/dev/vda{idx + 1}",
            }
        )
    return rows


def _installed_disk_candidates(fd: int, disk_size: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    if _has_ext_superblock(fd, 0):
        candidates.append(
            {
                "number": None,
                "bootable": False,
                "type": None,
                "start_sector": 0,
                "sectors": disk_size // DISK_SECTOR_SIZE,
                "offset": 0,
                "root_device": "/dev/vda",
            }
        )
    partitions = _mbr_partitions(fd, disk_size)
    linux = [
        part
        for part in partitions
        if part["type"] not in MBR_EXTENDED_TYPES
        and part["type"] not in MBR_SWAP_TYPES
        and _has_ext_superblock(fd, int(part["offset"]))
    ]
    linux.sort(
        key=lambda part: (
            0 if part["bootable"] else 1,
            0 if part["type"] in MBR_LINUX_TYPES else 1,
            int(part["number"]),
        )
    )
    candidates.extend(linux)
    return candidates


class _ExtInode:
    def __init__(self, ino: int, raw: bytes) -> None:
        self.ino = ino
        self.raw = raw
        self.mode = _u16(raw, 0)
        self.size = _u32(raw, 4)
        if len(raw) >= 112:
            self.size |= _u32(raw, 108) << 32
        self.flags = _u32(raw, 32) if len(raw) >= 36 else 0
        self.blocks = raw[40:100]

    @property
    def file_type(self) -> int:
        return self.mode & 0xF000

    @property
    def is_dir(self) -> bool:
        return self.file_type == 0x4000

    @property
    def is_regular(self) -> bool:
        return self.file_type == 0x8000

    @property
    def is_symlink(self) -> bool:
        return self.file_type == 0xA000

    @property
    def uses_extents(self) -> bool:
        return bool(self.flags & EXT_EXTENTS_FL)


class _ExtReader:
    def __init__(self, fd: int, base_offset: int) -> None:
        self.fd = fd
        self.base_offset = base_offset
        self.superblock = _read_at(fd, base_offset + EXT_SUPERBLOCK_OFFSET, 1024)
        if len(self.superblock) < 1024 or _u16(self.superblock, 56) != EXT_SUPER_MAGIC:
            raise KaijuError("installed disk root partition is not ext2/3/4")
        self.block_size = 1024 << _u32(self.superblock, 24)
        self.blocks_per_group = _u32(self.superblock, 32)
        self.inodes_per_group = _u32(self.superblock, 40)
        self.first_data_block = _u32(self.superblock, 20)
        self.inode_size = _u16(self.superblock, 88) or 128
        desc_size = _u16(self.superblock, 254) if len(self.superblock) >= 256 else 32
        self.group_desc_size = max(32, desc_size)
        self.group_desc_table_block = self.first_data_block + 1

    def _block_offset(self, block: int) -> int:
        return self.base_offset + block * self.block_size

    def _read_block(self, block: int) -> bytes:
        return _read_at(self.fd, self._block_offset(block), self.block_size)

    def _group_desc(self, group: int) -> bytes:
        offset = self._block_offset(self.group_desc_table_block) + group * self.group_desc_size
        desc = _read_at(self.fd, offset, self.group_desc_size)
        if len(desc) < 32:
            raise KaijuError("truncated ext group descriptor")
        return desc

    def inode(self, ino: int) -> _ExtInode:
        if ino <= 0:
            raise KaijuError("invalid ext inode number")
        group = (ino - 1) // self.inodes_per_group
        index = (ino - 1) % self.inodes_per_group
        desc = self._group_desc(group)
        table = _u32(desc, 8)
        if len(desc) >= 44:
            table |= _u32(desc, 40) << 32
        offset = self._block_offset(table) + index * self.inode_size
        raw = _read_at(self.fd, offset, self.inode_size)
        if len(raw) < 128:
            raise KaijuError("truncated ext inode")
        return _ExtInode(ino, raw)

    def _extents_from_node(self, node: bytes) -> list[tuple[int, int, int]]:
        if len(node) < 12 or _u16(node, 0) != EXTENT_HEADER_MAGIC:
            raise KaijuError("unsupported ext inode block map")
        entries = _u16(node, 2)
        depth = _u16(node, 6)
        result: list[tuple[int, int, int]] = []
        if depth == 0:
            for idx in range(entries):
                off = 12 + idx * 12
                if off + 12 > len(node):
                    break
                logical = _u32(node, off)
                raw_length = _u16(node, off + 4)
                length = raw_length if raw_length <= 0x8000 else raw_length - 0x8000
                start = _u32(node, off + 8) | (_u16(node, off + 6) << 32)
                if length:
                    result.append((logical, start, length))
            return result
        for idx in range(entries):
            off = 12 + idx * 12
            if off + 12 > len(node):
                break
            leaf = _u32(node, off + 4) | (_u16(node, off + 8) << 32)
            result.extend(self._extents_from_node(self._read_block(leaf)))
        return result

    def _extents(self, inode: _ExtInode) -> list[tuple[int, int, int]]:
        if inode.uses_extents:
            return self._extents_from_node(inode.blocks)
        direct: list[tuple[int, int, int]] = []
        for logical in range(12):
            block = _u32(inode.blocks, logical * 4)
            if block:
                direct.append((logical, block, 1))
        return direct

    def read_file(self, inode: _ExtInode, *, max_bytes: int = INSTALLED_BOOT_MAX_BYTES) -> bytes:
        if inode.size > max_bytes:
            raise KaijuError(f"installed boot file too large: {inode.size} bytes")
        if inode.is_symlink and inode.size <= len(inode.blocks) and not inode.uses_extents:
            return inode.blocks[: inode.size]
        output = bytearray(inode.size)
        for logical, physical, length in self._extents(inode):
            target_offset = logical * self.block_size
            if target_offset >= inode.size:
                continue
            want = min(length * self.block_size, inode.size - target_offset)
            data = _read_at(self.fd, self._block_offset(physical), want)
            output[target_offset : target_offset + len(data)] = data
        return bytes(output)

    def list_dir(self, inode: _ExtInode) -> dict[str, int]:
        if not inode.is_dir:
            raise KaijuError("path is not a directory")
        data = self.read_file(inode, max_bytes=64 * 1024 * 1024)
        entries: dict[str, int] = {}
        offset = 0
        while offset + 8 <= len(data):
            ino = _u32(data, offset)
            rec_len = _u16(data, offset + 4)
            name_len = data[offset + 6]
            if rec_len < 8:
                break
            name_bytes = data[offset + 8 : offset + 8 + name_len]
            if ino and name_bytes not in (b".", b".."):
                name = name_bytes.decode("utf-8", errors="surrogateescape")
                entries[name] = ino
            offset += rec_len
        return entries

    def lookup(self, path: str, *, follow_symlinks: bool = True, depth: int = 0) -> _ExtInode:
        if depth > 8:
            raise KaijuError("too many symlink hops in installed disk")
        parts = [part for part in path.strip("/").split("/") if part]
        inode = self.inode(2)
        parent_path = "/"
        for idx, part in enumerate(parts):
            entries = self.list_dir(inode)
            if part not in entries:
                raise KaijuError(f"installed disk path not found: {path}")
            next_inode = self.inode(entries[part])
            if follow_symlinks and next_inode.is_symlink:
                target = self.read_file(next_inode, max_bytes=4096).decode("utf-8", errors="surrogateescape")
                rest = "/".join(parts[idx + 1 :])
                if target.startswith("/"):
                    new_path = target
                else:
                    base = parent_path.rstrip("/")
                    new_path = f"{base}/{target}" if base else f"/{target}"
                if rest:
                    new_path = f"{new_path.rstrip('/')}/{rest}"
                return self.lookup(new_path, follow_symlinks=True, depth=depth + 1)
            inode = next_inode
            parent_path = "/" + "/".join(parts[: idx + 1])
        return inode


def _version_suffix(name: str, prefix: str) -> str:
    return name[len(prefix) :] if name.startswith(prefix) else ""


def _natural_key(value: str) -> list[int | str]:
    key: list[int | str] = []
    for part in re.split(r"(\d+)", value):
        if not part:
            continue
        key.append(int(part) if part.isdigit() else part)
    return key


def _select_installed_boot_pair(names: list[str]) -> tuple[str, str] | None:
    name_set = set(names)
    kernels = sorted(
        (name for name in names if name.startswith("vmlinuz-")),
        key=_natural_key,
        reverse=True,
    )
    for kernel in kernels:
        version = _version_suffix(kernel, "vmlinuz-")
        initrd = f"initrd.img-{version}"
        if initrd in name_set:
            return kernel, initrd
    if "vmlinuz" in name_set and "initrd.img" in name_set:
        return "vmlinuz", "initrd.img"
    return None


def _probe_installed_boot(disk_path: Path) -> dict[str, Any]:
    require_regular_local_file(disk_path, "Kali disk image")
    fd = os.open(disk_path, os.O_RDONLY | _cloexec() | _nofollow())
    problems: list[str] = []
    try:
        disk_size = os.fstat(fd).st_size
        for candidate in _installed_disk_candidates(fd, disk_size):
            try:
                fs = _ExtReader(fd, int(candidate["offset"]))
                boot_entries = fs.list_dir(fs.lookup("/boot"))
                selected = _select_installed_boot_pair(list(boot_entries.keys()))
                if not selected:
                    problems.append(f"no vmlinuz/initrd.img pair in partition {candidate['root_device']}")
                    continue
                kernel_name, initrd_name = selected
                kernel_inode = fs.lookup(f"/boot/{kernel_name}")
                initrd_inode = fs.lookup(f"/boot/{initrd_name}")
                if not kernel_inode.is_regular or not initrd_inode.is_regular:
                    problems.append(f"boot files are not regular files in partition {candidate['root_device']}")
                    continue
                if kernel_inode.size <= 0 or initrd_inode.size <= 0:
                    problems.append(f"boot files are empty in partition {candidate['root_device']}")
                    continue
                if kernel_inode.size > INSTALLED_BOOT_MAX_BYTES or initrd_inode.size > INSTALLED_BOOT_MAX_BYTES:
                    problems.append(f"boot files exceed size limit in partition {candidate['root_device']}")
                    continue
                return {
                    "schema": "wuci-kaiju-installed-boot-probe-v1",
                    "status": "pass",
                    "disk_path": str(disk_path),
                    "root_device": candidate["root_device"],
                    "partition_number": candidate["number"],
                    "partition_start_sector": candidate["start_sector"],
                    "filesystem": "ext",
                    "kernel_path": f"/boot/{kernel_name}",
                    "initrd_path": f"/boot/{initrd_name}",
                    "kernel_bytes": kernel_inode.size,
                    "initrd_bytes": initrd_inode.size,
                    "append": f"root={candidate['root_device']} ro console=tty0 console=ttyS0,115200n8",
                    "problems": [],
                }
            except KaijuError as exc:
                problems.append(str(exc))
        return {
            "schema": "wuci-kaiju-installed-boot-probe-v1",
            "status": "fail",
            "disk_path": str(disk_path),
            "problems": problems or ["no supported ext root partition found"],
        }
    finally:
        os.close(fd)


def _prepare_transient_dir(path: Path) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        path.mkdir(parents=True, exist_ok=True)
        return
    if stat.S_ISLNK(info.st_mode):
        raise KaijuError(f"transient boot directory must not be a symlink: {path}")
    if not stat.S_ISDIR(info.st_mode):
        raise KaijuError(f"transient boot path must be a directory: {path}")


def _write_transient_file(path: Path, data: bytes) -> None:
    reject_unsafe_existing_path(path, "transient installed boot file")
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _skip_newc_archives(data: bytes) -> int | None:
    offset = 0
    archives = 0
    size = len(data)
    while offset < size:
        while offset < size and data[offset] == 0:
            offset += 1
        if offset >= size:
            return offset if archives else None
        if data[offset : offset + 6] != b"070701":
            return offset if archives else None
        archives += 1
        while offset + 110 <= size:
            if data[offset : offset + 6] != b"070701":
                return None
            try:
                file_size = int(data[offset + 54 : offset + 62], 16)
                name_size = int(data[offset + 94 : offset + 102], 16)
            except ValueError:
                return None
            name_start = offset + 110
            name_end = name_start + name_size
            if name_size <= 0 or name_end > size:
                return None
            name = data[name_start : name_end - 1]
            data_start = (name_end + 3) & ~3
            data_end = data_start + file_size
            next_offset = (data_end + 3) & ~3
            if data_end > size or next_offset > size:
                return None
            offset = next_offset
            if name == b"TRAILER!!!":
                break
        else:
            return None
    return offset if archives else None


def _validate_installed_initrd(data: bytes) -> None:
    if data.startswith(INITRD_TAIL_MAGICS):
        return
    offset = _skip_newc_archives(data)
    if offset is None:
        raise KaijuError("installed initrd is not a supported initramfs/newc layout")
    while offset < len(data) and data[offset] == 0:
        offset += 1
    if offset >= len(data):
        return
    if data[offset:].startswith(INITRD_TAIL_MAGICS):
        return
    raise KaijuError(f"installed initrd has unsupported tail magic at byte {offset}")


def _extract_installed_boot_pair(disk_path: Path, disk_root: Path, probe: dict[str, Any]) -> tuple[Path, Path, str]:
    if probe.get("status") != "pass":
        raise KaijuError("installed disk is not ready for direct serial boot")
    require_regular_local_file(disk_path, "Kali disk image")
    fd = os.open(disk_path, os.O_RDONLY | _cloexec() | _nofollow())
    try:
        start_sector = int(probe.get("partition_start_sector", 0))
        fs = _ExtReader(fd, start_sector * DISK_SECTOR_SIZE)
        kernel_data = fs.read_file(fs.lookup(str(probe["kernel_path"])))
        initrd_data = fs.read_file(fs.lookup(str(probe["initrd_path"])))
    finally:
        os.close(fd)
    _validate_installed_initrd(initrd_data)
    work = disk_root / INSTALLED_BOOT_ROOT
    _prepare_transient_dir(work)
    kernel_path = work / "vmlinuz"
    initrd_path = work / "initrd.img"
    _write_transient_file(kernel_path, kernel_data)
    _write_transient_file(initrd_path, initrd_data)
    return kernel_path, initrd_path, str(probe["append"])


def _build_qemu_argv(
    qemu: str,
    memory_mib: int,
    cpus: int,
    *,
    cdrom: str | None = None,
    disk: str | None = None,
    network: bool = False,
    kernel: str | None = None,
    initrd: str | None = None,
    append: str | None = None,
    boot_disk: bool = False,
    share_path: str | Path | None = None,
    share_tag: str = "wuci-src",
) -> list[str]:
    """Construct the QEMU argv.
    - boot_disk=True: attach disk as primary boot device (post-install Kali), no ISO/cdrom.
    - share_path: add virtio-9p read-only share of host path (for bringing repo into guest).
    """
    argv: list[str] = [qemu, "-m", str(memory_mib), "-smp", str(cpus)]
    if boot_disk:
        # Post-install: prefer direct kernel serial boot so terminal-only QEMU
        # does not depend on a graphical GRUB menu.
        if kernel and initrd:
            argv.extend(["-kernel", str(kernel), "-initrd", str(initrd)])
            if append:
                argv.extend(["-append", append])
        if disk:
            argv.extend(["-drive", f"file={disk},format=raw,if=virtio"])
        if not kernel or not initrd:
            argv.extend(["-boot", "c"])
    else:
        if kernel and initrd:
            argv.extend(["-kernel", str(kernel), "-initrd", str(initrd)])
            if append:
                argv.extend(["-append", append])
            if cdrom:
                # Still provide the ISO as CD-ROM device so the installer can mount its own media
                argv.extend(["-cdrom", str(cdrom)])
        elif cdrom:
            argv.extend(["-cdrom", str(cdrom), "-boot", "d"])
        if disk:
            argv.extend(["-drive", f"file={disk},format=raw,if=virtio"])
    argv.extend(["-nographic", "-serial", "mon:stdio", "-no-reboot"])
    if network:
        argv.extend(["-nic", "user,model=virtio-net-pci"])
    else:
        argv.extend(["-net", "none"])
    if share_path:
        sp = str(share_path)
        # readonly 9p share; guest can mount_tag and see outer tree (e.g. to run noxframe inside Kali)
        argv.extend(["-fsdev", f"local,id=kaijusrc,path={sp},readonly=on,security_model=mapped"])
        argv.extend(["-device", f"virtio-9p-pci,fsdev=kaijusrc,mount_tag={share_tag}"])
    return argv


def build_live_boot_argv(plan: dict[str, Any]) -> list[str]:
    """Turn a boot plan into actual argv to exec. Performs kernel extraction (with ticker)
    only for installer (non-boot_disk) direct mode. Supports --boot-disk and --share-repo.
    """
    if not isinstance(plan, dict) or plan.get("schema") != BOOT_SCHEMA:
        raise KaijuError("invalid boot plan for live launch")
    boot_disk = bool(plan.get("boot_disk", False))
    disk_info = plan.get("disk", {})
    disk_path = disk_info.get("disk_path") if disk_info.get("status") == "pass" else None
    if boot_disk and not disk_path:
        raise KaijuError("disk required for live boot-disk launch")
    qemu = plan.get("qemu_bin") or (plan.get("argv") or [DEFAULT_QEMU_BIN])[0]
    mib = int(plan.get("memory_mib", DEFAULT_MEMORY_MIB))
    cpus = int(plan.get("cpus", DEFAULT_CPUS))
    net = plan.get("network") == "user"
    share_path = plan.get("share_path")
    share_tag = plan.get("share_tag", "wuci-src")

    # Prefer the discovered full path (may be qemu-kvm etc on some distros) so exec doesn't rely on bare name in PATH
    disc = plan.get("qemu_discovered")
    qemu_req = plan.get("qemu_bin", DEFAULT_QEMU_BIN)
    qemu = disc if (disc and disc != "not found on PATH") else qemu_req

    ticker = _make_kaiju_ticker("wuci-kaiju boot")
    k_path: Path | None = None
    i_path: Path | None = None
    append: str | None = None
    img_path = None
    if boot_disk:
        installed_boot = plan.get("installed_boot", {})
        if installed_boot.get("status") != "pass":
            problems = "; ".join(str(p) for p in installed_boot.get("problems", []))
            suffix = f": {problems}" if problems else ""
            raise KaijuError("installed Kali disk kernel/initrd not discoverable for terminal boot" + suffix)
        disk_root = Path(str(disk_info.get("disk_root") or Path(str(disk_path)).parent))
        k_path, i_path, append = _extract_installed_boot_pair(Path(str(disk_path)), disk_root, installed_boot)
        _boot_log("direct installed kernel+initrd ready (GRUB bypass)")
    else:
        iso_info = plan.get("iso", {})
        if iso_info.get("status") != "pass":
            raise KaijuError("Kali ISO not ready for installer boot")
        img_str = iso_info.get("image_path", "")
        if not img_str:
            raise KaijuError("missing image_path in plan")
        img_path = Path(img_str)
        if plan.get("direct_kernel_supported"):
            _boot_log("preparing serial console kernel boot (installer)")
            work = img_path.parent / ".kaiju-boot"
            try:
                k_path, i_path = _extract_boot_kernel_pair(img_path, work, ticker=ticker)
            except Exception as exc:
                k_path = i_path = None
                _boot_log(f"kernel extract fallback: {exc}")
            if k_path and i_path:
                append = "console=ttyS0,115200n8 earlyprintk=ttyS0,115200 console=tty0 debian-installer/framebuffer=false"
                _boot_log("direct kernel+initrd ready (no isolinux)")
    actual_argv = _build_qemu_argv(
        qemu,
        mib,
        cpus,
        cdrom=None if boot_disk else (str(img_path) if img_path else None),
        disk=disk_path,
        network=net,
        kernel=str(k_path) if k_path else None,
        initrd=str(i_path) if i_path else None,
        append=append,
        boot_disk=boot_disk,
        share_path=share_path,
        share_tag=share_tag,
    )
    ticker.finish(ok=True)
    return actual_argv


def _cleanup_boot_artifacts(iso_image_path: str | Path) -> None:
    """Remove transient extracted kernel/initrd after boot completes."""
    try:
        p = Path(iso_image_path)
        work = p.parent / ".kaiju-boot"
        for fn in ("vmlinuz", "initrd.gz"):
            f = work / fn
            if f.exists() and f.is_file():
                f.unlink()
        if work.exists():
            try:
                work.rmdir()
            except OSError:
                pass
    except Exception:
        pass


def _cleanup_installed_boot_artifacts(disk_root: str | Path) -> None:
    """Remove transient installed-disk kernel/initrd after boot completes."""
    try:
        work = Path(disk_root) / INSTALLED_BOOT_ROOT
        for fn in ("vmlinuz", "initrd.img"):
            path = work / fn
            if path.exists() and path.is_file():
                path.unlink()
        if work.exists():
            try:
                work.rmdir()
            except OSError:
                pass
    except Exception:
        pass


def _reset_terminal_to_sane() -> None:
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        return
    try:
        sys.stdout.write("\033[?1049l\033[?25h\033[0m\033[?7h\033[r")
        sys.stdout.flush()
    except OSError:
        return
    try:
        fd = sys.stdin.fileno()
        attrs = termios.tcgetattr(fd)
        attrs[3] |= termios.ICANON | termios.ECHO | termios.ISIG
        termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    except (OSError, termios.error):
        pass


def _run_qemu_terminal(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    is_tty = sys.stdout.isatty() and sys.stdin.isatty()
    old_attrs = None
    fd = None
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    if is_tty:
        fd = sys.stdin.fileno()
        try:
            old_attrs = termios.tcgetattr(fd)
        except (OSError, termios.error):
            old_attrs = None
        sys.stdout.write("\033[?1049h\033[H\033[2J\033[?25l")
        sys.stdout.flush()
        try:
            size = shutil.get_terminal_size(fallback=(80, 24))
            rows, cols = size.lines, size.columns
            winsz = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)
        except Exception:
            pass
    try:
        return subprocess.run(argv, check=False, shell=False, env=env)
    finally:
        if is_tty:
            sys.stdout.write("\033[?1049l\033[?25h\033[0m\r\n")
            sys.stdout.flush()
            if old_attrs is not None and fd is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)
                except (OSError, termios.error):
                    pass
        _reset_terminal_to_sane()


def clean(iso_root: Path | None = None, disk_root: Path | None = None) -> dict[str, Any]:
    """Wipe installed ISO and disk state (for clean demos/recordings from beginning)."""
    iso_r = default_iso_root() if iso_root is None else iso_root
    disk_r = default_disk_root() if disk_root is None else disk_root
    removed: list[str] = []
    for root in (iso_r, disk_r):
        if root.exists():
            for entry in list(root.iterdir()):
                try:
                    if entry.is_file() or entry.is_symlink():
                        entry.unlink()
                        removed.append(str(entry))
                    elif entry.is_dir() and entry.name.startswith(".kaiju"):
                        # transient
                        shutil.rmtree(entry, ignore_errors=True)
                        removed.append(str(entry))
                except Exception:
                    pass
    # also nuke any transient boot dir at iso root
    trans = iso_r / ".kaiju-boot"
    if trans.exists():
        try:
            shutil.rmtree(trans, ignore_errors=True)
            removed.append(str(trans))
        except Exception:
            pass
    return {
        "schema": "wuci-kaiju-clean-v1",
        "status": "cleaned",
        "removed": removed,
    }


def install_iso(
    source: Path,
    *,
    iso_root: Path | None = None,
    name: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    source = source if source.is_absolute() else Path.cwd() / source
    source_info = require_regular_local_file(source, "Kali ISO source")
    iso_name = safe_iso_name(name or source.name)
    root = default_iso_root() if iso_root is None else iso_root
    ensure_output_directory_root(root, "Kali ISO workspace root")
    dest = root / iso_name
    try:
        if source.resolve(strict=True) == dest.resolve(strict=False):
            raise KaijuError("Kali ISO source and destination must differ")
    except OSError:
        pass
    prepare_output_path(dest, "installed Kali ISO", force=force)

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{iso_name}.", dir=str(root))
    digests = {
        "sha256": hashlib.sha256(),
        "sha384": hashlib.sha384(),
        "sha512": hashlib.sha512(),
    }
    total = 0
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    ticker = _make_kaiju_ticker("wuci-kaiju iso")
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        os.close(tmp_fd)
        os.unlink(tmp_name)
        raise KaijuError(f"could not open Kali ISO source: {source}") from exc
    try:
        opened = os.fstat(source_fd)
        if opened.st_ino != source_info.st_ino or opened.st_dev != source_info.st_dev:
            raise KaijuError(f"Kali ISO source changed while opening: {source}")
        ticker.pulse(detail=f"copy {source.name}")
        with os.fdopen(tmp_fd, "wb") as out_handle:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                for digest in digests.values():
                    digest.update(chunk)
                out_handle.write(chunk)
                ticker.tick(total, source_info.st_size, detail=f"{total // (1024*1024)}MiB")
            out_handle.flush()
            os.fsync(out_handle.fileno())
        ticker.finish(ok=True)
        if total == 0:
            raise KaijuError("Kali ISO source is empty")
        prepare_output_path(dest, "installed Kali ISO", force=force)
        os.replace(tmp_name, dest)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        ticker.finish(ok=False)
        raise
    finally:
        os.close(source_fd)

    manifest: dict[str, Any] = {
        "schema": ISO_SCHEMA,
        "name": "WUCI-KAIJU Kali ISO",
        "installed_utc": utc_now(),
        "source_path": str(source),
        "source_basename": source.name,
        "image_path": str(dest),
        "image_bytes": total,
        "digest_vector": {name: digest.hexdigest() for name, digest in digests.items()},
        "boot_profile": {
            "graphics": "none",
            "serial": "stdio",
            "default_network": "none",
            "launcher": DEFAULT_QEMU_BIN,
        },
        "guards": {
            "source_symlink": "rejected",
            "source_hardlink": "rejected",
            "installed_symlink": "rejected",
            "installed_hardlink": "rejected",
            "shell": "disabled",
            "network": "disabled by default",
        },
        "non_claims": [
            "not a host shell",
            "not NOXFRAME runtime containment",
            "not a Kali tool execution grant",
            "not a network authorization",
        ],
    }
    write_json_atomic(iso_manifest_path(root), manifest)
    return manifest


def verify_iso_install(iso_root: Path | None = None) -> dict[str, Any]:
    root = default_iso_root() if iso_root is None else iso_root
    problems: list[str] = []
    try:
        manifest = read_iso_manifest(root)
    except KaijuError as exc:
        return {
            "schema": "wuci-kaiju-iso-verification-v1",
            "status": "fail",
            "iso_root": str(root),
            "problems": [str(exc)],
        }
    if manifest.get("schema") != ISO_SCHEMA:
        problems.append("ISO manifest schema mismatch")
    image_path_value = manifest.get("image_path")
    if not isinstance(image_path_value, str):
        problems.append("ISO manifest image_path missing")
        image_path = root / "missing.iso"
    else:
        image_path = Path(image_path_value)
    try:
        digest_vector, size = file_digest_vector(image_path, "installed Kali ISO")
    except KaijuError as exc:
        problems.append(str(exc))
        digest_vector = {}
        size = -1
    if digest_vector and manifest.get("digest_vector") != digest_vector:
        problems.append("installed ISO digest mismatch")
    if size >= 0 and manifest.get("image_bytes") != size:
        problems.append("installed ISO size mismatch")
    return {
        "schema": "wuci-kaiju-iso-verification-v1",
        "status": "pass" if not problems else "fail",
        "iso_root": str(root),
        "image_path": str(image_path),
        "image_bytes": size,
        "problems": problems,
    }


def iso_status_text(iso_root: Path | None = None) -> str:
    result = verify_iso_install(iso_root)
    rows = [
        "schema: wuci-kaiju-iso-status-v1",
        f"status: {result['status']}",
        f"iso_root: {result['iso_root']}",
    ]
    if result["status"] == "pass":
        rows.extend(
            [
                f"image: {result['image_path']}",
                f"bytes: {result['image_bytes']}",
                "boot: non-graphical QEMU plan available",
            ]
        )
    else:
        rows.append("boot: unavailable until a local ISO is installed")
        rows.extend(f"problem: {problem}" for problem in result.get("problems", []))
    rows.append("")
    return "\n".join(rows)


def create_disk(
    *,
    disk_root: Path | None = None,
    size_mib: int,
    force: bool = False,
    name: str = "kali.raw",
) -> dict[str, Any]:
    if size_mib < 1 or size_mib > 262144:
        raise KaijuError("disk size must be between 1 and 262144 MiB")
    if "/" in name or name in {"", ".", ".."}:
        raise KaijuError("disk name must be a plain filename")
    root = default_disk_root() if disk_root is None else disk_root
    ensure_output_directory_root(root, "disk workspace root")
    disk_path = root / name
    prepare_output_path(disk_path, "disk image", force=force)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=f".{name}.", dir=str(root))
    ticker = _make_kaiju_ticker("wuci-kaiju disk")
    try:
        ticker.pulse(detail=f"alloc {size_mib}MiB sparse")
        os.ftruncate(tmp_fd, size_mib * 1024 * 1024)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = -1
        os.replace(tmp_name, disk_path)
        ticker.finish(ok=True)
    except Exception:
        if tmp_fd >= 0:
            os.close(tmp_fd)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        ticker.finish(ok=False)
        raise
    manifest: dict[str, Any] = {
        "schema": DISK_SCHEMA,
        "created_utc": utc_now(),
        "disk_path": str(disk_path),
        "format": "raw",
        "size_mib": size_mib,
        "mutable": True,
        "guards": {
            "shell": "disabled",
            "network": "not applicable",
            "symlink": "rejected",
            "hardlink": "rejected",
        },
        "non_claims": [
            "not public evidence",
            "not runtime containment",
            "not encrypted storage",
        ],
    }
    write_json_atomic(disk_manifest_path(root), manifest)
    return manifest


def verify_disk(disk_root: Path | None = None) -> dict[str, Any]:
    root = default_disk_root() if disk_root is None else disk_root
    problems: list[str] = []
    try:
        manifest = read_disk_manifest(root)
    except KaijuError as exc:
        return {
            "schema": "wuci-kaiju-disk-verification-v1",
            "status": "fail",
            "disk_root": str(root),
            "problems": [str(exc)],
        }
    if manifest.get("schema") != DISK_SCHEMA:
        problems.append("disk manifest schema mismatch")
    disk_path_value = manifest.get("disk_path")
    if not isinstance(disk_path_value, str):
        problems.append("disk manifest disk_path missing")
        disk_path = root / "missing.raw"
    else:
        disk_path = Path(disk_path_value)
    try:
        info = require_regular_local_file(disk_path, "Kali disk image")
    except KaijuError as exc:
        problems.append(str(exc))
        size = -1
    else:
        size = info.st_size
        if manifest.get("size_mib") != size // (1024 * 1024):
            problems.append("disk size mismatch")
    return {
        "schema": "wuci-kaiju-disk-verification-v1",
        "status": "pass" if not problems else "fail",
        "disk_root": str(root),
        "disk_path": str(disk_path),
        "disk_bytes": size,
        "problems": problems,
    }


def disk_status_text(disk_root: Path | None = None) -> str:
    result = verify_disk(disk_root)
    rows = [
        "schema: wuci-kaiju-disk-status-v1",
        f"status: {result['status']}",
        f"disk_root: {result['disk_root']}",
    ]
    if result["status"] == "pass":
        rows.extend([f"disk: {result['disk_path']}", f"bytes: {result['disk_bytes']}"])
    else:
        rows.append("disk: absent")
        rows.extend(f"problem: {problem}" for problem in result.get("problems", []))
    rows.append("")
    return "\n".join(rows)


def discover_qemu(qemu_bin: str = DEFAULT_QEMU_BIN) -> str | None:
    candidates = [qemu_bin]
    if qemu_bin == DEFAULT_QEMU_BIN:
        candidates.extend(candidate for candidate in DEFAULT_QEMU_CANDIDATES if candidate not in candidates)
    for candidate in candidates:
        if os.sep in candidate:
            path = Path(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
            continue
        found = shutil.which(candidate)
        if found:
            return found
    return None


def qemu_supports_virtio_9p(qemu_bin: str | None) -> bool:
    if not qemu_bin:
        return False
    try:
        result = subprocess.run(
            [qemu_bin, "-device", "help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return "virtio-9p-pci" in result.stdout


def boot_plan(
    *,
    iso_root: Path | None = None,
    disk_root: Path | None = None,
    qemu_bin: str = DEFAULT_QEMU_BIN,
    memory_mib: int = DEFAULT_MEMORY_MIB,
    cpus: int = DEFAULT_CPUS,
    network: bool = False,
    boot_disk: bool = False,
    share_repo: Path | None = None,
    share_tag: str = "wuci-src",
) -> dict[str, Any]:
    if memory_mib < 512 or memory_mib > 262144:
        raise KaijuError("memory must be between 512 and 262144 MiB")
    if cpus < 1 or cpus > 256:
        raise KaijuError("cpus must be between 1 and 256")
    qemu_path = discover_qemu(qemu_bin)
    share_problem = ""
    share_path = share_repo
    if share_repo and not qemu_supports_virtio_9p(qemu_path or qemu_bin):
        share_problem = "QEMU does not advertise virtio-9p-pci; use --allow-network and git clone inside Kali"
        share_path = None
    disk_root_path = default_disk_root() if disk_root is None else disk_root
    disk_result = verify_disk(disk_root)
    disk_path = disk_result.get("disk_path") if disk_result["status"] == "pass" else None
    if boot_disk and not disk_path:
        raise KaijuError("a disk image is required for boot-disk (installed system) mode")
    installed_boot: dict[str, Any] = {
        "schema": "wuci-kaiju-installed-boot-probe-v1",
        "status": "not-required",
        "problems": [],
    }
    boot_kernel = boot_initrd = boot_append = None
    if boot_disk:
        iso_result: dict[str, Any] = {
            "schema": "wuci-kaiju-iso-status-v1",
            "status": "not-required",
            "iso_root": str(default_iso_root() if iso_root is None else iso_root),
            "note": "booting installed system from disk; ISO not used",
        }
        img_path = ""
        installed_boot = _probe_installed_boot(Path(str(disk_path)))
        direct_supported = installed_boot.get("status") == "pass"
        if direct_supported:
            boot_kernel = str(disk_root_path / INSTALLED_BOOT_ROOT / "vmlinuz")
            boot_initrd = str(disk_root_path / INSTALLED_BOOT_ROOT / "initrd.img")
            boot_append = str(installed_boot["append"])
    else:
        iso_result = verify_iso_install(iso_root)
        if iso_result["status"] != "pass":
            raise KaijuError("Kali ISO is not installed: " + "; ".join(iso_result["problems"]))
        img_path = str(iso_result["image_path"])
        direct_supported = False
        if qemu_path:
            try:
                if (_locate_iso_file(Path(img_path), "install.amd/vmlinuz") and
                        _locate_iso_file(Path(img_path), "install.amd/initrd.gz")):
                    direct_supported = True
            except Exception:
                direct_supported = False
    argv = _build_qemu_argv(
        qemu_path or qemu_bin,
        memory_mib,
        cpus,
        cdrom=None if boot_disk else img_path,
        disk=disk_path,
        network=network,
        kernel=boot_kernel,
        initrd=boot_initrd,
        append=boot_append,
        boot_disk=boot_disk,
        share_path=share_path,
        share_tag=share_tag,
    )
    if boot_disk and not direct_supported:
        argv = []
    if share_problem:
        argv = []
    plan_status = "blocked" if (boot_disk and not direct_supported) or share_problem else "ready"
    result: dict[str, Any] = {
        "schema": BOOT_SCHEMA,
        "status": plan_status,
        "argv": argv,
        "qemu_bin": qemu_bin,
        "qemu_discovered": qemu_path or "not found on PATH",
        "qemu_candidates": list(DEFAULT_QEMU_CANDIDATES) if qemu_bin == DEFAULT_QEMU_BIN else [qemu_bin],
        "graphics": "none",
        "console": "serial mon:stdio",
        "network": "user" if network else "none",
        "iso": iso_result,
        "disk": disk_result,
        "memory_mib": memory_mib,
        "cpus": cpus,
        "boot_disk": boot_disk,
        "direct_kernel_supported": direct_supported,
        "installed_boot": installed_boot,
        "launch_mode": (
            "direct-installed-kernel+serial"
            if boot_disk and direct_supported
            else ("installed-disk-terminal-boot-blocked" if boot_disk else ("direct-kernel+serial" if direct_supported else "cdrom+isolinux"))
        ),
        "exit_hint": "Ctrl-a x to quit QEMU (nographic). Installed-disk mode bypasses GRUB when a readable kernel/initrd pair is found on the raw disk.",
        "non_claims": [
            "NOXFRAME is launching a local VM process, not enforcing a kernel sandbox",
            "Kali tools are not exposed as NOXFRAME commands",
            "network and host shares are disabled unless explicitly requested for the bridge",
            "the guest is a separate QEMU process; inner noxframe instances are just normal processes inside it",
        ],
    }
    if share_repo:
        result["share"] = not bool(share_problem)
        result["share_requested"] = True
        result["share_status"] = "unsupported" if share_problem else "ready"
        result["share_requested_path"] = str(share_repo)
        result["share_tag"] = share_tag
        if share_problem:
            result["share_problem"] = share_problem
        else:
            result["share_path"] = str(share_repo)
            result["guest_mount_hint"] = f"mkdir -p /mnt/wuci && mount -t 9p -o trans=virtio,version=9p2000.L {share_tag} /mnt/wuci"
    if direct_supported and not boot_disk:
        result["append"] = "console=ttyS0,115200n8 earlyprintk=ttyS0,115200 console=tty0 debian-installer/framebuffer=false"
    return result


def iter_dicts(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        found.append(value)
        for child in value.values():
            found.extend(iter_dicts(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(iter_dicts(child))
    return found


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if manifest.get("schema") != SCHEMA:
        problems.append("schema mismatch")
    if manifest.get("name") != "WUCI-KAIJU":
        problems.append("name mismatch")

    boundary = manifest.get("boundary")
    if not isinstance(boundary, dict):
        problems.append("boundary must be an object")
    else:
        for key in ("host_execution", "network_access", "shell"):
            if boundary.get(key) != "unavailable":
                problems.append(f"boundary {key} must be unavailable")
        if boundary.get("runtime_sandbox_claim") != "none":
            problems.append("boundary runtime_sandbox_claim must be none")

    boot_bridge = manifest.get("boot_bridge")
    if boot_bridge is not None:
        if not isinstance(boot_bridge, dict):
            problems.append("boot_bridge must be an object")
        else:
            if boot_bridge.get("graphics") != "none":
                problems.append("boot_bridge graphics must be none")
            if boot_bridge.get("default_network") != "none":
                problems.append("boot_bridge default_network must be none")
            if boot_bridge.get("host_execution") != "explicit --allow-kaiju-boot only":
                problems.append("boot_bridge host_execution must require --allow-kaiju-boot")

    for item in iter_dicts(manifest):
        for key in item:
            if key in FORBIDDEN_KEYS:
                problems.append(f"forbidden key present: {key}")

    purposes = manifest.get("purposes")
    if not isinstance(purposes, list):
        problems.append("purposes must be a list")
        return problems

    seen: set[str] = set()
    for index, purpose in enumerate(purposes):
        if not isinstance(purpose, dict):
            problems.append(f"purpose {index} must be an object")
            continue
        purpose_id = purpose.get("id")
        if not isinstance(purpose_id, str) or not purpose_id:
            problems.append(f"purpose {index} has invalid id")
            continue
        if purpose_id in seen:
            problems.append(f"duplicate purpose id: {purpose_id}")
        seen.add(purpose_id)
        if purpose.get("risk_gate") not in {"metadata-only", "blocked-by-noxframe"}:
            problems.append(f"{purpose_id}: invalid risk_gate")
        tools = purpose.get("selected_tools")
        if not isinstance(tools, list) or not tools:
            problems.append(f"{purpose_id}: selected_tools must be non-empty")
            continue
        for tool_index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                problems.append(f"{purpose_id}: tool {tool_index} must be an object")
                continue
            missing = sorted(REQUIRED_TOOL_KEYS - set(tool))
            if missing:
                problems.append(f"{purpose_id}: tool {tool_index} missing {','.join(missing)}")
            if tool.get("host_execution") != "unavailable":
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} host_execution must be unavailable")
            if tool.get("disposition") not in ALLOWED_DISPOSITIONS:
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} invalid disposition")
            url = tool.get("kali_url")
            if not isinstance(url, str) or not url.startswith("https://www.kali.org/tools/"):
                problems.append(f"{purpose_id}: {tool.get('name', tool_index)} must use Kali tool URL")

    missing_purposes = sorted(set(REQUIRED_PURPOSES) - seen)
    extra_purposes = sorted(seen - set(REQUIRED_PURPOSES))
    if missing_purposes:
        problems.append("missing required purpose(s): " + ",".join(missing_purposes))
    if extra_purposes:
        problems.append("unexpected purpose(s): " + ",".join(extra_purposes))

    denials = manifest.get("global_denials")
    if not isinstance(denials, list) or "no offensive scanning" not in denials:
        problems.append("global_denials must include no offensive scanning")
    return problems


def load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = default_manifest_path() if path is None else path
    return read_public_json(manifest_path)


def verify_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = default_manifest_path() if path is None else path
    manifest = load_manifest(manifest_path)
    problems = validate_manifest(manifest)
    purposes = manifest.get("purposes", [])
    tool_count = 0
    if isinstance(purposes, list):
        for purpose in purposes:
            if isinstance(purpose, dict) and isinstance(purpose.get("selected_tools"), list):
                tool_count += len(purpose["selected_tools"])
    return {
        "schema": "wuci-kaiju-verification-v1",
        "status": "pass" if not problems else "fail",
        "manifest": str(manifest_path),
        "purpose_count": len(purposes) if isinstance(purposes, list) else 0,
        "selected_tool_count": tool_count,
        "problems": problems,
    }


def manifest_status_text(manifest: dict[str, Any]) -> str:
    purposes = manifest.get("purposes", [])
    tool_count = 0
    blocked = 0
    if isinstance(purposes, list):
        for purpose in purposes:
            if not isinstance(purpose, dict):
                continue
            if purpose.get("risk_gate") == "blocked-by-noxframe":
                blocked += 1
            tools = purpose.get("selected_tools")
            if isinstance(tools, list):
                tool_count += len(tools)
    return "\n".join(
        [
            "schema: wuci-kaiju-status-v1",
            f"name: {manifest.get('name', 'WUCI-KAIJU')}",
            f"catalog_schema: {manifest.get('schema')}",
            f"purposes: {len(purposes) if isinstance(purposes, list) else 0}",
            f"selected_tools: {tool_count}",
            f"blocked_purposes: {blocked}",
            "kali_tool_execution: unavailable",
            "iso_boot_bridge: non-graphical QEMU, explicit opt-in",
            "default_vm_network: none",
            "shell: unavailable",
            "non_claim: not runtime containment",
            "",
        ]
    )


def manifest_policy_text(manifest: dict[str, Any]) -> str:
    boundary = manifest.get("boundary", {})
    denials = manifest.get("global_denials", [])
    rows = [
        "schema: wuci-kaiju-policy-v1",
        f"mode: {boundary.get('mode', 'metadata-only') if isinstance(boundary, dict) else 'metadata-only'}",
        "kali_tool_execution: unavailable",
        "iso_boot_bridge: explicit local QEMU bridge only",
        "default_vm_network: none",
        "shell: unavailable",
        "substrate_use: catalog read/verify/list plus operator-supplied ISO boot",
        "",
        "denials:",
    ]
    if isinstance(denials, list):
        rows.extend(f"- {item}" for item in denials)
    rows.append("")
    return "\n".join(rows)


def purpose_rows(manifest: dict[str, Any], purpose_id: str | None = None) -> list[str]:
    rows: list[str] = []
    purposes = manifest.get("purposes", [])
    if not isinstance(purposes, list):
        return ["kaiju: invalid manifest purposes"]
    for purpose in purposes:
        if not isinstance(purpose, dict):
            continue
        current_id = purpose.get("id")
        if purpose_id is not None and current_id != purpose_id:
            continue
        rows.append(
            f"{current_id}: {purpose.get('summary', '')} gate={purpose.get('risk_gate', 'unknown')}"
        )
        tools = purpose.get("selected_tools", [])
        if isinstance(tools, list):
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                rows.append(
                    "  - "
                    f"{tool.get('package')}: {tool.get('role')} "
                    f"disposition={tool.get('disposition')} host_execution={tool.get('host_execution')}"
                )
    if purpose_id is not None and not rows:
        rows.append(f"kaiju: no purpose named {purpose_id}")
    return rows


def manifest_list_text(manifest: dict[str, Any], purpose_id: str | None = None) -> str:
    return "\n".join(["schema: wuci-kaiju-purpose-list-v1", *purpose_rows(manifest, purpose_id), ""])


def resolve_manifest_arg(value: str | None) -> Path:
    if value is None:
        return default_manifest_path()
    path = Path(value)
    return path if path.is_absolute() else Path.cwd() / path


def resolve_root_arg(value: str | None, default: Path) -> Path:
    if value is None:
        return default
    path = Path(value)
    return path if path.is_absolute() else Path.cwd() / path


def command_status(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_status_text(manifest), end="")
    return 0


def command_policy(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_policy_text(manifest), end="")
    return 0


def command_list(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(manifest_list_text(manifest, args.purpose), end="")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    result = verify_manifest(resolve_manifest_arg(args.manifest))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["status"] == "pass":
        print(
            "wuci-kaiju: PASS "
            f"purposes={result['purpose_count']} selected_tools={result['selected_tool_count']}"
        )
    else:
        print("wuci-kaiju: FAIL")
        for problem in result["problems"]:
            print(f"- {problem}")
    return 0 if result["status"] == "pass" else 1


def command_manifest(args: argparse.Namespace) -> int:
    manifest = load_manifest(resolve_manifest_arg(args.manifest))
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def command_iso(args: argparse.Namespace) -> int:
    iso_root = resolve_root_arg(args.iso_root, default_iso_root())
    subcommand = args.iso_command or "status"
    if subcommand == "status":
        print(iso_status_text(iso_root), end="")
        return 0
    if subcommand == "install":
        manifest = install_iso(
            Path(args.source),
            iso_root=iso_root,
            name=args.name,
            force=args.force,
        )
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju iso: installed {manifest['image_path']}")
            print(f"bytes: {manifest['image_bytes']}")
            print(f"sha256: {manifest['digest_vector']['sha256']}")
        return 0
    if subcommand == "verify":
        result = verify_iso_install(iso_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju iso verify: {result['status']}")
            for problem in result.get("problems", []):
                print(f"problem: {problem}")
        return 0 if result["status"] == "pass" else 1
    raise KaijuError(f"unsupported iso command: {subcommand}")


def command_disk(args: argparse.Namespace) -> int:
    disk_root = resolve_root_arg(args.disk_root, default_disk_root())
    subcommand = args.disk_command or "status"
    if subcommand == "status":
        print(disk_status_text(disk_root), end="")
        return 0
    if subcommand == "create":
        manifest = create_disk(
            disk_root=disk_root,
            size_mib=args.size_mib,
            force=args.force,
            name=args.name,
        )
        if args.json:
            print(json.dumps(manifest, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju disk: created {manifest['disk_path']}")
            print(f"size-mib: {manifest['size_mib']}")
        return 0
    if subcommand == "verify":
        result = verify_disk(disk_root)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"wuci-kaiju disk verify: {result['status']}")
            for problem in result.get("problems", []):
                print(f"problem: {problem}")
        return 0 if result["status"] == "pass" else 1
    raise KaijuError(f"unsupported disk command: {subcommand}")


def command_clean(args: argparse.Namespace) -> int:
    result = clean()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("wuci-kaiju clean: state wiped for fresh start")
        for r in result.get("removed", []):
            print(f"  removed: {r}")
    return 0


def command_boot(args: argparse.Namespace) -> int:
    share = repo_root() if getattr(args, "share_repo", False) else None
    plan = boot_plan(
        iso_root=resolve_root_arg(args.iso_root, default_iso_root()),
        disk_root=resolve_root_arg(args.disk_root, default_disk_root()),
        qemu_bin=args.qemu_bin,
        memory_mib=args.memory_mib,
        cpus=args.cpus,
        network=args.allow_network,
        boot_disk=getattr(args, "boot_disk", False),
        share_repo=share,
    )
    if args.json or not args.run:
        print(json.dumps(plan, indent=2, sort_keys=True))
    if not args.run:
        return 0
    disc = plan.get("qemu_discovered")
    if not disc or disc == "not found on PATH":
        raise KaijuError(f"QEMU executable not found: {args.qemu_bin}; {QEMU_INSTALL_HINT}")
    if plan.get("status") != "ready":
        print(f"wuci-kaiju: boot plan {plan.get('status')}", file=sys.stderr)
        if plan.get("share_problem"):
            print(f"wuci-kaiju: {plan['share_problem']}", file=sys.stderr)
        for problem in plan.get("installed_boot", {}).get("problems", []):
            print(f"wuci-kaiju: {problem}", file=sys.stderr)
        return 1
    try:
        argv = build_live_boot_argv(plan)
    except KaijuError as exc:
        print(f"wuci-kaiju: {exc}", file=sys.stderr)
        return 1
    print("wuci-kaiju boot: launching non-graphical QEMU")
    print("launch_mode: " + plan.get("launch_mode", "cdrom"))
    if plan.get("share"):
        print("share: " + plan.get("share_path", ""))
        print("guest hint: " + plan.get("guest_mount_hint", ""))
    print("argv: " + " ".join(argv))
    if plan.get("boot_disk"):
        print("note: booting installed Kali by direct kernel/initrd serial path; GRUB is bypassed.")
    if plan.get("share"):
        print("note: 9p share ready. Inside guest: mkdir -p /mnt/wuci && mount -t 9p -o trans=virtio,version=9p2000.L wuci-src /mnt/wuci")
        print("      then: cd /mnt/wuci && python3 tools/wuci-noxframe   # starts another noxframe inside the kaiju guest")
    print("      Network in guest (for git clone) requires --allow-network. Exit qemu with Ctrl-a x .")
    result = _run_qemu_terminal(argv)
    _cleanup_boot_artifacts(plan.get("iso", {}).get("image_path", ""))
    _cleanup_installed_boot_artifacts(plan.get("disk", {}).get("disk_root", default_disk_root()))
    return result.returncode


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify and inspect the WUCI-KAIJU catalog.")
    parser.add_argument(
        "--manifest",
        help="WUCI-KAIJU manifest path; defaults to docs/noxframe/wuci_kaiju_manifest.json",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="show catalog status")
    subparsers.add_parser("policy", help="show catalog boundary policy")
    list_parser = subparsers.add_parser("list", help="list selected tools by purpose")
    list_parser.add_argument("--purpose", help="filter to one purpose id")
    verify_parser = subparsers.add_parser("verify", help="verify catalog structure and guards")
    verify_parser.add_argument("--json", action="store_true", help="emit JSON verification result")
    subparsers.add_parser("manifest", help="print canonical manifest JSON")

    iso_parser = subparsers.add_parser("iso", help="install and verify a local Kali ISO")
    iso_parser.add_argument("--iso-root", help="NOXFRAME Kaiju ISO workspace")
    iso_subparsers = iso_parser.add_subparsers(dest="iso_command")
    iso_subparsers.add_parser("status", help="show installed ISO status")
    iso_install = iso_subparsers.add_parser("install", help="copy a local operator-supplied ISO")
    iso_install.add_argument("source", help="local Kali ISO path")
    iso_install.add_argument("--name", help="installed ISO filename; defaults to source basename")
    iso_install.add_argument("--force", action="store_true", help="replace an existing installed ISO")
    iso_install.add_argument("--json", action="store_true", help="emit JSON install manifest")
    iso_verify = iso_subparsers.add_parser("verify", help="verify installed ISO digest evidence")
    iso_verify.add_argument("--json", action="store_true", help="emit JSON verification result")

    disk_parser = subparsers.add_parser("disk", help="create and verify a raw Kali VM disk")
    disk_parser.add_argument("--disk-root", help="NOXFRAME Kaiju disk workspace")
    disk_subparsers = disk_parser.add_subparsers(dest="disk_command")
    disk_subparsers.add_parser("status", help="show disk status")
    disk_create = disk_subparsers.add_parser("create", help="create a sparse raw disk image")
    disk_create.add_argument("--size-mib", type=int, required=True, help="disk size in MiB")
    disk_create.add_argument("--name", default="kali.raw", help="disk filename")
    disk_create.add_argument("--force", action="store_true", help="replace an existing disk image")
    disk_create.add_argument("--json", action="store_true", help="emit JSON disk manifest")
    disk_verify = disk_subparsers.add_parser("verify", help="verify disk image metadata")
    disk_verify.add_argument("--json", action="store_true", help="emit JSON verification result")

    clean_parser = subparsers.add_parser("clean", help="wipe kaiju iso/disk state for a clean from-scratch recording/demo")
    clean_parser.add_argument("--json", action="store_true")

    boot_parser = subparsers.add_parser("boot", help="build or run a non-graphical QEMU Kali boot (installer or installed disk)")
    boot_parser.add_argument("--iso-root", help="NOXFRAME Kaiju ISO workspace")
    boot_parser.add_argument("--disk-root", help="NOXFRAME Kaiju disk workspace")
    boot_parser.add_argument("--qemu-bin", default=DEFAULT_QEMU_BIN, help="QEMU executable")
    boot_parser.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB, help="VM memory in MiB")
    boot_parser.add_argument("--cpus", type=int, default=DEFAULT_CPUS, help="VM CPU count")
    boot_parser.add_argument("--allow-network", action="store_true", help="enable QEMU user networking (for git etc inside guest)")
    boot_parser.add_argument("--boot-disk", "--from-disk", dest="boot_disk", action="store_true", help="boot the installed Kali system from the raw disk (after installer has written to it); no ISO")
    boot_parser.add_argument("--share-repo", action="store_true", help="expose the wuci source tree read-only to the guest via 9p (mount_tag=wuci-src). Useful to run inner noxframe without separate clone.")
    boot_parser.add_argument("--run", action="store_true", help="launch QEMU instead of printing the plan")
    boot_parser.add_argument("--json", action="store_true", help="emit JSON boot plan")

    args = parser.parse_args(argv)
    if args.command is None:
        args.command = "status"
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "status":
            return command_status(args)
        if args.command == "policy":
            return command_policy(args)
        if args.command == "list":
            return command_list(args)
        if args.command == "verify":
            return command_verify(args)
        if args.command == "manifest":
            return command_manifest(args)
        if args.command == "iso":
            return command_iso(args)
        if args.command == "disk":
            return command_disk(args)
        if args.command == "clean":
            return command_clean(args)
        if args.command == "boot":
            return command_boot(args)
    except KaijuError as exc:
        print(f"wuci-kaiju: {exc}", file=sys.stderr)
        return 1
    raise KaijuError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
