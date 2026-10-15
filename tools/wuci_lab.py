#!/usr/bin/env python3
"""Launch a tightly bounded Wuci lab virtual machine.

This supervisor is deliberately host-side and stdlib-only.  It binds every
boot input to an operator-supplied SHA-256 digest, keeps the raw base image
behind either a private volatile qcow2 overlay or a named persistent qcow2
overlay, and constructs QEMU as a fixed argument vector.

The hostile profile is fail-closed, but it is still defense in depth around a
QEMU/KVM process.  It is not a claim that QEMU, KVM, the host kernel, firmware,
or hardware are free from vulnerabilities or side channels.
"""

from __future__ import annotations

import argparse
import copy
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import termios
import time
import tty
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = REPO_ROOT / "build"
DEFAULT_STATE_ROOT = BUILD_ROOT / "wuci-lab"

SUPERVISOR_VERSION = "wuci-lab-supervisor-v1"
STATUS_SCHEMA = "wuci.lab.status.v1"
OVERLAY_SCHEMA = "wuci.lab.overlay.v1"
OVERLAY_INSPECTION_SCHEMA = "wuci.lab.overlay-inspection.v1"
OVERLAY_REMOVAL_SCHEMA = "wuci.lab.overlay-removal.v1"
OVERLAY_RESET_SCHEMA = "wuci.lab.overlay-reset.v1"
HOSTILE_PAYLOAD_SCHEMA = "wuci.lab.hostile-payload.v1"
LAUNCH_SCHEMA = "wuci.lab.launch-plan.v1"

NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

MIN_MEMORY_MIB = 512
MAX_MEMORY_MIB = 16384
DEFAULT_MEMORY_MIB = 4096
MIN_CPUS = 1
MAX_CPUS = 8
DEFAULT_CPUS = 2

MAX_KERNEL_BYTES = 512 * 1024 * 1024
MAX_INITRD_BYTES = 2 * 1024 * 1024 * 1024
MAX_BASE_BYTES = 256 * 1024 * 1024 * 1024
MAX_HOSTILE_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_HOSTILE_PAYLOAD_MEDIA_BYTES = 96 * 1024 * 1024
MAX_HOSTILE_RUNTIME_FILE_BYTES = 1024 * 1024 * 1024
MAX_HOSTILE_CONSOLE_BYTES = 32 * 1024 * 1024
MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES = 1024 * 1024
HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS = 5
HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS = 0.1
MAX_MANIFEST_BYTES = 64 * 1024
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024

QEMU_SANDBOX = (
    "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
)
QEMU_USER_NETDEV = (
    "user,id=wuci-net,restrict=off,ipv6=off,"
    "net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,"
    "dhcpstart=10.0.2.15"
)
TCG_CPU_MODEL = (
    "Broadwell-v4,pcid=off,x2apic=off,tsc-deadline=off,"
    "invpcid=off,spec-ctrl=off"
)
KERNEL_ARGUMENTS = (
    "root=/dev/vda",
    "rw",
    "rootfstype=ext4",
    "console=ttyS0,115200",
    "panic=10",
)
KERNEL_APPEND = " ".join(KERNEL_ARGUMENTS)
FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS = ("nosoftlockup",)
HOSTILE_CONSOLE_RENDERING = "escaped-ascii"
HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST = (
    "tab-0x09",
    "line-feed-0x0a",
    "printable-ascii-0x20-0x7e",
)
HOSTILE_HANDLED_SIGNALS = (
    signal.SIGHUP,
    signal.SIGINT,
    signal.SIGQUIT,
    signal.SIGTERM,
    signal.SIGTSTP,
)
HOSTILE_HANDLED_SIGNAL_NAMES = tuple(
    signal.Signals(signum).name for signum in HOSTILE_HANDLED_SIGNALS
)
DEFERRED_VOLATILE_ROOT = "{private-volatile-qcow2-created-at-launch}"
DEFERRED_HOSTILE_PAYLOAD = "{private-read-only-hostile-payload-media-created-at-launch}"
HOSTILE_PAYLOAD_GUEST_MEDIA = Path("/run/wuci-payload.ext4")
TRUSTED_BWRAP = Path("/usr/bin/bwrap")
TRUSTED_QEMU = Path("/usr/bin/qemu-system-x86_64")
TRUSTED_QEMU_IMG = Path("/usr/bin/qemu-img")
TRUSTED_MKE2FS = Path("/usr/sbin/mke2fs")
TRUSTED_DEBUGFS = Path("/usr/sbin/debugfs")
TRUSTED_MKE2FS_VERSION = "1.47.0"
HOSTILE_RUNTIME_DIRECTORIES = (
    Path("/usr/lib/x86_64-linux-gnu"),
    Path("/usr/share/qemu"),
    Path("/usr/share/seabios"),
)
HOSTILE_RUNTIME_DIRECTORY_ALIASES = (
    (
        Path("/usr/lib/x86_64-linux-gnu"),
        Path("/lib/x86_64-linux-gnu"),
    ),
)
HOSTILE_RUNTIME_FILES = (
    (
        Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
        Path("/lib64/ld-linux-x86-64.so.2"),
    ),
    (Path("/etc/ld.so.cache"), Path("/etc/ld.so.cache")),
)
HOSTILE_BWRAP_FLAGS = (
    "--die-with-parent",
    "--new-session",
    "--unshare-user",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup",
    "--unshare-net",
)
HOSTILE_LOCKED_MEMORY_BYTES = 8 * 1024 * 1024
HOSTILE_OPEN_FILES = 256
# RLIMIT_NPROC is an account-wide host-task ceiling, not a VM-internal
# process limit.  Keep enough deterministic room for a normal desktop account
# to create bubblewrap and QEMU while retaining a finite, evidence-bound cap.
HOSTILE_ACCOUNT_TASK_LIMIT = 2048
HOSTILE_MIN_ACCOUNT_TASK_HEADROOM = 128
HOSTILE_ADDRESS_SPACE_OVERHEAD_BYTES = 4 * 1024 * 1024 * 1024
HOSTILE_FILE_SIZE_OVERHEAD_BYTES = 4 * 1024 * 1024 * 1024

NONCLAIMS = (
    "This is a local VM isolation boundary, not proof that QEMU, KVM, the host "
    "kernel, firmware, or hardware are vulnerability-free.",
    "No safety claim is made for arbitrary malware, hypervisor escapes, "
    "side channels, denial of service, or attacks on the physical host.",
    "The internet mode permits guest-initiated traffic and is not a no-network "
    "or anonymity boundary.",
    "Persistent overlays retain guest writes, including potentially hostile "
    "state, until the operator removes them.",
    "A private volatile overlay is removed on normal or handled-error supervisor "
    "unwind; SIGKILL, host crash, or power loss can leave private stale state.",
    "The hostile cell assumes attacker-controlled guest root; unprivileged "
    "QEMU refers only to the host-side QEMU process.",
    "No production readiness, independent audit, certification, or external "
    "authority is claimed.",
)


class LabError(RuntimeError):
    """A fail-closed lab configuration or runtime error."""


class _HostileConsoleSignal(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


@contextlib.contextmanager
def _block_handled_signals_during_allocation() -> Iterator[set[signal.Signals]]:
    """Defer handled signals until a new resource has an exact identity."""
    try:
        previous = signal.pthread_sigmask(
            signal.SIG_BLOCK, HOSTILE_HANDLED_SIGNALS
        )
    except (AttributeError, OSError, ValueError) as exc:
        raise LabError(
            "hostile transient allocation requires POSIX signal masking"
        ) from exc
    try:
        yield previous
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except (OSError, ValueError) as exc:
            raise LabError(
                "hostile transient allocation could not restore its signal mask"
            ) from exc


@dataclass(frozen=True)
class BoundFile:
    path: Path
    sha256: str
    size: int
    mode: int
    device: int
    inode: int

    def public(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "mode": f"{self.mode:04o}",
        }


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LabError(f"duplicate JSON key rejected: {key}")
        value[key] = item
    return value


def parse_json_object(raw: str, context: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                LabError(f"{context} contains non-finite number: {token}")
            ),
        )
    except LabError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise LabError(f"{context} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise LabError(f"{context} must be a JSON object")
    return value


def validate_sha256(value: str, label: str = "SHA-256") -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise LabError(f"{label} must be exactly 64 lowercase hexadecimal characters")
    return value


def validate_overlay_name(value: str) -> str:
    if not isinstance(value, str) or NAME_RE.fullmatch(value) is None:
        raise LabError(
            "overlay name must match [a-z][a-z0-9-]{0,47}; "
            "paths, dot components, and uppercase names are rejected"
        )
    return value


def _raw_path(value: str | os.PathLike[str], label: str) -> str:
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw:
        raise LabError(f"{label} path must be a non-empty string")
    if "\x00" in raw or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw):
        raise LabError(f"{label} path contains a control character")
    if "\\" in raw:
        raise LabError(f"{label} path contains a backslash")
    if "," in raw:
        raise LabError(f"{label} path contains a QEMU option separator")
    if raw.startswith("//"):
        raise LabError(f"{label} path has an ambiguous leading separator")
    components = raw.split("/")
    for index, component in enumerate(components):
        if component in {".", ".."}:
            raise LabError(f"{label} path contains a dot or traversal component")
        if component == "" and index not in {0, len(components) - 1}:
            raise LabError(f"{label} path contains an empty component")
    if len(raw) > 4096:
        raise LabError(f"{label} path is too long")
    return raw


def absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    raw = _raw_path(value, label)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return Path(os.path.abspath(os.fspath(candidate)))


def _existing_components(path: Path) -> Iterator[Path]:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        yield current


def reject_symlink_components(path: Path, label: str, *, leaf_may_be_missing: bool = False) -> None:
    components = tuple(_existing_components(path))
    for index, current in enumerate(components):
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if leaf_may_be_missing and index == len(components) - 1:
                return
            raise LabError(f"{label} path component is missing: {current}") from None
        except OSError as exc:
            raise LabError(f"cannot inspect {label} path component {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise LabError(f"{label} path must not contain symlinks: {current}")
        if index != len(components) - 1 and not stat.S_ISDIR(info.st_mode):
            raise LabError(f"{label} parent component must be a directory: {current}")


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _regular_lstat(
    path: Path,
    label: str,
    *,
    min_bytes: int = 1,
    max_bytes: int | None = None,
    require_private_write: bool = False,
) -> os.stat_result:
    reject_symlink_components(path, label)
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LabError(f"{label} is missing or unreadable: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise LabError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise LabError(f"{label} hardlink rejected: {path}")
    if info.st_mode & 0o022:
        raise LabError(f"{label} must not be group/world writable: {path}")
    if require_private_write and info.st_mode & 0o077:
        raise LabError(f"{label} must have private permissions: {path}")
    if info.st_size < min_bytes:
        raise LabError(f"{label} is too small: {path}")
    if max_bytes is not None and info.st_size > max_bytes:
        raise LabError(f"{label} exceeds the {max_bytes}-byte limit: {path}")
    return info


def _open_regular(path: Path, label: str, expected: os.stat_result) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LabError(f"cannot safely open {label}: {path}") from exc
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(expected):
        os.close(fd)
        raise LabError(f"{label} changed while being opened: {path}")
    return fd


def validate_bound_file(
    value: str | os.PathLike[str],
    expected_sha256: str,
    label: str,
    *,
    max_bytes: int,
) -> BoundFile:
    digest_expected = validate_sha256(expected_sha256, f"{label} SHA-256")
    path = absolute_path(value, label)
    before = _regular_lstat(path, label, max_bytes=max_bytes)
    fd = _open_regular(path, label, before)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise LabError(f"{label} exceeds the {max_bytes}-byte limit: {path}")
            digest.update(chunk)
        after = os.fstat(fd)
        if total != before.st_size or _stat_identity(before) != _stat_identity(after):
            raise LabError(f"{label} changed while being hashed: {path}")
        try:
            path_after = os.lstat(path)
        except OSError as exc:
            raise LabError(f"{label} path changed while being hashed: {path}") from exc
        if _stat_identity(after) != _stat_identity(path_after):
            raise LabError(f"{label} path changed while being hashed: {path}")
    finally:
        os.close(fd)
    observed = digest.hexdigest()
    if observed != digest_expected:
        raise LabError(
            f"{label} digest mismatch: expected {digest_expected}, observed {observed}"
        )
    return BoundFile(
        path=path,
        sha256=observed,
        size=before.st_size,
        mode=stat.S_IMODE(before.st_mode),
        device=before.st_dev,
        inode=before.st_ino,
    )


def validate_boot_inputs(
    kernel: str | os.PathLike[str],
    kernel_sha256: str,
    initrd: str | os.PathLike[str],
    initrd_sha256: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
) -> dict[str, BoundFile]:
    return {
        "kernel": validate_bound_file(
            kernel, kernel_sha256, "kernel", max_bytes=MAX_KERNEL_BYTES
        ),
        "initrd": validate_bound_file(
            initrd, initrd_sha256, "initrd", max_bytes=MAX_INITRD_BYTES
        ),
        "base_image": validate_bound_file(
            base_image, base_sha256, "base image", max_bytes=MAX_BASE_BYTES
        ),
    }


def _path_exists_lstat(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LabError(f"cannot inspect path {path}: {exc}") from exc
    return True


def _under_root(path: Path, root: Path, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise LabError(f"{label} must stay under {root}: {path}") from exc
    if path == root:
        raise LabError(f"{label} must be below, not equal to, {root}")


def ensure_state_root(value: str | os.PathLike[str]) -> Path:
    state_root = validate_state_root_location(value)
    build_root = absolute_path(BUILD_ROOT, "build root")
    reject_symlink_components(build_root, "build root")
    if not build_root.is_dir():
        raise LabError(f"build root must be a directory: {build_root}")

    current = build_root
    relative = state_root.relative_to(build_root)
    for component in relative.parts:
        current = current / component
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise LabError(f"cannot create private state directory {current}: {exc}") from exc
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise LabError(f"cannot inspect state directory {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LabError(f"state path must contain only directories: {current}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LabError(f"state directory must have mode 0700 or stricter: {current}")
    return state_root


def validate_state_root_location(value: str | os.PathLike[str]) -> Path:
    """Validate a state-root location without creating or changing it."""
    state_root = absolute_path(value, "state root")
    build_root = absolute_path(BUILD_ROOT, "build root")
    _under_root(state_root, build_root, "state root")
    reject_symlink_components(build_root, "build root")
    if not build_root.is_dir():
        raise LabError(f"build root must be a directory: {build_root}")

    current = build_root
    for component in state_root.relative_to(build_root).parts:
        current = current / component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        except OSError as exc:
            raise LabError(f"cannot inspect state path {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LabError(f"state path must contain only directories: {current}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LabError(f"state directory must have mode 0700 or stricter: {current}")
    return state_root


def _ensure_private_child(root: Path, name: str) -> Path:
    child = root / name
    _under_root(child, root, "state child")
    try:
        os.mkdir(child, 0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise LabError(f"cannot create state directory {child}: {exc}") from exc
    info = os.lstat(child)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LabError(f"state child must be a directory: {child}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise LabError(f"state child must have mode 0700 or stricter: {child}")
    return child


def overlay_paths(state_root: Path, name: str) -> dict[str, Path]:
    safe_name = validate_overlay_name(name)
    overlays = state_root / "overlays"
    locks = state_root / "locks"
    return {
        "overlay_directory": overlays,
        "lock_directory": locks,
        "image": overlays / f"{safe_name}.qcow2",
        "manifest": overlays / f"{safe_name}.json",
        "lock": locks / f"{safe_name}.lock",
    }


@contextlib.contextmanager
def overlay_lock(state_root_value: str | os.PathLike[str], name: str) -> Iterator[Path]:
    state_root = ensure_state_root(state_root_value)
    paths = overlay_paths(state_root, name)
    _ensure_private_child(state_root, "overlays")
    _ensure_private_child(state_root, "locks")
    lock_path = paths["lock"]
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LabError(f"cannot safely open overlay lock {lock_path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LabError(f"overlay lock must be a single-link regular file: {lock_path}")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LabError(f"overlay lock must have private permissions: {lock_path}")
        path_info = os.lstat(lock_path)
        if _stat_identity(info) != _stat_identity(path_info):
            raise LabError(f"overlay lock path changed while opening: {lock_path}")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LabError(f"overlay is busy under another supervisor: {name}") from None
        yield lock_path
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LabError(f"cannot open directory for durability: {path}") from exc
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink_created_file_exact(
    path: Path,
    identity: tuple[int, int],
    label: str,
) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LabError(f"cannot inspect {label} during exact rollback: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LabError(f"{label} is no longer a single-link regular file: {path}")
    if (info.st_dev, info.st_ino) != identity:
        raise LabError(f"{label} inode changed before exact rollback: {path}")
    try:
        os.unlink(path)
    except OSError as exc:
        raise LabError(f"cannot unlink exact {label} during rollback: {path}") from exc
    _fsync_directory(path.parent)


def _write_new_json(
    path: Path,
    value: Mapping[str, Any],
    label: str,
    *,
    defer_handled_signals: bool = False,
) -> tuple[int, int]:
    payload = canonical_json(value).encode("utf-8")
    if len(payload) > MAX_MANIFEST_BYTES:
        raise LabError(f"{label} exceeds the manifest size limit")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            try:
                fd = os.open(path, flags, 0o600)
            except OSError as exc:
                raise LabError(
                    f"cannot create {label} without overwrite: {path}"
                ) from exc
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise LabError(
                    f"new {label} is not a single-link regular file: {path}"
                )
            if stat.S_IMODE(opened.st_mode) & 0o077:
                raise LabError(
                    f"new {label} does not have private permissions: {path}"
                )
            identity = (opened.st_dev, opened.st_ino)
        offset = 0
        while offset < len(payload):
            assert fd is not None
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise LabError(f"short write while creating {label}: {path}")
            offset += written
        os.fsync(fd)
        final = os.fstat(fd)
        path_info = os.lstat(path)
        if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1:
            raise LabError(f"new {label} changed type or link count: {path}")
        if _stat_identity(final) != _stat_identity(path_info):
            raise LabError(f"new {label} path changed while being written: {path}")
        os.close(fd)
        fd = None
        _fsync_directory(path.parent)
    except BaseException as original:
        cleanup_errors: list[str] = []
        if fd is not None:
            try:
                os.close(fd)
            except OSError as close_error:
                cleanup_errors.append(f"cannot close new {label}: {close_error}")
        try:
            if identity is not None:
                _unlink_created_file_exact(path, identity, label)
        except LabError as cleanup_error:
            cleanup_errors.append(str(cleanup_error))
        if cleanup_errors:
            raise LabError(
                f"{label} creation failed and exact rollback was incomplete: "
                + "; ".join(cleanup_errors)
            ) from original
        raise
    if identity is None:
        raise LabError(f"{label} creation did not establish an inode identity")
    return identity


def _read_regular_text(path: Path, label: str, max_bytes: int) -> str:
    before = _regular_lstat(path, label, max_bytes=max_bytes, require_private_write=True)
    fd = _open_regular(path, label, before)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise LabError(f"{label} exceeds the {max_bytes}-byte limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        if total != before.st_size or _stat_identity(before) != _stat_identity(after):
            raise LabError(f"{label} changed while being read: {path}")
        if _stat_identity(after) != _stat_identity(os.lstat(path)):
            raise LabError(f"{label} path changed while being read: {path}")
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LabError(f"{label} must be UTF-8 text") from exc


def _sanitized_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }


def _find_executable(value: str | None, default_name: str, label: str) -> Path:
    requested = value or default_name
    if "/" not in requested:
        discovered = shutil.which(requested, path=_sanitized_environment()["PATH"])
        if discovered is None:
            raise LabError(f"{label} executable not found on the fixed system PATH: {requested}")
        requested = discovered
    path = absolute_path(requested, label)
    info = _regular_lstat(path, label, max_bytes=1024 * 1024 * 1024)
    if info.st_mode & 0o111 == 0 or not os.access(path, os.X_OK):
        raise LabError(f"{label} must be executable: {path}")
    return path


def _trusted_system_executable(
    value: str | os.PathLike[str],
    expected: Path,
    label: str,
) -> Path:
    path = absolute_path(value, label)
    if path != expected:
        raise LabError(f"{label} must be exact {expected}")
    info = _regular_lstat(path, label, max_bytes=1024 * 1024 * 1024)
    if info.st_uid != 0:
        raise LabError(f"{label} must be root-owned: {path}")
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise LabError(f"{label} must not be setuid or setgid: {path}")
    if info.st_mode & 0o111 == 0 or not os.access(path, os.X_OK):
        raise LabError(f"{label} must be executable: {path}")
    return path


def _trusted_mke2fs(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    path = _trusted_system_executable(value, TRUSTED_MKE2FS, label)
    result = _run_capture([str(path), "-V"], timeout=10)
    lines = [
        line.strip()
        for line in (result.stdout + result.stderr).splitlines()
        if line.strip()
    ]
    expected_version = (
        f"mke2fs {TRUSTED_MKE2FS_VERSION} (5-Feb-2023)"
    )
    expected_library = (
        f"Using EXT2FS Library version {TRUSTED_MKE2FS_VERSION}"
    )
    if (
        len(lines) != 2
        or lines[0] != expected_version
        or lines[1] != expected_library
    ):
        raise LabError(
            f"{label} must report exact e2fsprogs version "
            f"{TRUSTED_MKE2FS_VERSION}"
        )
    return path


def _trusted_debugfs(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    path = _trusted_system_executable(value, TRUSTED_DEBUGFS, label)
    result = _run_capture([str(path), "-V"], timeout=10)
    lines = [
        line.strip()
        for line in (result.stdout + result.stderr).splitlines()
        if line.strip()
    ]
    expected_version = (
        f"debugfs {TRUSTED_MKE2FS_VERSION} (5-Feb-2023)"
    )
    expected_library = (
        f"Using EXT2FS Library version {TRUSTED_MKE2FS_VERSION}"
    )
    if (
        len(lines) != 2
        or lines[0] != expected_version
        or lines[1] != expected_library
    ):
        raise LabError(
            f"{label} must report exact e2fsprogs version "
            f"{TRUSTED_MKE2FS_VERSION}"
        )
    return path


def _system_tool_trust_status(
    value: str | os.PathLike[str],
    expected: Path,
    label: str,
) -> dict[str, Any]:
    try:
        path = _trusted_system_executable(value, expected, label)
    except LabError as exc:
        return {
            "trusted": False,
            "path": str(value),
            "expected_path": str(expected),
            "reason": str(exc),
        }
    return {
        "trusted": True,
        "path": str(path),
        "expected_path": str(expected),
        "reason": None,
    }


def _kill_and_reap_process_group(process: subprocess.Popen[bytes]) -> None:
    """Kill the unreaped session leader's process group, then reap the leader.

    Callers are trusted fixed tools. A deliberately re-sessioned descendant is
    outside what a process-group boundary can recover, so failure to kill the
    original group is reported rather than silently reduced to direct-child
    cleanup.
    """
    group_error: OSError | None = None
    direct_error: OSError | None = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        group_error = exc
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except OSError as kill_error:
            direct_error = kill_error
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise LabError(
            f"failed to reap terminated command process group: {process.args[0]}"
        ) from exc
    if group_error is not None:
        direct_detail = (
            f"; direct-child kill also failed: {direct_error}"
            if direct_error is not None
            else ""
        )
        raise LabError(
            "failed to terminate the complete command process group; "
            f"the direct child was reaped: {process.args[0]}: {group_error}"
            f"{direct_detail}"
        ) from group_error


def _run_capture(
    argv: Sequence[str],
    *,
    timeout: float,
    allow_failure: bool = False,
    environment: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[str]:
    command = list(argv)
    descriptors = tuple(pass_fds)
    if not command or not all(isinstance(item, str) and item for item in command):
        raise LabError("command argv must contain non-empty strings")
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or timeout <= 0
        or len(set(descriptors)) != len(descriptors)
        or any(
            type(descriptor) is not int or descriptor < 0
            for descriptor in descriptors
        )
    ):
        raise LabError("command capture contract is invalid")
    process: subprocess.Popen[bytes] | None = None
    streams: dict[str, Any] = {}
    try:
        with _block_handled_signals_during_allocation() as previous_mask:

            def restore_child_signal_mask() -> None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

            process = subprocess.Popen(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                env=(
                    _sanitized_environment()
                    if environment is None
                    else dict(environment)
                ),
                close_fds=True,
                pass_fds=descriptors,
                restore_signals=True,
                start_new_session=True,
                umask=0o077,
                preexec_fn=restore_child_signal_mask,
            )
            if process.stdout is None or process.stderr is None:
                raise LabError("command capture pipes were not created")
            streams = {"stdout": process.stdout, "stderr": process.stderr}
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        total = 0
        deadline = time.monotonic() + float(timeout)
        failure: str | None = None
        with selectors.DefaultSelector() as selector:
            for name, stream in streams.items():
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "timeout"
                    break
                events = selector.select(remaining)
                if not events:
                    failure = "timeout"
                    break
                for key, _mask in events:
                    remaining_capacity = MAX_TOOL_OUTPUT_BYTES - total
                    try:
                        chunk = os.read(
                            key.fd,
                            min(65536, remaining_capacity + 1),
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(chunk) > remaining_capacity:
                        failure = "output-limit"
                        break
                    captured[key.data].extend(chunk)
                    total += len(chunk)
                if failure is not None:
                    break
        if failure is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
            else:
                try:
                    returncode = process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = "timeout"
        if failure is not None:
            _kill_and_reap_process_group(process)
            if failure == "output-limit":
                raise LabError(
                    "command combined stdout/stderr exceeds the "
                    f"{MAX_TOOL_OUTPUT_BYTES}-byte safety limit: {command[0]}"
                )
            raise LabError(
                f"command timed out after {float(timeout):g} seconds: {command[0]}"
            )
        try:
            stdout = bytes(captured["stdout"]).decode("utf-8", errors="strict")
            stderr = bytes(captured["stderr"]).decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise LabError(f"command output is not valid UTF-8: {command[0]}") from exc
        stdout = stdout.replace("\r\n", "\n").replace("\r", "\n")
        stderr = stderr.replace("\r\n", "\n").replace("\r", "\n")
        result = subprocess.CompletedProcess(command, returncode, stdout, stderr)
    except LabError:
        if process is not None and process.returncode is None:
            _kill_and_reap_process_group(process)
        raise
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        if process is not None and process.returncode is None:
            _kill_and_reap_process_group(process)
        raise LabError(f"command failed to execute: {command[0]}: {exc}") from exc
    except BaseException:
        if process is not None and process.returncode is None:
            _kill_and_reap_process_group(process)
        raise
    finally:
        for stream in streams.values():
            try:
                stream.close()
            except OSError:
                pass
    if result.returncode != 0 and not allow_failure:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[0][:400]}" if detail else ""
        raise LabError(f"command exited {result.returncode}: {command[0]}{suffix}")
    return result


def _kvm_device_status(kvm_device: str | os.PathLike[str] = "/dev/kvm") -> dict[str, Any]:
    expected_path = Path("/dev/kvm")
    status: dict[str, Any] = {
        "path": str(kvm_device),
        "expected_path": str(expected_path),
        "exact_path": False,
        "character_device": False,
        "owner_uid": None,
        "owner_gid": None,
        "root_owned": False,
        "mode": None,
        "device_major": None,
        "device_minor": None,
        "expected_device_major": 10,
        "expected_device_minor": 232,
        "major_minor_match": False,
        "world_readable": False,
        "world_writable": False,
        "unprivileged_user": os.geteuid() != 0,
        "readable": False,
        "writable": False,
        "readable_by_current_user": False,
        "writable_by_current_user": False,
        "trusted": False,
        "reason": None,
    }
    try:
        path = absolute_path(kvm_device, "KVM device")
        status["path"] = str(path)
        status["exact_path"] = path == expected_path
        reject_symlink_components(path, "KVM device")
        info = os.lstat(path)
    except (LabError, OSError) as exc:
        status["reason"] = str(exc)
        return status

    character = stat.S_ISCHR(info.st_mode)
    device_major: int | None = None
    device_minor: int | None = None
    if character:
        try:
            device_major = os.major(info.st_rdev)
            device_minor = os.minor(info.st_rdev)
        except (AttributeError, TypeError, ValueError, OSError):
            pass
    try:
        readable = character and os.access(path, os.R_OK, effective_ids=True)
        writable = character and os.access(path, os.W_OK, effective_ids=True)
    except (NotImplementedError, TypeError, OSError):
        # Hostile mode is Linux-only. If effective-ID access checks are not
        # available, do not substitute a real-ID or root-biased answer.
        readable = False
        writable = False

    exact_path = path == expected_path
    root_owned = info.st_uid == 0
    world_readable = bool(info.st_mode & stat.S_IROTH)
    world_writable = bool(info.st_mode & stat.S_IWOTH)
    major_minor_match = device_major == 10 and device_minor == 232
    unprivileged_user = os.geteuid() != 0
    trusted = all(
        (
            exact_path,
            character,
            root_owned,
            major_minor_match,
            not world_readable,
            not world_writable,
            unprivileged_user,
            readable,
            writable,
        )
    )
    reasons: list[str] = []
    if not exact_path:
        reasons.append("path is not exact /dev/kvm")
    if not character:
        reasons.append("not a character device")
    if not root_owned:
        reasons.append("not root-owned")
    if not major_minor_match:
        actual = (
            f"{device_major}:{device_minor}"
            if device_major is not None and device_minor is not None
            else "unavailable"
        )
        reasons.append(f"device number is {actual}, expected 10:232")
    if world_readable:
        reasons.append("world-readable")
    if world_writable:
        reasons.append("world-writable")
    if not unprivileged_user:
        reasons.append("current user is root")
    if not readable:
        reasons.append("not readable by the current unprivileged user")
    if not writable:
        reasons.append("not writable by the current unprivileged user")

    status.update(
        {
            "path": str(path),
            "exact_path": exact_path,
            "character_device": character,
            "owner_uid": info.st_uid,
            "owner_gid": info.st_gid,
            "root_owned": root_owned,
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "device_major": device_major,
            "device_minor": device_minor,
            "major_minor_match": major_minor_match,
            "world_readable": world_readable,
            "world_writable": world_writable,
            "unprivileged_user": unprivileged_user,
            "readable": readable,
            "writable": writable,
            "readable_by_current_user": readable,
            "writable_by_current_user": writable,
            "trusted": trusted,
            "reason": None if trusted else "; ".join(reasons),
        }
    )
    return status


def _trusted_kvm_device_record(value: object) -> bool:
    return bool(
        isinstance(value, Mapping)
        and value.get("path") == "/dev/kvm"
        and value.get("expected_path") == "/dev/kvm"
        and value.get("exact_path") is True
        and value.get("character_device") is True
        and value.get("owner_uid") == 0
        and value.get("root_owned") is True
        and value.get("device_major") == 10
        and value.get("device_minor") == 232
        and value.get("expected_device_major") == 10
        and value.get("expected_device_minor") == 232
        and value.get("major_minor_match") is True
        and value.get("world_readable") is False
        and value.get("world_writable") is False
        and value.get("unprivileged_user") is True
        and value.get("readable") is True
        and value.get("writable") is True
        and value.get("readable_by_current_user") is True
        and value.get("writable_by_current_user") is True
        and value.get("trusted") is True
    )


def _trusted_bwrap() -> Path:
    path = absolute_path(TRUSTED_BWRAP, "bubblewrap")
    if path != TRUSTED_BWRAP:
        raise LabError("hostile mode requires exact /usr/bin/bwrap")
    info = _regular_lstat(path, "bubblewrap", max_bytes=128 * 1024 * 1024)
    if info.st_uid != 0:
        raise LabError("hostile mode requires root-owned /usr/bin/bwrap")
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise LabError("hostile mode requires /usr/bin/bwrap without setuid/setgid bits")
    if info.st_mode & 0o111 == 0 or not os.access(path, os.X_OK):
        raise LabError("hostile mode requires executable /usr/bin/bwrap")
    return path


def probe_bwrap() -> dict[str, Any]:
    try:
        path = _trusted_bwrap()
        version = _run_capture([str(path), "--version"], timeout=10)
        help_result = _run_capture([str(path), "--help"], timeout=10)
        required = {
            *HOSTILE_BWRAP_FLAGS,
            "--tmpfs",
            "--dir",
            "--proc",
            "--dev",
            "--dev-bind",
            "--ro-bind",
            "--bind",
            "--remount-ro",
            "--clearenv",
            "--setenv",
            "--hostname",
            "--chdir",
            "--cap-drop",
            "--perms",
        }
        missing = sorted(option for option in required if option not in help_result.stdout)
        if missing:
            raise LabError(
                "bubblewrap lacks required hostile-boundary options: "
                + ", ".join(missing)
            )
    except LabError as exc:
        return {
            "available": False,
            "trusted": False,
            "path": str(TRUSTED_BWRAP),
            "version": None,
            "reason": str(exc),
        }
    version_lines = version.stdout.strip().splitlines()
    return {
        "available": True,
        "trusted": True,
        "path": str(path),
        "version": version_lines[0][:200] if version_lines else None,
        "reason": None,
    }


def probe_host(
    qemu: str | None = None,
    *,
    kvm_device: str | os.PathLike[str] = "/dev/kvm",
) -> dict[str, Any]:
    resolved_qemu: Path | None = None
    try:
        resolved_qemu = _find_executable(qemu, "qemu-system-x86_64", "QEMU")
        qemu_path = _trusted_system_executable(
            resolved_qemu,
            TRUSTED_QEMU,
            "QEMU capability probe",
        )
    except LabError as exc:
        return {
            "qemu_available": False,
            "qemu_path": str(resolved_qemu) if resolved_qemu is not None else None,
            "qemu_version": None,
            "q35_supported": False,
            "qemu_sandbox_supported": False,
            "kvm_accel_supported": False,
            "tcg_accel_supported": False,
            "kvm_device": _kvm_device_status(kvm_device),
            "bubblewrap": probe_bwrap(),
            "system_tools": {
                "qemu": {
                    "trusted": False,
                    "path": (
                        str(resolved_qemu) if resolved_qemu is not None else None
                    ),
                    "expected_path": str(TRUSTED_QEMU),
                    "reason": str(exc),
                },
                "qemu_img": _system_tool_trust_status(
                    TRUSTED_QEMU_IMG,
                    TRUSTED_QEMU_IMG,
                    "hostile qemu-img",
                ),
            },
            "non_root_user": os.geteuid() != 0,
            "probe_error": str(exc),
        }

    version = _run_capture([str(qemu_path), "--version"], timeout=10, allow_failure=True)
    machines = _run_capture([str(qemu_path), "-machine", "help"], timeout=10, allow_failure=True)
    accelerators = _run_capture([str(qemu_path), "-accel", "help"], timeout=10, allow_failure=True)
    help_result = _run_capture([str(qemu_path), "--help"], timeout=10, allow_failure=True)
    sandbox_probe = _run_capture(
        [str(qemu_path), "-sandbox", QEMU_SANDBOX, "--version"],
        timeout=10,
        allow_failure=True,
    )
    version_line = (version.stdout or version.stderr).splitlines()
    machine_text = machines.stdout + "\n" + machines.stderr
    accel_text = accelerators.stdout + "\n" + accelerators.stderr
    help_text = help_result.stdout + "\n" + help_result.stderr
    return {
        "qemu_available": all(
            result.returncode == 0
            for result in (version, machines, accelerators, help_result, sandbox_probe)
        ),
        "qemu_path": str(qemu_path),
        "qemu_version": version_line[0][:300] if version_line else None,
        "q35_supported": re.search(r"(?m)^\s*q35\s", machine_text) is not None,
        "qemu_sandbox_supported": (
            re.search(r"(?m)^\s*-sandbox(?:\s|$)", help_text) is not None
            and sandbox_probe.returncode == 0
        ),
        "kvm_accel_supported": re.search(r"(?m)^\s*kvm\s*$", accel_text) is not None,
        "tcg_accel_supported": re.search(r"(?m)^\s*tcg\s*$", accel_text) is not None,
        "kvm_device": _kvm_device_status(kvm_device),
        "bubblewrap": probe_bwrap(),
        "system_tools": {
            "qemu": {
                "trusted": True,
                "path": str(qemu_path),
                "expected_path": str(TRUSTED_QEMU),
                "reason": None,
            },
            "qemu_img": _system_tool_trust_status(
                TRUSTED_QEMU_IMG,
                TRUSTED_QEMU_IMG,
                "hostile qemu-img",
            ),
        },
        "non_root_user": os.geteuid() != 0,
        "probe_error": None,
    }


def _hostile_blockers(capabilities: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not capabilities.get("qemu_available"):
        blockers.append("QEMU capability probes did not all pass")
    if not capabilities.get("q35_supported"):
        blockers.append("QEMU q35 machine support is required")
    if not capabilities.get("qemu_sandbox_supported"):
        blockers.append("QEMU sandbox support is required")
    if not capabilities.get("kvm_accel_supported"):
        blockers.append("QEMU KVM acceleration support is required")
    kvm = capabilities.get("kvm_device")
    if not _trusted_kvm_device_record(kvm):
        reason = kvm.get("reason") if isinstance(kvm, Mapping) else None
        detail = f": {reason}" if isinstance(reason, str) and reason else ""
        blockers.append(
            "trusted exact root-owned /dev/kvm character device 10:232, "
            "without world read/write access and readable/writable by the "
            f"current unprivileged user, is required{detail}"
        )
    if not capabilities.get("non_root_user"):
        blockers.append("hostile mode refuses to run as root")
    system_tools = capabilities.get("system_tools")
    for key, expected, label in (
        ("qemu", TRUSTED_QEMU, "QEMU"),
        ("qemu_img", TRUSTED_QEMU_IMG, "qemu-img"),
    ):
        record = system_tools.get(key) if isinstance(system_tools, Mapping) else None
        if not isinstance(record, Mapping) or not (
            record.get("trusted") and record.get("path") == str(expected)
        ):
            reason = record.get("reason") if isinstance(record, Mapping) else None
            detail = f": {reason}" if isinstance(reason, str) and reason else ""
            blockers.append(f"trusted exact {expected} {label} is required{detail}")
    bubblewrap = capabilities.get("bubblewrap")
    if not isinstance(bubblewrap, Mapping) or not (
        bubblewrap.get("available")
        and bubblewrap.get("trusted")
        and bubblewrap.get("path") == str(TRUSTED_BWRAP)
    ):
        reason = bubblewrap.get("reason") if isinstance(bubblewrap, Mapping) else None
        detail = f": {reason}" if isinstance(reason, str) and reason else ""
        blockers.append(f"trusted exact /usr/bin/bwrap is required{detail}")
    return blockers


def select_acceleration(
    profile: str,
    requested: str,
    capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    if profile not in {"developer", "analysis", "hostile"}:
        raise LabError(f"unsupported profile: {profile}")
    if requested not in {"auto", "kvm", "tcg"}:
        raise LabError(f"unsupported acceleration request: {requested}")
    if not capabilities.get("qemu_available"):
        raise LabError(str(capabilities.get("probe_error") or "QEMU probes failed"))
    if not capabilities.get("q35_supported"):
        raise LabError("QEMU q35 machine support is required")
    if not capabilities.get("qemu_sandbox_supported"):
        raise LabError("QEMU sandbox support is required")

    kvm = capabilities.get("kvm_device")
    kvm_ready = bool(
        capabilities.get("kvm_accel_supported")
        and isinstance(kvm, Mapping)
        and kvm.get("character_device")
        and kvm.get("readable")
        and kvm.get("writable")
    )
    if profile == "hostile":
        if requested == "tcg":
            raise LabError("hostile mode forbids TCG fallback")
        blockers = _hostile_blockers(capabilities)
        if blockers:
            raise LabError("hostile mode refused: " + "; ".join(blockers))
        return {
            "selected": "kvm",
            "tcg_fallback": False,
            "label": "KVM REQUIRED (hostile fail-closed profile)",
        }

    if requested == "kvm":
        if not kvm_ready:
            raise LabError("KVM was explicitly requested but is not available")
        return {"selected": "kvm", "tcg_fallback": False, "label": "KVM"}
    if requested == "tcg":
        if not capabilities.get("tcg_accel_supported"):
            raise LabError("TCG was explicitly requested but is not supported")
        return {
            "selected": "tcg",
            "tcg_fallback": True,
            "label": "TCG SOFTWARE EMULATION (reduced isolation and performance)",
        }
    if kvm_ready:
        return {"selected": "kvm", "tcg_fallback": False, "label": "KVM"}
    if capabilities.get("tcg_accel_supported"):
        return {
            "selected": "tcg",
            "tcg_fallback": True,
            "label": "TCG FALLBACK (KVM unavailable; not hostile-workload eligible)",
        }
    raise LabError("neither KVM nor TCG acceleration is available")


def _overlay_manifest(name: str, base: BoundFile) -> dict[str, Any]:
    return {
        "schema": OVERLAY_SCHEMA,
        "created_by": SUPERVISOR_VERSION,
        "name": name,
        "format": "qcow2",
        "storage": "persistent",
        "base_image": {
            "path": str(base.path),
            "format": "raw",
            "size": base.size,
            "sha256": base.sha256,
        },
        "boundary": {
            "guest_writes_persist": True,
            "host_shares": False,
            "network_authority": False,
            "production_ready_claimed": False,
            "runtime_sandbox_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
        },
        "nonclaims": list(NONCLAIMS),
    }


def _validate_overlay_manifest(
    value: Any,
    name: str,
    base: BoundFile,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "created_by",
        "name",
        "format",
        "storage",
        "base_image",
        "boundary",
        "nonclaims",
    }:
        raise LabError("overlay manifest has unexpected or missing fields")
    if value.get("schema") != OVERLAY_SCHEMA or value.get("created_by") != SUPERVISOR_VERSION:
        raise LabError("overlay manifest schema or producer is unsupported")
    if value.get("name") != name or value.get("format") != "qcow2" or value.get("storage") != "persistent":
        raise LabError("overlay manifest identity or format mismatch")
    expected_base = {
        "path": str(base.path),
        "format": "raw",
        "size": base.size,
        "sha256": base.sha256,
    }
    if value.get("base_image") != expected_base:
        raise LabError("overlay base-image digest, size, format, or path binding mismatch")
    expected_boundary = _overlay_manifest(name, base)["boundary"]
    if value.get("boundary") != expected_boundary:
        raise LabError("overlay boundary flags are invalid")
    if value.get("nonclaims") != list(NONCLAIMS):
        raise LabError("overlay nonclaims are incomplete or altered")
    return value


def _qemu_img_info(qemu_img: Path, overlay: Path) -> dict[str, Any]:
    result = _run_capture(
        [str(qemu_img), "info", "--output=json", str(overlay)],
        timeout=30,
    )
    return parse_json_object(result.stdout, "qemu-img information")


def _validate_qcow_info(
    info: Mapping[str, Any],
    overlay: Path,
    base: BoundFile,
) -> None:
    if info.get("format") != "qcow2":
        raise LabError("persistent overlay is not qcow2")
    if info.get("filename") != str(overlay):
        raise LabError("qemu-img reported an unexpected overlay filename")
    if info.get("backing-filename-format") != "raw":
        raise LabError("persistent overlay backing format must be raw")
    if info.get("full-backing-filename") != str(base.path):
        raise LabError("persistent overlay backing path differs from the bound base image")
    if info.get("virtual-size") != base.size:
        raise LabError("persistent overlay virtual size differs from the bound base image")
    format_specific = info.get("format-specific")
    data = format_specific.get("data") if isinstance(format_specific, Mapping) else None
    if not isinstance(data, Mapping):
        raise LabError("persistent overlay lacks qcow2 format details")
    if data.get("corrupt") is not False:
        raise LabError("persistent overlay is marked corrupt or has no exact corruption status")
    if data.get("lazy-refcounts") is not False:
        raise LabError("persistent overlay must disable lazy refcounts")


def _remove_exact_file(path: Path, identity: tuple[int, int] | None = None) -> None:
    """Best-effort rollback for a file created by the current operation only."""
    try:
        info = os.lstat(path)
    except OSError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return
    if identity is not None and (info.st_dev, info.st_ino) != identity:
        return
    try:
        os.unlink(path)
    except OSError:
        return


def _create_overlay_unlocked(
    *,
    state: Path,
    name: str,
    base: BoundFile,
    qemu_img_path: Path,
) -> dict[str, Any]:
    """Create one exact named overlay while its caller holds its lock."""
    paths = overlay_paths(state, name)
    overlays = _ensure_private_child(state, "overlays")
    _ensure_private_child(state, "locks")
    for key in ("image", "manifest"):
        if _path_exists_lstat(paths[key]):
            raise LabError(f"overlay create refuses collision at {paths[key]}")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{name}.",
        suffix=".qcow2.tmp",
        dir=overlays,
    )
    temporary = Path(temporary_name)
    os.fchmod(fd, 0o600)
    reserved = os.fstat(fd)
    os.close(fd)
    committed_identity: tuple[int, int] | None = None
    manifest_identity: tuple[int, int] | None = None
    try:
        _run_capture(
            [
                str(qemu_img_path),
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                str(base.path),
                str(temporary),
            ],
            timeout=120,
        )
        built = _regular_lstat(
            temporary,
            "temporary persistent overlay",
            max_bytes=MAX_BASE_BYTES,
            require_private_write=True,
        )
        if (built.st_dev, built.st_ino) != (reserved.st_dev, reserved.st_ino):
            raise LabError("qemu-img replaced the reserved temporary overlay inode")
        _validate_qcow_info(_qemu_img_info(qemu_img_path, temporary), temporary, base)
        base_after_build = validate_bound_file(
            base.path,
            base.sha256,
            "base image after overlay creation",
            max_bytes=MAX_BASE_BYTES,
        )
        if base_after_build.size != base.size:
            raise LabError("base image size changed during overlay creation")
        try:
            os.link(temporary, paths["image"], follow_symlinks=False)
        except FileExistsError:
            raise LabError(f"overlay create refuses collision at {paths['image']}") from None
        except OSError as exc:
            raise LabError(f"cannot atomically commit persistent overlay: {exc}") from exc
        os.unlink(temporary)
        committed = _regular_lstat(
            paths["image"],
            "persistent overlay",
            max_bytes=MAX_BASE_BYTES,
            require_private_write=True,
        )
        committed_identity = (committed.st_dev, committed.st_ino)
        _fsync_directory(overlays)
        manifest_identity = _write_new_json(
            paths["manifest"],
            _overlay_manifest(name, base),
            "overlay manifest",
        )
        return _inspect_overlay_unlocked(
            state=state,
            name=name,
            base=base,
            qemu_img_path=qemu_img_path,
        )
    except BaseException as original:
        _remove_exact_file(temporary, (reserved.st_dev, reserved.st_ino))
        rollback_errors: list[str] = []
        for path, identity, label in (
            (paths["manifest"], manifest_identity, "overlay manifest"),
            (paths["image"], committed_identity, "persistent overlay"),
        ):
            if identity is None:
                continue
            try:
                _unlink_created_file_exact(path, identity, label)
            except LabError as cleanup_error:
                rollback_errors.append(str(cleanup_error))
        if rollback_errors:
            raise LabError(
                "overlay creation failed and exact rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from original
        raise


def create_overlay(
    *,
    state_root: str | os.PathLike[str],
    name: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    qemu_img: str | None = None,
) -> dict[str, Any]:
    safe_name = validate_overlay_name(name)
    base = validate_bound_file(
        base_image, base_sha256, "base image", max_bytes=MAX_BASE_BYTES
    )
    qemu_img_path = _find_executable(qemu_img, "qemu-img", "qemu-img")
    state = ensure_state_root(state_root)
    with overlay_lock(state, safe_name):
        return _create_overlay_unlocked(
            state=state,
            name=safe_name,
            base=base,
            qemu_img_path=qemu_img_path,
        )


def _inspect_overlay_unlocked(
    *,
    state: Path,
    name: str,
    base: BoundFile,
    qemu_img_path: Path,
) -> dict[str, Any]:
    paths = overlay_paths(state, name)
    image_info = _regular_lstat(
        paths["image"],
        "persistent overlay",
        max_bytes=MAX_BASE_BYTES,
        require_private_write=True,
    )
    manifest_raw = _read_regular_text(
        paths["manifest"], "overlay manifest", MAX_MANIFEST_BYTES
    )
    manifest = _validate_overlay_manifest(
        parse_json_object(manifest_raw, "overlay manifest"),
        name,
        base,
    )
    qemu_info = _qemu_img_info(qemu_img_path, paths["image"])
    _validate_qcow_info(qemu_info, paths["image"], base)
    return {
        "schema": OVERLAY_INSPECTION_SCHEMA,
        "status": "valid",
        "name": name,
        "image": {
            "path": str(paths["image"]),
            "format": "qcow2",
            "allocated_file_size": image_info.st_size,
            "virtual_size": qemu_info["virtual-size"],
            "single_link_regular_file": True,
            "private_permissions": True,
        },
        "base_image": base.public(),
        "manifest": manifest,
        "boundary": {
            "guest_writes_persist": True,
            "base_image_mutated": False,
            "concurrent_supervisor_lock": True,
            "host_shares": False,
        },
        "claims": {
            "production_ready_claimed": False,
            "runtime_sandbox_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
        },
        "nonclaims": list(NONCLAIMS),
    }


def inspect_overlay(
    *,
    state_root: str | os.PathLike[str],
    name: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    qemu_img: str | None = None,
) -> dict[str, Any]:
    safe_name = validate_overlay_name(name)
    base = validate_bound_file(
        base_image, base_sha256, "base image", max_bytes=MAX_BASE_BYTES
    )
    qemu_img_path = _find_executable(qemu_img, "qemu-img", "qemu-img")
    state = ensure_state_root(state_root)
    with overlay_lock(state, safe_name):
        return _inspect_overlay_unlocked(
            state=state,
            name=safe_name,
            base=base,
            qemu_img_path=qemu_img_path,
        )


def overlay_confirmation(action: str, name: str, base_sha256: str) -> str:
    if action not in {"remove", "reset"}:
        raise LabError(f"unsupported overlay lifecycle action: {action}")
    safe_name = validate_overlay_name(name)
    digest = validate_sha256(base_sha256, "base image SHA-256")
    return f"{action}:{safe_name}:{digest}"


def _require_overlay_confirmation(
    action: str,
    name: str,
    base_sha256: str,
    confirmation: str,
) -> None:
    expected = overlay_confirmation(action, name, base_sha256)
    if confirmation != expected:
        raise LabError(
            f"overlay {action} is destructive and requires exact --confirm "
            f"{expected}"
        )


def _unlink_existing_file_exact(
    path: Path,
    expected_identity: tuple[int, ...],
    label: str,
    max_bytes: int,
) -> None:
    current = _regular_lstat(
        path,
        label,
        max_bytes=max_bytes,
        require_private_write=True,
    )
    if _stat_identity(current) != expected_identity:
        raise LabError(f"{label} changed before exact removal: {path}")
    try:
        os.unlink(path)
    except OSError as exc:
        raise LabError(f"cannot remove exact {label} {path}: {exc}") from exc
    _fsync_directory(path.parent)


def _remove_overlay_unlocked(
    *,
    state: Path,
    name: str,
    base: BoundFile,
    qemu_img_path: Path,
) -> dict[str, Any]:
    """Validate and remove exactly two named files while holding the lock."""
    paths = overlay_paths(state, name)
    image_before = _regular_lstat(
        paths["image"],
        "persistent overlay",
        max_bytes=MAX_BASE_BYTES,
        require_private_write=True,
    )
    manifest_before = _regular_lstat(
        paths["manifest"],
        "overlay manifest",
        max_bytes=MAX_MANIFEST_BYTES,
        require_private_write=True,
    )
    inspected = _inspect_overlay_unlocked(
        state=state,
        name=name,
        base=base,
        qemu_img_path=qemu_img_path,
    )
    image_identity = _stat_identity(image_before)
    manifest_identity = _stat_identity(manifest_before)
    for path, identity, label, maximum in (
        (paths["image"], image_identity, "persistent overlay", MAX_BASE_BYTES),
        (paths["manifest"], manifest_identity, "overlay manifest", MAX_MANIFEST_BYTES),
    ):
        current = _regular_lstat(
            path,
            label,
            max_bytes=maximum,
            require_private_write=True,
        )
        if _stat_identity(current) != identity:
            raise LabError(f"{label} changed during removal validation: {path}")

    _unlink_existing_file_exact(
        paths["image"], image_identity, "persistent overlay", MAX_BASE_BYTES
    )
    try:
        _unlink_existing_file_exact(
            paths["manifest"],
            manifest_identity,
            "overlay manifest",
            MAX_MANIFEST_BYTES,
        )
    except LabError as exc:
        raise LabError(
            "persistent overlay image was removed, but exact manifest removal "
            f"failed; manual inspection is required: {exc}"
        ) from exc
    return {
        "schema": OVERLAY_REMOVAL_SCHEMA,
        "status": "removed",
        "name": name,
        "removed_paths": [str(paths["image"]), str(paths["manifest"])],
        "base_image": base.public(),
        "validated_before_removal": inspected,
        "exact_named_files_only": True,
        "broad_deletion_used": False,
        "nonclaims": list(NONCLAIMS),
    }


def remove_overlay(
    *,
    state_root: str | os.PathLike[str],
    name: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    confirmation: str,
    qemu_img: str | None = None,
) -> dict[str, Any]:
    safe_name = validate_overlay_name(name)
    digest = validate_sha256(base_sha256, "base image SHA-256")
    _require_overlay_confirmation("remove", safe_name, digest, confirmation)
    base = validate_bound_file(
        base_image, digest, "base image", max_bytes=MAX_BASE_BYTES
    )
    qemu_img_path = _find_executable(qemu_img, "qemu-img", "qemu-img")
    state = ensure_state_root(state_root)
    with overlay_lock(state, safe_name):
        return _remove_overlay_unlocked(
            state=state,
            name=safe_name,
            base=base,
            qemu_img_path=qemu_img_path,
        )


def reset_overlay(
    *,
    state_root: str | os.PathLike[str],
    name: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    confirmation: str,
    qemu_img: str | None = None,
) -> dict[str, Any]:
    safe_name = validate_overlay_name(name)
    digest = validate_sha256(base_sha256, "base image SHA-256")
    _require_overlay_confirmation("reset", safe_name, digest, confirmation)
    base = validate_bound_file(
        base_image, digest, "base image", max_bytes=MAX_BASE_BYTES
    )
    qemu_img_path = _find_executable(qemu_img, "qemu-img", "qemu-img")
    state = ensure_state_root(state_root)
    with overlay_lock(state, safe_name):
        removed = _remove_overlay_unlocked(
            state=state,
            name=safe_name,
            base=base,
            qemu_img_path=qemu_img_path,
        )
        try:
            created = _create_overlay_unlocked(
                state=state,
                name=safe_name,
                base=base,
                qemu_img_path=qemu_img_path,
            )
        except BaseException as exc:
            raise LabError(
                "overlay reset removed the old persistent state, but fresh "
                f"overlay creation failed: {exc}"
            ) from exc
    return {
        "schema": OVERLAY_RESET_SCHEMA,
        "status": "reset",
        "name": safe_name,
        "base_image": base.public(),
        "removed": removed,
        "overlay": created,
        "exact_named_files_only": True,
        "broad_deletion_used": False,
        "nonclaims": list(NONCLAIMS),
    }


def _unlink_exact_volatile_overlay(
    path: Path,
    identity: tuple[int, int],
) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LabError(f"volatile overlay disappeared before cleanup: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LabError(
            f"volatile overlay must remain a single-link regular file: {path}"
        )
    if (info.st_dev, info.st_ino) != identity:
        raise LabError(f"volatile overlay path changed before cleanup: {path}")
    try:
        os.unlink(path)
    except OSError as exc:
        raise LabError(f"cannot remove exact volatile overlay {path}: {exc}") from exc
    _fsync_directory(path.parent)


@contextlib.contextmanager
def private_volatile_overlay(
    *,
    state_root: str | os.PathLike[str],
    base: BoundFile,
    qemu_img_path: Path,
    defer_handled_signals: bool = False,
) -> Iterator[dict[str, Any]]:
    """Create, validate, and always clean one explicit volatile qcow2."""
    state = ensure_state_root(state_root)
    volatile_directory = _ensure_private_child(state, "volatile")
    fd: int | None = None
    temporary: Path | None = None
    identity: tuple[int, int] | None = None
    prepared = False
    try:
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            fd, temporary_name = tempfile.mkstemp(
                prefix=".wuci-volatile.",
                suffix=".qcow2",
                dir=volatile_directory,
            )
            temporary = Path(temporary_name)
            reserved = os.fstat(fd)
            identity = (reserved.st_dev, reserved.st_ino)
            os.fchmod(fd, 0o600)
            os.close(fd)
            fd = None
        if temporary is None or identity is None:
            raise LabError("volatile overlay allocation lacked an exact identity")
        _run_capture(
            [
                str(qemu_img_path),
                "create",
                "-q",
                "-f",
                "qcow2",
                "-F",
                "raw",
                "-b",
                str(base.path),
                str(temporary),
            ],
            timeout=120,
        )
        built = _regular_lstat(
            temporary,
            "volatile overlay",
            max_bytes=MAX_BASE_BYTES,
            require_private_write=True,
        )
        if (built.st_dev, built.st_ino) != identity:
            raise LabError("qemu-img replaced the reserved volatile overlay inode")
        qemu_info = _qemu_img_info(qemu_img_path, temporary)
        _validate_qcow_info(qemu_info, temporary, base)
        base_after_build = validate_bound_file(
            base.path,
            base.sha256,
            "base image after volatile overlay creation",
            max_bytes=MAX_BASE_BYTES,
        )
        if base_after_build.size != base.size:
            raise LabError("base image size changed during volatile overlay creation")
        prepared = True
        yield {
            "path": str(temporary),
            "format": "qcow2",
            "allocated_file_size": built.st_size,
            "virtual_size": qemu_info["virtual-size"],
            "base_path": str(base.path),
            "base_sha256": base.sha256,
            "single_link_regular_file": True,
            "private_permissions": True,
            "cleanup_on_supervisor_unwind": True,
            "cleanup_after_sigkill_or_host_crash_claimed": False,
        }
    finally:
        if fd is not None:
            os.close(fd)
        if temporary is not None and identity is not None:
            if prepared:
                _unlink_exact_volatile_overlay(temporary, identity)
            else:
                _remove_exact_file(temporary, identity)
                _fsync_directory(volatile_directory)


def _observe_bound_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
) -> BoundFile:
    before = _regular_lstat(path, label, max_bytes=max_bytes)
    fd = _open_regular(path, label, before)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise LabError(f"{label} exceeds the {max_bytes}-byte limit")
            digest.update(block)
        after = os.fstat(fd)
        if total != before.st_size or _stat_identity(before) != _stat_identity(after):
            raise LabError(f"{label} changed while being hashed: {path}")
        try:
            path_after = os.lstat(path)
        except OSError as exc:
            raise LabError(f"{label} path changed while being hashed: {path}") from exc
        if _stat_identity(after) != _stat_identity(path_after):
            raise LabError(f"{label} path changed while being hashed: {path}")
    finally:
        os.close(fd)
    return BoundFile(
        path=path,
        sha256=digest.hexdigest(),
        size=total,
        mode=stat.S_IMODE(before.st_mode),
        device=before.st_dev,
        inode=before.st_ino,
    )


def _copy_bound_payload(
    source: BoundFile,
    destination: Path,
    *,
    defer_handled_signals: bool = False,
) -> tuple[int, int]:
    before = _regular_lstat(
        source.path,
        "hostile payload source",
        max_bytes=MAX_HOSTILE_PAYLOAD_BYTES,
    )
    if (
        before.st_dev != source.device
        or before.st_ino != source.inode
        or before.st_size != source.size
        or stat.S_IMODE(before.st_mode) != source.mode
    ):
        raise LabError("hostile payload source changed before private snapshot")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd: int | None = None
    destination_fd: int | None = None
    identity: tuple[int, int] | None = None
    digest = hashlib.sha256()
    total = 0
    try:
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            source_fd = _open_regular(
                source.path, "hostile payload source", before
            )
            try:
                destination_fd = os.open(destination, flags, 0o600)
            except OSError as exc:
                raise LabError(
                    "cannot reserve private hostile payload snapshot "
                    f"{destination}: {exc}"
                ) from exc
            created = os.fstat(destination_fd)
            if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
                raise LabError(
                    "private hostile payload snapshot is not a single-link file"
                )
            identity = (created.st_dev, created.st_ino)
        assert source_fd is not None
        assert destination_fd is not None
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_HOSTILE_PAYLOAD_BYTES:
                raise LabError("hostile payload source exceeded its bounded size")
            digest.update(block)
            offset = 0
            while offset < len(block):
                written = os.write(destination_fd, block[offset:])
                if written <= 0:
                    raise LabError("short write while snapshotting hostile payload")
                offset += written
        os.fsync(destination_fd)
        source_after = os.fstat(source_fd)
        destination_after = os.fstat(destination_fd)
        if _stat_identity(source_after) != _stat_identity(before):
            raise LabError("hostile payload source changed while being snapshotted")
        try:
            source_path_after = os.lstat(source.path)
        except OSError as exc:
            raise LabError(
                "hostile payload source path changed while being snapshotted"
            ) from exc
        if _stat_identity(source_after) != _stat_identity(source_path_after):
            raise LabError("hostile payload source path changed while being snapshotted")
        if total != source.size or digest.hexdigest() != source.sha256:
            raise LabError("hostile payload source digest changed during snapshot")
        if (
            destination_after.st_dev,
            destination_after.st_ino,
        ) != identity or destination_after.st_size != source.size:
            raise LabError("private hostile payload snapshot inode or size changed")
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
    except BaseException as original:
        try:
            if identity is not None:
                _unlink_created_file_exact(
                    destination, identity, "private hostile payload snapshot"
                )
        except LabError as cleanup_error:
            raise LabError(
                "hostile payload snapshot failed and exact cleanup was incomplete: "
                f"{cleanup_error}"
            ) from original
        raise
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    if identity is None:
        raise LabError("hostile payload snapshot did not establish an inode identity")
    return identity


def _hostile_payload_uuid(digest: str) -> str:
    raw = bytearray.fromhex(digest[:32])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    value = raw.hex()
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def _hostile_payload_manifest(source: BoundFile) -> dict[str, Any]:
    return {
        "schema": HOSTILE_PAYLOAD_SCHEMA,
        "source": {"sha256": source.sha256, "size": source.size},
        "guest": {
            "payload_path": "/payload/payload.bin",
            "manifest_path": "/payload/manifest.json",
            "secondary_device": "/dev/vdb",
            "mount_policy": "read-only",
        },
        "boundary": {
            "host_execution": False,
            "host_source_shared": False,
            "guest_media_read_only": True,
            "network_enabled": False,
            "persistent_storage_enabled": False,
        },
    }


def _hostile_payload_media_size(source_size: int) -> int:
    quantum = 4 * 1024 * 1024
    requested = source_size + 16 * 1024 * 1024
    size = max(16 * 1024 * 1024, ((requested + quantum - 1) // quantum) * quantum)
    if size > MAX_HOSTILE_PAYLOAD_MEDIA_BYTES:
        raise LabError("hostile payload media size exceeds its fixed bound")
    return size


def _debugfs_dump_digest(
    *,
    debugfs_path: Path,
    media_fd: int,
    operation: Path,
    guest_path: str,
    output_name: str,
    expected_size: int,
    expected_sha256: str,
    defer_handled_signals: bool,
) -> dict[str, Any]:
    if (
        guest_path not in {"/payload.bin", "/manifest.json"}
        or output_name not in {
            "readback-payload.bin",
            "readback-manifest.json",
        }
        or type(expected_size) is not int
        or expected_size < 0
        or expected_size > MAX_HOSTILE_PAYLOAD_BYTES
        or SHA256_RE.fullmatch(expected_sha256) is None
    ):
        raise LabError("hostile payload readback contract is invalid")
    output = operation / output_name
    output_fd: int | None = None
    output_identity: tuple[int, int] | None = None
    primary_error: BaseException | None = None
    try:
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            output_fd = os.open(
                output,
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            created = os.fstat(output_fd)
            if (
                not stat.S_ISREG(created.st_mode)
                or created.st_nlink != 1
                or stat.S_IMODE(created.st_mode) & 0o077
            ):
                raise LabError(
                    "hostile payload readback output is not a private "
                    "single-link file"
                )
            output_identity = (created.st_dev, created.st_ino)
        assert output_fd is not None
        result = _run_capture(
            [
                str(debugfs_path),
                "-R",
                f"dump {guest_path} /proc/self/fd/{output_fd}",
                f"/proc/self/fd/{media_fd}",
            ],
            timeout=30,
            pass_fds=(media_fd, output_fd),
        )
        expected_stderr = (
            f"debugfs {TRUSTED_MKE2FS_VERSION} (5-Feb-2023)\n"
        )
        if result.stdout != "" or result.stderr != expected_stderr:
            raise LabError(
                f"hostile payload debugfs readback differs for {guest_path}"
            )
        os.fsync(output_fd)
        observed = os.fstat(output_fd)
        path_observed = os.lstat(output)
        if (
            output_identity is None
            or (observed.st_dev, observed.st_ino) != output_identity
            or _stat_identity(observed) != _stat_identity(path_observed)
            or observed.st_size != expected_size
        ):
            raise LabError(
                f"hostile payload readback metadata differs for {guest_path}"
            )
        digest = hashlib.sha256()
        offset = 0
        while offset < expected_size:
            block = os.pread(
                output_fd,
                min(1024 * 1024, expected_size - offset),
                offset,
            )
            if not block:
                raise LabError(
                    f"hostile payload readback is truncated for {guest_path}"
                )
            digest.update(block)
            offset += len(block)
        if digest.hexdigest() != expected_sha256:
            raise LabError(
                f"hostile payload readback digest differs for {guest_path}"
            )
        return {
            "guest_path": guest_path,
            "size": expected_size,
            "sha256": expected_sha256,
        }
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: LabError | None = None
        if output_fd is not None:
            try:
                os.close(output_fd)
            except OSError as exc:
                cleanup_error = LabError(
                    f"cannot close hostile payload readback output: {exc}"
                )
        if output_identity is not None:
            try:
                _unlink_created_file_exact(
                    output,
                    output_identity,
                    "hostile payload readback output",
                )
            except LabError as exc:
                cleanup_error = exc
        if cleanup_error is not None:
            if primary_error is not None:
                raise LabError(
                    "hostile payload readback failed and exact cleanup was "
                    f"incomplete: {cleanup_error}"
                ) from primary_error
            raise cleanup_error


def _verify_hostile_payload_media_contents(
    *,
    media_path: Path,
    media_identity: tuple[int, int],
    operation: Path,
    source: BoundFile,
    manifest: Mapping[str, Any],
    debugfs_path: Path,
    defer_handled_signals: bool,
) -> dict[str, Any]:
    before = _regular_lstat(
        media_path,
        "hostile payload media before semantic readback",
        max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
        require_private_write=True,
    )
    if (before.st_dev, before.st_ino) != media_identity:
        raise LabError("hostile payload media changed before semantic readback")
    media_fd = _open_regular(
        media_path,
        "hostile payload media before semantic readback",
        before,
    )
    try:
        manifest_bytes = canonical_json(manifest).encode("utf-8")
        payload_record = _debugfs_dump_digest(
            debugfs_path=debugfs_path,
            media_fd=media_fd,
            operation=operation,
            guest_path="/payload.bin",
            output_name="readback-payload.bin",
            expected_size=source.size,
            expected_sha256=source.sha256,
            defer_handled_signals=defer_handled_signals,
        )
        manifest_record = _debugfs_dump_digest(
            debugfs_path=debugfs_path,
            media_fd=media_fd,
            operation=operation,
            guest_path="/manifest.json",
            output_name="readback-manifest.json",
            expected_size=len(manifest_bytes),
            expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            defer_handled_signals=defer_handled_signals,
        )
        after = os.fstat(media_fd)
        path_after = os.lstat(media_path)
        if (
            _stat_identity(after) != _stat_identity(before)
            or _stat_identity(after) != _stat_identity(path_after)
        ):
            raise LabError("hostile payload media changed during semantic readback")
    finally:
        os.close(media_fd)
    return {
        "filesystem": "ext4",
        "debugfs_path": str(debugfs_path),
        "debugfs_version": TRUSTED_MKE2FS_VERSION,
        "payload": payload_record,
        "manifest": manifest_record,
        "exact_guest_file_bytes_verified": True,
    }


def _rmdir_created_directory_exact(
    path: Path,
    identity: tuple[int, int],
    label: str,
) -> None:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise LabError(f"cannot inspect exact {label} directory {path}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
        raise LabError(f"exact {label} directory identity changed: {path}")
    try:
        os.rmdir(path)
    except OSError as exc:
        raise LabError(f"cannot remove exact empty {label} directory {path}: {exc}") from exc
    _fsync_directory(path.parent)


def _remove_payload_operation_exact(
    operation: Path,
    root: Path,
    operation_identity: tuple[int, int],
    root_identity: tuple[int, int],
    files: Sequence[tuple[Path, tuple[int, int] | None, str]],
) -> None:
    errors: list[str] = []
    for path, identity, label in files:
        if identity is None:
            continue
        try:
            _unlink_created_file_exact(path, identity, label)
        except LabError as exc:
            errors.append(str(exc))
    for path, identity, label in (
        (root, root_identity, "payload staging root"),
        (operation, operation_identity, "payload operation"),
    ):
        try:
            _rmdir_created_directory_exact(path, identity, label)
        except LabError as exc:
            errors.append(str(exc))
    if errors:
        raise LabError("hostile payload cleanup was incomplete: " + "; ".join(errors))


@contextlib.contextmanager
def private_hostile_payload_media(
    *,
    state_root: str | os.PathLike[str],
    source: BoundFile,
    mke2fs_path: Path,
    debugfs_path: Path,
    defer_handled_signals: bool = False,
) -> Iterator[dict[str, Any]]:
    """Snapshot one payload into guest-read-only, private transient ext4 media."""
    state = ensure_state_root(state_root)
    payload_directory = _ensure_private_child(state, "payloads")
    operation: Path | None = None
    operation_identity: tuple[int, int] | None = None
    root: Path | None = None
    root_identity: tuple[int, int] | None = None
    try:
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            operation = Path(
                tempfile.mkdtemp(
                    prefix=".wuci-payload.", dir=payload_directory
                )
            )
            operation_info = os.lstat(operation)
            operation_identity = (
                operation_info.st_dev,
                operation_info.st_ino,
            )
            operation.chmod(0o700)
            root = operation / "root"
            os.mkdir(root, 0o700)
            root_info = os.lstat(root)
            root_identity = (root_info.st_dev, root_info.st_ino)
    except BaseException as original:
        cleanup_errors: list[str] = []
        if root is not None and root_identity is not None:
            try:
                _rmdir_created_directory_exact(
                    root, root_identity, "payload staging root"
                )
            except LabError as exc:
                cleanup_errors.append(str(exc))
        elif root is not None:
            try:
                root_exists = _path_exists_lstat(root)
            except LabError as exc:
                cleanup_errors.append(str(exc))
            else:
                if root_exists:
                    cleanup_errors.append(
                        "payload staging root was created without a validated "
                        f"identity: {root}"
                    )
        if operation is not None and operation_identity is not None:
            try:
                _rmdir_created_directory_exact(
                    operation, operation_identity, "payload operation"
                )
            except LabError as exc:
                cleanup_errors.append(str(exc))
        elif operation is not None:
            cleanup_errors.append(
                "payload operation was created without a validated identity: "
                f"{operation}"
            )
        if cleanup_errors:
            raise LabError(
                "hostile payload setup failed and exact cleanup was incomplete: "
                + "; ".join(cleanup_errors)
            ) from original
        raise
    if (
        operation is None
        or operation_identity is None
        or root is None
        or root_identity is None
    ):
        raise LabError("hostile payload staging identities were not established")
    snapshot = root / "payload.bin"
    manifest_path = root / "manifest.json"
    media_path = operation / "payload.ext4"
    snapshot_identity: tuple[int, int] | None = None
    manifest_identity: tuple[int, int] | None = None
    media_identity: tuple[int, int] | None = None
    cleanup_files: list[tuple[Path, tuple[int, int] | None, str]] = []
    try:
        snapshot_identity = _copy_bound_payload(
            source,
            snapshot,
            defer_handled_signals=defer_handled_signals,
        )
        manifest = _hostile_payload_manifest(source)
        manifest_identity = _write_new_json(
            manifest_path,
            manifest,
            "hostile payload manifest",
            defer_handled_signals=defer_handled_signals,
        )
        manifest_fd: int | None = None
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            try:
                manifest_fd = os.open(
                    manifest_path,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                os.fchmod(manifest_fd, 0o400)
                os.fsync(manifest_fd)
            finally:
                if manifest_fd is not None:
                    os.close(manifest_fd)
        fixed_time = 946684800
        os.utime(snapshot, (fixed_time, fixed_time), follow_symlinks=False)
        os.utime(manifest_path, (fixed_time, fixed_time), follow_symlinks=False)
        os.utime(root, (fixed_time, fixed_time), follow_symlinks=False)

        media_size = _hostile_payload_media_size(source.size)
        media_fd: int | None = None
        allocation_context = (
            _block_handled_signals_during_allocation()
            if defer_handled_signals
            else contextlib.nullcontext()
        )
        with allocation_context:
            try:
                media_fd = os.open(
                    media_path,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                reserved = os.fstat(media_fd)
                media_identity = (reserved.st_dev, reserved.st_ino)
                os.fchmod(media_fd, 0o600)
                os.ftruncate(media_fd, media_size)
                os.fsync(media_fd)
                reserved = os.fstat(media_fd)
                if (reserved.st_dev, reserved.st_ino) != media_identity:
                    raise LabError(
                        "reserved hostile payload media inode changed"
                    )
            finally:
                if media_fd is not None:
                    os.close(media_fd)
        environment = _sanitized_environment()
        environment["E2FSPROGS_FAKE_TIME"] = str(fixed_time)
        uuid = _hostile_payload_uuid(source.sha256)
        _run_capture(
            [
                str(mke2fs_path),
                "-q",
                "-F",
                "-t",
                "ext4",
                "-b",
                "4096",
                "-I",
                "256",
                "-m",
                "0",
                "-U",
                uuid,
                "-L",
                "WUCI_PAYLOAD",
                "-O",
                "none",
                "-E",
                "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,no_copy_xattrs,"
                f"hash_seed={uuid}",
                "-d",
                str(root),
                str(media_path),
            ],
            timeout=120,
            environment=environment,
        )
        built = _regular_lstat(
            media_path,
            "hostile payload media",
            max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
            require_private_write=True,
        )
        if (built.st_dev, built.st_ino) != media_identity or built.st_size != media_size:
            raise LabError("mke2fs replaced or resized the reserved payload-media inode")
        if media_identity is None:
            raise LabError("hostile payload media identity was not established")
        semantic_readback = _verify_hostile_payload_media_contents(
            media_path=media_path,
            media_identity=media_identity,
            operation=operation,
            source=source,
            manifest=manifest,
            debugfs_path=debugfs_path,
            defer_handled_signals=defer_handled_signals,
        )
        os.chmod(media_path, 0o400, follow_symlinks=False)
        media = _observe_bound_file(
            media_path,
            "hostile payload media",
            max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
        )
        if (media.device, media.inode) != media_identity:
            raise LabError(
                "hostile payload media inode changed after semantic readback"
            )
        source_after = validate_bound_file(
            source.path,
            source.sha256,
            "hostile payload source after media creation",
            max_bytes=MAX_HOSTILE_PAYLOAD_BYTES,
        )
        if source_after.public() != source.public():
            raise LabError("hostile payload source metadata changed during media creation")
        cleanup_files = [
            (media_path, media_identity, "hostile payload media"),
            (manifest_path, manifest_identity, "hostile payload manifest"),
            (snapshot, snapshot_identity, "private hostile payload snapshot"),
        ]
        yield {
            "schema": HOSTILE_PAYLOAD_SCHEMA,
            "source": source.public(),
            "manifest": manifest,
            "semantic_readback": semantic_readback,
            "media": {
                **media.public(),
                "format": "raw-ext4",
                "filesystem_uuid": uuid,
                "guest_device": "/dev/vdb",
                "qemu_read_only": True,
                "host_mode": "0400",
            },
            "cleanup_on_supervisor_unwind": True,
            "cleanup_after_sigkill_or_host_crash_claimed": False,
        }
    except BaseException as original:
        files = cleanup_files or [
            (media_path, media_identity, "hostile payload media"),
            (manifest_path, manifest_identity, "hostile payload manifest"),
            (snapshot, snapshot_identity, "private hostile payload snapshot"),
        ]
        try:
            _remove_payload_operation_exact(
                operation,
                root,
                operation_identity,
                root_identity,
                files,
            )
        except LabError as cleanup_error:
            raise LabError(
                "hostile payload operation failed and exact cleanup was incomplete: "
                f"{cleanup_error}"
            ) from original
        raise
    else:
        _remove_payload_operation_exact(
            operation,
            root,
            operation_identity,
            root_identity,
            cleanup_files,
        )


def _validate_resources(memory_mib: int, cpus: int) -> None:
    if not isinstance(memory_mib, int) or isinstance(memory_mib, bool):
        raise LabError("memory MiB must be an integer")
    if not MIN_MEMORY_MIB <= memory_mib <= MAX_MEMORY_MIB:
        raise LabError(
            f"memory MiB must be between {MIN_MEMORY_MIB} and {MAX_MEMORY_MIB}"
        )
    if not isinstance(cpus, int) or isinstance(cpus, bool):
        raise LabError("CPU count must be an integer")
    if not MIN_CPUS <= cpus <= MAX_CPUS:
        raise LabError(f"CPU count must be between {MIN_CPUS} and {MAX_CPUS}")


def _kernel_append_for_acceleration(selected: str) -> str:
    if selected not in {"kvm", "tcg"}:
        raise LabError(f"unsupported selected acceleration: {selected}")
    arguments = KERNEL_APPEND.split()
    if selected == "tcg":
        arguments.extend(FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS)
    return " ".join(arguments)


def _build_qemu_argv(
    *,
    qemu_path: Path,
    inputs: Mapping[str, BoundFile],
    root_disk: Path,
    root_format: str,
    storage: str,
    network: str,
    profile: str,
    acceleration: Mapping[str, Any],
    memory_mib: int,
    cpus: int,
    payload_media: Path | None = None,
) -> list[str]:
    if root_format not in {"raw", "qcow2"}:
        raise LabError(f"unsupported root disk format: {root_format}")
    if payload_media is not None and not (
        profile == "hostile"
        and storage == "volatile"
        and network == "none"
        and acceleration.get("selected") == "kvm"
    ):
        raise LabError(
            "read-only payload ingress is restricted to offline, volatile, "
            "KVM hostile launches"
        )
    drive = (
        f"file={root_disk},if=none,id=wuci-root,format={root_format},"
        "cache=writeback,aio=threads"
    )

    selected = acceleration["selected"]
    cpu = "host" if selected == "kvm" else TCG_CPU_MODEL
    argv = [
        str(qemu_path),
        "-nodefaults",
        "-no-user-config",
        "-machine",
        f"q35,accel={selected}",
        "-cpu",
        cpu,
        "-m",
        str(memory_mib),
        "-smp",
        str(cpus),
        "-name",
        f"wuci-lab-{profile},debug-threads=on",
        "-sandbox",
        QEMU_SANDBOX,
        "-monitor",
        "none",
        "-nographic",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-kernel",
        str(inputs["kernel"].path),
        "-initrd",
        str(inputs["initrd"].path),
        "-append",
        _kernel_append_for_acceleration(selected),
        "-drive",
        drive,
        "-device",
        "virtio-blk-pci,drive=wuci-root,bootindex=1",
    ]
    if payload_media is not None:
        argv.extend(
            [
                "-drive",
                f"file={payload_media},if=none,id=wuci-payload,format=raw,"
                "readonly=on,cache=writeback,aio=threads",
                "-device",
                "virtio-blk-pci,drive=wuci-payload",
            ]
        )
    if network == "none":
        argv.extend(["-nic", "none"])
    elif network == "internet":
        argv.extend(
            [
                "-netdev",
                QEMU_USER_NETDEV,
                "-device",
                "virtio-net-pci,netdev=wuci-net",
            ]
        )
    else:
        raise LabError(f"unsupported network mode: {network}")
    return argv


def _hostile_runtime_binding(
    source_value: str | os.PathLike[str],
    destination_value: str | os.PathLike[str],
    *,
    kind: str,
    label: str,
    max_bytes: int | None,
    expected_bound: BoundFile | None = None,
) -> dict[str, Any]:
    source = absolute_path(source_value, label)
    destination_raw = _raw_path(destination_value, f"{label} destination")
    destination = Path(destination_raw)
    if not destination.is_absolute():
        raise LabError(f"{label} destination must be absolute")
    destination = Path(os.path.abspath(os.fspath(destination)))
    if kind == "file":
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 1
        ):
            raise LabError(f"{label} requires a positive file-size limit")
        info = _regular_lstat(source, label, max_bytes=max_bytes)
    elif kind == "directory":
        if max_bytes is not None:
            raise LabError(f"{label} directory must not carry a file-size limit")
        if expected_bound is not None:
            raise LabError(f"{label} directory cannot carry a bound-file identity")
        reject_symlink_components(source, label)
        try:
            info = os.lstat(source)
        except OSError as exc:
            raise LabError(f"{label} is missing or unreadable: {source}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise LabError(f"{label} must be a directory: {source}")
        if info.st_mode & 0o022:
            raise LabError(f"{label} must not be group/world writable: {source}")
    else:
        raise LabError(f"invalid hostile runtime binding kind: {kind}")
    if expected_bound is not None:
        if not isinstance(expected_bound, BoundFile):
            raise LabError(f"{label} expected binding is invalid")
        observed_identity = (
            source,
            info.st_dev,
            info.st_ino,
            info.st_size,
            stat.S_IMODE(info.st_mode),
        )
        expected_identity = (
            expected_bound.path,
            expected_bound.device,
            expected_bound.inode,
            expected_bound.size,
            expected_bound.mode,
        )
        if observed_identity != expected_identity:
            raise LabError(f"{label} changed after boot-input validation")
    return {
        "source": str(source),
        "destination": str(destination),
        "kind": kind,
        "device": info.st_dev,
        "inode": info.st_ino,
        "links": info.st_nlink,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }


def _hostile_read_only_bindings(
    qemu_path: Path,
    inputs: Mapping[str, BoundFile],
) -> list[dict[str, Any]]:
    requests: list[
        tuple[Path, Path, str, str, int | None, BoundFile | None]
    ] = [
        (
            qemu_path,
            qemu_path,
            "file",
            "hostile QEMU executable",
            MAX_HOSTILE_RUNTIME_FILE_BYTES,
            None,
        ),
    ]
    requests.extend(
        (
            path,
            path,
            "directory",
            f"hostile QEMU runtime directory {path}",
            None,
            None,
        )
        for path in HOSTILE_RUNTIME_DIRECTORIES
    )
    requests.extend(
        (
            source,
            destination,
            "directory",
            "hostile QEMU runtime alias",
            None,
            None,
        )
        for source, destination in HOSTILE_RUNTIME_DIRECTORY_ALIASES
    )
    requests.extend(
        (
            source,
            destination,
            "file",
            "hostile QEMU runtime file",
            MAX_HOSTILE_RUNTIME_FILE_BYTES,
            None,
        )
        for source, destination in HOSTILE_RUNTIME_FILES
    )
    for key, label, max_bytes in (
        ("kernel", "hostile bound kernel", MAX_KERNEL_BYTES),
        ("initrd", "hostile bound initrd", MAX_INITRD_BYTES),
        ("base_image", "hostile bound base image", MAX_BASE_BYTES),
    ):
        bound = inputs.get(key)
        if not isinstance(bound, BoundFile):
            raise LabError(f"hostile launch lacks a validated {key} input")
        requests.append(
            (bound.path, bound.path, "file", label, max_bytes, bound)
        )

    bindings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for source, destination, kind, label, max_bytes, expected_bound in requests:
        record = _hostile_runtime_binding(
            source,
            destination,
            kind=kind,
            label=label,
            max_bytes=max_bytes,
            expected_bound=expected_bound,
        )
        key = (record["source"], record["destination"])
        if key in seen:
            continue
        seen.add(key)
        bindings.append(record)
    return bindings


def _hostile_directory_skeleton(
    bindings: Sequence[Mapping[str, Any]],
    volatile_directory: Path,
) -> list[str]:
    directories = {
        Path("/dev"),
        Path("/proc"),
        Path("/run"),
        Path("/sys"),
        Path("/tmp"),
        Path("/var"),
        Path("/var/tmp"),
        volatile_directory,
    }
    for record in bindings:
        destination_value = record.get("destination")
        kind = record.get("kind")
        if not isinstance(destination_value, str) or kind not in {"file", "directory"}:
            raise LabError("hostile runtime binding record is invalid")
        destination = Path(destination_value)
        current = destination if kind == "directory" else destination.parent
        while current != Path("/"):
            directories.add(current)
            current = current.parent
    current = volatile_directory
    while current != Path("/"):
        directories.add(current)
        current = current.parent
    return [
        str(path)
        for path in sorted(directories, key=lambda item: (len(item.parts), str(item)))
    ]


def _hostile_resource_limits(
    *,
    memory_mib: int,
    base_image_bytes: int,
) -> dict[str, int]:
    _validate_resources(memory_mib, MIN_CPUS)
    if (
        not isinstance(base_image_bytes, int)
        or isinstance(base_image_bytes, bool)
        or not 1 <= base_image_bytes <= MAX_BASE_BYTES
    ):
        raise LabError("hostile resource limits require a valid base-image size")
    guest_memory_bytes = memory_mib * 1024 * 1024
    return {
        "address_space_bytes": (
            guest_memory_bytes * 2 + HOSTILE_ADDRESS_SPACE_OVERHEAD_BYTES
        ),
        "locked_memory_bytes": HOSTILE_LOCKED_MEMORY_BYTES,
        "file_size_bytes": base_image_bytes + HOSTILE_FILE_SIZE_OVERHEAD_BYTES,
        "open_files": HOSTILE_OPEN_FILES,
        "processes": HOSTILE_ACCOUNT_TASK_LIMIT,
        "core_bytes": 0,
    }


def _resource_limit_constants() -> dict[str, int]:
    return {
        "address_space_bytes": resource.RLIMIT_AS,
        "locked_memory_bytes": resource.RLIMIT_MEMLOCK,
        "file_size_bytes": resource.RLIMIT_FSIZE,
        "open_files": resource.RLIMIT_NOFILE,
        "processes": resource.RLIMIT_NPROC,
        "core_bytes": resource.RLIMIT_CORE,
    }


def _real_uid_task_count() -> int:
    real_uid = os.getuid()
    total = 0
    try:
        entries = os.scandir("/proc")
    except OSError as exc:
        raise LabError(
            f"cannot inspect account-wide host task usage: {exc}"
        ) from exc
    with entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            status = Path("/proc") / entry.name / "status"
            try:
                with status.open("rb", buffering=0) as stream:
                    data = stream.read(128 * 1024 + 1)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise LabError(
                    f"cannot inspect host task record {status}: {exc}"
                ) from exc
            if len(data) > 128 * 1024:
                raise LabError(f"host task record is unexpectedly large: {status}")
            observed_uid: int | None = None
            threads: int | None = None
            for line in data.splitlines():
                if line.startswith(b"Uid:"):
                    fields = line.split()
                    if len(fields) != 5:
                        raise LabError(
                            f"host task UID record is malformed: {status}"
                        )
                    try:
                        observed_uid = int(fields[1])
                    except ValueError as exc:
                        raise LabError(
                            f"host task UID record is malformed: {status}"
                        ) from exc
                elif line.startswith(b"Threads:"):
                    fields = line.split()
                    if len(fields) != 2:
                        raise LabError(
                            f"host task thread record is malformed: {status}"
                        )
                    try:
                        threads = int(fields[1])
                    except ValueError as exc:
                        raise LabError(
                            f"host task thread record is malformed: {status}"
                        ) from exc
            if observed_uid == real_uid:
                if threads is None or threads < 1:
                    raise LabError(
                        f"host task thread count is invalid: {status}"
                    )
                total += threads
    if total < 1:
        raise LabError("account-wide host task usage could not be measured")
    return total


def _validate_host_resource_limit_capacity(limits: Mapping[str, Any]) -> None:
    constants = _resource_limit_constants()
    if set(limits) != set(constants):
        raise LabError("hostile host-resource limit record is invalid")
    for name, limit_constant in constants.items():
        value = limits.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise LabError(f"hostile {name} limit must be a non-negative integer")
        _soft, hard = resource.getrlimit(limit_constant)
        if hard != resource.RLIM_INFINITY and value > hard:
            raise LabError(
                f"hostile {name} limit {value} exceeds the host hard limit {hard}"
            )
    account_tasks = _real_uid_task_count()
    process_limit = int(limits["processes"])
    if (
        process_limit - account_tasks
        < HOSTILE_MIN_ACCOUNT_TASK_HEADROOM
    ):
        raise LabError(
            "hostile account-wide RLIMIT_NPROC ceiling leaves fewer than "
            f"{HOSTILE_MIN_ACCOUNT_TASK_HEADROOM} host-task slots "
            f"(observed={account_tasks}, limit={process_limit})"
        )


def _resource_limit_preexec(limits: Mapping[str, Any]) -> Callable[[], None]:
    _validate_host_resource_limit_capacity(limits)
    ordered = tuple(
        (limit_constant, int(limits[name]))
        for name, limit_constant in _resource_limit_constants().items()
    )

    def apply_limits() -> None:
        for limit_constant, value in ordered:
            resource.setrlimit(limit_constant, (value, value))

    return apply_limits


def _build_hostile_bwrap_argv(
    *,
    qemu_argv: Sequence[str],
    qemu_path: Path,
    inputs: Mapping[str, BoundFile],
    state_root: Path,
    bubblewrap: Mapping[str, Any],
    resource_limits: Mapping[str, Any],
    payload_media: BoundFile | None = None,
    defer_payload: bool = False,
) -> tuple[list[str], dict[str, Any]]:
    if not (
        bubblewrap.get("available")
        and bubblewrap.get("trusted")
        and bubblewrap.get("path") == str(TRUSTED_BWRAP)
    ):
        raise LabError("hostile mode requires trusted exact /usr/bin/bwrap")
    _validate_host_resource_limit_capacity(resource_limits)
    if payload_media is not None and defer_payload:
        raise LabError("hostile payload media cannot be both bound and deferred")
    bindings = _hostile_read_only_bindings(qemu_path, inputs)
    if payload_media is not None:
        payload_binding = _hostile_runtime_binding(
            payload_media.path,
            HOSTILE_PAYLOAD_GUEST_MEDIA,
            kind="file",
            label="hostile read-only payload media",
            max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
            expected_bound=payload_media,
        )
        payload_binding["purpose"] = "guest-read-only hostile payload media"
        bindings.append(payload_binding)
    elif defer_payload:
        bindings.append(
            {
                "source": DEFERRED_HOSTILE_PAYLOAD,
                "destination": str(HOSTILE_PAYLOAD_GUEST_MEDIA),
                "kind": "file",
                "deferred": True,
                "purpose": "guest-read-only hostile payload media",
            }
        )
    volatile_directory = state_root / "volatile"
    skeleton = _hostile_directory_skeleton(bindings, volatile_directory)
    environment = {
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin",
        "XDG_CONFIG_HOME": "/tmp",
    }
    argv = [str(TRUSTED_BWRAP), *HOSTILE_BWRAP_FLAGS]
    argv.extend(
        [
            "--cap-drop",
            "ALL",
            "--hostname",
            "wuci-hostile",
            "--clearenv",
            "--perms",
            "0700",
            "--tmpfs",
            "/",
        ]
    )
    for directory in skeleton:
        argv.extend(["--dir", directory])
    argv.extend(
        [
            "--dev",
            "/dev",
            "--dev-bind",
            "/dev/kvm",
            "/dev/kvm",
            "--proc",
            "/proc",
        ]
    )
    for destination in ("/tmp", "/run", "/var/tmp"):
        argv.extend(["--perms", "0700", "--tmpfs", destination])
    for record in bindings:
        argv.extend(["--ro-bind", record["source"], record["destination"]])
    argv.extend(
        [
            "--bind",
            DEFERRED_VOLATILE_ROOT,
            DEFERRED_VOLATILE_ROOT,
            "--remount-ro",
            "/",
            "--chdir",
            "/tmp",
        ]
    )
    for key, value in environment.items():
        argv.extend(["--setenv", key, value])
    argv.extend(["--", *qemu_argv])
    return argv, {
        "supervisor": "bubblewrap",
        "path": str(TRUSTED_BWRAP),
        "empty_private_root": True,
        "root_read_only_after_setup": True,
        "namespace_flags": list(HOSTILE_BWRAP_FLAGS),
        "private_tmpfs": ["/tmp", "/run", "/var/tmp"],
        "read_only_bindings": bindings,
        "read_write_bindings": [
            {
                "source": DEFERRED_VOLATILE_ROOT,
                "destination": DEFERRED_VOLATILE_ROOT,
                "purpose": "private volatile qcow2 overlay only",
            }
        ],
        "device_bindings": [
            {"source": "/dev/kvm", "destination": "/dev/kvm"}
        ],
        "directory_skeleton": skeleton,
        "environment": environment,
        "host_network_namespace_unshared": True,
        "host_resource_limits": {
            "applied_before_bubblewrap_exec": True,
            "inherited_by_qemu": True,
            "limits": dict(resource_limits),
        },
    }


def launch_plan(
    *,
    kernel: str | os.PathLike[str],
    kernel_sha256: str,
    initrd: str | os.PathLike[str],
    initrd_sha256: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    state_root: str | os.PathLike[str] = DEFAULT_STATE_ROOT,
    profile: str = "developer",
    storage: str = "volatile",
    overlay: str | None = None,
    network: str = "none",
    acceleration: str = "auto",
    memory_mib: int = DEFAULT_MEMORY_MIB,
    cpus: int = DEFAULT_CPUS,
    qemu: str | None = None,
    qemu_img: str | None = None,
    hostile_payload: str | os.PathLike[str] | None = None,
    hostile_payload_sha256: str | None = None,
    capabilities: Mapping[str, Any] | None = None,
    overlay_is_locked: bool = False,
) -> dict[str, Any]:
    if profile not in {"developer", "analysis", "hostile"}:
        raise LabError(f"unsupported profile: {profile}")
    if storage not in {"volatile", "persistent"}:
        raise LabError(f"unsupported storage mode: {storage}")
    if network not in {"none", "internet"}:
        raise LabError(f"unsupported network mode: {network}")
    if storage == "volatile" and overlay is not None:
        raise LabError("--overlay is only valid with persistent storage")
    if storage == "persistent" and overlay is None:
        raise LabError("persistent storage requires an explicit --overlay name")
    if profile == "hostile" and network != "none":
        raise LabError("hostile mode forbids internet networking")
    if profile == "hostile" and storage != "volatile":
        raise LabError("hostile mode forbids persistent storage")
    if (hostile_payload is None) != (hostile_payload_sha256 is None):
        raise LabError(
            "--hostile-payload and --hostile-payload-sha256 are required together"
        )
    if hostile_payload is not None and profile != "hostile":
        raise LabError("payload ingress is restricted to the hostile profile")
    _validate_resources(memory_mib, cpus)

    inputs = validate_boot_inputs(
        kernel,
        kernel_sha256,
        initrd,
        initrd_sha256,
        base_image,
        base_sha256,
    )
    payload_source = (
        validate_bound_file(
            hostile_payload,
            hostile_payload_sha256 or "",
            "hostile payload source",
            max_bytes=MAX_HOSTILE_PAYLOAD_BYTES,
        )
        if hostile_payload is not None
        else None
    )
    caps = dict(capabilities) if capabilities is not None else probe_host(qemu)
    selected = select_acceleration(profile, acceleration, caps)
    qemu_path_value = caps.get("qemu_path")
    if not isinstance(qemu_path_value, str):
        raise LabError("QEMU capability report lacks an executable path")
    qemu_path = _find_executable(qemu_path_value, "qemu-system-x86_64", "QEMU")
    qemu_img_path = _find_executable(qemu_img, "qemu-img", "qemu-img")
    if profile == "hostile":
        qemu_path = _trusted_system_executable(
            qemu_path,
            TRUSTED_QEMU,
            "hostile QEMU",
        )
        qemu_img_path = _trusted_system_executable(
            qemu_img_path,
            TRUSTED_QEMU_IMG,
            "hostile qemu-img",
        )
    mke2fs_path: Path | None = None
    debugfs_path: Path | None = None
    if payload_source is not None:
        mke2fs_path = _trusted_mke2fs(
            TRUSTED_MKE2FS,
            "hostile payload mke2fs",
        )
        debugfs_path = _trusted_debugfs(
            TRUSTED_DEBUGFS,
            "hostile payload debugfs",
        )
    state_location = validate_state_root_location(state_root)

    root_disk = Path(DEFERRED_VOLATILE_ROOT)
    root_format = "qcow2"
    overlay_report: dict[str, Any] | None = None
    if storage == "persistent":
        safe_name = validate_overlay_name(overlay or "")
        state = ensure_state_root(state_location)

        def inspect_locked() -> dict[str, Any]:
            return _inspect_overlay_unlocked(
                state=state,
                name=safe_name,
                base=inputs["base_image"],
                qemu_img_path=qemu_img_path,
            )

        if overlay_is_locked:
            overlay_report = inspect_locked()
        else:
            with overlay_lock(state, safe_name):
                overlay_report = inspect_locked()
        root_disk = Path(overlay_report["image"]["path"])
        root_format = "qcow2"

    qemu_argv = _build_qemu_argv(
        qemu_path=qemu_path,
        inputs=inputs,
        root_disk=root_disk,
        root_format=root_format,
        storage=storage,
        network=network,
        profile=profile,
        acceleration=selected,
        memory_mib=memory_mib,
        cpus=cpus,
        payload_media=(
            HOSTILE_PAYLOAD_GUEST_MEDIA if payload_source is not None else None
        ),
    )
    outer_boundary: dict[str, Any] | None = None
    host_resource_limits: dict[str, int] | None = None
    argv = qemu_argv
    if profile == "hostile":
        bubblewrap = caps.get("bubblewrap")
        if not isinstance(bubblewrap, Mapping):
            raise LabError("hostile mode lacks a bubblewrap capability record")
        host_resource_limits = _hostile_resource_limits(
            memory_mib=memory_mib,
            base_image_bytes=inputs["base_image"].size,
        )
        argv, outer_boundary = _build_hostile_bwrap_argv(
            qemu_argv=qemu_argv,
            qemu_path=qemu_path,
            inputs=inputs,
            state_root=state_location,
            bubblewrap=bubblewrap,
            resource_limits=host_resource_limits,
            defer_payload=payload_source is not None,
        )
    return {
        "schema": LAUNCH_SCHEMA,
        "decision": "launch-plan-valid",
        "argv_materialized": storage == "persistent",
        "profile": profile,
        "supervisor": {
            "state_root": str(state_location),
            "qemu_path": str(qemu_path),
            "qemu_img_path": str(qemu_img_path),
            "mke2fs_path": str(mke2fs_path) if mke2fs_path is not None else None,
            "mke2fs_version": (
                TRUSTED_MKE2FS_VERSION if mke2fs_path is not None else None
            ),
            "debugfs_path": (
                str(debugfs_path) if debugfs_path is not None else None
            ),
            "debugfs_version": (
                TRUSTED_MKE2FS_VERSION if debugfs_path is not None else None
            ),
            "bubblewrap_path": (
                str(TRUSTED_BWRAP) if profile == "hostile" else None
            ),
        },
        "inputs": {key: value.public() for key, value in inputs.items()},
        "payload_ingress": (
            {
                "schema": HOSTILE_PAYLOAD_SCHEMA,
                "source": payload_source.public(),
                "media": None,
                "deferred_media_token": DEFERRED_HOSTILE_PAYLOAD,
                "guest_device": "/dev/vdb",
                "guest_media_path": str(HOSTILE_PAYLOAD_GUEST_MEDIA),
                "guest_read_only": True,
                "host_source_shared": False,
                "host_execution": False,
                "bounded_source_bytes": MAX_HOSTILE_PAYLOAD_BYTES,
                "cleanup_on_supervisor_unwind": True,
                "cleanup_after_sigkill_or_host_crash_claimed": False,
            }
            if payload_source is not None
            else None
        ),
        "storage": {
            "mode": storage,
            "root_disk": str(root_disk) if storage == "persistent" else None,
            "deferred_root_disk_token": (
                None if storage == "persistent" else DEFERRED_VOLATILE_ROOT
            ),
            "root_format": root_format,
            "base_image_mutated": False,
            "qemu_temporary_snapshot": False,
            "explicit_private_volatile_overlay": storage == "volatile",
            "volatile_overlay_deferred_until_real_launch": storage == "volatile",
            "volatile_overlay_cleanup_on_supervisor_unwind": storage == "volatile",
            "volatile_overlay_cleanup_after_sigkill_or_host_crash": False,
            "guest_writes_persist": storage == "persistent",
            "overlay": overlay_report,
        },
        "network": {
            "mode": network,
            "guest_internet_enabled": network == "internet",
            "inbound_host_forwarding": False,
            "host_shares": False,
        },
        "acceleration": selected,
        "resources": {
            "memory_mib": memory_mib,
            "cpus": cpus,
            "limits": {
                "memory_mib": [MIN_MEMORY_MIB, MAX_MEMORY_MIB],
                "cpus": [MIN_CPUS, MAX_CPUS],
            },
        },
        "controls": {
            "direct_kernel_boot": True,
            "q35_machine": True,
            "nodefaults": True,
            "no_user_config": True,
            "monitor_disabled": True,
            "serial_stdio": True,
            "hostile_console_rendering": (
                HOSTILE_CONSOLE_RENDERING if profile == "hostile" else None
            ),
            "hostile_console_forwarded_byte_allowlist": (
                list(HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST)
                if profile == "hostile"
                else None
            ),
            "hostile_non_allowlisted_console_bytes_forwarded": (
                False if profile == "hostile" else None
            ),
            "hostile_console_stderr_merged": (
                True if profile == "hostile" else None
            ),
            "hostile_console_byte_limit": (
                MAX_HOSTILE_CONSOLE_BYTES if profile == "hostile" else None
            ),
            "hostile_console_input_buffer_byte_limit": (
                MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES
                if profile == "hostile"
                else None
            ),
            "hostile_stdin_one_way_pipe": (
                True if profile == "hostile" else None
            ),
            "hostile_tty_restoration_on_handled_exit": (
                True if profile == "hostile" else None
            ),
            "hostile_tty_input_flushed_before_handoff": (
                True if profile == "hostile" else None
            ),
            "hostile_process_group_absence_checked": (
                True if profile == "hostile" else None
            ),
            "hostile_handled_signals": (
                list(HOSTILE_HANDLED_SIGNAL_NAMES)
                if profile == "hostile"
                else None
            ),
            "hostile_console_descendant_drain_timeout_seconds": (
                HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS
                if profile == "hostile"
                else None
            ),
            "hostile_console_leader_exit_confirm_timeout_seconds": (
                HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS
                if profile == "hostile"
                else None
            ),
            "qemu_sandbox": QEMU_SANDBOX,
            "host_shares": False,
            "shell": False,
            "sanitized_environment": True,
            "hostile_requires_kvm": profile == "hostile",
            "hostile_requires_non_root": profile == "hostile",
            "hostile_outer_bubblewrap": profile == "hostile",
            "empty_private_host_root": profile == "hostile",
            "host_network_namespace_unshared": profile == "hostile",
            "exact_read_only_host_bindings": profile == "hostile",
            "volatile_overlay_only_read_write_binding": profile == "hostile",
            "exact_kvm_device_binding": profile == "hostile",
            "hostile_payload_read_only_secondary_media": (
                payload_source is not None
            ),
            "hostile_payload_host_source_shared": False,
            "hostile_payload_host_execution": False,
            "explicit_host_resource_limits": profile == "hostile",
            "implicit_qemu_snapshot": False,
            "explicit_private_volatile_overlay": storage == "volatile",
        },
        "outer_boundary": outer_boundary,
        "host_resource_limits": host_resource_limits,
        "qemu_argv": list(qemu_argv),
        "argv": list(argv),
        "environment": _sanitized_environment(),
        "claims": {
            "production_ready_claimed": False,
            "runtime_sandbox_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
            "hypervisor_escape_impossible_claimed": False,
        },
        "nonclaims": list(NONCLAIMS),
    }


def status_report(
    *,
    kernel: str | os.PathLike[str],
    kernel_sha256: str,
    initrd: str | os.PathLike[str],
    initrd_sha256: str,
    base_image: str | os.PathLike[str],
    base_sha256: str,
    qemu: str | None = None,
    capabilities: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    inputs = validate_boot_inputs(
        kernel,
        kernel_sha256,
        initrd,
        initrd_sha256,
        base_image,
        base_sha256,
    )
    caps = dict(capabilities) if capabilities is not None else probe_host(qemu)
    profiles: dict[str, Any] = {}
    for profile in ("developer", "analysis", "hostile"):
        try:
            acceleration = select_acceleration(profile, "auto", caps)
        except LabError as exc:
            profiles[profile] = {"launchable": False, "reason": str(exc)}
        else:
            profiles[profile] = {
                "launchable": True,
                "acceleration": acceleration,
                "reason": None,
            }
    return {
        "schema": STATUS_SCHEMA,
        "supervisor": SUPERVISOR_VERSION,
        "inputs": {key: value.public() for key, value in inputs.items()},
        "host": caps,
        "profiles": profiles,
        "defaults": {
            "storage": "volatile",
            "network": "none",
            "memory_mib": DEFAULT_MEMORY_MIB,
            "cpus": DEFAULT_CPUS,
        },
        "boundary": {
            "volatile_storage_uses_private_explicit_qcow2": True,
            "volatile_overlay_created_only_for_real_launch": True,
            "volatile_overlay_removed_on_supervisor_unwind": True,
            "volatile_overlay_removed_after_sigkill_or_host_crash_claimed": False,
            "implicit_qemu_snapshot_used": False,
            "persistent_storage_requires_named_overlay": True,
            "internet_requires_explicit_selection": True,
            "hostile_forbids_internet": True,
            "hostile_forbids_persistence": True,
            "hostile_forbids_tcg": True,
            "hostile_uses_empty_bubblewrap_root": True,
            "hostile_unshares_host_network_namespace": True,
            "host_shares_implemented": False,
        },
        "claims": {
            "production_ready_claimed": False,
            "runtime_sandbox_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
        },
        "nonclaims": list(NONCLAIMS),
    }


def _validated_plan_base(plan: Mapping[str, Any]) -> BoundFile:
    inputs = plan.get("inputs")
    record = inputs.get("base_image") if isinstance(inputs, Mapping) else None
    if not isinstance(record, Mapping):
        raise LabError("launch plan lacks a bound base image")
    path = record.get("path")
    digest = record.get("sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        raise LabError("launch plan base-image binding is invalid")
    base = validate_bound_file(
        path,
        digest,
        "base image at final launch boundary",
        max_bytes=MAX_BASE_BYTES,
    )
    if base.public() != dict(record):
        raise LabError("base image metadata changed before final launch")
    return base


def _validated_plan_payload_source(
    plan: Mapping[str, Any],
) -> BoundFile | None:
    ingress = plan.get("payload_ingress")
    if ingress is None:
        return None
    if not isinstance(ingress, Mapping) or ingress.get("schema") != HOSTILE_PAYLOAD_SCHEMA:
        raise LabError("launch plan hostile payload-ingress record is invalid")
    if plan.get("profile") != "hostile":
        raise LabError("payload ingress appeared outside the hostile profile")
    source_record = ingress.get("source")
    if not isinstance(source_record, Mapping) or set(source_record) != {
        "path",
        "sha256",
        "size",
        "mode",
    }:
        raise LabError("launch plan hostile payload source binding is invalid")
    path_value = source_record.get("path")
    digest_value = source_record.get("sha256")
    if not isinstance(path_value, str) or not isinstance(digest_value, str):
        raise LabError("launch plan hostile payload source binding is invalid")
    source = validate_bound_file(
        path_value,
        digest_value,
        "hostile payload source at launch boundary",
        max_bytes=MAX_HOSTILE_PAYLOAD_BYTES,
    )
    if source.public() != dict(source_record):
        raise LabError("hostile payload source metadata changed before launch")
    expected_policy = {
        "guest_device": "/dev/vdb",
        "guest_media_path": str(HOSTILE_PAYLOAD_GUEST_MEDIA),
        "guest_read_only": True,
        "host_source_shared": False,
        "host_execution": False,
        "bounded_source_bytes": MAX_HOSTILE_PAYLOAD_BYTES,
        "cleanup_on_supervisor_unwind": True,
        "cleanup_after_sigkill_or_host_crash_claimed": False,
    }
    for key, expected in expected_policy.items():
        if ingress.get(key) != expected:
            raise LabError(f"hostile payload ingress policy was altered: {key}")
    return source


def _validated_materialized_payload_media(
    plan: Mapping[str, Any],
    state: Path,
) -> BoundFile | None:
    source = _validated_plan_payload_source(plan)
    ingress = plan.get("payload_ingress")
    if source is None:
        return None
    if not isinstance(ingress, Mapping):
        raise LabError("launch plan hostile payload-ingress record is invalid")
    if ingress.get("deferred_media_token") is not None:
        raise LabError("hostile payload media is still deferred")
    report = ingress.get("media")
    if not isinstance(report, Mapping) or report.get("schema") != HOSTILE_PAYLOAD_SCHEMA:
        raise LabError("materialized hostile payload media report is invalid")
    if report.get("source") != source.public():
        raise LabError("hostile payload media source binding changed")
    expected_manifest = _hostile_payload_manifest(source)
    if report.get("manifest") != expected_manifest:
        raise LabError("hostile payload media manifest binding changed")
    supervisor = plan.get("supervisor")
    debugfs_value = (
        supervisor.get("debugfs_path")
        if isinstance(supervisor, Mapping)
        else None
    )
    debugfs_version = (
        supervisor.get("debugfs_version")
        if isinstance(supervisor, Mapping)
        else None
    )
    if not isinstance(debugfs_value, str) or (
        debugfs_version != TRUSTED_MKE2FS_VERSION
    ):
        raise LabError(
            "hostile payload launch lacks an exact debugfs binding"
        )
    debugfs_path = _trusted_debugfs(
        debugfs_value,
        "hostile payload debugfs at semantic launch boundary",
    )
    manifest_bytes = canonical_json(expected_manifest).encode("utf-8")
    expected_readback = {
        "filesystem": "ext4",
        "debugfs_path": str(debugfs_path),
        "debugfs_version": TRUSTED_MKE2FS_VERSION,
        "payload": {
            "guest_path": "/payload.bin",
            "size": source.size,
            "sha256": source.sha256,
        },
        "manifest": {
            "guest_path": "/manifest.json",
            "size": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "exact_guest_file_bytes_verified": True,
    }
    if (
        report.get("semantic_readback") != expected_readback
    ):
        raise LabError("hostile payload semantic-readback binding changed")
    media_record = report.get("media")
    if not isinstance(media_record, Mapping):
        raise LabError("materialized hostile payload media binding is invalid")
    path_value = media_record.get("path")
    digest_value = media_record.get("sha256")
    if not isinstance(path_value, str) or not isinstance(digest_value, str):
        raise LabError("materialized hostile payload media binding is invalid")
    media = validate_bound_file(
        path_value,
        digest_value,
        "hostile payload media at launch boundary",
        max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
    )
    expected_public = {
        key: media_record.get(key) for key in ("path", "sha256", "size", "mode")
    }
    if media.public() != expected_public or media.mode != 0o400:
        raise LabError("hostile payload media metadata changed before launch")
    payload_root = state / "payloads"
    _under_root(media.path, payload_root, "hostile payload media")
    if media_record.get("format") != "raw-ext4" or (
        media_record.get("guest_device") != "/dev/vdb"
        or media_record.get("qemu_read_only") is not True
        or media_record.get("host_mode") != "0400"
    ):
        raise LabError("hostile payload media policy record was altered")
    observed_readback = _verify_hostile_payload_media_contents(
        media_path=media.path,
        media_identity=(media.device, media.inode),
        operation=media.path.parent,
        source=source,
        manifest=expected_manifest,
        debugfs_path=debugfs_path,
        defer_handled_signals=True,
    )
    if observed_readback != expected_readback:
        raise LabError(
            "hostile payload semantic readback changed at launch boundary"
        )
    return media


def _materialize_volatile_plan(
    plan: Mapping[str, Any],
    overlay: Mapping[str, Any],
    payload_media: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    materialized = copy.deepcopy(dict(plan))
    argv = materialized.get("argv")
    if not isinstance(argv, list):
        raise LabError("volatile launch plan argv is invalid")
    if not all(isinstance(item, str) for item in argv):
        raise LabError("volatile launch plan argv contains a non-string item")
    profile = materialized.get("profile")
    expected_argv_tokens = 3 if profile == "hostile" else 1
    token_count = sum(item.count(DEFERRED_VOLATILE_ROOT) for item in argv)
    if token_count != expected_argv_tokens:
        raise LabError(
            "volatile launch plan has an invalid deferred root token count"
        )
    overlay_path = overlay.get("path")
    if not isinstance(overlay_path, str):
        raise LabError("materialized volatile overlay path is invalid")
    overlay_location = absolute_path(overlay_path, "materialized volatile overlay")
    if str(overlay_location) != overlay_path:
        raise LabError("materialized volatile overlay path is not canonical")
    for index, item in enumerate(argv):
        argv[index] = item.replace(DEFERRED_VOLATILE_ROOT, overlay_path)

    qemu_argv = materialized.get("qemu_argv")
    if not isinstance(qemu_argv, list) or not all(
        isinstance(item, str) for item in qemu_argv
    ):
        raise LabError("volatile launch plan QEMU argv is invalid")
    if sum(item.count(DEFERRED_VOLATILE_ROOT) for item in qemu_argv) != 1:
        raise LabError("volatile QEMU argv must contain exactly one deferred root token")
    for index, item in enumerate(qemu_argv):
        qemu_argv[index] = item.replace(DEFERRED_VOLATILE_ROOT, overlay_path)

    outer_boundary = materialized.get("outer_boundary")
    if profile == "hostile":
        if not isinstance(outer_boundary, dict):
            raise LabError("hostile volatile plan lacks an outer boundary record")
        write_bindings = outer_boundary.get("read_write_bindings")
        if not isinstance(write_bindings, list) or len(write_bindings) != 1:
            raise LabError("hostile volatile plan has invalid writable bindings")
        write_binding = write_bindings[0]
        if not isinstance(write_binding, dict) or (
            write_binding.get("source") != DEFERRED_VOLATILE_ROOT
            or write_binding.get("destination") != DEFERRED_VOLATILE_ROOT
        ):
            raise LabError("hostile volatile plan writable binding was altered")
        write_binding["source"] = overlay_path
        write_binding["destination"] = overlay_path
        write_binding["materialized"] = True

        ingress = materialized.get("payload_ingress")
        if ingress is None:
            if payload_media is not None or any(
                DEFERRED_HOSTILE_PAYLOAD in item for item in argv
            ):
                raise LabError("unexpected hostile payload media materialization")
        else:
            if not isinstance(ingress, dict) or payload_media is None:
                raise LabError("hostile payload launch requires materialized media")
            if sum(item.count(DEFERRED_HOSTILE_PAYLOAD) for item in argv) != 1:
                raise LabError("hostile payload plan has an invalid deferred token count")
            source_record = ingress.get("source")
            if payload_media.get("source") != source_record:
                raise LabError("hostile payload media does not match its source binding")
            media_record = payload_media.get("media")
            if not isinstance(media_record, Mapping):
                raise LabError("hostile payload media report is invalid")
            media_path_value = media_record.get("path")
            media_digest = media_record.get("sha256")
            if not isinstance(media_path_value, str) or not isinstance(media_digest, str):
                raise LabError("hostile payload media binding is invalid")
            bound_media = validate_bound_file(
                media_path_value,
                media_digest,
                "materialized hostile payload media",
                max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
            )
            if bound_media.mode != 0o400:
                raise LabError("materialized hostile payload media must have mode 0400")
            for index, item in enumerate(argv):
                argv[index] = item.replace(
                    DEFERRED_HOSTILE_PAYLOAD, str(bound_media.path)
                )
            read_bindings = outer_boundary.get("read_only_bindings")
            if not isinstance(read_bindings, list):
                raise LabError("hostile payload plan lacks read-only bindings")
            deferred_indices = [
                index
                for index, record in enumerate(read_bindings)
                if isinstance(record, Mapping)
                and record.get("source") == DEFERRED_HOSTILE_PAYLOAD
                and record.get("destination") == str(HOSTILE_PAYLOAD_GUEST_MEDIA)
                and record.get("deferred") is True
            ]
            if len(deferred_indices) != 1:
                raise LabError("hostile payload deferred read-only binding was altered")
            binding = _hostile_runtime_binding(
                bound_media.path,
                HOSTILE_PAYLOAD_GUEST_MEDIA,
                kind="file",
                label="materialized hostile read-only payload media",
                max_bytes=MAX_HOSTILE_PAYLOAD_MEDIA_BYTES,
                expected_bound=bound_media,
            )
            binding["purpose"] = "guest-read-only hostile payload media"
            binding["materialized"] = True
            read_bindings[deferred_indices[0]] = binding
            ingress["media"] = copy.deepcopy(dict(payload_media))
            ingress["deferred_media_token"] = None
    elif outer_boundary is not None:
        raise LabError("non-hostile volatile plan has an unexpected outer boundary")
    elif payload_media is not None or materialized.get("payload_ingress") is not None:
        raise LabError("payload media appeared outside a hostile launch")
    materialized["argv_materialized"] = True
    storage = materialized.get("storage")
    if not isinstance(storage, dict):
        raise LabError("volatile launch plan storage record is invalid")
    storage["root_disk"] = overlay_path
    storage["deferred_root_disk_token"] = None
    storage["volatile_overlay_deferred_until_real_launch"] = False
    storage["overlay"] = dict(overlay)
    return materialized


def _plan_bound_inputs(plan: Mapping[str, Any]) -> dict[str, BoundFile]:
    records = plan.get("inputs")
    expected_keys = {"kernel", "initrd", "base_image"}
    if not isinstance(records, Mapping) or set(records) != expected_keys:
        raise LabError("launch plan boot-input bindings are invalid")
    maximums = {
        "kernel": MAX_KERNEL_BYTES,
        "initrd": MAX_INITRD_BYTES,
        "base_image": MAX_BASE_BYTES,
    }
    result: dict[str, BoundFile] = {}
    for key in ("kernel", "initrd", "base_image"):
        record = records.get(key)
        if not isinstance(record, Mapping) or set(record) != {
            "path",
            "sha256",
            "size",
            "mode",
        }:
            raise LabError(f"launch plan {key} binding is invalid")
        path_value = record.get("path")
        digest_value = record.get("sha256")
        size_value = record.get("size")
        mode_value = record.get("mode")
        if not isinstance(path_value, str) or str(
            absolute_path(path_value, f"launch plan {key}")
        ) != path_value:
            raise LabError(f"launch plan {key} path is not canonical")
        digest = validate_sha256(digest_value, f"launch plan {key} SHA-256")
        if not isinstance(size_value, int) or isinstance(size_value, bool):
            raise LabError(f"launch plan {key} size is invalid")
        bound = validate_bound_file(
            path_value,
            digest,
            f"launch plan {key} immediately before exec",
            max_bytes=maximums[key],
        )
        if bound.public() != dict(record):
            raise LabError(
                f"launch plan {key} public binding changed before exec"
            )
        if size_value != bound.size or mode_value != f"{bound.mode:04o}":
            raise LabError(f"launch plan {key} metadata changed before exec")
        result[key] = bound
    return result


def _validated_qemu_launch_argv(
    plan: Mapping[str, Any],
    state: Path,
) -> tuple[list[str], Path, dict[str, BoundFile], Path, BoundFile | None]:
    qemu_argv = plan.get("qemu_argv")
    if not isinstance(qemu_argv, list) or not qemu_argv or not all(
        isinstance(item, str) and item for item in qemu_argv
    ):
        raise LabError("launch plan QEMU argv is invalid")
    if any(DEFERRED_VOLATILE_ROOT in item for item in qemu_argv):
        raise LabError("launch plan QEMU argv still contains a deferred root token")
    if any(DEFERRED_HOSTILE_PAYLOAD in item for item in qemu_argv):
        raise LabError("launch plan QEMU argv contains a deferred payload token")
    if "-snapshot" in qemu_argv or any("snapshot=on" in item for item in qemu_argv):
        raise LabError("implicit QEMU snapshot options are forbidden")

    supervisor = plan.get("supervisor")
    if not isinstance(supervisor, Mapping):
        raise LabError("launch plan supervisor record is invalid")
    qemu_value = supervisor.get("qemu_path")
    if not isinstance(qemu_value, str):
        raise LabError("launch plan lacks a QEMU executable binding")
    qemu_path = _find_executable(qemu_value, "qemu-system-x86_64", "QEMU")
    if str(qemu_path) != qemu_value:
        raise LabError("launch plan QEMU executable path is not canonical")

    inputs = _plan_bound_inputs(plan)
    storage = plan.get("storage")
    if not isinstance(storage, Mapping):
        raise LabError("launch plan storage record is invalid")
    storage_mode = storage.get("mode")
    root_value = storage.get("root_disk")
    root_format = storage.get("root_format")
    if storage_mode not in {"volatile", "persistent"} or not isinstance(
        root_value, str
    ):
        raise LabError("launch plan materialized root disk is invalid")
    root_disk = absolute_path(root_value, "launch plan root disk")
    if str(root_disk) != root_value or root_format != "qcow2":
        raise LabError("launch plan root-disk binding is invalid")
    root_info = _regular_lstat(
        root_disk,
        "launch plan root disk",
        max_bytes=MAX_BASE_BYTES,
        require_private_write=True,
    )
    if root_info.st_nlink != 1:
        raise LabError("launch plan root disk must be a single-link regular file")
    if storage_mode == "volatile":
        volatile_directory = state / "volatile"
        if root_disk.parent != volatile_directory:
            raise LabError("volatile root disk escaped the private volatile directory")

    profile = plan.get("profile")
    network = plan.get("network")
    acceleration = plan.get("acceleration")
    resources = plan.get("resources")
    if profile not in {"developer", "analysis", "hostile"}:
        raise LabError("launch plan profile is invalid")
    if not isinstance(network, Mapping) or network.get("mode") not in {
        "none",
        "internet",
    }:
        raise LabError("launch plan network record is invalid")
    if not isinstance(acceleration, Mapping) or acceleration.get("selected") not in {
        "kvm",
        "tcg",
    }:
        raise LabError("launch plan acceleration record is invalid")
    if not isinstance(resources, Mapping):
        raise LabError("launch plan resource record is invalid")
    memory_mib = resources.get("memory_mib")
    cpus = resources.get("cpus")
    _validate_resources(memory_mib, cpus)
    payload_media = _validated_materialized_payload_media(plan, state)
    expected = _build_qemu_argv(
        qemu_path=qemu_path,
        inputs=inputs,
        root_disk=root_disk,
        root_format="qcow2",
        storage=storage_mode,
        network=network["mode"],
        profile=profile,
        acceleration=acceleration,
        memory_mib=memory_mib,
        cpus=cpus,
        payload_media=(
            HOSTILE_PAYLOAD_GUEST_MEDIA if payload_media is not None else None
        ),
    )
    if qemu_argv != expected:
        raise LabError("launch plan QEMU argv does not match its exact policy inputs")
    return qemu_argv, qemu_path, inputs, root_disk, payload_media


def _validated_hostile_outer_argv(
    plan: Mapping[str, Any],
    state: Path,
    qemu_argv: list[str],
    qemu_path: Path,
    inputs: Mapping[str, BoundFile],
    root_disk: Path,
    payload_media: BoundFile | None,
) -> tuple[list[str], Mapping[str, Any]]:
    if plan.get("profile") != "hostile":
        raise LabError("hostile outer-boundary validation used for another profile")
    storage = plan.get("storage")
    network = plan.get("network")
    acceleration = plan.get("acceleration")
    if not isinstance(storage, Mapping) or storage.get("mode") != "volatile":
        raise LabError("hostile launch requires volatile storage")
    if not isinstance(network, Mapping) or network.get("mode") != "none":
        raise LabError("hostile launch requires guest networking to remain disabled")
    if not isinstance(acceleration, Mapping) or acceleration.get("selected") != "kvm":
        raise LabError("hostile launch requires KVM without fallback")
    if os.geteuid() == 0:
        raise LabError("hostile mode refuses to run as root")

    bwrap_path = _trusted_bwrap()
    supervisor = plan.get("supervisor")
    if not isinstance(supervisor, Mapping) or (
        supervisor.get("bubblewrap_path") != str(bwrap_path)
    ):
        raise LabError("hostile launch bubblewrap executable binding is invalid")
    trusted_qemu = _trusted_system_executable(
        qemu_path,
        TRUSTED_QEMU,
        "hostile QEMU at final exec boundary",
    )
    if trusted_qemu != qemu_path:
        raise LabError("hostile launch QEMU executable binding is invalid")
    qemu_img_value = supervisor.get("qemu_img_path")
    if not isinstance(qemu_img_value, str):
        raise LabError("hostile launch lacks a qemu-img executable binding")
    _trusted_system_executable(
        qemu_img_value,
        TRUSTED_QEMU_IMG,
        "hostile qemu-img at final exec boundary",
    )
    mke2fs_value = supervisor.get("mke2fs_path")
    mke2fs_version = supervisor.get("mke2fs_version")
    debugfs_value = supervisor.get("debugfs_path")
    debugfs_version = supervisor.get("debugfs_version")
    if payload_media is None:
        if any(
            value is not None
            for value in (
                mke2fs_value,
                mke2fs_version,
                debugfs_value,
                debugfs_version,
            )
        ):
            raise LabError(
                "hostile launch has an unexpected payload-tool binding"
            )
    else:
        if not isinstance(mke2fs_value, str) or (
            mke2fs_version != TRUSTED_MKE2FS_VERSION
        ) or not isinstance(debugfs_value, str) or (
            debugfs_version != TRUSTED_MKE2FS_VERSION
        ):
            raise LabError(
                "hostile payload launch lacks exact e2fsprogs bindings"
            )
        _trusted_mke2fs(
            mke2fs_value,
            "hostile payload mke2fs at final exec boundary",
        )
        _trusted_debugfs(
            debugfs_value,
            "hostile payload debugfs at final exec boundary",
        )
    kvm = _kvm_device_status("/dev/kvm")
    if not _trusted_kvm_device_record(kvm):
        detail = kvm.get("reason")
        suffix = f": {detail}" if isinstance(detail, str) and detail else ""
        raise LabError(
            "hostile launch lost its trusted exact root-owned /dev/kvm "
            f"character-device 10:232 boundary{suffix}"
        )

    resources = plan.get("resources")
    limits = plan.get("host_resource_limits")
    if not isinstance(resources, Mapping) or not isinstance(limits, Mapping):
        raise LabError("hostile launch lacks explicit host resource limits")
    expected_limits = _hostile_resource_limits(
        memory_mib=resources.get("memory_mib"),
        base_image_bytes=inputs["base_image"].size,
    )
    if dict(limits) != expected_limits:
        raise LabError("hostile host-resource limits were altered")
    _validate_host_resource_limit_capacity(limits)

    expected_argv, expected_boundary = _build_hostile_bwrap_argv(
        qemu_argv=qemu_argv,
        qemu_path=qemu_path,
        inputs=inputs,
        state_root=state,
        bubblewrap={
            "available": True,
            "trusted": True,
            "path": str(bwrap_path),
        },
        resource_limits=limits,
        payload_media=payload_media,
    )
    expected_argv = [
        item.replace(DEFERRED_VOLATILE_ROOT, str(root_disk))
        for item in expected_argv
    ]
    expected_write = expected_boundary["read_write_bindings"][0]
    expected_write["source"] = str(root_disk)
    expected_write["destination"] = str(root_disk)
    expected_write["materialized"] = True
    if payload_media is not None:
        payload_bindings = [
            record
            for record in expected_boundary["read_only_bindings"]
            if record.get("purpose") == "guest-read-only hostile payload media"
        ]
        if len(payload_bindings) != 1:
            raise LabError("hostile payload expected binding is invalid")
        payload_bindings[0]["materialized"] = True
    outer_boundary = plan.get("outer_boundary")
    if outer_boundary != expected_boundary:
        raise LabError("hostile outer-boundary record does not match the exact policy")
    argv = plan.get("argv")
    if argv != expected_argv:
        raise LabError("hostile bubblewrap argv does not match the exact outer policy")
    return expected_argv, limits


@dataclass
class _EscapedAsciiConsoleRenderer:
    pending_carriage_return: bool = False

    def render(self, block: bytes, *, final: bool = False) -> str:
        output: list[str] = []
        for value in block:
            if self.pending_carriage_return:
                if value == 0x0A:
                    output.append("\n")
                    self.pending_carriage_return = False
                    continue
                output.append("\\x0d")
                self.pending_carriage_return = False
            if value == 0x0D:
                self.pending_carriage_return = True
            elif value in {0x09, 0x0A} or 0x20 <= value <= 0x7E:
                output.append(chr(value))
            else:
                output.append(f"\\x{value:02x}")
        if final and self.pending_carriage_return:
            output.append("\\x0d")
            self.pending_carriage_return = False
        return "".join(output)


def _stdin_termios_snapshot() -> tuple[int, list[Any]] | None:
    try:
        descriptor = sys.stdin.fileno()
        if not os.isatty(descriptor):
            return None
        return descriptor, termios.tcgetattr(descriptor)
    except (AttributeError, OSError, termios.error):
        return None


def _prepare_stdin_termios() -> tuple[int, list[Any]] | None:
    return _stdin_termios_snapshot()


def _enter_stdin_raw_mode(
    snapshot: tuple[int, list[Any]] | None,
) -> None:
    if snapshot is None:
        return
    descriptor, _attributes = snapshot
    try:
        tty.setraw(descriptor, when=termios.TCSANOW)
    except (OSError, termios.error) as exc:
        raise LabError(
            "hostile console relay could not enter raw input mode"
        ) from exc


def _restore_stdin_termios(
    snapshot: tuple[int, list[Any]] | None,
) -> None:
    if snapshot is None:
        return
    descriptor, attributes = snapshot
    try:
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, attributes)
    except (OSError, termios.error) as exc:
        raise LabError(
            "hostile console relay could not restore host terminal state"
        ) from exc


@contextlib.contextmanager
def _hostile_console_signal_handlers() -> Iterator[dict[str, Any]]:
    previous: dict[int, Any] = {}
    state: dict[str, Any] = {
        "cleanup": False,
        "defer": False,
        "interrupted_signal": None,
    }

    def interrupt(signum: int, _frame: Any) -> None:
        if state["cleanup"] or state["interrupted_signal"] is not None:
            return
        state["interrupted_signal"] = signum
        if state["defer"]:
            return
        raise _HostileConsoleSignal(signum)

    try:
        for signum in HOSTILE_HANDLED_SIGNALS:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
    except BaseException as exc:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if isinstance(exc, _HostileConsoleSignal):
            raise
        if not isinstance(exc, ValueError):
            raise
        raise LabError(
            "hostile console signal handlers require the main thread"
        ) from exc
    try:
        yield state
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@contextlib.contextmanager
def _hostile_launch_cleanup_boundary() -> Iterator[contextlib.ExitStack]:
    """Cover hostile transient-materialization and console cleanup with signals."""
    try:
        with _hostile_console_signal_handlers() as signal_state:
            with contextlib.ExitStack() as stack:
                try:
                    yield stack
                finally:
                    # From this point onward a second handled signal must not
                    # interrupt exact payload/overlay cleanup.
                    signal_state["cleanup"] = True
    except _HostileConsoleSignal as exc:
        signal_name = signal.Signals(exc.signum).name
        raise LabError(
            "hostile launch interrupted by handled " f"{signal_name}"
        ) from None


def _hostile_console_process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_hostile_console_process_group_absence(
    process_group_id: int, timeout_seconds: float
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _hostile_console_process_group_exists(process_group_id):
            return True
        time.sleep(0.05)
    return not _hostile_console_process_group_exists(process_group_id)


def _terminate_hostile_console_process(
    process: subprocess.Popen[bytes],
) -> None:
    process_group_id = process.pid
    if not _hostile_console_process_group_exists(process_group_id):
        if process.poll() is None:
            raise LabError(
                "hostile console launch leader remained without its "
                "dedicated process group"
            )
        return
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    if _wait_for_hostile_console_process_group_absence(
        process_group_id, 5
    ):
        return
    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise LabError(
            "hostile console launch leader remained after SIGKILL"
        ) from exc
    if not _wait_for_hostile_console_process_group_absence(
        process_group_id, 5
    ):
        raise LabError(
            "hostile console process group remained after SIGKILL"
        )


def _cleanup_hostile_console_relay(
    *,
    selector: selectors.BaseSelector | None,
    process: subprocess.Popen[bytes] | None,
    snapshot: tuple[int, list[Any]] | None,
) -> None:
    errors: list[tuple[str, BaseException]] = []

    def attempt(label: str, callback: Callable[[], None]) -> None:
        try:
            callback()
        except BaseException as exc:
            errors.append((label, exc))

    if selector is not None:
        attempt("selector close", selector.close)
    if process is not None and process.stdin is not None:
        attempt("guest-input pipe close", process.stdin.close)
    if (
        process is not None
        and _hostile_console_process_group_exists(process.pid)
    ):
        attempt(
            "process-group termination",
            lambda: _terminate_hostile_console_process(process),
        )
    if process is not None and process.stdout is not None:
        attempt("console pipe close", process.stdout.close)
    attempt(
        "host terminal restoration and input flush",
        lambda: _restore_stdin_termios(snapshot),
    )
    if not errors:
        return
    if len(errors) == 1:
        raise errors[0][1]
    summary = "; ".join(
        f"{label}: {type(exc).__name__}: {ascii(str(exc))}"
        for label, exc in errors
    )
    raise LabError(
        f"hostile console relay cleanup had multiple failures: {summary}"
    ) from errors[0][1]


def _run_hostile_console_relay(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    preexec_fn: Callable[[], None],
) -> int:
    renderer = _EscapedAsciiConsoleRenderer()
    snapshot: tuple[int, list[Any]] | None = None
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    raw_bytes = 0
    try:
        with _hostile_console_signal_handlers() as signal_state:
            primary_error: BaseException | None = None
            try:
                snapshot = _prepare_stdin_termios()
                _enter_stdin_raw_mode(snapshot)
                try:
                    stdin_descriptor = sys.stdin.fileno()
                except (AttributeError, OSError) as exc:
                    raise LabError(
                        "hostile console relay requires a readable stdin"
                    ) from exc
                signal_state["defer"] = True
                try:
                    process = subprocess.Popen(
                        list(argv),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        shell=False,
                        cwd=cwd,
                        env=dict(environment),
                        close_fds=True,
                        restore_signals=True,
                        umask=0o077,
                        preexec_fn=preexec_fn,
                        start_new_session=True,
                    )
                finally:
                    signal_state["defer"] = False
                interrupted_signal = signal_state["interrupted_signal"]
                if interrupted_signal is not None:
                    raise _HostileConsoleSignal(interrupted_signal)
                if process.stdin is None or process.stdout is None:
                    raise LabError(
                        "hostile console relay pipes were not created"
                    )
                os.set_blocking(process.stdin.fileno(), False)
                selector = selectors.SelectSelector()
                selector.register(
                    process.stdout, selectors.EVENT_READ, "console"
                )
                selector.register(
                    stdin_descriptor, selectors.EVENT_READ, "operator"
                )
                console_open = True
                operator_open = True
                guest_input_registered = False
                pending_operator_input = bytearray()
                leader_exit_deadline: float | None = None
                while console_open:
                    for key, _mask in selector.select(timeout=0.5):
                        if key.data == "console":
                            block = os.read(
                                key.fileobj.fileno(), 65536
                            )
                            if not block:
                                selector.unregister(key.fileobj)
                                console_open = False
                                if process.poll() is None:
                                    try:
                                        process.wait(
                                            timeout=(
                                                HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS
                                            )
                                        )
                                    except subprocess.TimeoutExpired:
                                        pass
                                if process.poll() is None:
                                    raise LabError(
                                        "hostile console pipe closed while "
                                        "the launch leader remained alive"
                                    )
                                continue
                            raw_bytes += len(block)
                            if raw_bytes > MAX_HOSTILE_CONSOLE_BYTES:
                                raise LabError(
                                    "hostile console output exceeds the "
                                    f"{MAX_HOSTILE_CONSOLE_BYTES}-byte limit"
                                )
                            rendered = renderer.render(block)
                            if rendered:
                                sys.stdout.write(rendered)
                                sys.stdout.flush()
                        elif key.data == "operator" and operator_open:
                            operator = os.read(
                                stdin_descriptor, 65536
                            )
                            if not operator:
                                selector.unregister(stdin_descriptor)
                                operator_open = False
                                if not pending_operator_input:
                                    process.stdin.close()
                                continue
                            pending_operator_input.extend(operator)
                            if (
                                len(pending_operator_input)
                                > MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES
                            ):
                                raise LabError(
                                    "hostile console operator-input buffer "
                                    "exceeds the "
                                    f"{MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES}"
                                    "-byte limit"
                                )
                            if not guest_input_registered:
                                selector.register(
                                    process.stdin,
                                    selectors.EVENT_WRITE,
                                    "guest-input",
                                )
                                guest_input_registered = True
                        elif (
                            key.data == "guest-input"
                            and guest_input_registered
                        ):
                            try:
                                written = os.write(
                                    process.stdin.fileno(),
                                    pending_operator_input,
                                )
                            except BlockingIOError:
                                continue
                            except (BrokenPipeError, OSError):
                                selector.unregister(process.stdin)
                                guest_input_registered = False
                                pending_operator_input.clear()
                                process.stdin.close()
                                if operator_open:
                                    selector.unregister(stdin_descriptor)
                                    operator_open = False
                                continue
                            del pending_operator_input[:written]
                            if not pending_operator_input:
                                selector.unregister(process.stdin)
                                guest_input_registered = False
                                if not operator_open:
                                    process.stdin.close()
                    if process.poll() is not None and console_open:
                        if leader_exit_deadline is None:
                            leader_exit_deadline = (
                                time.monotonic()
                                + HOSTILE_CONSOLE_DESCENDANT_DRAIN_TIMEOUT_SECONDS
                            )
                        elif time.monotonic() >= leader_exit_deadline:
                            raise LabError(
                                "hostile console process-group member kept "
                                "the transcript pipe open after the launch "
                                "leader exited"
                            )
                final = renderer.render(b"", final=True)
                if final:
                    sys.stdout.write(final)
                    sys.stdout.flush()
                returncode = process.poll()
                if returncode is None:
                    raise LabError(
                        "hostile console launch leader remained after "
                        "console EOF"
                    )
                if _hostile_console_process_group_exists(process.pid):
                    raise LabError(
                        "hostile console process-group member remained after "
                        "the launch leader exited"
                    )
                return returncode
            except BaseException as exc:
                primary_error = exc
                raise
            finally:
                signal_state["cleanup"] = True
                try:
                    _cleanup_hostile_console_relay(
                        selector=selector,
                        process=process,
                        snapshot=snapshot,
                    )
                except BaseException as cleanup_error:
                    if primary_error is None:
                        raise
                    raise LabError(
                        "hostile console relay primary failure and cleanup "
                        "failure: "
                        f"primary={type(primary_error).__name__}: "
                        f"{ascii(str(primary_error))}; "
                        f"cleanup={type(cleanup_error).__name__}: "
                        f"{ascii(str(cleanup_error))}"
                    ) from cleanup_error
    except _HostileConsoleSignal as exc:
        signal_name = signal.Signals(exc.signum).name
        raise LabError(
            f"hostile console relay interrupted by handled {signal_name}"
        ) from None


def _execute_launch(plan: Mapping[str, Any], state: Path) -> int:
    argv = plan.get("argv")
    environment = plan.get("environment")
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(item, str) and item for item in argv)
    ):
        raise LabError("launch plan argv is invalid")
    if environment != _sanitized_environment():
        raise LabError("launch plan environment is invalid")
    if plan.get("argv_materialized") is not True:
        raise LabError("launch plan argv has not been materialized")
    if any(DEFERRED_VOLATILE_ROOT in item for item in argv):
        raise LabError("launch plan still contains a deferred root token")
    if any(DEFERRED_HOSTILE_PAYLOAD in item for item in argv):
        raise LabError("launch plan still contains a deferred payload token")
    qemu_argv, qemu_path, inputs, root_disk, payload_media = (
        _validated_qemu_launch_argv(plan, state)
    )
    profile = plan.get("profile")
    preexec_fn: Callable[[], None] | None = None
    if profile == "hostile":
        argv, limits = _validated_hostile_outer_argv(
            plan,
            state,
            qemu_argv,
            qemu_path,
            inputs,
            root_disk,
            payload_media,
        )
        preexec_fn = _resource_limit_preexec(limits)
        failure_label = "hostile bubblewrap/QEMU launch"
    else:
        if argv != qemu_argv or argv[0] != str(qemu_path):
            raise LabError("launch plan QEMU executable binding is invalid")
        if plan.get("outer_boundary") is not None:
            raise LabError("non-hostile plan contains an unexpected outer boundary")
        if plan.get("host_resource_limits") is not None:
            raise LabError("non-hostile plan contains hostile host-resource limits")
        failure_label = "QEMU launch"
    try:
        if profile == "hostile":
            if preexec_fn is None:
                raise LabError("hostile launch lacks resource limits")
            return _run_hostile_console_relay(
                argv,
                cwd=state,
                environment=environment,
                preexec_fn=preexec_fn,
            )
        result = subprocess.run(
            argv,
            check=False,
            shell=False,
            cwd=state,
            env=dict(environment),
            close_fds=True,
            restore_signals=True,
            umask=0o077,
            preexec_fn=preexec_fn,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError(f"{failure_label} failed: {exc}") from exc
    return result.returncode


def run_launch(
    plan: Mapping[str, Any],
    *,
    cwd: Path,
    emit_plan: bool = False,
) -> int:
    state = ensure_state_root(cwd)
    supervisor = plan.get("supervisor")
    if not isinstance(supervisor, Mapping) or supervisor.get("state_root") != str(state):
        raise LabError("launch plan state-root binding is invalid")
    storage = plan.get("storage")
    mode = storage.get("mode") if isinstance(storage, Mapping) else None
    if mode == "persistent":
        _validated_plan_base(plan)
        if emit_plan:
            sys.stderr.write(canonical_json(plan))
        return _execute_launch(plan, state)
    if mode != "volatile":
        raise LabError("launch plan storage mode is invalid")
    if plan.get("argv_materialized") is not False:
        raise LabError("volatile launch plan must defer its root overlay")
    qemu_img_value = supervisor.get("qemu_img_path")
    if not isinstance(qemu_img_value, str):
        raise LabError("volatile launch plan lacks a qemu-img binding")
    if plan.get("profile") == "hostile":
        qemu_value = supervisor.get("qemu_path")
        if not isinstance(qemu_value, str):
            raise LabError("hostile volatile launch lacks a QEMU binding")
        _trusted_bwrap()
        _trusted_system_executable(
            qemu_value,
            TRUSTED_QEMU,
            "hostile QEMU before volatile overlay creation",
        )
        qemu_img_path = _trusted_system_executable(
            qemu_img_value,
            TRUSTED_QEMU_IMG,
            "hostile qemu-img before volatile overlay creation",
        )
    else:
        qemu_img_path = _find_executable(qemu_img_value, "qemu-img", "qemu-img")
    base = _validated_plan_base(plan)
    payload_source = _validated_plan_payload_source(plan)
    mke2fs_path: Path | None = None
    debugfs_path: Path | None = None
    if payload_source is not None:
        mke2fs_value = supervisor.get("mke2fs_path")
        debugfs_value = supervisor.get("debugfs_path")
        if not isinstance(mke2fs_value, str) or not isinstance(
            debugfs_value, str
        ):
            raise LabError(
                "hostile payload plan lacks trusted e2fsprogs bindings"
            )
        mke2fs_path = _trusted_mke2fs(
            mke2fs_value,
            "hostile payload mke2fs before media creation",
        )
        debugfs_path = _trusted_debugfs(
            debugfs_value,
            "hostile payload debugfs before media verification",
        )
    stack_context: contextlib.AbstractContextManager[contextlib.ExitStack]
    if plan.get("profile") == "hostile":
        stack_context = _hostile_launch_cleanup_boundary()
    else:
        stack_context = contextlib.ExitStack()
    with stack_context as stack:
        payload_report = (
            stack.enter_context(
                private_hostile_payload_media(
                    state_root=state,
                    source=payload_source,
                    mke2fs_path=mke2fs_path,
                    debugfs_path=debugfs_path,
                    defer_handled_signals=True,
                )
            )
            if (
                payload_source is not None
                and mke2fs_path is not None
                and debugfs_path is not None
            )
            else None
        )
        overlay = stack.enter_context(
            private_volatile_overlay(
                state_root=state,
                base=base,
                qemu_img_path=qemu_img_path,
                defer_handled_signals=(
                    plan.get("profile") == "hostile"
                ),
            )
        )
        materialized = _materialize_volatile_plan(
            plan, overlay, payload_report
        )
        if emit_plan:
            sys.stderr.write(canonical_json(materialized))
        return _execute_launch(materialized, state)


def _add_boot_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kernel", required=True, help="exact vmlinuz path")
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--initrd", required=True, help="exact initramfs path")
    parser.add_argument("--initrd-sha256", required=True)
    parser.add_argument("--base-image", required=True, help="exact raw ext4 root image")
    parser.add_argument("--base-sha256", required=True)


def _add_base_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-image", required=True, help="exact raw ext4 root image")
    parser.add_argument("--base-sha256", required=True)


def _add_state_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-root",
        default=str(DEFAULT_STATE_ROOT),
        help=f"private state directory below {BUILD_ROOT} (default: %(default)s)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Digest-bound Wuci lab QEMU supervisor"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status", help="validate boot inputs and host capability")
    _add_boot_arguments(status)
    status.add_argument("--qemu")

    overlay = commands.add_parser("overlay", help="manage persistent qcow2 overlays")
    overlay_commands = overlay.add_subparsers(dest="overlay_command", required=True)
    create = overlay_commands.add_parser("create", help="create without overwrite")
    create.add_argument("name")
    _add_base_arguments(create)
    _add_state_argument(create)
    create.add_argument("--qemu-img")
    inspect = overlay_commands.add_parser("inspect", help="verify base binding and shape")
    inspect.add_argument("name")
    _add_base_arguments(inspect)
    _add_state_argument(inspect)
    inspect.add_argument("--qemu-img")
    remove = overlay_commands.add_parser(
        "remove", help="destructively remove one exact validated named overlay"
    )
    remove.add_argument("name")
    _add_base_arguments(remove)
    _add_state_argument(remove)
    remove.add_argument("--qemu-img")
    remove.add_argument(
        "--confirm",
        required=True,
        help="exact token remove:NAME:BASE_SHA256",
    )
    reset = overlay_commands.add_parser(
        "reset", help="destructively replace one exact validated named overlay"
    )
    reset.add_argument("name")
    _add_base_arguments(reset)
    _add_state_argument(reset)
    reset.add_argument("--qemu-img")
    reset.add_argument(
        "--confirm",
        required=True,
        help="exact token reset:NAME:BASE_SHA256",
    )

    launch = commands.add_parser("launch", help="plan or launch the VM")
    _add_boot_arguments(launch)
    _add_state_argument(launch)
    launch.add_argument(
        "--profile",
        choices=("developer", "analysis", "hostile"),
        default="developer",
    )
    launch.add_argument(
        "--storage", choices=("volatile", "persistent"), default="volatile"
    )
    launch.add_argument("--overlay")
    launch.add_argument("--network", choices=("none", "internet"), default="none")
    launch.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    launch.add_argument("--memory-mib", type=int, default=DEFAULT_MEMORY_MIB)
    launch.add_argument("--cpus", type=int, default=DEFAULT_CPUS)
    launch.add_argument("--qemu")
    launch.add_argument("--qemu-img")
    launch.add_argument(
        "--hostile-payload",
        help=(
            "exact regular-file sample for bounded hostile read-only ingress; "
            "requires --hostile-payload-sha256"
        ),
    )
    launch.add_argument(
        "--hostile-payload-sha256",
        help=(
            "exact lowercase SHA-256 for --hostile-payload; both options are "
            "required together"
        ),
    )
    launch.add_argument(
        "--dry-run",
        action="store_true",
        help="emit exact JSON plan without launching QEMU",
    )
    return parser


def _launch_from_args(args: argparse.Namespace) -> int:
    common = {
        "kernel": args.kernel,
        "kernel_sha256": args.kernel_sha256,
        "initrd": args.initrd,
        "initrd_sha256": args.initrd_sha256,
        "base_image": args.base_image,
        "base_sha256": args.base_sha256,
        "state_root": args.state_root,
        "profile": args.profile,
        "storage": args.storage,
        "overlay": args.overlay,
        "network": args.network,
        "acceleration": args.accel,
        "memory_mib": args.memory_mib,
        "cpus": args.cpus,
        "qemu": args.qemu,
        "qemu_img": args.qemu_img,
        "hostile_payload": args.hostile_payload,
        "hostile_payload_sha256": args.hostile_payload_sha256,
    }
    if args.storage == "persistent":
        name = validate_overlay_name(args.overlay or "")
        state = ensure_state_root(args.state_root)
        with overlay_lock(state, name):
            plan = launch_plan(**common, overlay_is_locked=True)
            if args.dry_run:
                sys.stdout.write(canonical_json(plan))
                return 0
            return run_launch(plan, cwd=state, emit_plan=True)
    plan = launch_plan(**common)
    if args.dry_run:
        sys.stdout.write(canonical_json(plan))
        return 0
    return run_launch(plan, cwd=Path(args.state_root), emit_plan=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            result = status_report(
                kernel=args.kernel,
                kernel_sha256=args.kernel_sha256,
                initrd=args.initrd,
                initrd_sha256=args.initrd_sha256,
                base_image=args.base_image,
                base_sha256=args.base_sha256,
                qemu=args.qemu,
            )
            sys.stdout.write(canonical_json(result))
            return 0
        if args.command == "overlay":
            operations = {
                "create": create_overlay,
                "inspect": inspect_overlay,
                "remove": remove_overlay,
                "reset": reset_overlay,
            }
            operation = operations.get(args.overlay_command)
            if operation is None:
                raise LabError(
                    f"unsupported overlay command: {args.overlay_command}"
                )
            keywords: dict[str, Any] = {
                "state_root": args.state_root,
                "name": args.name,
                "base_image": args.base_image,
                "base_sha256": args.base_sha256,
                "qemu_img": args.qemu_img,
            }
            if args.overlay_command in {"remove", "reset"}:
                keywords["confirmation"] = args.confirm
            result = operation(**keywords)
            sys.stdout.write(canonical_json(result))
            return 0
        if args.command == "launch":
            return _launch_from_args(args)
        raise LabError(f"unsupported command: {args.command}")
    except LabError as exc:
        sys.stderr.write(f"wuci-lab: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
