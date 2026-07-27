#!/usr/bin/env python3
"""Resolve, build, inspect, and boot-test WuciOS Lovelace Laboratory.

Only ``fetch`` and the separately explicit ``network-test`` use the network.
``build``, ``verify``, and the offline runtime tests consume exact local
inputs.  Lovelace is a separate, non-authoritative research/development
profile; this module does not broaden Noether Core.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Sequence

import noether_forge


REPO = Path(__file__).resolve().parents[2]
RELEASE_ROOT = REPO / "wucios/releases/lovelace-laboratory-v0.1.0"
PROFILE_PATH = REPO / "wucios/profiles/lovelace-laboratory.json"
NOETHER_RELEASE_ROOT = REPO / "wucios/releases/noether-forge-v2.4.0"
DEFAULT_CACHE = Path(
    os.environ.get(
        "LOVELACE_CACHE",
        REPO / "build/wucios/inputs/lovelace-laboratory-v0.1.0",
    )
)
DEFAULT_OUTPUT = Path(
    os.environ.get(
        "LOVELACE_OUTPUT",
        REPO / "build/wucios/lovelace-laboratory-v0.1.0",
    )
)
PACKAGE_LOCK_PATH = RELEASE_ROOT / "package-lock.json"
MKE2FS_CONFIG_PATH = RELEASE_ROOT / "mke2fs.conf"
BUILDER_VERSION = "wucios-lovelace-builder-v1"
EXPECTED_RELEASE_ID = "lovelace-laboratory-v0.1.0"
EXPECTED_RELEASE_DISPLAY_NAME = "WuciOS Lovelace Laboratory 0.1.0"
EXPECTED_RELEASE_SUBSTRATE = "alpine-3.24.1"
EXPECTED_PROFILE_CANONICAL_SHA256 = (
    "5eff47d1f3d8d1d5de051ef7a15c371003f5358d23ab340d96421f1138ce772f"
)
EXPECTED_RELEASE_CLAIMS = (
    "Separate non-authoritative research/development substrate",
    "Volatile launch is the default",
    "Persistent launch requires an explicitly named overlay",
    "Networking is absent by default and Internet NAT is explicit",
    "Hostile-code cells require usable KVM and fail closed otherwise",
)
EXPECTED_RELEASE_NON_CLAIMS = (
    "No Noether Core equivalence",
    "No release or production authority",
    "No certification or independent evaluation",
    "No perfect isolation or escape-proof execution",
    "No guarantee that malicious code is safe to execute",
    "No hostile-code isolation from TCG",
    "No graphical Ghidra claim in the initial artifact",
)
EXPECTED_SHARED_ALPINE_INPUT_USE = (
    "The GPG-authenticated Alpine standard ISO and bootstrap apk only; "
    "no Noether package lock or release evidence is reused."
)
EXPECTED_GHIDRA_LIMITATIONS = (
    "The official release page publishes SHA-256 but no detached asset "
    "signature.",
    "Alpine musl and bundled native-component compatibility must be "
    "established by the guest acceptance test.",
    "Ghidra parses attacker-controlled formats and is not a containment layer.",
    "Graphical operation is outside this initial headless acceptance target.",
)
RUNTIME_SOURCE_EXACT_PATHS = frozenset(
    {
        "Makefile",
        "LICENSE",
        "NOTICE",
        "README.md",
        "BUILD_NOTES.md",
        "docs/SECURITY_BOUNDARY.md",
        "docs/WUCI_OS.md",
        "docs/wuci_gate_boundary.json",
        "docs/wuci_cage_policy.json",
        "docs/wuci_qcage_policy.json",
        "docs/wuci_high_attestation_profile.json",
        "daylight-equation/SCORECARD.v1.json",
        "daylight-equation/specs/daylight-minimal-core-v0.4.md",
        "daylight-equation/rust/daylight-crypto/src/wuci_daylight.rs",
    }
)
RUNTIME_SOURCE_PREFIXES = (
    "src/",
    "include/",
    "tools/",
    "docs/noxframe/",
)
# These are host-side artifact/supervisor controllers, not guest programs.
# Keep the exclusion explicit so adding the currently untracked files to Git
# cannot silently change the image or invalidate already reviewed evidence.
HOST_ONLY_RUNTIME_SOURCE_PATHS = frozenset(
    {
        "tools/wuci_lab.py",
        "tools/wucios/lovelace_builder.py",
    }
)
EXPECTED_JAVA_HOME = "/usr/lib/jvm/java-21-openjdk"
BUSYBOX_RUNTIME_LINKS = (
    ("/bin/ash", "busybox"),
    ("/sbin/init", "../bin/busybox"),
    ("/sbin/mdev", "../bin/busybox"),
    ("/sbin/poweroff", "../bin/busybox"),
    ("/sbin/reboot", "../bin/busybox"),
    ("/sbin/halt", "../bin/busybox"),
    ("/bin/hostname", "busybox"),
)
MAX_NATIVE_WUCIJI_BYTES = 64 * 1024 * 1024
DOAS_PATH = "/usr/bin/doas"
DOAS_MODE = "04755"
DOAS_JUSTIFICATION = (
    "Guest-local administration through doas intentionally permits lab to "
    "obtain guest root; the hostile cell treats the whole guest, including "
    "guest root, as compromised and relies only on the outer host controls."
)
MAX_INDEX_SIZE = 32 * 1024 * 1024
MAX_BUILD_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_GHIDRA_EXPANDED_SIZE = 4 * 1024 * 1024 * 1024
MAX_GHIDRA_ENTRY_SIZE = 1024 * 1024 * 1024
MAX_GHIDRA_ENTRIES = 100_000
MAX_ROOT_TREE_ENTRIES = 250_000
MAX_TRANSIENT_PATH_SCAN_BYTES = 16 * 1024 * 1024 * 1024
MAX_BOUNDED_SUBPROCESS_TIMEOUT_SECONDS = 3600
BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS = 5
MAX_DEBUGFS_INVENTORY_STDOUT_BYTES = 64 * 1024 * 1024
MAX_DEBUGFS_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_DEBUGFS_INVENTORY_TOTAL_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_DEBUGFS_INVENTORY_INODE_ZERO_ENTRIES = MAX_ROOT_TREE_ENTRIES
MAX_DEBUGFS_INVENTORY_SECONDS = 3600
MAX_EMBEDDED_DEBUGFS_VERIFICATION_SECONDS = 3600
MAX_EXT4_SYMLINK_RESOLUTION_DEPTH = 40
MAX_EXT4_PATH_BYTES = 4096
# e2fsprogs 1.47.0 reports an inline `Fast link dest` only below the
# 60-byte ext4 i_block capacity; 60-byte targets use external storage.
MAX_EXT4_FAST_SYMLINK_TARGET_BYTES = 59
IMMUTABLE_GUEST_RUNTIME_PREFIXES = ("/bin", "/sbin", "/usr", "/opt")
EXPECTED_E2FSPROGS_VERSION = "1.47.0"
EXPECTED_FAKEROOT_VERSION = "1.33"
EXPECTED_XORRISO_VERSION = "1.5.8.pl02"
VALIDATION_CONTRACT: dict[str, dict[str, str]] = {
    "boot": {
        "measured_status": "locally-validated-tcg-functional-only",
        "evidence_path": "evidence/boot-test.json",
        "evidence_schema": "wucios.lovelace.boot_evidence.v1",
    },
    "language_matrix": {
        "measured_status": "locally-validated",
        "evidence_path": "evidence/boot-test.json",
        "evidence_schema": "wucios.lovelace.boot_evidence.v1",
    },
    "noxframe_guest_broker": {
        "measured_status": "locally-validated",
        "evidence_path": "evidence/noxframe-guest.json",
        "evidence_schema": "wucios.lovelace.noxframe_guest_evidence.v1",
    },
    "ghidra_headless": {
        "measured_status": "locally-validated",
        "evidence_path": "evidence/ghidra-headless.json",
        "evidence_schema": "wucios.lovelace.ghidra_headless_evidence.v1",
    },
    "persistent_round_trip": {
        "measured_status": "locally-validated",
        "evidence_path": "evidence/persistent-round-trip.json",
        "evidence_schema": "wucios.lovelace.persistence_evidence.v1",
    },
    "network_internet": {
        "measured_status": "locally-validated-explicit-mode",
        "evidence_path": "evidence/network-internet.json",
        "evidence_schema": "wucios.lovelace.network_evidence.v1",
    },
    "reproducible_build": {
        "measured_status": "locally-validated-byte-for-byte",
        "evidence_path": "evidence/reproducibility.json",
        "evidence_schema": "wucios.lovelace.reproducibility_evidence.v1",
    },
    "hostile_kvm_cell": {
        "measured_status": "locally-validated-kvm-layered-control-presence",
        "evidence_path": "evidence/hostile-kvm-cell.json",
        "evidence_schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
    },
    "hostile_payload_ingress": {
        "measured_status": (
            "locally-validated-kvm-fixed-benign-read-only-payload-ingress"
        ),
        "evidence_path": "evidence/hostile-payload-ingress.json",
        "evidence_schema": (
            "wucios.lovelace.hostile_payload_ingress_evidence.v1"
        ),
    },
}
MAX_STANDARD_VALIDATION_EVIDENCE_BYTES = 32 * 1024 * 1024
MAX_HOSTILE_VALIDATION_EVIDENCE_BYTES = 96 * 1024 * 1024
MAX_VALIDATION_EVIDENCE_BYTES_BY_SCHEMA = {
    "wucios.lovelace.boot_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.noxframe_guest_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.ghidra_headless_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.persistence_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.network_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.reproducibility_evidence.v1": (
        MAX_STANDARD_VALIDATION_EVIDENCE_BYTES
    ),
    # The hostile document may contain a complete 32 MiB escaped-ASCII
    # transcript. The larger serialized cap allows canonical JSON escaping
    # and the remaining bounded evidence fields without an unbounded read.
    "wucios.lovelace.hostile_kvm_cell_evidence.v1": (
        MAX_HOSTILE_VALIDATION_EVIDENCE_BYTES
    ),
    "wucios.lovelace.hostile_payload_ingress_evidence.v1": (
        MAX_HOSTILE_VALIDATION_EVIDENCE_BYTES
    ),
}
BOOT_MARKER = "LOVELACE_LABORATORY_BOOT"
OFFLINE_BOOT_LINE = (
    "LOVELACE_LABORATORY_BOOT "
    "profile=lovelace-laboratory storage=host-selected network=none"
)
INTERNET_BOOT_LINE = (
    "LOVELACE_LABORATORY_BOOT "
    "profile=lovelace-laboratory storage=host-selected network=internet"
)
HOSTILE_BOOT_LINE = OFFLINE_BOOT_LINE
CONSOLE_MARKER = "LOVELACE_LABORATORY_CONSOLE_READY"
LANGUAGE_MARKER = "LOVELACE_LANGUAGE_MATRIX_PASS python3 c cpp assembly rust go"
WUCIJI_MARKER = "LOVELACE_NATIVE_WUCI_JI_SELFTEST_PASS"
NOXFRAME_MARKER = "LOVELACE_NOXFRAME_PRESENT_PASS"
GHIDRA_PRESENT_MARKER = "LOVELACE_GHIDRA_HEADLESS_PRESENT_PASS"
GHIDRA_SEMANTIC_MARKER = "LOVELACE_GHIDRA_SEMANTIC_PASS"
GHIDRA_EXIT_LINE_PREFIX = "LOVELACE_GHIDRA_HEADLESS_EXIT status="
GHIDRA_EXIT_SUCCESS_MARKER = "LOVELACE_GHIDRA_HEADLESS_EXIT status=0"
GHIDRA_PASS_MARKER = "LOVELACE_GHIDRA_HEADLESS_PASS"
GHIDRA_SEMANTIC_SCRIPT_PATH = (
    "/usr/share/wucios/fixtures/ghidra/scripts"
)
GHIDRA_SEMANTIC_SCRIPT_NAME = "LovelaceGhidraSemanticCheck.java"
GHIDRA_VM_MEMORY_MIB = 6144
GHIDRA_FIXTURE_MD5 = "7af3bf4a75edc982a574d9e0290f96fd"
GHIDRA_FIXTURE_SHA256 = (
    "446c9e5b46a3eb21a7e09f2794bdd58c66491ebd927bc67c36b212d7da08eb8e"
)
QEMU_USER_NETDEV = (
    "user,id=wuci-net,restrict=off,ipv6=off,"
    "net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,"
    "dhcpstart=10.0.2.15"
)
QEMU_USER_NETWORK_DEVICE = "virtio-net-pci,netdev=wuci-net"
QEMU_USER_GUEST_IPV4_CIDR = "10.0.2.15/24"
QEMU_USER_GATEWAY_IPV4 = "10.0.2.2"
QEMU_USER_DNS_PROXY_IPV4 = "10.0.2.3"
GUEST_RESOLV_CONF = (
    "nameserver 10.0.2.3\n"
    "options timeout:2 attempts:3\n"
)
NETWORK_CONNECT_TIMEOUT_SECONDS = 15
NETWORK_TRANSFER_TIMEOUT_SECONDS = 90
NETWORK_VM_TIMEOUT_SECONDS = 1500
GHIDRA_PROCESS_TIMEOUT_SECONDS = 600
GHIDRA_PROCESS_KILL_GRACE_SECONDS = 30
GHIDRA_VM_TIMEOUT_SECONDS = 1500
GHIDRA_JAVA_COMPILER_OPTION = "-XX:-TieredCompilation"
GHIDRA_HEADLESS_MAXMEM = "2G"
TCG_CPU_MODEL = (
    "Broadwell-v4,pcid=off,x2apic=off,tsc-deadline=off,"
    "invpcid=off,spec-ctrl=off"
)
FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS = ("nosoftlockup",)
FORBIDDEN_TCG_DIAGNOSTICS = (
    "TCG doesn't support requested feature:",
)
FORBIDDEN_GUEST_RUNTIME_DIAGNOSTICS = (
    "Kernel panic - not syncing:",
    "watchdog: BUG: soft lockup",
    "BUG: unable to handle",
    "Oops:",
    "general protection fault",
    "EXT4-fs error",
    "Buffer I/O error",
    "Mounting root: failed.",
    "Launching initramfs emergency recovery shell.",
    "mount: mounting /dev/vda on /sysroot failed",
    "VFS: Cannot open root device",
    "VFS: Unable to mount root fs",
    "No filesystem could mount root",
    "No working init found.",
    "Failed to execute /init",
    "Attempted to kill init!",
)
HOSTILE_NETWORK_MARKER = "LOVELACE_HOSTILE_NETWORK_ABSENT_PASS"
HOSTILE_PAYLOAD_BYTES_MARKER = "LOVELACE_HOSTILE_PAYLOAD_BYTES_PASS"
HOSTILE_PAYLOAD_MANIFEST_MARKER = "LOVELACE_HOSTILE_PAYLOAD_MANIFEST_PASS"
HOSTILE_PAYLOAD_MARKER = "LOVELACE_HOSTILE_PAYLOAD_READONLY_PASS"
HOSTILE_PAYLOAD_SCHEMA = "wuci.lab.hostile-payload.v1"
HOSTILE_PAYLOAD_FIXTURE_PATH = (
    REPO / "wucios/fixtures/lovelace/hostile-payload.txt"
)
HOSTILE_PAYLOAD_FIXTURE_SIZE = 44
HOSTILE_PAYLOAD_FIXTURE_SHA256 = (
    "cf7fe660be24036a09dfde459549fc0cb2fa57fd6551d6b207e450d1f9b320d5"
)
HOSTILE_PAYLOAD_MANIFEST_SIZE = 527
HOSTILE_PAYLOAD_MANIFEST_SHA256 = (
    "4cf11e8d73cfa687af0f8f546071ecfdd759d63b587cf6a6f3e548b24e13b01b"
)
MAX_HOSTILE_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_HOSTILE_PAYLOAD_MEDIA_BYTES = 96 * 1024 * 1024
HOSTILE_PAYLOAD_GUEST_MEDIA = "/run/wuci-payload.ext4"
HOSTILE_PAYLOAD_GUEST_DEVICE = "/dev/vdb"
HOSTILE_PAYLOAD_MOUNTPOINT = "/mnt/wuci-payload"
HOSTILE_WUCIJI_MARKER = "LOVELACE_HOSTILE_WUCI_JI_PASS"
HOSTILE_NOXFRAME_MARKER = (
    "LOVELACE_NOXFRAME_BROKER_PASS python3 c cpp assembly rust go"
)
NOXFRAME_GHIDRA_MARKER = "LOVELACE_NOXFRAME_GHIDRA_HEADLESS_PASS"
NOXFRAME_GHIDRA_SEMANTIC_MARKER = (
    "LOVELACE_NOXFRAME_GHIDRA_SEMANTIC_PASS"
)
HOSTILE_NOXFRAME_RESULT_MARKER = "LOVELACE_HOSTILE_NOXFRAME_PASS"
HOSTILE_GHIDRA_MARKER = "LOVELACE_GHIDRA_HEADLESS_PASS"
HOSTILE_CELL_MARKER = "LOVELACE_HOSTILE_KVM_CELL_PASS"
HOSTILE_REQUIRED_LAYERS = (
    "usable-kvm-device",
    "unprivileged-qemu-process",
    "outer-bwrap-namespace",
    "qemu-sandbox-enabled",
    "resource-bounds-applied",
    "volatile-overlay-cleanup-observed",
    "observed-qemu-identity-disappearance",
    "network-device-absent",
    "host-shares-and-device-passthrough-absent",
)
HOSTILE_PAYLOAD_REQUIRED_LAYERS = (
    *HOSTILE_REQUIRED_LAYERS,
    "fixed-benign-payload-fixture-bound",
    "supervisor-payload-sha256-bound",
    "exact-trusted-debugfs-semantic-readback",
    "guest-payload-and-manifest-bytes-verified",
    "guest-read-only-mount-and-write-rejection",
    "payload-media-cleanup-observed",
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
HOSTILE_EVIDENCE_NONCLAIMS = (
    "This locally observes a specific KVM, bubblewrap, QEMU-sandbox, and "
    "resource-bound execution; it is not proof of perfect isolation.",
    "Only fixed benign acceptance fixtures are exercised by this producer; "
    "it does not establish that arbitrary malware is safe to execute.",
    "No claim is made against hypervisor escape, host-kernel defects, firmware "
    "or hardware defects, side channels, denial of service, or physical attack.",
    "The evidence is local, self-produced, non-authoritative for release, and "
    "is not an independent audit, certification, or production-readiness result.",
    "Volatile-overlay removal is observed after normal supervisor unwind only; "
    "SIGKILL, host crash, or power loss cleanup is not claimed.",
    "The workload may obtain full guest-root control through the intentional "
    "guest doas policy; guest-local privilege separation is not a containment "
    "layer.",
)
HOSTILE_SUPERVISOR_NONCLAIMS = (
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
MAX_HOSTILE_CONSOLE_BYTES = 32 * 1024 * 1024
MAX_FUNCTIONAL_CONSOLE_BYTES = 8 * 1024 * 1024
FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS = 5
MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES = 1024 * 1024
HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST = (
    "tab-0x09",
    "line-feed-0x0a",
    "printable-ascii-0x20-0x7e",
)
HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS = 180
HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS = 0.1
OUTPUT_LOCK_TIMEOUT_SECONDS = 30.0
OUTPUT_LOCK_RETRY_SECONDS = 0.05
HOSTILE_MEMORY_MIB = 6144
HOSTILE_CPUS = 2
HOSTILE_ADDRESS_SPACE_OVERHEAD_BYTES = 4 * 1024 * 1024 * 1024
HOSTILE_FILE_SIZE_OVERHEAD_BYTES = 4 * 1024 * 1024 * 1024


class LovelaceError(RuntimeError):
    pass


class _HostileProcessObservationError(LovelaceError):
    """A hostile-process rejection that retains a teardown-safe identity."""

    def __init__(
        self,
        message: str,
        teardown_identity: dict[str, Any],
    ) -> None:
        super().__init__(message)
        self.teardown_identity = dict(teardown_identity)


LAUNCH_CHOICES: dict[str, tuple[str, ...]] = {
    "profile": ("developer", "analysis", "hostile"),
    "storage": ("volatile", "persistent"),
    "network": ("none", "internet"),
    "accel": ("auto", "kvm", "tcg"),
}


class LovelaceArgumentParser(argparse.ArgumentParser):
    """Apply argparse choice checks to launch defaults sourced from the environment."""

    def parse_args(
        self,
        args: Sequence[str] | None = None,
        namespace: argparse.Namespace | None = None,
    ) -> argparse.Namespace:
        parsed = super().parse_args(args=args, namespace=namespace)
        if getattr(parsed, "command", None) == "launch":
            for field, allowed in LAUNCH_CHOICES.items():
                candidate = getattr(parsed, field)
                if candidate not in allowed:
                    self.error(
                        f"invalid launch {field} default {candidate!r}; "
                        f"choose one of: {', '.join(allowed)}"
                    )
        return parsed


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def validation_evidence_size_limit(schema: str) -> int:
    limit = MAX_VALIDATION_EVIDENCE_BYTES_BY_SCHEMA.get(schema)
    if type(limit) is not int or limit <= 0:
        raise LovelaceError(
            f"unsupported validation evidence size contract: {schema}"
        )
    return limit


def reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LovelaceError(f"duplicate JSON key rejected: {key}")
        value[key] = item
    return value


def parse_json_object(raw: bytes | str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                LovelaceError(
                    f"non-finite JSON number rejected in {label}: {token}"
                )
            ),
        )
    except LovelaceError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LovelaceError(f"cannot read JSON object {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise LovelaceError(f"JSON object required: {label}")
    return value


def load_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise LovelaceError(f"cannot read JSON object {path}: {exc}") from exc
    return parse_json_object(raw, os.fspath(path))


def digest_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def digest_file_rejecting_exact_bytes(
    path: Path, forbidden: bytes
) -> dict[str, Any]:
    if (
        len(forbidden) < 8
        or len(forbidden) > 4096
        or b"\0" in forbidden
    ):
        raise LovelaceError(
            "serialized exact-byte scan contract is invalid"
        )
    before = ensure_regular(
        path, "serialized exact-byte scan input", single_link=True
    )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    total = 0
    overlap = b""
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise LovelaceError(
                "serialized exact-byte scan input changed while opening"
            )
        while block := os.read(descriptor, 1024 * 1024):
            if forbidden in overlap + block:
                raise LovelaceError(
                    "serialized artifact embeds exact transient work-path bytes"
                )
            digest.update(block)
            total += len(block)
            overlap = (overlap + block)[-(len(forbidden) - 1) :]
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = path.lstat()
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        total != opened.st_size
        or identity(opened) != identity(after)
        or identity(opened) != identity(final)
    ):
        raise LovelaceError(
            "serialized artifact changed during exact-byte scan"
        )
    return {
        "schema": "wucios.lovelace.serialized_exact_path_scan.v1",
        "bytes_scanned": total,
        "sha256": digest.hexdigest(),
        "exact_plain_work_path_bytes_found": False,
    }


def digest_vector(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha512")}
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            for digest in digests.values():
                digest.update(block)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def ensure_regular(
    path: Path,
    label: str,
    *,
    size: int | None = None,
    single_link: bool = True,
) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise LovelaceError(f"{label} must be a regular file: {path}")
    if single_link and info.st_nlink != 1:
        raise LovelaceError(f"{label} hardlink rejected: {path}")
    if size is not None and info.st_size != size:
        raise LovelaceError(
            f"{label} size mismatch: expected {size}, got {info.st_size}"
        )
    return info


def verify_locked_file(path: Path, record: dict[str, Any], label: str) -> None:
    before = ensure_regular(
        path, label, size=record.get("size"), single_link=True
    )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise LovelaceError(f"cannot safely open {label}: {path}") from exc
    expected_sha512 = record.get("sha512")
    algorithms = (
        ("sha256", "sha512")
        if expected_sha512 is not None
        else ("sha256",)
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise LovelaceError(f"{label} changed while being opened")
        observed = _digest_descriptor_vector(
            descriptor, opened.st_size, algorithms
        )
        after = os.fstat(descriptor)
        try:
            final = path.lstat()
        except OSError as exc:
            raise LovelaceError(
                f"{label} disappeared during verification"
            ) from exc
        if (
            not stat.S_ISREG(final.st_mode)
            or _stat_identity(opened) != _stat_identity(after)
            or _stat_identity(opened) != _stat_identity(final)
        ):
            raise LovelaceError(f"{label} changed during verification")
    finally:
        os.close(descriptor)
    if observed["sha256"] != record.get("sha256"):
        raise LovelaceError(
            f"{label} SHA-256 mismatch: expected {record.get('sha256')}, "
            f"got {observed['sha256']}"
        )
    if expected_sha512 is not None and observed["sha512"] != expected_sha512:
        raise LovelaceError(f"{label} SHA-512 mismatch: {path.name}")


def run(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    check: bool = True,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[str]:
    command = [os.fspath(item) for item in argv]
    descriptors = tuple(pass_fds)
    if (
        not command
        or any(not isinstance(item, str) or not item for item in command)
        or type(timeout) is not int
        or timeout <= 0
        or len(set(descriptors)) != len(descriptors)
        or any(type(descriptor) is not int or descriptor < 0 for descriptor in descriptors)
    ):
        raise LovelaceError("subprocess contract is invalid")
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        check=False,
        timeout=timeout,
        pass_fds=descriptors,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-6000:]
        raise LovelaceError(
            f"command failed ({result.returncode}): {' '.join(command[:3])}: {detail}"
        )
    return result


def run_bounded(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
    check: bool = True,
    pass_fds: Sequence[int] = (),
    max_stdout_bytes: int,
    max_stderr_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Run a fixed argv while enforcing output limits during collection."""
    command = [os.fspath(item) for item in argv]
    descriptors = tuple(pass_fds)
    if (
        not command
        or any(not isinstance(item, str) or not item for item in command)
        or type(timeout) is not int
        or timeout <= 0
        or timeout > MAX_BOUNDED_SUBPROCESS_TIMEOUT_SECONDS
        or len(set(descriptors)) != len(descriptors)
        or any(
            type(descriptor) is not int or descriptor < 0
            for descriptor in descriptors
        )
        or type(max_stdout_bytes) is not int
        or max_stdout_bytes < 0
        or type(max_stderr_bytes) is not int
        or max_stderr_bytes < 0
    ):
        raise LovelaceError("bounded subprocess contract is invalid")
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            pass_fds=descriptors,
            start_new_session=True,
        )
    except OSError as exc:
        selector.close()
        raise LovelaceError(
            f"command launch failed: {' '.join(command[:3])}: {exc}"
        ) from exc
    except BaseException:
        selector.close()
        raise
    stdout = bytearray()
    stderr = bytearray()
    primary_failure: BaseException | None = None
    try:
        if process.stdout is None or process.stderr is None:
            raise LovelaceError("bounded subprocess pipes were not created")
        for stream, target, limit, label in (
            (process.stdout, stdout, max_stdout_bytes, "stdout"),
            (process.stderr, stderr, max_stderr_bytes, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(
                stream,
                selectors.EVENT_READ,
                (target, limit, label),
            )
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LovelaceError("bounded subprocess timed out")
            events = selector.select(timeout=min(0.25, remaining))
            if not events and process.poll() is not None:
                events = [
                    (key, selectors.EVENT_READ)
                    for key in selector.get_map().values()
                ]
            for key, _mask in events:
                try:
                    block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                target, limit, label = key.data
                if len(target) + len(block) > limit:
                    raise LovelaceError(
                        f"bounded subprocess {label} exceeds {limit} bytes"
                    )
                target.extend(block)
        remaining = max(0.0, deadline - time.monotonic())
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise LovelaceError("bounded subprocess timed out") from exc
    except BaseException as exc:
        primary_failure = exc
        try:
            _terminate_and_reap_bounded_process(
                process,
                context=f"bounded subprocess failed: {exc}",
            )
        except LovelaceError as cleanup_exc:
            raise cleanup_exc from exc
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if primary_failure is None and process.poll() is None:
            _terminate_and_reap_bounded_process(
                process,
                context="bounded subprocess collection ended unexpectedly",
            )
    try:
        stdout_text = stdout.decode("utf-8", errors="strict")
        stderr_text = stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LovelaceError("bounded subprocess output is not UTF-8") from exc
    result = subprocess.CompletedProcess(
        command,
        returncode,
        stdout_text,
        stderr_text,
    )
    if check and returncode != 0:
        detail = (stderr_text or stdout_text).strip()[-6000:]
        raise LovelaceError(
            f"command failed ({returncode}): {' '.join(command[:3])}: {detail}"
        )
    return result


def _terminate_and_reap_bounded_process(
    process: subprocess.Popen[bytes], *, context: str
) -> None:
    """Kill one isolated process group and prove bounded complete cleanup."""
    process_group = process.pid
    signal_error: OSError | None = None
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        signal_error = exc
    try:
        process.wait(timeout=BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise LovelaceError(
            f"{context}; bounded subprocess cleanup failed to reap process "
            f"group {process.pid} within "
            f"{BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS} seconds"
        ) from exc
    except OSError as exc:
        raise LovelaceError(
            f"{context}; bounded subprocess cleanup wait failed for process "
            f"group {process.pid}: {exc}"
        ) from exc
    if signal_error is not None:
        raise LovelaceError(
            f"{context}; bounded subprocess cleanup failed to signal process "
            f"group {process.pid}: {signal_error}"
        ) from signal_error
    deadline = (
        time.monotonic() + BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS
    )
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        except OSError as exc:
            raise LovelaceError(
                f"{context}; bounded subprocess cleanup could not verify "
                f"process group {process_group} absence: {exc}"
            ) from exc
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LovelaceError(
                f"{context}; bounded subprocess cleanup left process group "
                f"{process_group} present after "
                f"{BOUNDED_SUBPROCESS_REAP_TIMEOUT_SECONDS} seconds"
            )
        time.sleep(min(0.05, remaining))


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@contextlib.contextmanager
def pinned_regular_path(
    path: Path, label: str
) -> Iterable[tuple[str, tuple[int, ...]]]:
    """Yield a child-openable path for one identity-pinned regular file."""
    before = ensure_regular(path, label, single_link=True)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise LovelaceError(f"{label} changed while being opened")
        yield f"/proc/self/fd/{descriptor}", (descriptor,)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} disappeared during inspection") from exc
    if (
        not stat.S_ISREG(final.st_mode)
        or _stat_identity(opened) != _stat_identity(after)
        or _stat_identity(opened) != _stat_identity(final)
    ):
        raise LovelaceError(f"{label} changed during inspection")


class PinnedExt4Image:
    def __init__(
        self,
        path: Path,
        descriptor: int,
        opened: os.stat_result,
    ) -> None:
        self.path = path
        self.descriptor = descriptor
        self.opened = opened
        self.child_path = f"/proc/self/fd/{descriptor}"
        self.pass_fds = (descriptor,)

    def pread(self, size: int, offset: int) -> bytes:
        return os.pread(self.descriptor, size, offset)


def _digest_descriptor(
    descriptor: int, size: int, algorithm: str = "sha256"
) -> str:
    return _digest_descriptor_vector(
        descriptor, size, (algorithm,)
    )[algorithm]


def _digest_descriptor_vector(
    descriptor: int,
    size: int,
    algorithms: Sequence[str],
) -> dict[str, str]:
    if (
        type(descriptor) is not int
        or descriptor < 0
        or type(size) is not int
        or size < 0
        or not algorithms
        or len(set(algorithms)) != len(algorithms)
    ):
        raise LovelaceError("descriptor digest contract is invalid")
    digests = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            break
        for digest in digests.values():
            digest.update(block)
        offset += len(block)
    if offset != size:
        raise LovelaceError("pinned ext4 image digest read was truncated")
    return {
        algorithm: digest.hexdigest()
        for algorithm, digest in digests.items()
    }


@contextlib.contextmanager
def pinned_ext4_image(
    path: Path,
    artifact_record: dict[str, Any] | None = None,
) -> Iterable[PinnedExt4Image]:
    before = ensure_regular(path, "ext4 image", single_link=True)
    if artifact_record is not None:
        require_exact_keys(
            artifact_record,
            {"filename", "size", "sha256", "mode", "format"},
            "pinned ext4 artifact record",
        )
        if (
            artifact_record["mode"] != "0444"
            or artifact_record["format"] != "ext4"
            or type(artifact_record["size"]) is not int
            or artifact_record["size"] <= 0
            or not is_lower_hex(artifact_record["sha256"], 64)
            or stat.S_IMODE(before.st_mode) != 0o444
            or before.st_size != artifact_record["size"]
        ):
            raise LovelaceError("pinned ext4 artifact contract differs")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _stat_identity(opened) != _stat_identity(before)
        ):
            raise LovelaceError("ext4 image changed while being pinned")
        if (
            artifact_record is not None
            and _digest_descriptor(descriptor, opened.st_size)
            != artifact_record["sha256"]
        ):
            raise LovelaceError("pinned ext4 artifact SHA-256 differs")
        after_digest = os.fstat(descriptor)
        if _stat_identity(after_digest) != _stat_identity(opened):
            raise LovelaceError("ext4 image changed during pinned digest")
        yield PinnedExt4Image(path, descriptor, opened)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise LovelaceError("ext4 image disappeared during verification") from exc
    if (
        not stat.S_ISREG(final.st_mode)
        or _stat_identity(opened) != _stat_identity(after)
        or _stat_identity(opened) != _stat_identity(final)
    ):
        raise LovelaceError("ext4 image changed during verification")


@contextlib.contextmanager
def ext4_image_handle(
    image: Path | PinnedExt4Image,
) -> Iterable[PinnedExt4Image]:
    if isinstance(image, PinnedExt4Image):
        yield image
        return
    with pinned_ext4_image(image) as pinned:
        yield pinned


def trusted_host_tool(name: str) -> Path:
    discovered = shutil.which(
        name, path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    if discovered is None:
        raise LovelaceError(f"required host tool is missing: {name}")
    try:
        path = Path(discovered).resolve(strict=True)
    except OSError as exc:
        raise LovelaceError(
            f"cannot resolve required host tool: {name}"
        ) from exc
    info = ensure_regular(path, f"host tool {name}", single_link=False)
    if info.st_mode & 0o022 or info.st_mode & 0o111 == 0:
        raise LovelaceError(
            f"host tool must be executable and not group/world writable: {path}"
        )
    return path


def trusted_xorriso() -> Path:
    override = os.environ.get("LOVELACE_XORRISO")
    if not override:
        path = trusted_host_tool("xorriso")
    else:
        if (
            not os.path.isabs(override)
            or "\x00" in override
            or any(ord(character) < 0x20 for character in override)
        ):
            raise LovelaceError(
                "LOVELACE_XORRISO must be an absolute path without "
                "control characters"
            )
        try:
            path = Path(override).resolve(strict=True)
        except OSError as exc:
            raise LovelaceError(
                "cannot resolve explicit Lovelace xorriso"
            ) from exc
        info = ensure_regular(
            path, "explicit Lovelace xorriso", single_link=False
        )
        if (
            info.st_uid not in {0, os.geteuid()}
            or info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
            or info.st_mode & 0o111 == 0
        ):
            raise LovelaceError(
                "explicit Lovelace xorriso must be root/operator-owned, "
                "executable, non-set-ID, and not group/world writable"
            )
    version = run(
        [path, "-version"],
        env={
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
        },
        timeout=15,
    )
    if EXPECTED_XORRISO_VERSION not in (
        version.stdout + "\n" + version.stderr
    ):
        raise LovelaceError(
            f"xorriso must report exact supported version "
            f"{EXPECTED_XORRISO_VERSION}"
        )
    return path


def host_tool_record(path: Path, version: str) -> dict[str, Any]:
    info = ensure_regular(path, f"host tool {path.name}", single_link=False)
    return {
        "path": str(path),
        "version": version,
        "size": info.st_size,
        "sha256": digest_file(path),
    }


def write_json(path: Path, value: Any) -> None:
    try:
        noether_forge.atomic_write(path, canonical_json(value))
    except noether_forge.NoetherForgeError as exc:
        raise LovelaceError(str(exc)) from exc


def require_exact_keys(
    value: Any, keys: Iterable[str], label: str
) -> None:
    if not isinstance(value, dict):
        raise LovelaceError(f"{label} must be a JSON object")
    expected = set(keys)
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise LovelaceError(f"{label} keys differ: missing={missing}, extra={extra}")


def is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None
    )


def configuration() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    release = load_object(RELEASE_ROOT / "release.json")
    seeds = load_object(RELEASE_ROOT / "package-seeds.json")
    ghidra = load_object(RELEASE_ROOT / "ghidra-lock.json")
    profile = load_object(PROFILE_PATH)
    require_exact_keys(
        release,
        {
            "schema",
            "release_id",
            "display_name",
            "profile",
            "status",
            "architecture",
            "substrate",
            "source_date_epoch",
            "filesystem",
            "boot",
            "shared_alpine_input",
            "output_files",
            "claims",
            "non_claims",
        },
        "Lovelace release",
    )
    if (
        release["schema"] != "wucios.lovelace.release.v1"
        or release["release_id"] != EXPECTED_RELEASE_ID
        or release["display_name"] != EXPECTED_RELEASE_DISPLAY_NAME
        or release["profile"] != "lovelace-laboratory"
        or release["status"]
        != "NON_AUTHORITATIVE_RESEARCH_DEVELOPMENT_ARTIFACT"
        or release["architecture"] != "x86_64"
        or release["substrate"] != EXPECTED_RELEASE_SUBSTRATE
        or type(release["source_date_epoch"]) is not int
        or release["source_date_epoch"] <= 0
    ):
        raise LovelaceError("Lovelace release identity is invalid")
    if (
        release["claims"] != list(EXPECTED_RELEASE_CLAIMS)
        or release["non_claims"] != list(EXPECTED_RELEASE_NON_CLAIMS)
    ):
        raise LovelaceError("Lovelace release claim boundary is invalid")
    if (
        profile.get("id") != "lovelace-laboratory"
        or profile.get("default_profile") is not False
        or profile.get("authoritative_for_release") is not False
        or hashlib.sha256(canonical_json(profile)).hexdigest()
        != EXPECTED_PROFILE_CANONICAL_SHA256
    ):
        raise LovelaceError("Lovelace profile contract is invalid")
    filesystem = release["filesystem"]
    require_exact_keys(
        filesystem, {"format", "size_mib", "label", "uuid"}, "filesystem"
    )
    if (
        filesystem["format"] != "ext4"
        or type(filesystem["size_mib"]) is not int
        or not 4096 <= filesystem["size_mib"] <= 32768
        or not isinstance(filesystem["label"], str)
        or re.fullmatch(r"[A-Z0-9_]{1,16}", filesystem["label"]) is None
        or not isinstance(filesystem["uuid"], str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            filesystem["uuid"],
        )
        is None
    ):
        raise LovelaceError("filesystem contract is invalid")
    require_exact_keys(
        release["boot"],
        {
            "kernel_iso_path",
            "initramfs_iso_path",
            "kernel_filename",
            "initramfs_filename",
            "kernel_size",
            "kernel_sha256",
            "initramfs_size",
            "initramfs_sha256",
            "kernel_arguments",
        },
        "Lovelace boot",
    )
    require_exact_keys(
        release["shared_alpine_input"],
        {"path", "canonical_sha256", "use"},
        "shared Alpine input",
    )
    require_exact_keys(
        release["output_files"],
        {"base_image", "kernel", "initramfs", "manifest"},
        "Lovelace output files",
    )
    boot = release["boot"]
    if (
        boot["kernel_iso_path"] != "/boot/vmlinuz-lts"
        or boot["initramfs_iso_path"] != "/boot/initramfs-lts"
        or boot["kernel_filename"] != "vmlinuz-lts"
        or boot["initramfs_filename"] != "initramfs-lts"
        or type(boot["kernel_size"]) is not int
        or type(boot["initramfs_size"]) is not int
        or boot["kernel_size"] <= 0
        or boot["initramfs_size"] <= 0
        or not is_lower_hex(boot["kernel_sha256"], 64)
        or not is_lower_hex(boot["initramfs_sha256"], 64)
        or boot["kernel_arguments"]
        != [
            "root=/dev/vda",
            "rw",
            "rootfstype=ext4",
            "console=ttyS0,115200",
            "panic=10",
        ]
    ):
        raise LovelaceError("Lovelace boot contract is invalid")
    shared_input = release["shared_alpine_input"]
    if (
        shared_input["path"]
        != "wucios/releases/noether-forge-v2.4.0/alpine-input-lock.json"
        or not is_lower_hex(shared_input["canonical_sha256"], 64)
        or shared_input["use"] != EXPECTED_SHARED_ALPINE_INPUT_USE
    ):
        raise LovelaceError("shared Alpine input contract is invalid")
    if release["output_files"] != {
        "base_image": "lovelace-laboratory-x86_64.ext4",
        "kernel": "vmlinuz-lts",
        "initramfs": "initramfs-lts",
        "manifest": "manifest.json",
    }:
        raise LovelaceError("Lovelace output file contract is invalid")
    require_exact_keys(
        seeds,
        {
            "schema",
            "alpine_branch",
            "architecture",
            "repositories",
            "packages",
            "policy",
        },
        "package seeds",
    )
    require_exact_keys(
        seeds["policy"],
        {
            "fetch_only_by_explicit_command",
            "build_network_disabled",
            "exact_transitive_closure_required",
            "package_signatures_required",
            "package_scripts_during_build",
            "runtime_package_changes_redefine_baseline",
        },
        "package seed policy",
    )
    if (
        seeds.get("schema") != "wucios.lovelace.package_seeds.v1"
        or seeds.get("alpine_branch") != "v3.24"
        or seeds.get("architecture") != "x86_64"
        or not isinstance(seeds.get("repositories"), list)
        or not isinstance(seeds.get("packages"), list)
        or seeds["packages"] != sorted(set(seeds["packages"]))
        or len(seeds["packages"]) < 20
        or seeds["policy"]
        != {
            "fetch_only_by_explicit_command": True,
            "build_network_disabled": True,
            "exact_transitive_closure_required": True,
            "package_signatures_required": True,
            "package_scripts_during_build": False,
            "runtime_package_changes_redefine_baseline": False,
        }
    ):
        raise LovelaceError("package seed contract is invalid")
    repo_names: set[str] = set()
    repo_urls: set[str] = set()
    for repository in seeds["repositories"]:
        if (
            not isinstance(repository, dict)
            or set(repository) != {"name", "url"}
            or not isinstance(repository.get("name"), str)
            or re.fullmatch(r"[a-z][a-z0-9-]*", repository["name"]) is None
            or not isinstance(repository.get("url"), str)
            or not repository["url"].startswith(
                "https://dl-cdn.alpinelinux.org/alpine/v3.24/"
            )
            or repository["url"].endswith("/")
        ):
            raise LovelaceError("package repository seed is invalid")
        repo_names.add(repository["name"])
        repo_urls.add(repository["url"])
    if repo_names != {"main", "community"} or len(repo_urls) != 2:
        raise LovelaceError("exact Alpine main/community repositories required")
    require_exact_keys(
        ghidra,
        {
            "schema",
            "name",
            "version",
            "release_tag",
            "filename",
            "url",
            "size",
            "sha256",
            "published_digest_source",
            "published_detached_signature",
            "required_java_major",
            "install_path",
            "entry_point",
            "extensions",
            "limitations",
        },
        "Ghidra lock",
    )
    if (
        ghidra.get("schema") != "wucios.lovelace.ghidra_lock.v1"
        or ghidra.get("name") != "Ghidra"
        or ghidra.get("version") != "12.1.2"
        or ghidra.get("release_tag") != "Ghidra_12.1.2_build"
        or ghidra.get("filename")
        != "ghidra_12.1.2_PUBLIC_20260605.zip"
        or ghidra.get("required_java_major") != 21
        or ghidra.get("published_detached_signature") is not False
        or ghidra.get("url")
        != (
            "https://github.com/NationalSecurityAgency/ghidra/releases/"
            "download/Ghidra_12.1.2_build/"
            "ghidra_12.1.2_PUBLIC_20260605.zip"
        )
        or ghidra.get("published_digest_source")
        != (
            "https://github.com/NationalSecurityAgency/ghidra/releases/"
            "tag/Ghidra_12.1.2_build"
        )
        or not is_lower_hex(ghidra.get("sha256"), 64)
        or type(ghidra.get("size")) is not int
        or ghidra["size"] <= 0
        or ghidra.get("install_path") != "/opt/wucios/ghidra"
        or ghidra.get("entry_point") != "support/analyzeHeadless"
        or ghidra.get("extensions") != []
        or ghidra.get("limitations") != list(EXPECTED_GHIDRA_LIMITATIONS)
    ):
        raise LovelaceError("Ghidra lock is invalid")
    return release, seeds, ghidra


def shared_alpine_lock(release: dict[str, Any]) -> dict[str, Any]:
    lock_path = REPO / release["shared_alpine_input"]["path"]
    lock = load_object(lock_path)
    observed = hashlib.sha256(canonical_json(lock)).hexdigest()
    expected = release["shared_alpine_input"]["canonical_sha256"]
    if observed != expected:
        raise LovelaceError(
            f"shared authenticated Alpine input lock drift: expected {expected}, got {observed}"
        )
    if (
        lock.get("alpine_release") != "3.24.1"
        or lock.get("architecture") != "x86_64"
    ):
        raise LovelaceError("shared Alpine input identity is invalid")
    return lock


def cache_paths(cache: Path) -> dict[str, Path]:
    return {
        "boot": cache / "boot",
        "indexes": cache / "indexes",
        "packages": cache / "packages",
        "ghidra": cache / "ghidra",
    }


def safe_download_snapshot(
    url: str, destination: Path, *, maximum_size: int, user_agent: str
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    received = 0
    try:
        with os.fdopen(fd, "wb") as output:
            request = urllib.request.Request(
                url, headers={"User-Agent": user_agent}
            )
            with urllib.request.urlopen(request, timeout=90) as response:
                final_url = response.geturl()
                if not final_url.startswith("https://"):
                    raise LovelaceError("HTTPS download redirected outside HTTPS")
                while block := response.read(1024 * 1024):
                    received += len(block)
                    if received > maximum_size:
                        raise LovelaceError(
                            f"download exceeds size ceiling: {url}"
                        )
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        if received == 0:
            raise LovelaceError(f"empty download rejected: {url}")
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def boot_cache_records(alpine_lock: dict[str, Any]) -> list[dict[str, Any]]:
    media = alpine_lock["boot_media"]
    records = [{**media["iso"], "kind": "Alpine standard ISO"}]
    records.extend({**record, "kind": "Alpine standard ISO sidecar"} for record in media["sidecars"])
    records.append(
        {
            "filename": alpine_lock["release_signer"]["key_filename"],
            "url": alpine_lock["release_signer"]["key_url"],
            "size": alpine_lock["release_signer"]["key_size"],
            "sha256": alpine_lock["release_signer"]["key_sha256"],
            "kind": "Alpine release signing key",
        }
    )
    return records


def fetch_locked_file(record: dict[str, Any], destination_root: Path) -> None:
    try:
        noether_forge.download_locked(record, destination_root)
    except noether_forge.NoetherForgeError as exc:
        raise LovelaceError(str(exc)) from exc


def verify_boot_media(
    release: dict[str, Any],
    alpine_lock: dict[str, Any],
    boot_cache: Path,
    work: Path,
) -> tuple[Path, Path, Path]:
    gpg = trusted_host_tool("gpg")
    xorriso = trusted_xorriso()
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    for record in boot_cache_records(alpine_lock):
        verify_locked_file(
            boot_cache / record["filename"], record, record["kind"]
        )
    # Keep the homedir short enough for Linux's AF_UNIX gpg-agent socket limit.
    gpg_home = work / "g"
    gpg_home.mkdir(mode=0o700)
    run(
        [
            gpg,
            "--no-autostart",
            "--batch",
            "--homedir",
            gpg_home,
            "--import",
            boot_cache / alpine_lock["release_signer"]["key_filename"],
        ],
        env=environment,
    )
    media = alpine_lock["boot_media"]
    iso_record = media["iso"]
    iso = boot_cache / iso_record["filename"]
    if digest_file(iso, "sha512") != iso_record["sha512"]:
        raise LovelaceError("Alpine ISO SHA-512 mismatch")
    for role, algorithm in (
        ("sha256-digest", "sha256"),
        ("sha512-digest", "sha512"),
    ):
        sidecars = [
            item for item in media["sidecars"] if item.get("role") == role
        ]
        if len(sidecars) != 1:
            raise LovelaceError(
                f"Alpine media requires exactly one {role} sidecar"
            )
        text = (
            boot_cache / sidecars[0]["filename"]
        ).read_text(encoding="ascii").strip()
        if text.split() != [iso_record[algorithm], iso.name]:
            raise LovelaceError(
                f"published Alpine {algorithm} sidecar differs"
            )
    signatures = [
        item
        for item in media["sidecars"]
        if item.get("role") == "detached-signature"
    ]
    if len(signatures) != 1:
        raise LovelaceError(
            "Alpine media requires exactly one detached signature"
        )
    signature_result = run(
        [
            gpg,
            "--no-autostart",
            "--batch",
            "--homedir",
            gpg_home,
            "--status-fd",
            "1",
            "--verify",
            boot_cache / signatures[0]["filename"],
            iso,
        ],
        env=environment,
    )
    fingerprint = alpine_lock["release_signer"]["fingerprint"]
    if f"[GNUPG:] VALIDSIG {fingerprint} " not in signature_result.stdout:
        raise LovelaceError(
            "Alpine detached signature lacks the pinned signer fingerprint"
        )
    kernel = work / "boot/vmlinuz-lts"
    initramfs = work / "boot/initramfs-lts"
    for iso_path, destination in (
        (release["boot"]["kernel_iso_path"], kernel),
        (release["boot"]["initramfs_iso_path"], initramfs),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(
            [
                xorriso,
                "-osirrox",
                "on",
                "-indev",
                iso,
                "-extract",
                iso_path,
                destination,
            ],
            env=environment,
        )
        ensure_regular(
            destination, f"extracted Alpine ISO file {iso_path}"
        )
    verify_locked_file(
        kernel,
        {
            "size": release["boot"]["kernel_size"],
            "sha256": release["boot"]["kernel_sha256"],
        },
        "authenticated Alpine kernel",
    )
    verify_locked_file(
        initramfs,
        {
            "size": release["boot"]["initramfs_size"],
            "sha256": release["boot"]["initramfs_sha256"],
        },
        "authenticated Alpine initramfs",
    )
    return iso, kernel, initramfs


def materialize_apk_bootstrap(
    alpine_lock: dict[str, Any], initramfs: Path, work: Path
) -> tuple[Path, list[Path]]:
    record = alpine_lock["bootstrap"]["initramfs"]
    try:
        archive = noether_forge.read_locked_gzip(
            initramfs, record, "authenticated Alpine initramfs"
        )
        members = noether_forge.parse_newc_bootstrap(
            archive,
            alpine_lock["bootstrap"]["members"],
            expected_entry_count=record["entry_count"],
        )
        root = work / "apk-bootstrap"
        keys = noether_forge.materialize_bootstrap(root, members)
    except noether_forge.NoetherForgeError as exc:
        raise LovelaceError(str(exc)) from exc
    apk = noether_forge.bootstrap_apk_command(root)
    result = run([*apk, "--version"], env=apk_environment(work))
    if result.stdout.strip() != alpine_lock["bootstrap"]["apk_version"]:
        raise LovelaceError("authenticated bootstrap apk version drift")
    return root, keys


def apk_environment(work: Path) -> dict[str, str]:
    home = work / "apk-home"
    home.mkdir(exist_ok=True)
    return {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def apk_command(bootstrap: Path) -> list[str | os.PathLike[str]]:
    return noether_forge.bootstrap_apk_command(bootstrap)


def signed_index_payload(path: Path) -> tuple[bytes, str]:
    ensure_regular(path, "Alpine APK index")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 8:
                raise LovelaceError("APK index has an unexpected member count")
            index_members = [
                member
                for member in members
                if member.name == "APKINDEX" and member.isfile()
            ]
            signature_members = [
                member
                for member in members
                if member.name.startswith(".SIGN.RSA.") and member.isfile()
            ]
            if len(index_members) != 1 or len(signature_members) != 1:
                raise LovelaceError(
                    "APK index requires exactly one payload and RSA signature"
                )
            if index_members[0].size > MAX_INDEX_SIZE:
                raise LovelaceError("APK index payload exceeds size ceiling")
            stream = archive.extractfile(index_members[0])
            if stream is None:
                raise LovelaceError("APK index payload is unreadable")
            payload = stream.read(MAX_INDEX_SIZE + 1)
    except (OSError, tarfile.TarError) as exc:
        raise LovelaceError(f"APK index archive is invalid: {path}") from exc
    if len(payload) > MAX_INDEX_SIZE:
        raise LovelaceError("APK index payload exceeds size ceiling")
    return payload, signature_members[0].name.removeprefix(".SIGN.RSA.")


def parse_apk_index(path: Path, repository: str) -> dict[tuple[str, str, str], dict[str, str]]:
    payload, _signer = signed_index_payload(path)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LovelaceError(f"APK index is not UTF-8: {repository}") from exc
    records: dict[tuple[str, str, str], dict[str, str]] = {}
    for paragraph in text.strip().split("\n\n"):
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if len(line) >= 3 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        if not {"P", "V", "A"} <= set(fields):
            raise LovelaceError(f"APK index record is incomplete: {repository}")
        key = (fields["P"], fields["V"], fields["A"])
        if key in records:
            raise LovelaceError(
                f"duplicate APK index identity: {repository}:{key}"
            )
        records[key] = fields
    if not records:
        raise LovelaceError(f"APK index is empty: {repository}")
    return records


def copy_regular_atomic(source: Path, destination: Path) -> None:
    ensure_regular(source, "copy source", single_link=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with source.open("rb") as input_stream, os.fdopen(
            fd, "wb"
        ) as output_stream:
            shutil.copyfileobj(input_stream, output_stream, 1024 * 1024)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.chmod(temporary_name, 0o644)
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def package_metadata(path: Path) -> dict[str, str]:
    try:
        info = noether_forge.apk_pkginfo(path)
    except (noether_forge.NoetherForgeError, tarfile.TarError, OSError) as exc:
        raise LovelaceError(f"cannot parse APK metadata: {path.name}") from exc
    required = {"pkgname", "pkgver", "arch", "origin", "license", "size"}
    if not required <= set(info):
        raise LovelaceError(f"APK metadata is incomplete: {path.name}")
    return info


def verify_apk_signature(
    apk: Sequence[str | os.PathLike[str]],
    keys_dir: Path,
    package: Path,
    environment: dict[str, str],
) -> None:
    run(
        [*apk, "verify", "--keys-dir", keys_dir, package],
        env=environment,
        timeout=120,
    )


def fetch_package_closure(
    seeds: dict[str, Any],
    cache: Path,
    bootstrap: Path,
    keys_dir: Path,
    work: Path,
) -> dict[str, Any]:
    paths = cache_paths(cache)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    apk = apk_command(bootstrap)
    environment = apk_environment(work)
    repository_arguments: list[str] = []
    for repository in seeds["repositories"]:
        repository_arguments.extend(["--repository", repository["url"]])

    first_indexes: dict[str, tuple[Path, str]] = {}
    for repository in seeds["repositories"]:
        destination = work / f"index-before-{repository['name']}.tar.gz"
        safe_download_snapshot(
            f"{repository['url']}/{seeds['architecture']}/APKINDEX.tar.gz",
            destination,
            maximum_size=MAX_INDEX_SIZE,
            user_agent=f"{BUILDER_VERSION}/1",
        )
        verify_apk_signature(apk, keys_dir, destination, environment)
        first_indexes[repository["name"]] = (
            destination,
            digest_file(destination),
        )

    downloads = work / "resolved-packages"
    downloads.mkdir()
    (work / "apk-cache").mkdir()
    solver_root = work / "apk-solver-root"
    solver_root.mkdir()
    solver_repositories = work / "solver-empty-repositories"
    solver_repositories.write_bytes(b"")
    run(
        [
            *apk,
            "add",
            "--root",
            solver_root,
            "--initdb",
            "--usermode",
            "--no-network",
            "--repositories-file",
            solver_repositories,
            "--no-scripts",
        ],
        env=environment,
        timeout=120,
    )
    run(
        [
            *apk,
            "--root",
            solver_root,
            "--arch",
            seeds["architecture"],
            "--keys-dir",
            keys_dir,
            *repository_arguments,
            "--cache-dir",
            work / "apk-cache",
            "--cache-max-age",
            "0",
            "--no-logfile",
            "update",
        ],
        env=environment,
        timeout=300,
    )
    fetch_result = run(
        [
            *apk,
            "--root",
            solver_root,
            "--arch",
            seeds["architecture"],
            "--keys-dir",
            keys_dir,
            *repository_arguments,
            "--cache-dir",
            work / "apk-cache",
            "--cache-max-age",
            "0",
            "--no-logfile",
            "fetch",
            "--recursive",
            "--output",
            downloads,
            *seeds["packages"],
        ],
        env=environment,
        timeout=3600,
    )
    downloaded = sorted(downloads.iterdir(), key=lambda item: item.name)
    if not downloaded or len(downloaded) > 1000:
        raise LovelaceError(
            "resolved package closure count is implausible: "
            f"{len(downloaded)}; apk output: "
            f"{(fetch_result.stderr or fetch_result.stdout).strip()[:12000]}"
        )
    if any(
        re.fullmatch(r"[A-Za-z0-9+_.@~-]+\.apk", path.name) is None
        for path in downloaded
    ):
        raise LovelaceError("resolved package filename is unsafe")

    index_records: dict[
        tuple[str, str, str], list[tuple[str, dict[str, str]]]
    ] = {}
    locked_indexes: list[dict[str, Any]] = []
    for repository in seeds["repositories"]:
        current = work / f"index-after-{repository['name']}.tar.gz"
        safe_download_snapshot(
            f"{repository['url']}/{seeds['architecture']}/APKINDEX.tar.gz",
            current,
            maximum_size=MAX_INDEX_SIZE,
            user_agent=f"{BUILDER_VERSION}/1",
        )
        if digest_file(current) != first_indexes[repository["name"]][1]:
            raise LovelaceError(
                f"Alpine repository changed during resolution: {repository['name']}"
            )
        verify_apk_signature(apk, keys_dir, current, environment)
        records = parse_apk_index(current, repository["name"])
        for identity, fields in records.items():
            index_records.setdefault(identity, []).append(
                (repository["name"], fields)
            )
        signer = signed_index_payload(current)[1]
        cached_index = (
            paths["indexes"] / f"{repository['name']}-APKINDEX.tar.gz"
        )
        copy_regular_atomic(current, cached_index)
        vector = digest_vector(cached_index)
        locked_indexes.append(
            {
                "name": repository["name"],
                "url": repository["url"],
                "index_url": (
                    f"{repository['url']}/{seeds['architecture']}/"
                    "APKINDEX.tar.gz"
                ),
                "filename": cached_index.name,
                "size": cached_index.stat().st_size,
                **vector,
                "apk_signature_valid": True,
                "signer": signer,
                "record_count": len(records),
            }
        )

    locked_packages: list[dict[str, Any]] = []
    identities: dict[str, str] = {}
    for package in downloaded:
        ensure_regular(package, "resolved APK")
        verify_apk_signature(apk, keys_dir, package, environment)
        metadata = package_metadata(package)
        identity = (
            metadata["pkgname"],
            metadata["pkgver"],
            metadata["arch"],
        )
        matches = index_records.get(identity, [])
        if not matches and metadata["arch"] == "noarch":
            matches = index_records.get(
                (
                    metadata["pkgname"],
                    metadata["pkgver"],
                    seeds["architecture"],
                ),
                [],
            )
        if len(matches) != 1:
            raise LovelaceError(
                f"resolved APK identity is absent or ambiguous in locked indexes: {identity}"
            )
        repository_name, index_fields = matches[0]
        expected_filename = f"{metadata['pkgname']}-{metadata['pkgver']}.apk"
        if package.name != expected_filename:
            raise LovelaceError(
                f"resolved APK filename does not match identity: {package.name}"
            )
        if metadata["pkgname"] in identities:
            raise LovelaceError(
                f"multiple versions of package resolved: {metadata['pkgname']}"
            )
        identities[metadata["pkgname"]] = metadata["pkgver"]
        destination = paths["packages"] / package.name
        copy_regular_atomic(package, destination)
        vector = digest_vector(destination)
        record: dict[str, Any] = {
            "name": metadata["pkgname"],
            "version": metadata["pkgver"],
            "architecture": metadata["arch"],
            "filename": package.name,
            "repository": repository_name,
            "size": destination.stat().st_size,
            **vector,
            "installed_size": int(metadata["size"]),
            "origin": metadata["origin"],
            "license": metadata["license"],
            "signature_valid": True,
        }
        if "builddate" in metadata:
            record["builddate"] = int(metadata["builddate"])
        if index_fields.get("S") and int(index_fields["S"]) != record["size"]:
            raise LovelaceError(
                f"APK compressed size differs from index: {package.name}"
            )
        locked_packages.append(record)

    missing_seeds = sorted(set(seeds["packages"]) - set(identities))
    if missing_seeds:
        raise LovelaceError(f"requested packages were not resolved: {missing_seeds}")
    world = [
        f"{name}={identities[name]}" for name in sorted(seeds["packages"])
    ]
    return {
        "schema": "wucios.lovelace.package_lock.v1",
        "resolver": BUILDER_VERSION,
        "alpine_branch": seeds["alpine_branch"],
        "architecture": seeds["architecture"],
        "package_seeds_sha256": hashlib.sha256(
            canonical_json(seeds)
        ).hexdigest(),
        "repositories": sorted(locked_indexes, key=lambda item: item["name"]),
        "world": world,
        "package_count": len(locked_packages),
        "packages": sorted(locked_packages, key=lambda item: item["name"]),
        "policy": {
            "fetch_only_by_explicit_command": True,
            "offline_absolute_file_install": True,
            "package_scripts_during_build": False,
            "all_package_signatures_valid": True,
        },
        "resolver_stdout_tail": fetch_result.stdout[-2000:],
    }


def validate_package_lock(
    lock: dict[str, Any], seeds: dict[str, Any]
) -> None:
    require_exact_keys(
        lock,
        {
            "schema",
            "resolver",
            "alpine_branch",
            "architecture",
            "package_seeds_sha256",
            "repositories",
            "world",
            "package_count",
            "packages",
            "policy",
            "resolver_stdout_tail",
        },
        "Lovelace package lock",
    )
    require_exact_keys(
        lock["policy"],
        {
            "fetch_only_by_explicit_command",
            "offline_absolute_file_install",
            "package_scripts_during_build",
            "all_package_signatures_valid",
        },
        "Lovelace package-lock policy",
    )
    if (
        lock["schema"] != "wucios.lovelace.package_lock.v1"
        or lock["resolver"] != BUILDER_VERSION
        or lock["alpine_branch"] != "v3.24"
        or lock["architecture"] != "x86_64"
        or lock["package_seeds_sha256"]
        != hashlib.sha256(canonical_json(seeds)).hexdigest()
        or not isinstance(lock["repositories"], list)
        or not isinstance(lock["world"], list)
        or not isinstance(lock["packages"], list)
        or type(lock["package_count"]) is not int
        or lock["package_count"] != len(lock["packages"])
        or not 20 <= lock["package_count"] <= 1000
        or lock["policy"]
        != {
            "fetch_only_by_explicit_command": True,
            "offline_absolute_file_install": True,
            "package_scripts_during_build": False,
            "all_package_signatures_valid": True,
        }
        or not isinstance(lock["resolver_stdout_tail"], str)
        or len(lock["resolver_stdout_tail"]) > 2000
    ):
        raise LovelaceError("package lock identity or closure count is invalid")
    package_names: set[str] = set()
    filenames: set[str] = set()
    identities: dict[str, str] = {}
    for record in lock["packages"]:
        required = {
            "name",
            "version",
            "architecture",
            "filename",
            "repository",
            "size",
            "sha256",
            "sha512",
            "installed_size",
            "origin",
            "license",
            "signature_valid",
        }
        allowed = required | {"builddate"}
        if (
            not isinstance(record, dict)
            or not required <= set(record)
            or set(record) - allowed
        ):
            raise LovelaceError("package lock record is incomplete")
        if (
            not isinstance(record["name"], str)
            or not record["name"]
            or not isinstance(record["version"], str)
            or not record["version"]
            or not isinstance(record["filename"], str)
            or not isinstance(record["repository"], str)
            or record["repository"] not in {"main", "community"}
            or not isinstance(record["origin"], str)
            or not record["origin"]
            or not isinstance(record["license"], str)
            or not record["license"]
            or record["name"] in package_names
            or record["filename"] in filenames
            or record["architecture"] not in {"x86_64", "noarch"}
            or record["filename"]
            != f"{record['name']}-{record['version']}.apk"
            or not is_lower_hex(record["sha256"], 64)
            or not is_lower_hex(record["sha512"], 128)
            or record["signature_valid"] is not True
            or type(record["size"]) is not int
            or record["size"] <= 0
            or type(record["installed_size"]) is not int
            or record["installed_size"] < 0
            or (
                "builddate" in record
                and (
                    type(record["builddate"]) is not int
                    or record["builddate"] < 0
                )
            )
        ):
            raise LovelaceError("package lock record is invalid or duplicate")
        package_names.add(record["name"])
        filenames.add(record["filename"])
        identities[record["name"]] = record["version"]
    expected_world = [
        f"{name}={identities[name]}" for name in sorted(seeds["packages"])
    ]
    if lock["world"] != expected_world:
        raise LovelaceError("package lock world is not exact or sorted")
    if [item["name"] for item in lock["packages"]] != sorted(package_names):
        raise LovelaceError("package lock records are not sorted")
    repositories = lock["repositories"]
    if (
        [item.get("name") if isinstance(item, dict) else None for item in repositories]
        != ["community", "main"]
    ):
        raise LovelaceError("package lock repositories are not exact")
    seed_urls = {
        repository["name"]: repository["url"]
        for repository in seeds["repositories"]
    }
    repository_keys = {
        "name",
        "url",
        "index_url",
        "filename",
        "size",
        "sha256",
        "sha512",
        "apk_signature_valid",
        "signer",
        "record_count",
    }
    for record in repositories:
        require_exact_keys(record, repository_keys, "package-lock repository")
        name = record["name"]
        expected_url = seed_urls[name]
        if (
            record["url"] != expected_url
            or record["index_url"]
            != f"{expected_url}/x86_64/APKINDEX.tar.gz"
            or record["filename"] != f"{name}-APKINDEX.tar.gz"
            or type(record["size"]) is not int
            or record["size"] <= 0
            or not is_lower_hex(record["sha256"], 64)
            or not is_lower_hex(record["sha512"], 128)
            or record["apk_signature_valid"] is not True
            or not isinstance(record["signer"], str)
            or not record["signer"].endswith(".rsa.pub")
            or type(record["record_count"]) is not int
            or record["record_count"] <= 0
        ):
            raise LovelaceError(
                f"package-lock repository record is invalid: {name}"
            )


def fetch_inputs(cache: Path) -> dict[str, Any]:
    release, seeds, ghidra = configuration()
    alpine_lock = shared_alpine_lock(release)
    paths = cache_paths(cache)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    for record in boot_cache_records(alpine_lock):
        fetch_locked_file(record, paths["boot"])
    fetch_locked_file({**ghidra, "kind": "official Ghidra release"}, paths["ghidra"])
    with tempfile.TemporaryDirectory(
        prefix=".lovelace-fetch.", dir=DEFAULT_OUTPUT.parent
    ) as temporary:
        work = Path(temporary)
        _iso, _kernel, initramfs = verify_boot_media(
            release, alpine_lock, paths["boot"], work
        )
        bootstrap, keys = materialize_apk_bootstrap(
            alpine_lock, initramfs, work
        )
        lock = fetch_package_closure(
            seeds,
            cache,
            bootstrap,
            bootstrap / "etc/apk/keys",
            work,
        )
    validate_package_lock(lock, seeds)
    write_json(PACKAGE_LOCK_PATH, lock)
    return {
        "schema": "wucios.lovelace.fetch_result.v1",
        "status": "pass",
        "cache": str(cache),
        "package_lock": str(PACKAGE_LOCK_PATH.relative_to(REPO)),
        "package_count": lock["package_count"],
        "ghidra": {
            "filename": ghidra["filename"],
            "size": ghidra["size"],
            "sha256": ghidra["sha256"],
        },
        "network_boundary": "Only this explicit fetch command used the network.",
    }


def verify_inputs(
    cache: Path, work: Path
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    Path,
    Path,
    Path,
]:
    release, seeds, ghidra = configuration()
    if not PACKAGE_LOCK_PATH.is_file():
        raise LovelaceError(
            f"package lock is missing; run explicit fetch first: {PACKAGE_LOCK_PATH}"
        )
    lock = load_object(PACKAGE_LOCK_PATH)
    validate_package_lock(lock, seeds)
    alpine_lock = shared_alpine_lock(release)
    paths = cache_paths(cache)
    _iso, kernel, initramfs = verify_boot_media(
        release, alpine_lock, paths["boot"], work
    )
    bootstrap, _keys = materialize_apk_bootstrap(
        alpine_lock, initramfs, work
    )
    apk = apk_command(bootstrap)
    environment = apk_environment(work)
    keys_dir = bootstrap / "etc/apk/keys"

    repository_records: dict[str, dict[tuple[str, str, str], dict[str, str]]] = {}
    for record in lock["repositories"]:
        path = paths["indexes"] / record["filename"]
        verify_locked_file(path, record, f"{record['name']} APK index")
        verify_apk_signature(apk, keys_dir, path, environment)
        payload, signer = signed_index_payload(path)
        if (
            signer != record["signer"]
            or len(
                parse_apk_index(path, record["name"])
            )
            != record["record_count"]
            or not payload
        ):
            raise LovelaceError(
                f"locked APK index metadata drift: {record['name']}"
            )
        repository_records[record["name"]] = parse_apk_index(
            path, record["name"]
        )

    package_paths: list[Path] = []
    for record in lock["packages"]:
        path = paths["packages"] / record["filename"]
        verify_locked_file(path, record, f"locked APK {record['name']}")
        verify_apk_signature(apk, keys_dir, path, environment)
        metadata = package_metadata(path)
        identity = (
            metadata["pkgname"],
            metadata["pkgver"],
            metadata["arch"],
        )
        expected = (
            record["name"],
            record["version"],
            record["architecture"],
        )
        if identity != expected:
            raise LovelaceError(
                f"locked APK identity differs from metadata: {path.name}"
            )
        index_identity = identity
        if (
            index_identity
            not in repository_records[record["repository"]]
            and identity[2] == "noarch"
        ):
            index_identity = (identity[0], identity[1], "x86_64")
        if index_identity not in repository_records[record["repository"]]:
            raise LovelaceError(
                f"locked APK is not bound by its repository index: {path.name}"
            )
        package_paths.append(path)

    ghidra_path = paths["ghidra"] / ghidra["filename"]
    verify_locked_file(ghidra_path, ghidra, "official Ghidra release")
    return (
        release,
        seeds,
        ghidra,
        lock,
        kernel,
        initramfs,
        bootstrap,
    )


def snapshot_locked_regular(
    source: Path,
    destination: Path,
    *,
    size: int,
    sha256: str,
    label: str,
) -> None:
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
    ):
        raise LovelaceError(f"{label} snapshot contract is invalid")
    source_info = ensure_regular(source, label, size=size)
    source_fd = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination_fd: int | None = None
    try:
        opened = os.fstat(source_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != size
            or (opened.st_dev, opened.st_ino)
            != (source_info.st_dev, source_info.st_ino)
        ):
            raise LovelaceError(f"{label} changed while opening")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            copied += len(block)
            if copied > size:
                raise LovelaceError(f"{label} grew while snapshotting")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise LovelaceError(
                        f"short write while snapshotting {label}"
                    )
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        if (
            copied != size
            or digest.hexdigest() != sha256
            or (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
                opened.st_ctime_ns,
            )
        ):
            raise LovelaceError(
                f"{label} changed or failed its digest while snapshotting"
            )
    except BaseException:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)
    os.chmod(destination, 0o400)
    verify_locked_file(
        destination,
        {"size": size, "sha256": sha256},
        f"private {label} snapshot",
    )


def snapshot_build_inputs(
    cache: Path,
    package_lock: dict[str, Any],
    ghidra: dict[str, Any],
    work: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    snapshot_cache = work / "locked-input-snapshot"
    packages_destination = cache_paths(snapshot_cache)["packages"]
    packages_destination.mkdir(parents=True)
    source_paths = cache_paths(cache)
    package_bytes = 0
    for record in package_lock["packages"]:
        snapshot_locked_regular(
            source_paths["packages"] / record["filename"],
            packages_destination / record["filename"],
            size=record["size"],
            sha256=record["sha256"],
            label=f"locked APK {record['filename']}",
        )
        package_bytes += record["size"]
    ghidra_destination_root = cache_paths(snapshot_cache)["ghidra"]
    ghidra_destination_root.mkdir(parents=True)
    ghidra_destination = ghidra_destination_root / ghidra["filename"]
    snapshot_locked_regular(
        source_paths["ghidra"] / ghidra["filename"],
        ghidra_destination,
        size=ghidra["size"],
        sha256=ghidra["sha256"],
        label="locked Ghidra archive",
    )
    return (
        snapshot_cache,
        ghidra_destination,
        {
            "schema": "wucios.lovelace.input_snapshot.v1",
            "private_build_root": True,
            "network_used": False,
            "package_count": len(package_lock["packages"]),
            "package_bytes": package_bytes,
            "ghidra_bytes": ghidra["size"],
            "all_sizes_and_sha256_verified_while_copying": True,
        },
    )


def installed_apk_identities(path: Path) -> list[tuple[str, str, str]]:
    try:
        return noether_forge.installed_apk_identities(path)
    except (noether_forge.NoetherForgeError, OSError) as exc:
        raise LovelaceError("cannot parse installed APK database") from exc


def install_offline_root(
    root: Path,
    lock: dict[str, Any],
    cache: Path,
    bootstrap: Path,
    work: Path,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=False)
    empty_repositories = work / "empty-repositories"
    empty_repositories.write_bytes(b"")
    package_root = cache_paths(cache)["packages"]
    package_paths = [
        package_root / record["filename"] for record in lock["packages"]
    ]
    command = [
        *apk_command(bootstrap),
        "add",
        "--root",
        root,
        "--initdb",
        "--usermode",
        "--no-cache",
        "--no-logfile",
        "--no-network",
        "--force-non-repository",
        "--repositories-file",
        empty_repositories,
        "--arch",
        "x86_64",
        "--keys-dir",
        bootstrap / "etc/apk/keys",
        "--no-scripts",
        *package_paths,
        *lock["world"],
    ]
    result = run(
        command,
        env=apk_environment(work),
        timeout=3600,
    )
    installed = root / "lib/apk/db/installed"
    ensure_regular(
        installed, "Lovelace root filesystem APK database", single_link=False
    )
    expected = sorted(
        (
            record["name"],
            record["version"],
            record["architecture"],
        )
        for record in lock["packages"]
    )
    observed = installed_apk_identities(installed)
    if observed != expected:
        raise LovelaceError(
            "offline root filesystem package identities differ from exact lock"
        )
    apk_build_log = root / "var/log/apk.log"
    if apk_build_log.exists() or apk_build_log.is_symlink():
        raise LovelaceError(
            "APK created a transient build log despite --no-logfile"
        )
    return {
        "package_count": len(observed),
        "installed_identities_exact": True,
        "network_used": False,
        "package_scripts_executed": False,
        "apk_build_log_embedded": False,
        "stdout_tail": result.stdout[-2000:],
    }


def validated_relative_path(name: str, label: str) -> PurePosixPath:
    if (
        not name
        or "\0" in name
        or "\\" in name
        or name.startswith("/")
    ):
        raise LovelaceError(f"{label} path is unsafe: {name!r}")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise LovelaceError(f"{label} path is unsafe: {name!r}")
    return path


def overlay_file_mode(relative: PurePosixPath) -> int:
    return (
        0o755
        if relative.parts[:3]
        in {("usr", "local", "bin"), ("usr", "local", "sbin")}
        else 0o600
        if relative.as_posix() == "etc/shadow"
        else 0o644
    )


def overlay_source_manifest() -> dict[str, Any]:
    overlay = RELEASE_ROOT / "overlay"
    records: list[dict[str, Any]] = []
    for source in sorted(overlay.rglob("*"), key=lambda item: item.as_posix()):
        relative = PurePosixPath(source.relative_to(overlay).as_posix())
        info = source.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LovelaceError(
                f"tracked overlay supports regular files only: {source}"
            )
        records.append(
            {
                "path": relative.as_posix(),
                "mode": f"{overlay_file_mode(relative):04o}",
                "sha256": digest_file(source),
            }
        )
    return {"file_count": len(records), "files": records}


def copy_overlay(root: Path) -> list[dict[str, Any]]:
    overlay = RELEASE_ROOT / "overlay"
    records: list[dict[str, Any]] = []
    for source in sorted(overlay.rglob("*"), key=lambda item: item.as_posix()):
        relative = source.relative_to(overlay)
        destination = root / relative
        info = source.lstat()
        if stat.S_ISDIR(info.st_mode):
            destination.mkdir(parents=True, exist_ok=True)
            os.chmod(destination, 0o755)
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LovelaceError(
                f"tracked overlay supports regular files only: {source}"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        mode = overlay_file_mode(PurePosixPath(relative.as_posix()))
        os.chmod(destination, mode)
        records.append(
            {
                "path": relative.as_posix(),
                "mode": f"{mode:04o}",
                "sha256": digest_file(destination),
            }
        )
    expected = overlay_source_manifest()["files"]
    if records != expected:
        raise LovelaceError("copied overlay manifest differs from source inputs")
    return records


def runtime_source_path_selected(relative: str) -> bool:
    if relative in HOST_ONLY_RUNTIME_SOURCE_PATHS:
        return False
    return relative in RUNTIME_SOURCE_EXACT_PATHS or relative.startswith(
        RUNTIME_SOURCE_PREFIXES
    )


def validated_runtime_symlink_target(target: str, label: str) -> str:
    try:
        encoded = target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LovelaceError(
            f"tracked runtime symlink target is not ASCII: {label}"
        ) from exc
    if (
        not target
        or target.startswith("/")
        or target.endswith("/")
        or "//" in target
        or any(part in {"", ".", ".."} for part in target.split("/"))
        or re.fullmatch(r"[A-Za-z0-9._+@/-]+", target) is None
        or len(encoded) > MAX_EXT4_FAST_SYMLINK_TARGET_BYTES
    ):
        raise LovelaceError(
            f"malformed or non-fast tracked symlink rejected: {label}"
        )
    return target


def tracked_runtime_sources() -> list[Path]:
    result = run(
        [trusted_host_tool("git"), "ls-files", "-z"],
        cwd=REPO,
        env={
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
        },
    )
    selected: list[Path] = []
    for raw in result.stdout.split("\0"):
        if not raw:
            continue
        if runtime_source_path_selected(raw):
            selected.append(REPO / raw)
    return sorted(selected, key=lambda item: item.relative_to(REPO).as_posix())


def runtime_source_manifest() -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for source in tracked_runtime_sources():
        relative = source.relative_to(REPO)
        info = source.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = validated_runtime_symlink_target(
                os.readlink(source), relative.as_posix()
            )
            records.append(
                {
                    "path": relative.as_posix(),
                    "type": "symlink",
                    "target": target,
                }
            )
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise LovelaceError(
                    f"tracked runtime source hardlink rejected: {relative}"
                )
            mode = 0o755 if info.st_mode & 0o111 else 0o644
            records.append(
                {
                    "path": relative.as_posix(),
                    "type": "regular",
                    "mode": f"{mode:04o}",
                    "size": info.st_size,
                    "sha256": digest_file(source),
                }
            )
        elif source.is_dir():
            continue
        else:
            raise LovelaceError(
                f"unsupported tracked runtime source type: {relative}"
            )
    return {
        "file_count": len(records),
        "files": records,
        "scope": [
            "native Wuci-Ji source and Makefile",
            "tools",
            "NOXFRAME documentation",
        ],
    }


def copy_runtime_sources(root: Path) -> dict[str, Any]:
    destination_root = root / "opt/wuci-ji"
    destination_root.mkdir(parents=True)
    os.chmod(destination_root, 0o755)
    records: list[dict[str, Any]] = []
    for source in tracked_runtime_sources():
        relative = source.relative_to(REPO)
        destination = destination_root / relative
        info = source.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = validated_runtime_symlink_target(
                os.readlink(source), relative.as_posix()
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, destination)
            records.append(
                {
                    "path": relative.as_posix(),
                    "type": "symlink",
                    "target": target,
                }
            )
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise LovelaceError(
                    f"tracked runtime source hardlink rejected: {relative}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            mode = 0o755 if info.st_mode & 0o111 else 0o644
            os.chmod(destination, mode)
            records.append(
                {
                    "path": relative.as_posix(),
                    "type": "regular",
                    "mode": f"{mode:04o}",
                    "size": destination.stat().st_size,
                    "sha256": digest_file(destination),
                }
            )
        elif source.is_dir():
            # A tracked gitlink may be an uninitialized submodule directory.
            continue
        else:
            raise LovelaceError(
                f"unsupported tracked runtime source type: {relative}"
            )
    for candidate in sorted(
        destination_root.rglob("*"), key=lambda item: item.as_posix()
    ):
        if stat.S_ISDIR(candidate.lstat().st_mode):
            os.chmod(candidate, 0o755)
    launcher = root / "usr/local/bin/noxframe"
    info = ensure_regular(
        launcher,
        "Lovelace NOXFRAME launcher",
        single_link=False,
    )
    if info.st_mode & 0o111 == 0:
        raise LovelaceError("Lovelace NOXFRAME launcher is not executable")
    result = {
        "file_count": len(records),
        "files": records,
        "scope": [
            "native Wuci-Ji source and Makefile",
            "tools",
            "NOXFRAME documentation",
        ],
    }
    if result != runtime_source_manifest():
        raise LovelaceError(
            "copied runtime source manifest differs from current inputs"
        )
    return result


def native_asm_sources() -> list[Path]:
    makefile = REPO / "Makefile"
    ensure_regular(makefile, "Wuci-Ji Makefile", single_link=False)
    matches = re.findall(
        r"(?m)^ASM_SOURCES := ([^\r\n]+)$",
        makefile.read_text(encoding="utf-8"),
    )
    if len(matches) != 1:
        raise LovelaceError(
            "Makefile must define exactly one single-line ASM_SOURCES list"
        )
    names = matches[0].split()
    if not names or len(names) != len(set(names)):
        raise LovelaceError("Makefile ASM_SOURCES is empty or has duplicates")
    sources: list[Path] = []
    for name in names:
        if re.fullmatch(r"src/[A-Za-z0-9_.-]+\.s", name) is None:
            raise LovelaceError(
                f"unsafe Makefile ASM_SOURCES member rejected: {name!r}"
            )
        source = REPO / name
        ensure_regular(source, "native assembly source", single_link=False)
        sources.append(source)
    return sources


def native_source_records() -> list[dict[str, Any]]:
    return [
        {
            "path": source.relative_to(REPO).as_posix(),
            "sha256": digest_file(source),
        }
        for source in native_asm_sources()
    ]


def native_host_tool_records() -> dict[str, dict[str, Any]]:
    assembler = trusted_host_tool("as")
    linker = trusted_host_tool("ld")
    assembler_version = run([assembler, "--version"]).stdout.splitlines()[0]
    linker_version = run([linker, "--version"]).stdout.splitlines()[0]
    return {
        "assembler": host_tool_record(assembler, assembler_version),
        "linker": host_tool_record(linker, linker_version),
    }


def build_native_wuciji(root: Path, work: Path) -> dict[str, Any]:
    assembler = trusted_host_tool("as")
    linker = trusted_host_tool("ld")
    host_tools = native_host_tool_records()
    build_root = work / "native-wuci-ji"
    build_root.mkdir(mode=0o700)
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    sources = native_asm_sources()
    objects: list[Path] = []
    for source in sources:
        object_path = build_root / f"{source.stem}.o"
        run(
            [assembler, "--64", "-o", object_path, source],
            cwd=REPO,
            env=environment,
            timeout=120,
        )
        ensure_regular(
            object_path, "isolated native Wuci-Ji object", single_link=True
        )
        objects.append(object_path)
    source = build_root / "wuci-ji"
    run(
        [linker, "-o", source, *objects],
        cwd=REPO,
        env=environment,
        timeout=300,
    )
    info = ensure_regular(
        source, "isolated host-built Wuci-Ji binary", single_link=True
    )
    if info.st_mode & 0o111 == 0:
        raise LovelaceError("isolated host-built Wuci-Ji is not executable")
    destinations = [
        root / "opt/wuci-ji/build/wuci-ji",
        root / "usr/local/bin/wuci-ji",
    ]
    for destination in destinations:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination == root / "opt/wuci-ji/build/wuci-ji":
            os.chmod(destination.parent, 0o755)
        shutil.copyfile(source, destination)
        os.chmod(destination, 0o755)
    return {
        "path": "/usr/local/bin/wuci-ji",
        "size": source.stat().st_size,
        "sha256": digest_file(source),
        "source": "isolated direct GNU as/ld build from the working source tree",
        "sources": native_source_records(),
        "host_tools": host_tools,
    }


def safe_extract_ghidra(archive_path: Path, destination: Path) -> dict[str, Any]:
    ensure_regular(archive_path, "Ghidra archive")
    destination.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    expanded = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_GHIDRA_ENTRIES:
                raise LovelaceError(
                    "Ghidra archive entry count is empty or exceeds its ceiling"
                )
            for entry in entries:
                relative = validated_relative_path(
                    entry.filename.rstrip("/"), "Ghidra archive"
                )
                name = relative.as_posix()
                if name in seen:
                    raise LovelaceError(
                        f"duplicate Ghidra archive member: {name}"
                    )
                seen.add(name)
                if entry.flag_bits & 0x1:
                    raise LovelaceError(
                        f"encrypted Ghidra archive member rejected: {name}"
                    )
                mode = (entry.external_attr >> 16) & 0o177777
                file_type = stat.S_IFMT(mode)
                is_directory = entry.is_dir()
                if is_directory:
                    if entry.file_size != 0:
                        raise LovelaceError(
                            f"Ghidra directory carries data: {name}"
                        )
                elif file_type not in {0, stat.S_IFREG}:
                    raise LovelaceError(
                        f"non-regular Ghidra archive member rejected: {name}"
                    )
                if (
                    entry.file_size > MAX_GHIDRA_ENTRY_SIZE
                    or expanded + entry.file_size > MAX_GHIDRA_EXPANDED_SIZE
                ):
                    raise LovelaceError(
                        "Ghidra archive exceeds expanded-size limits"
                    )
                expanded += entry.file_size
                target = destination.joinpath(*relative.parts)
                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    os.chmod(target, 0o755)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry, "r") as source, target.open(
                    "xb"
                ) as output:
                    copied = 0
                    while block := source.read(1024 * 1024):
                        copied += len(block)
                        if copied > entry.file_size:
                            raise LovelaceError(
                                f"Ghidra member exceeds declared size: {name}"
                            )
                        output.write(block)
                if copied != entry.file_size:
                    raise LovelaceError(
                        f"Ghidra member is truncated: {name}"
                    )
                executable = bool(mode & 0o111)
                os.chmod(target, 0o755 if executable else 0o644)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, LovelaceError):
            raise
        raise LovelaceError("Ghidra archive extraction failed") from exc
    top_levels = {PurePosixPath(name).parts[0] for name in seen}
    if len(top_levels) != 1:
        raise LovelaceError("Ghidra archive requires exactly one top-level root")
    top = destination / next(iter(top_levels))
    os.chmod(destination, 0o755)
    for candidate in sorted(
        destination.rglob("*"), key=lambda item: item.as_posix()
    ):
        if stat.S_ISDIR(candidate.lstat().st_mode):
            os.chmod(candidate, 0o755)
    entry_point = top / "support/analyzeHeadless"
    ensure_regular(entry_point, "Ghidra analyzeHeadless", single_link=False)
    os.chmod(entry_point, 0o755)
    return {
        "entry_count": len(seen),
        "expanded_size": expanded,
        "top_level": top.name,
    }


def install_ghidra(
    root: Path, archive: Path, ghidra_lock: dict[str, Any], work: Path
) -> dict[str, Any]:
    staging = work / "ghidra-expanded"
    result = safe_extract_ghidra(archive, staging)
    source = staging / result["top_level"]
    destination = root / "opt/wucios/ghidra"
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(root / "opt", 0o755)
    os.chmod(destination.parent, 0o755)
    if destination.exists() or destination.is_symlink():
        raise LovelaceError("Ghidra destination collision")
    os.replace(source, destination)
    ensure_regular(
        destination / ghidra_lock["entry_point"],
        "installed Ghidra headless entry point",
        single_link=False,
    )
    return {
        "name": ghidra_lock["name"],
        "version": ghidra_lock["version"],
        "archive_sha256": ghidra_lock["sha256"],
        "install_path": ghidra_lock["install_path"],
        "entry_point": ghidra_lock["entry_point"],
        "expanded_size": result["expanded_size"],
        "entry_count": result["entry_count"],
        "published_detached_signature": False,
        "runtime_validation": "pending guest boot test",
    }


def install_java_link(root: Path) -> str:
    jvm_root = root / "usr/lib/jvm"
    candidates = sorted(
        path
        for path in jvm_root.iterdir()
        if path.is_dir() and (path / "bin/java").is_file()
    )
    candidates = [
        path
        for path in candidates
        if "21" in path.name
    ]
    if len(candidates) != 1:
        raise LovelaceError(
            f"exactly one OpenJDK 21 home required, found {[item.name for item in candidates]}"
        )
    expected = root / EXPECTED_JAVA_HOME.removeprefix("/")
    if candidates[0] != expected:
        raise LovelaceError(
            "OpenJDK 21 home differs from the pinned guest path: "
            f"{candidates[0].relative_to(root)}"
        )
    link = jvm_root / "default-jvm"
    if link.exists() or link.is_symlink():
        if link.is_symlink():
            link.unlink()
        else:
            raise LovelaceError("default JVM path is not a symlink")
    os.symlink(candidates[0].name, link)
    return EXPECTED_JAVA_HOME


def install_busybox_runtime_links(root: Path) -> list[str]:
    busybox = root / "bin/busybox"
    ensure_regular(busybox, "installed BusyBox", single_link=False)
    final: list[str] = []
    for guest_path, target in BUSYBOX_RUNTIME_LINKS:
        name = guest_path.removeprefix("/")
        path = root / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() and os.readlink(path) == target:
                final.append(guest_path)
                continue
            raise LovelaceError(
                f"required BusyBox runtime link collides: /{name}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
        final.append(guest_path)
    return final


def build_ghidra_fixture(root: Path, work: Path) -> dict[str, Any]:
    source = REPO / "wucios/fixtures/lovelace/ghidra-smoke.s"
    ensure_regular(source, "Ghidra smoke source")
    assembler = trusted_host_tool("as")
    linker = trusted_host_tool("ld")
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    fixture_work = work / "ghidra-fixture"
    fixture_work.mkdir()
    object_path = fixture_work / "ghidra-smoke.o"
    binary = fixture_work / "ghidra-smoke"
    run(
        [assembler, "--64", "-o", object_path, source],
        cwd=REPO,
        env=environment,
    )
    run(
        [
            linker,
            "-m",
            "elf_x86_64",
            "-nostdlib",
            "--build-id=none",
            "-o",
            binary,
            object_path,
        ],
        cwd=REPO,
        env=environment,
    )
    destination_root = root / "usr/share/wucios/fixtures/ghidra"
    destination_root.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination_root / source.name)
    shutil.copyfile(binary, destination_root / "ghidra-smoke")
    os.chmod(destination_root / source.name, 0o644)
    os.chmod(destination_root / "ghidra-smoke", 0o755)
    semantic_script = (
        destination_root
        / "scripts"
        / GHIDRA_SEMANTIC_SCRIPT_NAME
    )
    ensure_regular(
        semantic_script, "Ghidra semantic acceptance script"
    )
    binary_bytes = binary.read_bytes()
    binary_md5 = hashlib.md5(
        binary_bytes, usedforsecurity=False
    ).hexdigest()
    binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
    if (
        binary_md5 != GHIDRA_FIXTURE_MD5
        or binary_sha256 != GHIDRA_FIXTURE_SHA256
    ):
        raise LovelaceError("Ghidra fixture binary identity differs")
    return {
        "source": f"/usr/share/wucios/fixtures/ghidra/{source.name}",
        "source_size": source.stat().st_size,
        "source_sha256": digest_file(source),
        "binary": "/usr/share/wucios/fixtures/ghidra/ghidra-smoke",
        "binary_size": binary.stat().st_size,
        "binary_sha256": binary_sha256,
        "binary_md5_identity": binary_md5,
        "semantic_script": (
            f"{GHIDRA_SEMANTIC_SCRIPT_PATH}/"
            f"{GHIDRA_SEMANTIC_SCRIPT_NAME}"
        ),
        "semantic_script_sha256": digest_file(semantic_script),
        "semantic_marker": GHIDRA_SEMANTIC_MARKER,
    }


def runtime_marker() -> dict[str, Any]:
    return {
        "schema": "wucios.lovelace.runtime.v1",
        "profile": "lovelace-laboratory",
        "authoritative_for_release": False,
        "default_profile": False,
        "noxframe_guest_broker": True,
    }


def embed_contracts(
    root: Path,
    release: dict[str, Any],
    package_lock: dict[str, Any],
    ghidra_lock: dict[str, Any],
) -> None:
    values = {
        "release.json": release,
        "profile.json": load_object(PROFILE_PATH),
        "package-lock.json": package_lock,
        "ghidra-lock.json": ghidra_lock,
        "lovelace-runtime.json": runtime_marker(),
    }
    share = root / "usr/share/wucios"
    share.mkdir(parents=True, exist_ok=True)
    for name, value in values.items():
        path = share / name
        path.write_bytes(canonical_json(value))
        os.chmod(path, 0o644)


def normalize_root_tree(root: Path, epoch: int) -> dict[str, int]:
    counts = {
        "regular": 0,
        "directory": 0,
        "symlink": 0,
        "owner_read_added": 0,
    }
    for directory, names, files in os.walk(root, topdown=False):
        current = Path(directory)
        for name in sorted(files):
            path = current / name
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                counts["regular"] += 1
                if not info.st_mode & stat.S_IRUSR:
                    os.chmod(path, stat.S_IMODE(info.st_mode) | stat.S_IRUSR)
                    counts["owner_read_added"] += 1
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            elif stat.S_ISLNK(info.st_mode):
                counts["symlink"] += 1
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            else:
                raise LovelaceError(
                    f"unsupported special file in root tree: {path}"
                )
        for name in sorted(names):
            path = current / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                counts["directory"] += 1
                required = stat.S_IRUSR | stat.S_IXUSR
                if stat.S_IMODE(info.st_mode) & required != required:
                    os.chmod(path, stat.S_IMODE(info.st_mode) | required)
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            elif stat.S_ISLNK(info.st_mode):
                counts["symlink"] += 1
                os.utime(path, (epoch, epoch), follow_symlinks=False)
            else:
                raise LovelaceError(
                    f"unsupported root tree entry: {path}"
                )
        os.utime(current, (epoch, epoch), follow_symlinks=False)
    counts["directory"] += 1
    return counts


def harden_privileged_files(root: Path) -> dict[str, Any]:
    removed: list[str] = []
    for directory, names, files in os.walk(root):
        current = Path(directory)
        for name in [*sorted(names), *sorted(files)]:
            path = current / name
            info = path.lstat()
            if not (
                stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
            ):
                continue
            privileged = info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            if privileged:
                os.chmod(
                    path,
                    stat.S_IMODE(info.st_mode)
                    & ~(stat.S_ISUID | stat.S_ISGID),
                )
                removed.append("/" + path.relative_to(root).as_posix())
    doas = root / "usr/bin/doas"
    ensure_regular(doas, "installed doas", single_link=False)
    os.chmod(doas, 0o4755)
    final_setid: list[dict[str, str]] = []
    for directory, names, files in os.walk(root):
        current = Path(directory)
        for name in [*sorted(names), *sorted(files)]:
            path = current / name
            info = path.lstat()
            if (
                (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                and info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            ):
                final_setid.append(
                    {
                        "path": "/" + path.relative_to(root).as_posix(),
                        "mode": f"{stat.S_IMODE(info.st_mode):05o}",
                    }
                )
    final_setid.sort(key=lambda item: item["path"])
    expected_final = [{"path": DOAS_PATH, "mode": DOAS_MODE}]
    if final_setid != expected_final:
        raise LovelaceError(
            f"final set-ID inventory differs: {final_setid}"
        )
    return {
        "suid_sgid_removed": sorted(removed),
        "single_justified_suid": DOAS_PATH,
        "final_setid_inventory": final_setid,
        "justification": DOAS_JUSTIFICATION,
    }


def validate_root_tree_paths(root: Path) -> int:
    count = 0
    for directory, names, files in os.walk(root):
        names.sort()
        files.sort()
        for name in [*names, *files]:
            count += 1
            if count > MAX_ROOT_TREE_ENTRIES:
                raise LovelaceError(
                    "root tree exceeds the deterministic-entry ceiling"
                )
            if (
                not name
                or name in {".", ".."}
                or "\\" in name
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in name
                )
            ):
                raise LovelaceError(
                    f"root tree contains an unsafe filename: {name!r}"
                )
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if len(relative.encode("utf-8")) > 4096:
                raise LovelaceError(
                    f"root tree path exceeds 4096 UTF-8 bytes: {relative!r}"
                )
    return count


def reject_transient_build_path_leaks(
    root: Path, work: Path
) -> dict[str, Any]:
    require_real_directory(root, "staged root for transient-path scan")
    root_before = root.lstat()
    require_real_directory(work, "transient private build root")
    work_info = work.lstat()
    try:
        canonical_work = work.resolve(strict=True)
    except OSError as exc:
        raise LovelaceError(
            "transient private build root cannot be resolved"
        ) from exc
    needle = os.fsencode(os.fspath(work))
    if (
        not work.is_absolute()
        or canonical_work != work
        or work_info.st_uid != os.geteuid()
        or stat.S_IMODE(work_info.st_mode) & 0o077
        or len(needle) < 8
        or b"\0" in needle
        or len(needle) > 4096
    ):
        raise LovelaceError("transient build path scan contract is invalid")
    files_scanned = 0
    directories_scanned = 0
    symlinks_scanned = 0
    xattrs_scanned = 0
    bytes_scanned = 0

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def scan_payload(
        payload: bytes, relative: str, payload_kind: str
    ) -> None:
        nonlocal bytes_scanned
        bytes_scanned += len(payload)
        if bytes_scanned > MAX_TRANSIENT_PATH_SCAN_BYTES:
            raise LovelaceError(
                "staged root exceeds the transient-path scan byte ceiling"
            )
        if needle in payload:
            raise LovelaceError(
                "staged root embeds its transient build path in "
                f"{payload_kind}: {relative}"
            )

    def scan_xattrs(
        path: Path,
        relative: str,
        expected_identity: tuple[int, ...],
    ) -> None:
        nonlocal xattrs_scanned
        if identity(path.lstat()) != expected_identity:
            raise LovelaceError(
                f"staged entry changed before xattr scan: {relative}"
            )
        try:
            names = sorted(os.listxattr(path, follow_symlinks=False))
        except OSError as exc:
            raise LovelaceError(
                f"cannot list staged xattrs without following links: {relative}"
            ) from exc
        for name in names:
            scan_payload(
                os.fsencode(name), relative, "xattr name"
            )
            try:
                value = os.getxattr(path, name, follow_symlinks=False)
            except OSError as exc:
                raise LovelaceError(
                    f"cannot read staged xattr without following links: "
                    f"{relative}:{name}"
                ) from exc
            xattrs_scanned += 1
            scan_payload(value, relative, f"xattr {name!r}")
        if identity(path.lstat()) != expected_identity:
            raise LovelaceError(
                f"staged entry changed during xattr scan: {relative}"
            )

    def scan_symlink(path: Path, relative: str) -> None:
        nonlocal symlinks_scanned
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode):
            raise LovelaceError(
                f"staged symlink changed before transient-path scan: {relative}"
            )
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise LovelaceError(
                f"cannot read staged symlink payload: {relative}"
            ) from exc
        scan_payload(os.fsencode(target), relative, "symlink target")
        scan_xattrs(path, relative, identity(before))
        after = path.lstat()
        if identity(after) != identity(before):
            raise LovelaceError(
                f"staged symlink changed during transient-path scan: {relative}"
            )
        symlinks_scanned += 1

    for directory, names, files in os.walk(root):
        names.sort()
        files.sort()
        current = Path(directory)
        current_before = current.lstat()
        if not stat.S_ISDIR(current_before.st_mode):
            raise LovelaceError(
                f"staged directory changed during transient-path scan: {current}"
            )
        current_relative = (
            "." if current == root else current.relative_to(root).as_posix()
        )
        scan_xattrs(
            current, current_relative, identity(current_before)
        )
        directories_scanned += 1
        for name in files:
            path = current / name
            before = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(before.st_mode):
                scan_symlink(path, relative)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise LovelaceError(
                    f"unsupported staged file type during transient-path scan: "
                    f"{relative}"
                )
            files_scanned += 1
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or identity(opened) != identity(before)
                ):
                    raise LovelaceError(
                        f"staged file changed while opening: {path}"
                    )
                overlap = b""
                file_bytes = 0
                while block := os.read(descriptor, 1024 * 1024):
                    candidate = overlap + block
                    if needle in candidate:
                        raise LovelaceError(
                            "staged root embeds its transient build path: "
                            f"{relative}"
                        )
                    file_bytes += len(block)
                    bytes_scanned += len(block)
                    if bytes_scanned > MAX_TRANSIENT_PATH_SCAN_BYTES:
                        raise LovelaceError(
                            "staged root exceeds the transient-path scan "
                            "byte ceiling"
                        )
                    overlap = candidate[-(len(needle) - 1) :]
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            scan_xattrs(path, relative, identity(opened))
            final = path.lstat()
            if (
                file_bytes != opened.st_size
                or identity(after) != identity(opened)
                or identity(final) != identity(opened)
            ):
                raise LovelaceError(
                    f"staged file changed during transient-path scan: {path}"
                )
        for name in names:
            path = current / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                scan_symlink(path, path.relative_to(root).as_posix())
            elif not stat.S_ISDIR(info.st_mode):
                raise LovelaceError(
                    "unsupported staged directory entry during "
                    f"transient-path scan: {path.relative_to(root).as_posix()}"
                )
        current_after = current.lstat()
        if identity(current_after) != identity(current_before):
            raise LovelaceError(
                f"staged directory changed during transient-path scan: "
                f"{current_relative}"
            )
    root_after = root.lstat()
    if identity(root_after) != identity(root_before):
        raise LovelaceError(
            "staged root changed during transient-path scan"
        )
    return {
        "schema": "wucios.lovelace.transient_path_scan.v2",
        "status": "pass",
        "coverage": [
            "regular-file-bytes",
            "symlink-target-bytes",
            "xattr-name-bytes",
            "xattr-value-bytes",
        ],
        "regular_files_scanned": files_scanned,
        "directories_scanned": directories_scanned,
        "symlinks_scanned": symlinks_scanned,
        "xattrs_scanned": xattrs_scanned,
        "bytes_scanned": bytes_scanned,
        "exact_plain_work_path_bytes_found": False,
    }


def require_clean_debugfs_stderr(
    result: subprocess.CompletedProcess[str], label: str
) -> None:
    if (
        result.returncode != 0
        or re.fullmatch(
            rf"debugfs {re.escape(EXPECTED_E2FSPROGS_VERSION)} "
            r"\([^()\r\n]{1,80}\)\n?",
            result.stderr,
        )
        is None
    ):
        detail = result.stderr.strip()[-1000:]
        raise LovelaceError(
            f"{label} emitted an error or unexpected diagnostic: {detail}"
        )


def ext4_path_inventory(
    image: Path | PinnedExt4Image, debugfs: Path
) -> list[dict[str, Any]]:
    with ext4_image_handle(image) as pinned:
        return _ext4_path_inventory_pinned(
            pinned.child_path,
            debugfs,
            pass_fds=pinned.pass_fds,
            scratch_directory=pinned.path.parent,
        )


def _ext4_path_inventory_pinned(
    image: str,
    debugfs: Path,
    *,
    pass_fds: Sequence[int],
    scratch_directory: Path,
) -> list[dict[str, Any]]:
    pending: list[tuple[int, PurePosixPath, int]] = [
        (2, PurePosixPath("/"), 2)
    ]
    visited_directories: set[int] = set()
    directory_paths: dict[int, PurePosixPath] = {2: PurePosixPath("/")}
    records: dict[str, dict[str, Any]] = {}
    total_output_bytes = 0
    inode_zero_entries = 0
    inventory_deadline = time.monotonic() + MAX_DEBUGFS_INVENTORY_SECONDS
    while pending:
        remaining = inventory_deadline - time.monotonic()
        if remaining <= 0:
            raise LovelaceError("ext4 path inventory exceeded its time budget")
        batch_timeout = min(600, max(1, int(remaining)))
        batch_directories: list[tuple[int, PurePosixPath, int]] = []
        while pending and len(batch_directories) < 1024:
            directory_inode, directory_path, parent_inode = pending.pop()
            if directory_inode in visited_directories:
                raise LovelaceError(
                    "ext4 path inventory encountered a directory alias"
                )
            visited_directories.add(directory_inode)
            batch_directories.append(
                (directory_inode, directory_path, parent_inode)
            )
        if not batch_directories:
            continue
        batch_fd, batch_name = tempfile.mkstemp(
            prefix="debugfs-inventory.", dir=scratch_directory
        )
        batch = Path(batch_name)
        try:
            batch.unlink()
            with os.fdopen(
                os.dup(batch_fd), "w", encoding="ascii", newline="\n"
            ) as stream:
                for (
                    directory_inode,
                    _directory_path,
                    _parent_inode,
                ) in batch_directories:
                    stream.write(f"ls -p -l <{directory_inode}>\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.lseek(batch_fd, 0, os.SEEK_SET)
            listing = run_bounded(
                [
                    debugfs,
                    "-f",
                    f"/proc/self/fd/{batch_fd}",
                    image,
                ],
                timeout=batch_timeout,
                pass_fds=(*pass_fds, batch_fd),
                max_stdout_bytes=MAX_DEBUGFS_INVENTORY_STDOUT_BYTES,
                max_stderr_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
            )
        finally:
            os.close(batch_fd)
            try:
                batch.unlink()
            except FileNotFoundError:
                pass
        total_output_bytes += len(listing.stdout.encode("utf-8"))
        total_output_bytes += len(listing.stderr.encode("utf-8"))
        if total_output_bytes > MAX_DEBUGFS_INVENTORY_TOTAL_OUTPUT_BYTES:
            raise LovelaceError(
                "ext4 path inventory exceeds its aggregate output ceiling"
            )
        if time.monotonic() > inventory_deadline:
            raise LovelaceError("ext4 path inventory exceeded its time budget")
        require_clean_debugfs_stderr(listing, "debugfs inode inventory")
        expected_commands = [
            f"debugfs: ls -p -l <{directory_inode}>"
            for directory_inode, _directory_path, _parent_inode in batch_directories
        ]
        observed_commands: list[str] = []
        observed_dot_entries: set[int] = set()
        observed_dotdot_entries: set[int] = set()
        current_directory: tuple[int, PurePosixPath, int] | None = None
        for line in listing.stdout.splitlines():
            if time.monotonic() > inventory_deadline:
                raise LovelaceError(
                    "ext4 path inventory exceeded its time budget"
                )
            if not line:
                continue
            if line.startswith("debugfs: "):
                observed_commands.append(line)
                command_index = len(observed_commands) - 1
                if (
                    command_index >= len(expected_commands)
                    or line != expected_commands[command_index]
                ):
                    raise LovelaceError(
                        "debugfs path inventory command order differs"
                    )
                current_directory = batch_directories[command_index]
                continue
            if current_directory is None or not line.startswith("/"):
                raise LovelaceError(
                    "debugfs path inventory returned unexpected output"
                )
            fields = line.split("/", 7)
            if (
                len(fields) != 8
                or not fields[1].isdigit()
                or re.fullmatch(r"[0-7]{6}", fields[2]) is None
                or not fields[3].isdigit()
                or not fields[4].isdigit()
                or fields[7] != ""
            ):
                raise LovelaceError(
                    "debugfs returned a malformed directory entry"
                )
            inode = int(fields[1])
            mode = int(fields[2], 8)
            uid = int(fields[3])
            gid = int(fields[4])
            name = fields[5]
            if inode == 0:
                if fields[2:] == ["000000", "0", "0", "", "0", ""]:
                    inode_zero_entries += 1
                    if (
                        inode_zero_entries
                        > MAX_DEBUGFS_INVENTORY_INODE_ZERO_ENTRIES
                    ):
                        raise LovelaceError(
                            "ext4 path inventory exceeds its inode-zero "
                            "entry ceiling"
                        )
                    continue
                raise LovelaceError(
                    "debugfs path inventory returned a nonempty inode-zero "
                    f"entry: {line!r}"
                )
            directory_inode, directory_path, parent_inode = current_directory
            if (
                name == "."
                and stat.S_ISDIR(mode)
                and inode == directory_inode
            ):
                if directory_inode in observed_dot_entries:
                    raise LovelaceError(
                        "debugfs path inventory returned duplicate dot entry"
                    )
                observed_dot_entries.add(inode)
                if directory_path == PurePosixPath("/"):
                    records["/"] = {
                        "path": "/",
                        "inode": inode,
                        "mode": f"{mode:06o}",
                        "type": "directory",
                        "uid": uid,
                        "gid": gid,
                        "size": None,
                    }
                continue
            if name == "..":
                if (
                    not stat.S_ISDIR(mode)
                    or inode != parent_inode
                    or directory_inode in observed_dotdot_entries
                ):
                    raise LovelaceError(
                        "debugfs path inventory returned invalid dotdot entry"
                    )
                observed_dotdot_entries.add(directory_inode)
                continue
            if (
                not name
                or "/" in name
                or "\\" in name
                or len(name.encode("utf-8")) > 255
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in name
                )
            ):
                raise LovelaceError(
                    f"unsafe ext4 inventory name rejected: {name!r}"
                )
            entry_path = directory_path / name
            path_text = entry_path.as_posix()
            if len(path_text.encode("utf-8")) > 4096:
                raise LovelaceError(
                    "ext4 inventory path exceeds 4096 UTF-8 bytes"
                )
            file_type = (
                "directory"
                if stat.S_ISDIR(mode)
                else "regular"
                if stat.S_ISREG(mode)
                else "symlink"
                if stat.S_ISLNK(mode)
                else "unsupported"
            )
            if file_type == "unsupported":
                raise LovelaceError(
                    f"unsupported ext4 entry type: {path_text}"
                )
            size_text = fields[6]
            if file_type == "directory":
                if size_text != "":
                    raise LovelaceError(
                        "debugfs returned a directory size unexpectedly: "
                        f"{path_text}"
                    )
                size: int | None = None
            else:
                if not size_text.isdigit():
                    raise LovelaceError(
                        "debugfs returned a malformed entry size: "
                        f"{path_text}"
                    )
                size = int(size_text)
            record = {
                "path": path_text,
                "inode": inode,
                "mode": f"{mode:06o}",
                "type": file_type,
                "uid": uid,
                "gid": gid,
                "size": size,
            }
            if path_text in records:
                raise LovelaceError(
                    f"duplicate ext4 path inventory entry: {path_text}"
                )
            records[path_text] = record
            if stat.S_ISDIR(mode):
                previous_directory = directory_paths.get(inode)
                if previous_directory is not None:
                    raise LovelaceError(
                        "ext4 path inventory encountered a directory alias: "
                        f"{previous_directory} and {entry_path}"
                    )
                directory_paths[inode] = entry_path
                pending.append((inode, entry_path, directory_inode))
            # The serialized filesystem contains the staged entries plus the
            # root inode and the one canonical /lost+found directory created
            # by mke2fs.  The verifier below accounts for both structural
            # paths explicitly before comparing the staged-tree ceiling.
            if len(records) > MAX_ROOT_TREE_ENTRIES + 2:
                raise LovelaceError(
                    "ext4 path inventory exceeds its entry ceiling"
                )
        if (
            observed_commands != expected_commands
            or observed_dot_entries
            != {
                inode
                for inode, _path, _parent_inode in batch_directories
            }
            or observed_dotdot_entries
            != {
                inode
                for inode, _path, _parent_inode in batch_directories
            }
        ):
            raise LovelaceError(
                "debugfs path inventory command coverage differs"
            )
    validate_ext4_root_inventory_record(records.get("/"))
    return [records[path] for path in sorted(records)]


def ext4_inode_inventory(
    image: Path | PinnedExt4Image, debugfs: Path
) -> list[int]:
    return sorted(
        {record["inode"] for record in ext4_path_inventory(image, debugfs)}
    )


def validate_ext4_root_inventory_record(root: Any) -> None:
    if (
        not isinstance(root, dict)
        or root.get("path") != "/"
        or root.get("inode") != 2
        or root.get("type") != "directory"
        or root.get("mode") != "040755"
        or root.get("uid") != 0
        or root.get("gid") != 0
        or root.get("size") is not None
    ):
        raise LovelaceError(
            "ext4 path inventory root inode metadata differs"
        )


def ext4_inventory_by_path(
    inventory: Sequence[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in inventory:
        require_exact_keys(
            record,
            {"path", "inode", "mode", "type", "uid", "gid", "size"},
            "ext4 path inventory record",
        )
        path = record["path"]
        mode = record["mode"]
        entry_type = record["type"]
        parsed_mode = (
            int(mode, 8)
            if isinstance(mode, str)
            and re.fullmatch(r"[0-7]{6}", mode) is not None
            else None
        )
        mode_type = (
            "directory"
            if parsed_mode is not None and stat.S_ISDIR(parsed_mode)
            else "regular"
            if parsed_mode is not None and stat.S_ISREG(parsed_mode)
            else "symlink"
            if parsed_mode is not None and stat.S_ISLNK(parsed_mode)
            else None
        )
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path in result
            or type(record["inode"]) is not int
            or record["inode"] <= 0
            or not isinstance(mode, str)
            or re.fullmatch(r"[0-7]{6}", mode) is None
            or not isinstance(entry_type, str)
            or entry_type not in {"directory", "regular", "symlink"}
            or mode_type != entry_type
            or type(record["uid"]) is not int
            or record["uid"] < 0
            or type(record["gid"]) is not int
            or record["gid"] < 0
            or (
                entry_type == "directory"
                and record["size"] is not None
            )
            or (
                entry_type != "directory"
                and (
                    type(record["size"]) is not int
                    or record["size"] < 0
                )
            )
        ):
            raise LovelaceError("ext4 path inventory record is invalid")
        result[path] = dict(record)
    return result


def validate_final_setid_inventory(
    inventory: Sequence[dict[str, Any]],
) -> list[dict[str, str]]:
    by_path = ext4_inventory_by_path(inventory)
    observed: list[dict[str, str]] = []
    for record in by_path.values():
        mode = int(record["mode"], 8)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            observed.append(
                {
                    "path": record["path"],
                    "mode": f"{stat.S_IMODE(mode):05o}",
                }
            )
    observed.sort(key=lambda item: item["path"])
    expected = [{"path": DOAS_PATH, "mode": DOAS_MODE}]
    if observed != expected:
        raise LovelaceError(
            f"final ext4 set-ID inventory differs: {observed}"
        )
    doas = by_path.get(DOAS_PATH)
    if (
        doas is None
        or doas["type"] != "regular"
        or doas["uid"] != 0
        or doas["gid"] != 0
    ):
        raise LovelaceError(
            "final ext4 doas entry is not a root-owned regular file"
        )
    return observed


def require_simple_guest_path(path: str, label: str) -> PurePosixPath:
    if (
        re.fullmatch(r"/[A-Za-z0-9._+@/-]+", path) is None
        or "//" in path
    ):
        raise LovelaceError(f"{label} path is unsafe: {path!r}")
    relative = validated_relative_path(path.removeprefix("/"), label)
    return PurePosixPath("/") / relative


def remaining_embedded_debugfs_timeout(
    deadline: float | int | None,
    command_timeout: int,
) -> int:
    """Return a conservative per-command timeout within one shared deadline."""
    if deadline is None:
        return command_timeout
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (float, int))
        or type(command_timeout) is not int
        or command_timeout <= 0
    ):
        raise LovelaceError(
            "exact embedded ext4 verification deadline is invalid"
        )
    remaining = deadline - time.monotonic()
    # run_bounded intentionally accepts integer seconds only. Refuse to begin
    # a new command inside the final partial second rather than extend the
    # aggregate deadline by rounding up.
    if not remaining >= 1:
        raise LovelaceError(
            "exact embedded ext4 verification exceeded its aggregate "
            "time budget"
        )
    return min(command_timeout, int(remaining))


def require_embedded_debugfs_deadline(deadline: float | int) -> None:
    if not time.monotonic() < deadline:
        raise LovelaceError(
            "exact embedded ext4 verification exceeded its aggregate "
            "time budget"
        )


def read_ext4_symlink_target(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    record: dict[str, Any],
    *,
    label: str,
    deadline: float | int | None = None,
) -> str:
    """Read one bounded, ASCII ext4 fast-symlink target by pinned inode."""
    mode = record.get("mode")
    if (
        record.get("type") != "symlink"
        or type(record.get("inode")) is not int
        or record["inode"] <= 0
        or type(record.get("size")) is not int
        or not 0 < record["size"] <= MAX_EXT4_FAST_SYMLINK_TARGET_BYTES
        or record.get("uid") != 0
        or record.get("gid") != 0
        or not isinstance(mode, str)
        or re.fullmatch(r"[0-7]{6}", mode) is None
        or stat.S_IMODE(int(mode, 8)) != 0o777
    ):
        raise LovelaceError(f"{label} is not a safe root-owned ext4 symlink")
    command_timeout = remaining_embedded_debugfs_timeout(deadline, 120)
    with ext4_image_handle(image) as pinned:
        result = run_bounded(
            [
                debugfs,
                "-R",
                f"stat <{record['inode']}>",
                pinned.child_path,
            ],
            timeout=command_timeout,
            check=False,
            pass_fds=pinned.pass_fds,
            max_stdout_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
            max_stderr_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
        )
    require_clean_debugfs_stderr(result, label)
    targets = [
        match.group(1)
        for line in result.stdout.splitlines()
        if (match := re.fullmatch(r'Fast link dest: "([^"\r\n]+)"', line))
    ]
    if len(targets) != 1:
        raise LovelaceError(f"{label} target is unavailable or ambiguous")
    target = targets[0]
    try:
        encoded_target = target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LovelaceError(f"{label} target is not ASCII") from exc
    if (
        len(encoded_target) != record["size"]
        or len(encoded_target) > MAX_EXT4_FAST_SYMLINK_TARGET_BYTES
        or re.fullmatch(r"[A-Za-z0-9._+@/-]+", target) is None
        or "//" in target
        or target.endswith("/")
    ):
        raise LovelaceError(f"{label} target is unsafe")
    return target


def resolve_ext4_guest_path(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    inventory: dict[str, dict[str, Any]],
    guest_path: str,
    *,
    label: str,
) -> tuple[str, dict[str, Any]]:
    """Resolve an inventory path without allowing escape or unbounded links."""
    requested = require_simple_guest_path(guest_path, label)
    resolved: list[str] = []
    pending = list(requested.parts[1:])
    followed_symlinks = 0
    while pending:
        if len(resolved) + len(pending) > MAX_EXT4_PATH_BYTES:
            raise LovelaceError(f"{label} resolution is too deep")
        component = pending.pop(0)
        if component == "..":
            if not resolved:
                raise LovelaceError(f"{label} symlink target escapes guest root")
            resolved.pop()
            continue
        if (
            not component
            or component == "."
            or re.fullmatch(r"[A-Za-z0-9._+@-]+", component) is None
        ):
            raise LovelaceError(f"{label} symlink target is unsafe")
        resolved.append(component)
        resolved_path = "/" + "/".join(resolved)
        if len(resolved_path.encode("ascii")) > MAX_EXT4_PATH_BYTES:
            raise LovelaceError(f"{label} resolved path is too long")
        record = inventory.get(resolved_path)
        if record is None:
            raise LovelaceError(
                f"{label} resolution target is missing: {resolved_path}"
            )
        if record["type"] == "symlink":
            followed_symlinks += 1
            if followed_symlinks > MAX_EXT4_SYMLINK_RESOLUTION_DEPTH:
                raise LovelaceError(
                    f"{label} exceeds the symlink-resolution ceiling"
                )
            target = read_ext4_symlink_target(
                image,
                debugfs,
                record,
                label=f"{label} symlink {resolved_path}",
            )
            absolute_target = target.startswith("/")
            target_parts = target.removeprefix("/").split("/")
            if absolute_target:
                resolved = []
            else:
                resolved.pop()
            pending = [*target_parts, *pending]
            continue
        if pending:
            mode = int(record["mode"], 8)
            if (
                record["type"] != "directory"
                or record["uid"] != 0
                or record["gid"] != 0
                or stat.S_IMODE(mode)
                & (stat.S_ISUID | stat.S_ISGID | 0o022)
                or stat.S_IMODE(mode) & 0o001 == 0
            ):
                raise LovelaceError(
                    f"{label} resolution crosses an unsafe directory "
                    f"ancestor: {resolved_path}"
                )
    return "/" + "/".join(resolved), record


def validate_required_runtime_executable_paths(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    inventory: dict[str, dict[str, Any]],
    guest_paths: Sequence[str],
) -> None:
    for guest_path in guest_paths:
        resolved_path, record = resolve_ext4_guest_path(
            image,
            debugfs,
            inventory,
            guest_path,
            label=f"required runtime path {guest_path}",
        )
        if not any(
            resolved_path == prefix
            or resolved_path.startswith(prefix + "/")
            for prefix in IMMUTABLE_GUEST_RUNTIME_PREFIXES
        ):
            raise LovelaceError(
                "required runtime path resolves outside immutable guest "
                f"prefixes: {guest_path} -> {resolved_path}"
            )
        mode = int(record["mode"], 8)
        if (
            record["type"] != "regular"
            or record["uid"] != 0
            or record["gid"] != 0
            or type(record["size"]) is not int
            or record["size"] <= 0
            or stat.S_IMODE(mode) & 0o111 == 0
            or stat.S_IMODE(mode)
            & (stat.S_ISUID | stat.S_ISGID | 0o022)
        ):
            raise LovelaceError(
                "required runtime path does not resolve to a root-owned, "
                "non-set-ID, non-writable executable regular file: "
                f"{guest_path} -> {resolved_path}"
            )


def validate_ext4_regular_binding(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    inventory: dict[str, dict[str, Any]],
    guest_path: str,
    *,
    expected_mode: int,
    expected_size: int,
    expected_sha256: str,
    label: str,
    expected_uid: int = 0,
    expected_gid: int = 0,
    deadline: float | int | None = None,
) -> None:
    require_simple_guest_path(guest_path, label)
    if (
        type(expected_size) is not int
        or expected_size < 0
        or expected_size > MAX_TRANSIENT_PATH_SCAN_BYTES
        or not is_lower_hex(expected_sha256, 64)
        or type(expected_uid) is not int
        or expected_uid < 0
        or type(expected_gid) is not int
        or expected_gid < 0
    ):
        raise LovelaceError(f"{label} binding is invalid")
    record = inventory.get(guest_path)
    if (
        record is None
        or record["type"] != "regular"
        or stat.S_IMODE(int(record["mode"], 8)) != expected_mode
        or record["uid"] != expected_uid
        or record["gid"] != expected_gid
        or record["size"] != expected_size
    ):
        raise LovelaceError(
            f"{label} type, ownership, mode, or size differs in ext4 image"
        )
    command_timeout = remaining_embedded_debugfs_timeout(deadline, 600)
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-content.", dir="/tmp"
    ) as temporary:
        destination = Path(temporary) / "content"
        with ext4_image_handle(image) as pinned:
            result = run_bounded(
                [
                    debugfs,
                    "-R",
                    f"dump {guest_path} {destination}",
                    pinned.child_path,
                ],
                timeout=command_timeout,
                check=False,
                pass_fds=pinned.pass_fds,
                max_stdout_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
                max_stderr_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
            )
        require_clean_debugfs_stderr(result, label)
        if result.stdout != "":
            raise LovelaceError(f"{label} debugfs dump output differs")
        info = ensure_regular(destination, label, single_link=True)
        if info.st_size != expected_size:
            raise LovelaceError(f"{label} size differs in ext4 image")
        if digest_file(destination) != expected_sha256:
            raise LovelaceError(f"{label} SHA-256 differs in ext4 image")


def validate_ext4_symlink_binding(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    inventory: dict[str, dict[str, Any]],
    guest_path: str,
    *,
    expected_target: str,
    label: str,
    deadline: float | int | None = None,
) -> None:
    require_simple_guest_path(guest_path, label)
    if (
        not expected_target
        or re.fullmatch(r"[A-Za-z0-9._+@/-]+", expected_target) is None
        or "\0" in expected_target
        or "\n" in expected_target
        or "\r" in expected_target
        or '"' in expected_target
    ):
        raise LovelaceError(f"{label} target is unsafe")
    record = inventory.get(guest_path)
    if (
        record is None
        or record["type"] != "symlink"
        or stat.S_IMODE(int(record["mode"], 8)) != 0o777
        or record["uid"] != 0
        or record["gid"] != 0
        or record["size"] != len(expected_target.encode("ascii"))
    ):
        raise LovelaceError(f"{label} is not the expected ext4 symlink")
    if read_ext4_symlink_target(
        image, debugfs, record, label=label, deadline=deadline
    ) != expected_target:
        raise LovelaceError(f"{label} target differs in ext4 image")


def _format_uuid_bytes(value: bytes) -> str:
    if len(value) != 16:
        raise LovelaceError("ext4 UUID field has an invalid size")
    raw = value.hex()
    return (
        f"{raw[0:8]}-{raw[8:12]}-{raw[12:16]}-"
        f"{raw[16:20]}-{raw[20:32]}"
    )


def ext4_metadata_readback(
    image: Path | PinnedExt4Image,
) -> dict[str, Any]:
    source_path = image.path if isinstance(image, PinnedExt4Image) else image
    if isinstance(image, PinnedExt4Image):
        before = os.fstat(image.descriptor)
        descriptor = os.dup(image.descriptor)
    else:
        before = ensure_regular(
            source_path, "ext4 metadata readback image", single_link=True
        )
        descriptor = os.open(
            source_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise LovelaceError(
                "ext4 image changed while opening metadata readback"
            )
        superblock = os.pread(descriptor, 1024, 1024)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = source_path.lstat()
    if (
        len(superblock) != 1024
        or _stat_identity(opened) != _stat_identity(after)
        or _stat_identity(opened) != _stat_identity(final)
    ):
        raise LovelaceError(
            "ext4 image changed during metadata readback"
        )
    integer = lambda offset, size=4: int.from_bytes(
        superblock[offset : offset + size], "little"
    )
    if integer(0x38, 2) != 0xEF53:
        raise LovelaceError("ext4 metadata readback magic differs")
    if any(superblock[offset] != 0 for offset in range(0x274, 0x278)):
        raise LovelaceError(
            "ext4 superblock high timestamp bytes are not zero"
        )
    inode_count = integer(0x00)
    free_inode_count = integer(0x10)
    if (
        inode_count <= 0
        or free_inode_count < 0
        or free_inode_count > inode_count
    ):
        raise LovelaceError("ext4 inode counters are invalid")
    return {
        "filesystem_uuid": _format_uuid_bytes(superblock[0x68:0x78]),
        "directory_hash_seed": _format_uuid_bytes(
            superblock[0xEC:0xFC]
        ),
        "mtime": integer(0x2C),
        "wtime": integer(0x30),
        "lastcheck": integer(0x40),
        "mkfs_time": integer(0x108),
        "timestamp_high_bytes_zero": True,
        "allocated_inode_count": inode_count - free_inode_count,
    }


def ext4_inode_timestamp_readback(
    image: Path | PinnedExt4Image,
    inode_numbers: Sequence[int],
    *,
    expected_epoch: int,
) -> dict[str, Any]:
    if (
        type(expected_epoch) is not int
        or not 0 <= expected_epoch <= 0x7FFFFFFF
        or not inode_numbers
        or len(inode_numbers) > MAX_ROOT_TREE_ENTRIES + 16
        or list(inode_numbers) != sorted(set(inode_numbers))
        or any(type(inode) is not int or inode <= 0 for inode in inode_numbers)
    ):
        raise LovelaceError(
            "ext4 inode timestamp readback contract is invalid"
        )
    source_path = image.path if isinstance(image, PinnedExt4Image) else image
    if isinstance(image, PinnedExt4Image):
        before = os.fstat(image.descriptor)
        descriptor = os.dup(image.descriptor)
    else:
        before = ensure_regular(
            source_path,
            "ext4 inode timestamp readback image",
            single_link=True,
        )
        descriptor = os.open(
            source_path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
            or opened.st_size != before.st_size
        ):
            raise LovelaceError(
                "ext4 image changed while opening inode timestamp readback"
            )
        superblock = os.pread(descriptor, 1024, 1024)
        if len(superblock) != 1024:
            raise LovelaceError("ext4 superblock readback is truncated")

        integer = lambda offset, size=4: int.from_bytes(
            superblock[offset : offset + size], "little"
        )
        if integer(0x38, 2) != 0xEF53:
            raise LovelaceError("ext4 inode readback magic differs")
        inode_count = integer(0x00)
        free_inode_count = integer(0x10)
        blocks_count = integer(0x04) | (integer(0x150) << 32)
        first_data_block = integer(0x14)
        log_block_size = integer(0x18)
        blocks_per_group = integer(0x20)
        inodes_per_group = integer(0x28)
        first_nonreserved_inode = integer(0x54)
        inode_size = integer(0x58, 2)
        feature_compat = integer(0x5C)
        feature_incompat = integer(0x60)
        feature_ro_compat = integer(0x64)
        descriptor_size = integer(0xFE, 2)
        first_meta_bg = integer(0x104)
        minimum_extra_isize = integer(0x15C, 2)
        desired_extra_isize = integer(0x15E, 2)
        log_groups_per_flex = integer(0x174, 1)
        checksum_type = integer(0x175, 1)
        if (
            inode_count <= 0
            or free_inode_count < 0
            or free_inode_count > inode_count
            or blocks_count <= first_data_block
            or log_block_size != 2
            or blocks_per_group != 32768
            or inodes_per_group != 8192
            or first_data_block != 0
            or first_nonreserved_inode != 11
            or inode_size != 256
            or descriptor_size != 64
            or feature_compat != 0x3C
            or feature_incompat != 0x2C2
            or feature_ro_compat != 0x46B
            or first_meta_bg != 0
            or minimum_extra_isize != 32
            or desired_extra_isize != 32
            or log_groups_per_flex != 4
            or checksum_type != 1
            or any(superblock[offset] != 0 for offset in range(0x274, 0x278))
            or inode_numbers[-1] > inode_count
        ):
            raise LovelaceError(
                "ext4 inode timestamp geometry is unsupported or invalid"
            )
        block_size = 4096
        if blocks_count * block_size != opened.st_size:
            raise LovelaceError(
                "ext4 block geometry differs from the image size"
            )
        group_count = (
            blocks_count - first_data_block + blocks_per_group - 1
        ) // blocks_per_group
        inode_group_count = (
            inode_count + inodes_per_group - 1
        ) // inodes_per_group
        if (
            group_count != inode_group_count
            or group_count <= 0
            or inode_count != group_count * inodes_per_group
        ):
            raise LovelaceError(
                "ext4 block and inode group geometry differs"
            )
        descriptor_table_offset = (
            (first_data_block + 1) * block_size
        )
        if (
            descriptor_table_offset < 0
            or group_count * descriptor_size
            > opened.st_size - descriptor_table_offset
        ):
            raise LovelaceError(
                "ext4 group descriptor table is out of image bounds"
            )
        expected_base_time = expected_epoch.to_bytes(4, "little")
        digest = hashlib.sha256(
            b"wucios-lovelace-ext4-timestamps-v1\0"
        )
        bitmap_digest = hashlib.sha256(
            b"wucios-lovelace-ext4-inode-bitmap-v1\0"
        )
        with_extra_timestamps = 0
        without_extra_timestamps = 0
        descriptor_cache: dict[int, bytes] = {}
        inode_table_blocks: dict[int, int] = {}
        allocated_inodes: list[int] = []
        group_free_inode_total = 0
        inode_table_blocks_per_group = (
            inodes_per_group * inode_size + block_size - 1
        ) // block_size
        for group in range(group_count):
            descriptor_offset = (
                descriptor_table_offset + group * descriptor_size
            )
            descriptor_record = os.pread(
                descriptor, descriptor_size, descriptor_offset
            )
            if len(descriptor_record) != descriptor_size:
                raise LovelaceError(
                    "ext4 group descriptor readback is truncated"
                )
            descriptor_cache[group] = descriptor_record
            inode_bitmap_block = int.from_bytes(
                descriptor_record[0x04:0x08], "little"
            ) | (
                int.from_bytes(
                    descriptor_record[0x24:0x28], "little"
                )
                << 32
            )
            inode_table_block = int.from_bytes(
                descriptor_record[0x08:0x0C], "little"
            ) | (
                int.from_bytes(
                    descriptor_record[0x28:0x2C], "little"
                )
                << 32
            )
            group_free_inodes = int.from_bytes(
                descriptor_record[0x0E:0x10], "little"
            ) | (
                int.from_bytes(
                    descriptor_record[0x2E:0x30], "little"
                )
                << 16
            )
            descriptor_flags = int.from_bytes(
                descriptor_record[0x12:0x14], "little"
            )
            if (
                descriptor_flags & ~0x7
                or (
                    descriptor_flags & 0x1
                    and group_free_inodes != inodes_per_group
                )
                or inode_bitmap_block <= 0
                or inode_bitmap_block >= blocks_count
                or inode_table_block <= 0
                or inode_table_block + inode_table_blocks_per_group
                > blocks_count
                or group_free_inodes > inodes_per_group
            ):
                raise LovelaceError(
                    "ext4 inode allocation descriptor is invalid"
                )
            inode_table_blocks[group] = inode_table_block
            bitmap = os.pread(
                descriptor,
                inodes_per_group // 8,
                inode_bitmap_block * block_size,
            )
            if len(bitmap) != inodes_per_group // 8:
                raise LovelaceError(
                    "ext4 inode allocation bitmap is truncated"
                )
            bitmap_digest.update(group.to_bytes(4, "little"))
            bitmap_digest.update(bitmap)
            group_allocated = 0
            first_inode = group * inodes_per_group + 1
            for index in range(inodes_per_group):
                if bitmap[index // 8] & (1 << (index % 8)):
                    allocated_inodes.append(first_inode + index)
                    group_allocated += 1
            if group_free_inodes != inodes_per_group - group_allocated:
                raise LovelaceError(
                    "ext4 group free-inode counter differs from its bitmap"
                )
            group_free_inode_total += group_free_inodes
        if (
            allocated_inodes != list(inode_numbers)
            or group_free_inode_total != free_inode_count
            or len(allocated_inodes) != inode_count - free_inode_count
        ):
            raise LovelaceError(
                "ext4 allocated inode set differs from the verified inventory"
            )
        for inode_number in inode_numbers:
            group = (inode_number - 1) // inodes_per_group
            index = (inode_number - 1) % inodes_per_group
            if group >= group_count:
                raise LovelaceError(
                    "ext4 inode timestamp group is out of range"
                )
            inode_table_block = inode_table_blocks[group]
            inode_offset = (
                inode_table_block * block_size + index * inode_size
            )
            if (
                inode_table_block <= 0
                or inode_table_block >= blocks_count
                or inode_offset < 0
                or inode_offset + inode_size > opened.st_size
            ):
                raise LovelaceError(
                    "ext4 inode table readback is out of image bounds"
                )
            raw_inode = os.pread(
                descriptor, inode_size, inode_offset
            )
            if len(raw_inode) != inode_size:
                raise LovelaceError(
                    "ext4 inode timestamp readback is truncated"
                )
            base_times = (
                raw_inode[0x08:0x0C],
                raw_inode[0x0C:0x10],
                raw_inode[0x10:0x14],
            )
            if (
                any(value != expected_base_time for value in base_times)
                or raw_inode[0x14:0x18] != b"\0" * 4
            ):
                raise LovelaceError(
                    "ext4 inode base timestamp or deletion time differs: "
                    f"inode {inode_number}"
                )
            extra_isize = int.from_bytes(
                raw_inode[0x80:0x82], "little"
            )
            if extra_isize == 0:
                if inode_number not in {1, 3, 4, 5, 6, 9, 10}:
                    raise LovelaceError(
                        "ext4 populated inode lacks exact extended fields: "
                        f"inode {inode_number}"
                    )
                without_extra_timestamps += 1
                selected_extra = b"\0" * 24
            elif extra_isize != 32:
                raise LovelaceError(
                    "ext4 inode extra timestamp geometry is invalid: "
                    f"inode {inode_number}"
                )
            else:
                with_extra_timestamps += 1
                if (
                    raw_inode[0x90:0x94] != expected_base_time
                    or any(
                        int.from_bytes(raw_inode[offset : offset + 4], "little")
                        != 0
                        for offset in (0x84, 0x88, 0x8C, 0x94)
                    )
                ):
                    raise LovelaceError(
                        "ext4 inode extended timestamp differs from the "
                        f"source epoch: inode {inode_number}"
                    )
                selected_extra = raw_inode[0x80:0x98]
            digest.update(inode_number.to_bytes(4, "little"))
            digest.update(raw_inode[0x08:0x18])
            digest.update(selected_extra)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = source_path.lstat()
    if (
        _stat_identity(opened) != _stat_identity(after)
        or _stat_identity(opened) != _stat_identity(final)
    ):
        raise LovelaceError(
            "ext4 image changed during inode timestamp readback"
        )
    return {
        "schema": "wucios.lovelace.ext4_inode_timestamp_readback.v1",
        "inode_count": len(inode_numbers),
        "first_nonreserved_inode": first_nonreserved_inode,
        "inode_size": inode_size,
        "block_size": block_size,
        "inodes_per_group": inodes_per_group,
        "group_count": group_count,
        "blocks_count": blocks_count,
        "feature_compat": feature_compat,
        "feature_incompat": feature_incompat,
        "feature_ro_compat": feature_ro_compat,
        "descriptor_size": descriptor_size,
        "timestamp_epoch": expected_epoch,
        "allocated_inode_count": len(allocated_inodes),
        "allocated_inode_bitmap_sha256": bitmap_digest.hexdigest(),
        "inodes_with_extra_timestamp_fields": with_extra_timestamps,
        "inodes_without_extra_timestamp_fields": (
            without_extra_timestamps
        ),
        "base_atime_ctime_mtime_equal_epoch": True,
        "deletion_time_zero": True,
        "crtime_equal_epoch_where_present": True,
        "extra_timestamp_bits_zero_where_present": True,
        "raw_timestamp_fields_sha256": digest.hexdigest(),
    }


def require_ext4_path_absent(
    image: Path | PinnedExt4Image, debugfs: Path, guest_path: str
) -> None:
    if (
        not isinstance(guest_path, str)
        or re.fullmatch(r"/[A-Za-z0-9._/-]+", guest_path) is None
        or "//" in guest_path
        or any(part in {".", ".."} for part in guest_path.split("/")[1:])
    ):
        raise LovelaceError("ext4 absence path contract is invalid")
    with ext4_image_handle(image) as pinned:
        result = run_bounded(
            [debugfs, "-R", f"stat {guest_path}", pinned.child_path],
            timeout=120,
            check=False,
            pass_fds=pinned.pass_fds,
            max_stdout_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
            max_stderr_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
        )
    expected = f"{guest_path}: File not found by ext2_lookup"
    if (
        result.returncode != 0
        or result.stdout.strip()
        or not any(
            line.strip() == expected for line in result.stderr.splitlines()
        )
    ):
        raise LovelaceError(
            f"forbidden transient path is present or ambiguous: {guest_path}"
        )


def normalize_ext4_metadata(
    image: Path,
    *,
    epoch: int,
    filesystem_uuid: str,
    debugfs: Path,
    work: Path,
) -> dict[str, Any]:
    reachable_inodes = ext4_inode_inventory(image, debugfs)
    reserved_inodes = list(range(1, 11))
    inodes = sorted(set(reachable_inodes) | set(reserved_inodes))
    fd, batch_name = tempfile.mkstemp(
        prefix="debugfs-normalize.", dir=work
    )
    batch = Path(batch_name)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(f"set_current_time @{epoch}\n")
            for inode in inodes:
                filespec = f"<{inode}>"
                for field in ("atime", "ctime", "mtime", "crtime"):
                    stream.write(
                        f"set_inode_field {filespec} {field} @{epoch}\n"
                    )
                for field in (
                    "atime_extra",
                    "ctime_extra",
                    "mtime_extra",
                    "crtime_extra",
                ):
                    stream.write(
                        f"set_inode_field {filespec} {field} 0\n"
                    )
            stream.write(
                f"set_super_value hash_seed {filesystem_uuid}\n"
            )
            stream.write(f"set_super_value mkfs_time @{epoch}\n")
            stream.write(f"set_super_value lastcheck @{epoch}\n")
            stream.write("set_super_value mtime @0\n")
            stream.write(f"set_super_value wtime @{epoch}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(batch, 0o600)
        environment = {
            "E2FSPROGS_FAKE_TIME": str(epoch),
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
        }
        result = run(
            [debugfs, "-w", "-f", batch, image],
            env=environment,
            timeout=3600,
        )
    finally:
        try:
            batch.unlink()
        except FileNotFoundError:
            pass
    require_clean_debugfs_stderr(
        result, "debugfs ext4 metadata normalization"
    )
    expected_command_count = 6 + 8 * len(inodes)
    observed_command_count = sum(
        line.startswith("debugfs: ")
        for line in result.stdout.splitlines()
    )
    expected_status_lines = {
        f"Setting current time to {time.asctime(time.gmtime(epoch))}"
    }
    unexpected_output = [
        line
        for line in result.stdout.splitlines()
        if (
            line
            and not line.startswith("debugfs: ")
            and line not in expected_status_lines
        )
    ]
    observed_status_lines = {
        line
        for line in result.stdout.splitlines()
        if line in expected_status_lines
    }
    if (
        observed_command_count != expected_command_count
        or observed_status_lines != expected_status_lines
        or unexpected_output
    ):
        raise LovelaceError(
            "debugfs ext4 metadata normalization command coverage differs: "
            f"expected {expected_command_count}, observed "
            f"{observed_command_count}, unexpected "
            f"{unexpected_output[:3]!r}"
        )
    readback = ext4_metadata_readback(image)
    expected_readback = {
        "filesystem_uuid": filesystem_uuid,
        "directory_hash_seed": filesystem_uuid,
        "mtime": 0,
        "wtime": epoch,
        "lastcheck": epoch,
        "mkfs_time": epoch,
        "timestamp_high_bytes_zero": True,
        "allocated_inode_count": len(inodes),
    }
    if readback != expected_readback:
        raise LovelaceError(
            "normalized ext4 metadata readback differs: "
            f"expected {expected_readback}, got {readback}"
        )
    timestamp_readback = ext4_inode_timestamp_readback(
        image, inodes, expected_epoch=epoch
    )
    return {
        "normalized_inode_count": len(inodes),
        "reachable_inode_count": len(reachable_inodes),
        "reserved_inode_count": len(reserved_inodes),
        "timestamp_epoch": epoch,
        "directory_hash_seed": filesystem_uuid,
        "allocated_inode_timestamp_fields_normalized": True,
        "extra_timestamp_bits_zeroed_where_present": True,
        "superblock_readback": readback,
        "inode_timestamp_readback": timestamp_readback,
        "debugfs_stdout_tail": result.stdout[-1000:],
    }


def make_ext4_image(
    root: Path,
    image: Path,
    release: dict[str, Any],
    work: Path,
) -> dict[str, Any]:
    filesystem = release["filesystem"]
    mke2fs = trusted_host_tool("mke2fs")
    debugfs = trusted_host_tool("debugfs")
    e2fsck = trusted_host_tool("e2fsck")
    fakeroot = trusted_host_tool("fakeroot")
    chown = trusted_host_tool("chown")
    find = trusted_host_tool("find")
    host_stat = trusted_host_tool("stat")
    ensure_regular(
        MKE2FS_CONFIG_PATH,
        "pinned Lovelace mke2fs configuration",
    )
    e2fsprogs_version_result = run([mke2fs, "-V"])
    e2fsprogs_version = (
        e2fsprogs_version_result.stdout
        + e2fsprogs_version_result.stderr
    ).splitlines()[0]
    debugfs_version_result = run([debugfs, "-V"])
    debugfs_version = (
        debugfs_version_result.stdout + debugfs_version_result.stderr
    ).splitlines()[0]
    e2fsck_version_result = run([e2fsck, "-V"])
    e2fsck_version = (
        e2fsck_version_result.stdout + e2fsck_version_result.stderr
    ).splitlines()[0]
    fakeroot_version_result = run([fakeroot, "--version"])
    fakeroot_version = (
        fakeroot_version_result.stdout + fakeroot_version_result.stderr
    ).strip()
    if (
        e2fsprogs_version != f"mke2fs {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)"
        or debugfs_version
        != f"debugfs {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)"
        or e2fsck_version
        != f"e2fsck {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)"
        or fakeroot_version
        != f"fakeroot version {EXPECTED_FAKEROOT_VERSION}"
    ):
        raise LovelaceError(
            "deterministic ext4 build requires exactly mke2fs/debugfs "
            f"{EXPECTED_E2FSPROGS_VERSION} and fakeroot "
            f"{EXPECTED_FAKEROOT_VERSION}"
        )
    staged_entry_count = validate_root_tree_paths(root)
    image.parent.mkdir(parents=True, exist_ok=True)
    with image.open("xb") as stream:
        stream.truncate(filesystem["size_mib"] * 1024 * 1024)
    state = work / "fakeroot.state"
    root_chown = run(
        [
            fakeroot,
            "-s",
            state,
            chown,
            "-hR",
            "0:0",
            root,
        ],
        timeout=600,
        check=False,
    )
    if root_chown.returncode not in {0, 1}:
        raise LovelaceError("fakeroot could not record root ownership")
    ownership_check = run(
        [
            fakeroot,
            "-i",
            state,
            find,
            root,
            "-xdev",
            "(",
            "!",
            "-uid",
            "0",
            "-o",
            "!",
            "-gid",
            "0",
            ")",
            "-print",
            "-quit",
        ],
        timeout=600,
    )
    if ownership_check.stdout.strip():
        raise LovelaceError(
            "fakeroot did not record root ownership for the complete tree"
        )
    for owned_path in (root / "home/lab", root / "work"):
        lab_chown = run(
            [
                fakeroot,
                "-i",
                state,
                "-s",
                state,
                chown,
                "-hR",
                "1000:1000",
                owned_path,
            ],
            timeout=600,
            check=False,
        )
        if lab_chown.returncode not in {0, 1}:
            raise LovelaceError(
                f"fakeroot could not record lab ownership: {owned_path}"
            )
        lab_check = run(
            [
                fakeroot,
                "-i",
                state,
                host_stat,
                "-c",
                "%u:%g",
                owned_path,
            ]
        )
        if lab_check.stdout.strip() != "1000:1000":
            raise LovelaceError(
                f"fakeroot lab ownership verification failed: {owned_path}"
            )
    # The ownership traversal updates directory atimes. Normalize once more
    # immediately before mke2fs imports the staged tree.
    normalize_root_tree(root, release["source_date_epoch"])
    fake_time_environment = {
        "E2FSPROGS_FAKE_TIME": str(release["source_date_epoch"]),
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "MKE2FS_CONFIG": str(MKE2FS_CONFIG_PATH),
        "MKE2FS_DEVICE_SECTSIZE": "512",
        "MKE2FS_DEVICE_PHYS_SECTSIZE": "4096",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TZ": "UTC",
    }
    blocks_count = filesystem["size_mib"] * 1024 * 1024 // 4096
    features = (
        "has_journal,ext_attr,resize_inode,dir_index,filetype,extent,"
        "64bit,flex_bg,sparse_super,large_file,huge_file,dir_nlink,"
        "extra_isize,metadata_csum"
    )
    result = run(
        [
            fakeroot,
            "-i",
            state,
            mke2fs,
            "-q",
            "-F",
            "-t",
            "ext4",
            "-T",
            "default",
            "-b",
            "4096",
            "-I",
            "256",
            "-N",
            "524288",
            "-G",
            "16",
            "-g",
            "32768",
            "-m",
            "0",
            "-o",
            "linux",
            "-e",
            "continue",
            "-L",
            filesystem["label"],
            "-U",
            filesystem["uuid"],
            "-M",
            "/",
            "-O",
            features,
            "-J",
            "size=64",
            "-E",
            (
                "lazy_itable_init=0,lazy_journal_init=0,"
                "root_owner=0:0,nodiscard,"
                f"hash_seed={filesystem['uuid']}"
            ),
            "-d",
            root,
            image,
            str(blocks_count),
        ],
        env=fake_time_environment,
        timeout=3600,
    )
    normalization = normalize_ext4_metadata(
        image,
        epoch=release["source_date_epoch"],
        filesystem_uuid=filesystem["uuid"],
        debugfs=debugfs,
        work=work,
    )
    check = run(
        [e2fsck, "-fn", image],
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
        },
        timeout=600,
        check=False,
    )
    if check.returncode not in {0, 1}:
        raise LovelaceError(
            f"generated ext4 image failed e2fsck: {check.stderr[-2000:]}"
        )
    serialized_path_scan = digest_file_rejecting_exact_bytes(
        image, os.fsencode(os.fspath(work))
    )
    os.chmod(image, 0o444)
    return {
        "format": "ext4",
        "logical_size": image.stat().st_size,
        "sha256": serialized_path_scan["sha256"],
        "label": filesystem["label"],
        "uuid": filesystem["uuid"],
        "block_size": 4096,
        "blocks_count": blocks_count,
        "inode_size": 256,
        "inode_count": 524288,
        "features": features.split(","),
        "journal_size_mib": 64,
        "staged_entry_count": staged_entry_count,
        "mke2fs_config": {
            "path": MKE2FS_CONFIG_PATH.relative_to(REPO).as_posix(),
            "sha256": digest_file(MKE2FS_CONFIG_PATH),
        },
        "host_tools": {
            "mke2fs": host_tool_record(mke2fs, e2fsprogs_version),
            "debugfs": host_tool_record(debugfs, debugfs_version),
            "e2fsck": host_tool_record(e2fsck, e2fsck_version),
            "fakeroot": host_tool_record(fakeroot, fakeroot_version),
        },
        "metadata_normalization": normalization,
        "serialized_exact_path_scan": serialized_path_scan,
        "mke2fs_stdout": result.stdout[-1000:],
        "mke2fs_stderr": result.stderr[-1000:],
        "e2fsck_status": check.returncode,
    }


def commit_sparse_image(
    source: Path, destination: Path, *, expected_sha256: str
) -> None:
    ensure_regular(source, "generated sparse image")
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise LovelaceError("generated sparse image digest is invalid")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        ensure_regular(
            destination, "existing Lovelace base image", single_link=True
        )
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        run(
            [
                trusted_host_tool("cp"),
                "--sparse=always",
                "--reflink=auto",
                "--",
                source,
                temporary,
            ],
            timeout=3600,
        )
        ensure_regular(temporary, "copied sparse image")
        if (
            temporary.stat().st_size != source.stat().st_size
            or digest_file(temporary) != expected_sha256
        ):
            raise LovelaceError("cross-filesystem sparse image copy differs")
        os.chmod(temporary, 0o444)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def source_inputs_manifest() -> dict[str, Any]:
    sources = [
        Path(__file__),
        RELEASE_ROOT / "release.json",
        RELEASE_ROOT / "package-seeds.json",
        RELEASE_ROOT / "ghidra-lock.json",
        PACKAGE_LOCK_PATH,
        MKE2FS_CONFIG_PATH,
        PROFILE_PATH,
        REPO / "wucios/schemas/lovelace-laboratory-profile.schema.json",
        REPO / "wucios/fixtures/lovelace/ghidra-smoke.s",
        HOSTILE_PAYLOAD_FIXTURE_PATH,
        REPO / "tools/wuci_lab.py",
    ]
    sources.extend(
        path
        for path in sorted(
            (RELEASE_ROOT / "overlay").rglob("*"),
            key=lambda item: item.as_posix(),
        )
        if path.is_file()
    )
    records = []
    for path in sources:
        ensure_regular(path, "Lovelace source input", single_link=False)
        records.append(
            {
                "path": path.relative_to(REPO).as_posix(),
                "size": path.stat().st_size,
                "sha256": digest_file(path),
            }
        )
    records.sort(key=lambda item: item["path"])
    return {
        "schema": "wucios.lovelace.source_inputs.v1",
        "builder": BUILDER_VERSION,
        "files": records,
    }


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def require_real_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} is missing: {path}") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise LovelaceError(f"{label} must be a real directory: {path}")


@contextlib.contextmanager
def output_lock(output: Path) -> Iterable[None]:
    require_real_directory(output, "Lovelace output root")
    lock_path = output / ".build.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    acquired = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise LovelaceError(
                "Lovelace output lock must be a private owned regular file"
            )
        deadline = time.monotonic() + OUTPUT_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(
                    descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
                )
                acquired = True
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LovelaceError(
                        "timed out waiting for the Lovelace output lock "
                        f"after {OUTPUT_LOCK_TIMEOUT_SECONDS:g} seconds"
                    ) from exc
                time.sleep(min(OUTPUT_LOCK_RETRY_SECONDS, remaining))
        yield
    finally:
        try:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def preserve_superseded_validation(
    previous_release: Path,
    output: Path,
    *,
    replacement_base_sha256: str,
) -> None:
    manifest_path = previous_release / "manifest.json"
    evidence_path = previous_release / "evidence"
    if not manifest_path.exists() and not evidence_path.exists():
        return
    archive_root = output / "superseded-validation"
    if archive_root.exists() or archive_root.is_symlink():
        require_real_directory(
            archive_root, "superseded-validation archive"
        )
    else:
        archive_root.mkdir(mode=0o700)
    old_manifest_sha256: str | None = None
    old_base_sha256: str | None = None
    if manifest_path.exists() or manifest_path.is_symlink():
        ensure_regular(
            manifest_path, "superseded build manifest", single_link=True
        )
        old_manifest_sha256 = digest_file(manifest_path)
        try:
            old_manifest = load_object(manifest_path)
            candidate = old_manifest.get("artifacts", {}).get(
                "base_image", {}
            ).get("sha256")
            if isinstance(candidate, str) and re.fullmatch(
                r"[0-9a-f]{64}", candidate
            ):
                old_base_sha256 = candidate
        except LovelaceError:
            old_base_sha256 = None
    archive_prefix = (
        old_base_sha256
        or old_manifest_sha256
        or "unbound-validation"
    )
    archive = Path(
        tempfile.mkdtemp(
            prefix=f"{archive_prefix}.", dir=archive_root
        )
    )
    os.chmod(archive, 0o700)
    if manifest_path.exists():
        os.replace(manifest_path, archive / "manifest.json")
    if evidence_path.exists() or evidence_path.is_symlink():
        require_real_directory(
            evidence_path, "superseded validation evidence"
        )
        os.replace(evidence_path, archive / "evidence")
    write_json(
        archive / "superseded.json",
        {
            "schema": "wucios.lovelace.superseded_validation.v1",
            "status": "superseded-local-evidence-preserved",
            "old_manifest_sha256": old_manifest_sha256,
            "old_base_image_sha256": old_base_sha256,
            "replacement_base_image_sha256": replacement_base_sha256,
            "authoritative_for_release": False,
        },
    )
    fsync_directory(archive)
    fsync_directory(archive_root)


def publish_staged_release(
    staged_release: Path,
    output: Path,
    *,
    replacement_base_sha256: str,
) -> None:
    require_real_directory(staged_release, "staged Lovelace release")
    final_release = output / "release"
    previous_container: Path | None = None
    previous_release: Path | None = None
    if final_release.exists() or final_release.is_symlink():
        require_real_directory(final_release, "existing Lovelace release")
        previous_container = Path(
            tempfile.mkdtemp(prefix=".lovelace-previous.", dir=output)
        )
        previous_release = previous_container / "release"
        os.replace(final_release, previous_release)
        fsync_directory(output)
    try:
        os.replace(staged_release, final_release)
        fsync_directory(output)
    except BaseException:
        if (
            previous_release is not None
            and previous_release.exists()
            and not final_release.exists()
        ):
            os.replace(previous_release, final_release)
            fsync_directory(output)
        raise
    if previous_release is not None and previous_container is not None:
        preserve_superseded_validation(
            previous_release,
            output,
            replacement_base_sha256=replacement_base_sha256,
        )
        require_real_directory(
            previous_release, "superseded Lovelace release"
        )
        shutil.rmtree(previous_release)
        previous_container.rmdir()
        fsync_directory(output)


def build_staged(
    cache: Path,
    release_dir: Path,
    *,
    source_inputs_before: dict[str, Any],
    runtime_sources_before: dict[str, Any],
) -> dict[str, Any]:
    require_real_directory(release_dir, "staged Lovelace release")
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-build.", dir="/tmp"
    ) as temporary:
        work = Path(temporary)
        (
            release,
            _seeds,
            ghidra,
            package_lock,
            kernel,
            initramfs,
            bootstrap,
        ) = verify_inputs(cache, work)
        (
            private_cache,
            private_ghidra,
            input_snapshot,
        ) = snapshot_build_inputs(cache, package_lock, ghidra, work)
        root = work / "root"
        install_result = install_offline_root(
            root, package_lock, private_cache, bootstrap, work
        )
        overlay_records = copy_overlay(root)
        source_result = copy_runtime_sources(root)
        native_result = build_native_wuciji(root, work)
        embed_contracts(root, release, package_lock, ghidra)
        java_home = install_java_link(root)
        busybox_links = install_busybox_runtime_links(root)
        ghidra_result = install_ghidra(
            root,
            private_ghidra,
            ghidra,
            work,
        )
        fixture_result = build_ghidra_fixture(root, work)
        for path, mode in (
            (root / "root", 0o700),
            (root / "home/lab", 0o700),
            (root / "work", 0o700),
            (root / "tmp", 0o1777),
        ):
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, mode)
        privilege_result = harden_privileged_files(root)
        tree_counts = normalize_root_tree(
            root, release["source_date_epoch"]
        )
        transient_path_scan = reject_transient_build_path_leaks(root, work)
        if (
            transient_path_scan["regular_files_scanned"]
            != tree_counts["regular"]
            or transient_path_scan["directories_scanned"]
            != tree_counts["directory"]
            or transient_path_scan["symlinks_scanned"]
            != tree_counts["symlink"]
            or os.fspath(work) in install_result["stdout_tail"]
        ):
            raise LovelaceError(
                "transient build-path scan coverage or manifest output differs"
            )
        input_snapshot["transient_path_scan"] = transient_path_scan
        image_temp = work / release["output_files"]["base_image"]
        image_result = make_ext4_image(root, image_temp, release, work)

        kernel_destination = release_dir / release["output_files"]["kernel"]
        initramfs_destination = (
            release_dir / release["output_files"]["initramfs"]
        )
        image_destination = (
            release_dir / release["output_files"]["base_image"]
        )
        copy_regular_atomic(kernel, kernel_destination)
        copy_regular_atomic(initramfs, initramfs_destination)
        commit_sparse_image(
            image_temp,
            image_destination,
            expected_sha256=image_result["sha256"],
        )
        os.chmod(image_destination, 0o444)

        manifest = {
            "schema": "wucios.lovelace.build_manifest.v1",
            "status": "locally-built-non-authoritative",
            "builder": BUILDER_VERSION,
            "release_id": release["release_id"],
            "profile": "lovelace-laboratory",
            "authoritative_for_release": False,
            "artifacts": {
                "base_image": {
                    "filename": image_destination.name,
                    "size": image_destination.stat().st_size,
                    "sha256": image_result["sha256"],
                    "mode": "0444",
                    "format": "ext4",
                },
                "kernel": {
                    "filename": kernel_destination.name,
                    "size": kernel_destination.stat().st_size,
                    "sha256": digest_file(kernel_destination),
                },
                "initramfs": {
                    "filename": initramfs_destination.name,
                    "size": initramfs_destination.stat().st_size,
                    "sha256": digest_file(initramfs_destination),
                },
            },
            "package_install": install_result,
            "input_snapshot": input_snapshot,
            "package_lock_sha256": digest_file(PACKAGE_LOCK_PATH),
            "overlay": {
                "file_count": len(overlay_records),
                "files": overlay_records,
            },
            "source_tree": source_result,
            "native_wuci_ji": native_result,
            "java_home": java_home,
            "busybox_runtime_links": busybox_links,
            "ghidra": ghidra_result,
            "ghidra_fixture": fixture_result,
            "root_tree_counts": tree_counts,
            "privileged_files": privilege_result,
            "filesystem": image_result,
            "source_inputs": source_inputs_before,
            "defaults": {
                "storage": "volatile",
                "network": "none",
                "noxframe": "metadata-only",
            },
            "hostile_cell": {
                "requires_kvm": True,
                "software_emulation_fallback": False,
                "network": "none",
                "storage": "volatile",
                "persistent_storage": False,
                "host_shares": False,
            },
            "validation": {
                field: "NOT_MEASURED" for field in VALIDATION_CONTRACT
            },
            "validation_evidence": {
                field: None for field in VALIDATION_CONTRACT
            },
            "non_claims": release["non_claims"],
        }
        if os.fsencode(os.fspath(work)) in canonical_json(manifest):
            raise LovelaceError(
                "canonical build manifest embeds exact transient "
                "work-path bytes"
            )
        write_json(
            release_dir / release["output_files"]["manifest"], manifest
        )
        if (
            source_inputs_manifest() != source_inputs_before
            or runtime_source_manifest() != runtime_sources_before
            or source_result != runtime_sources_before
        ):
            raise LovelaceError(
                "source inputs changed while building the staged release"
            )
    return manifest


def _build_unlocked(cache: Path, output: Path) -> dict[str, Any]:
    source_inputs_before = source_inputs_manifest()
    runtime_sources_before = runtime_source_manifest()
    with tempfile.TemporaryDirectory(
        prefix=".lovelace-release-stage.", dir=output
    ) as stage_name:
        stage_root = Path(stage_name)
        release_dir = stage_root / "release"
        release_dir.mkdir(mode=0o755)
        manifest = build_staged(
            cache,
            release_dir,
            source_inputs_before=source_inputs_before,
            runtime_sources_before=runtime_sources_before,
        )
        verify_build(stage_root)
        if (
            source_inputs_manifest() != source_inputs_before
            or runtime_source_manifest() != runtime_sources_before
        ):
            raise LovelaceError(
                "source inputs changed before staged release publication"
            )
        publish_staged_release(
            release_dir,
            output,
            replacement_base_sha256=manifest["artifacts"]["base_image"][
                "sha256"
            ],
        )
    return manifest


def build(cache: Path, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    require_real_directory(output, "Lovelace output root")
    with output_lock(output):
        return _build_unlocked(cache, output)


def artifact_paths(output: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    release, _seeds, _ghidra = configuration()
    require_real_directory(output, "Lovelace artifact output root")
    try:
        output_root = output.resolve(strict=True)
    except OSError as exc:
        raise LovelaceError(
            "Lovelace artifact output root cannot be resolved"
        ) from exc
    release_dir = output_root / "release"
    require_real_directory(release_dir, "Lovelace release root")
    try:
        resolved_release_dir = release_dir.resolve(strict=True)
    except OSError as exc:
        raise LovelaceError(
            "Lovelace release root cannot be resolved"
        ) from exc
    if resolved_release_dir != release_dir:
        raise LovelaceError(
            "Lovelace release root escaped the selected output root"
        )
    manifest_path = release_dir / release["output_files"]["manifest"]
    snapshot = _transaction_file_snapshot(
        manifest_path,
        "Lovelace build manifest",
        max_bytes=MAX_BUILD_MANIFEST_BYTES,
    )
    manifest = parse_json_object(snapshot["data"], os.fspath(manifest_path))
    paths = {
        "manifest": manifest_path,
        "base_image": release_dir / release["output_files"]["base_image"],
        "kernel": release_dir / release["output_files"]["kernel"],
        "initramfs": release_dir / release["output_files"]["initramfs"],
        "evidence": release_dir / "evidence",
    }
    return manifest, paths


def canonical_object_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _validated_artifact_record(
    record: Any, name: str
) -> dict[str, Any]:
    expected_keys = {"filename", "size", "sha256"}
    if name == "base_image":
        expected_keys |= {"mode", "format"}
    require_exact_keys(record, expected_keys, f"{name} artifact record")
    filename = record["filename"]
    if (
        not isinstance(filename, str)
        or not filename
        or PurePosixPath(filename).name != filename
        or filename in {".", ".."}
    ):
        raise LovelaceError(f"{name} artifact filename is invalid")
    if type(record["size"]) is not int or record["size"] <= 0:
        raise LovelaceError(f"{name} artifact size is invalid")
    if not is_lower_hex(record["sha256"], 64):
        raise LovelaceError(f"{name} artifact SHA-256 is invalid")
    if name == "base_image" and (
        record["mode"] != "0444" or record["format"] != "ext4"
    ):
        raise LovelaceError("base image artifact mode or format is invalid")
    return dict(record)


def canonical_artifact_vector(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return the exact artifact/source identity carried by every proof lane."""
    immutable_fields = {
        "schema",
        "status",
        "builder",
        "release_id",
        "profile",
        "authoritative_for_release",
        "artifacts",
        "package_install",
        "input_snapshot",
        "package_lock_sha256",
        "overlay",
        "source_tree",
        "native_wuci_ji",
        "java_home",
        "busybox_runtime_links",
        "ghidra",
        "ghidra_fixture",
        "root_tree_counts",
        "privileged_files",
        "filesystem",
        "source_inputs",
        "defaults",
        "hostile_cell",
        "non_claims",
    }
    require_exact_keys(
        manifest,
        immutable_fields | {"validation", "validation_evidence"},
        "artifact-vector build manifest",
    )
    immutable_manifest = {
        field: manifest[field] for field in sorted(immutable_fields)
    }
    artifacts = manifest.get("artifacts")
    require_exact_keys(
        artifacts,
        {"base_image", "kernel", "initramfs"},
        "artifact vector artifacts",
    )
    release_id = manifest.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise LovelaceError("artifact vector release identity is invalid")
    if manifest.get("builder") != BUILDER_VERSION:
        raise LovelaceError("artifact vector builder identity is invalid")
    package_lock_sha256 = manifest.get("package_lock_sha256")
    if not is_lower_hex(package_lock_sha256, 64):
        raise LovelaceError("artifact vector package-lock digest is invalid")
    source_inputs = manifest.get("source_inputs")
    runtime_sources = manifest.get("source_tree")
    if not isinstance(source_inputs, dict) or not isinstance(
        runtime_sources, dict
    ):
        raise LovelaceError(
            "artifact vector source-input manifests are invalid"
        )
    embedded_records = {
        field: manifest.get(field)
        for field in (
            "overlay",
            "native_wuci_ji",
            "java_home",
            "busybox_runtime_links",
            "privileged_files",
        )
    }
    if any(value is None for value in embedded_records.values()):
        raise LovelaceError(
            "artifact vector embedded-build records are incomplete"
        )
    return {
        "schema": "wucios.lovelace.artifact_vector.v2",
        "release_id": release_id,
        "builder": BUILDER_VERSION,
        "artifacts": {
            name: _validated_artifact_record(artifacts[name], name)
            for name in ("base_image", "kernel", "initramfs")
        },
        "package_lock_sha256": package_lock_sha256,
        "source_inputs_sha256": canonical_object_sha256(source_inputs),
        "runtime_sources_sha256": canonical_object_sha256(runtime_sources),
        "embedded_build_records_sha256": canonical_object_sha256(
            embedded_records
        ),
        "immutable_build_manifest_sha256": canonical_object_sha256(
            immutable_manifest
        ),
    }


def validate_manifest_artifact_locks(
    manifest: dict[str, Any], release: dict[str, Any]
) -> None:
    vector = canonical_artifact_vector(manifest)
    artifacts = vector["artifacts"]
    output_files = release["output_files"]
    boot = release["boot"]
    base = artifacts["base_image"]
    if base != {
        "filename": output_files["base_image"],
        "size": release["filesystem"]["size_mib"] * 1024 * 1024,
        "sha256": base["sha256"],
        "mode": "0444",
        "format": "ext4",
    }:
        raise LovelaceError(
            "base image artifact record differs from the release lock"
        )
    if artifacts["kernel"] != {
        "filename": output_files["kernel"],
        "size": boot["kernel_size"],
        "sha256": boot["kernel_sha256"],
    }:
        raise LovelaceError(
            "kernel artifact record differs from the release boot lock"
        )
    if artifacts["initramfs"] != {
        "filename": output_files["initramfs"],
        "size": boot["initramfs_size"],
        "sha256": boot["initramfs_sha256"],
    }:
        raise LovelaceError(
            "initramfs artifact record differs from the release boot lock"
        )


def validate_ghidra_manifest_records(
    manifest: dict[str, Any], ghidra_lock: dict[str, Any]
) -> None:
    fixture = manifest.get("ghidra_fixture")
    semantic_script_source = (
        RELEASE_ROOT
        / "overlay"
        / GHIDRA_SEMANTIC_SCRIPT_PATH.lstrip("/")
        / GHIDRA_SEMANTIC_SCRIPT_NAME
    )
    require_exact_keys(
        fixture,
        {
            "source",
            "source_size",
            "source_sha256",
            "binary",
            "binary_size",
            "binary_sha256",
            "binary_md5_identity",
            "semantic_script",
            "semantic_script_sha256",
            "semantic_marker",
        },
        "Ghidra fixture record",
    )
    if (
        fixture["source"]
        != "/usr/share/wucios/fixtures/ghidra/ghidra-smoke.s"
        or type(fixture["source_size"]) is not int
        or fixture["source_size"] <= 0
        or fixture["source_size"]
        != (REPO / "wucios/fixtures/lovelace/ghidra-smoke.s").stat().st_size
        or fixture["source_sha256"]
        != digest_file(REPO / "wucios/fixtures/lovelace/ghidra-smoke.s")
        or fixture["binary"]
        != "/usr/share/wucios/fixtures/ghidra/ghidra-smoke"
        or type(fixture["binary_size"]) is not int
        or fixture["binary_size"] <= 0
        or fixture["binary_sha256"] != GHIDRA_FIXTURE_SHA256
        or fixture["binary_md5_identity"] != GHIDRA_FIXTURE_MD5
        or fixture["semantic_script"]
        != (
            f"{GHIDRA_SEMANTIC_SCRIPT_PATH}/"
            f"{GHIDRA_SEMANTIC_SCRIPT_NAME}"
        )
        or not is_lower_hex(fixture["semantic_script_sha256"], 64)
        or fixture["semantic_script_sha256"]
        != digest_file(semantic_script_source)
        or fixture["semantic_marker"] != GHIDRA_SEMANTIC_MARKER
    ):
        raise LovelaceError("Ghidra fixture record is invalid")
    installed = manifest.get("ghidra")
    require_exact_keys(
        installed,
        {
            "name",
            "version",
            "archive_sha256",
            "install_path",
            "entry_point",
            "expanded_size",
            "entry_count",
            "published_detached_signature",
            "runtime_validation",
        },
        "installed Ghidra record",
    )
    if (
        installed["name"] != ghidra_lock["name"]
        or installed["version"] != ghidra_lock["version"]
        or installed["archive_sha256"] != ghidra_lock["sha256"]
        or installed["install_path"] != ghidra_lock["install_path"]
        or installed["entry_point"] != ghidra_lock["entry_point"]
        or type(installed["expanded_size"]) is not int
        or not 0 < installed["expanded_size"] <= MAX_GHIDRA_EXPANDED_SIZE
        or type(installed["entry_count"]) is not int
        or not 0 < installed["entry_count"] <= MAX_GHIDRA_ENTRIES
        or installed["published_detached_signature"] is not False
        or installed["runtime_validation"] != "pending guest boot test"
    ):
        raise LovelaceError("installed Ghidra record is invalid")


def _require_evidence(condition: bool, message: str) -> None:
    if not condition:
        raise LovelaceError(message)


def _validate_evidence_binding_shape(
    binding: Any,
    contract: dict[str, str],
    vector: dict[str, Any],
    label: str,
) -> None:
    require_exact_keys(
        binding,
        {
            "path",
            "sha256",
            "schema",
            "base_image_sha256",
            "artifact_vector_sha256",
        },
        label,
    )
    expected = {
        "path": contract["evidence_path"],
        "sha256": binding["sha256"],
        "schema": contract["evidence_schema"],
        "base_image_sha256": vector["artifacts"]["base_image"]["sha256"],
        "artifact_vector_sha256": canonical_object_sha256(vector),
    }
    if binding != expected or not is_lower_hex(binding["sha256"], 64):
        raise LovelaceError(f"{label} is invalid")


def _validate_input_verification(
    verification: Any,
    manifest: dict[str, Any],
    vector: dict[str, Any],
    label: str,
) -> None:
    require_exact_keys(
        verification,
        {
            "schema",
            "status",
            "release_id",
            "artifacts",
            "package_count",
            "offline_package_install",
            "base_image_read_only",
            "ext4_check",
            "runtime_marker",
            "required_runtime_paths",
            "boot",
            "ghidra_headless",
            "validation_evidence",
            "authoritative_for_release",
            "non_claims",
        },
        label,
    )
    snapshot = manifest.get("input_snapshot")
    _require_evidence(
        isinstance(snapshot, dict)
        and type(snapshot.get("package_count")) is int
        and snapshot["package_count"] > 0,
        f"{label} manifest package count is invalid",
    )
    _require_evidence(
        verification["schema"] == "wucios.lovelace.build_verification.v1"
        and verification["status"] == "pass"
        and verification["release_id"] == vector["release_id"]
        and verification["artifacts"] == vector["artifacts"]
        and type(verification["package_count"]) is int
        and verification["package_count"] == snapshot["package_count"]
        and verification["offline_package_install"] is True
        and verification["base_image_read_only"] is True
        and verification["ext4_check"] == "pass"
        and verification["runtime_marker"] == runtime_marker()
        and verification["required_runtime_paths"] == "pass"
        and verification["boot"]
        in {
            "NOT_MEASURED",
            VALIDATION_CONTRACT["boot"]["measured_status"],
        }
        and verification["ghidra_headless"]
        in {
            "NOT_MEASURED",
            VALIDATION_CONTRACT["ghidra_headless"]["measured_status"],
        }
        and verification["authoritative_for_release"] is False
        and verification["non_claims"] == manifest.get("non_claims"),
        f"{label} identity or invariant differs",
    )
    nested_bindings = verification["validation_evidence"]
    if not isinstance(nested_bindings, dict) or not set(nested_bindings) <= set(
        VALIDATION_CONTRACT
    ):
        raise LovelaceError(f"{label} validation evidence map is invalid")
    boot_fields = {"boot", "language_matrix"}
    present_boot_fields = boot_fields & set(nested_bindings)
    if present_boot_fields not in (set(), boot_fields):
        raise LovelaceError(
            f"{label} boot/language evidence group is incomplete"
        )
    if present_boot_fields == boot_fields and (
        nested_bindings["boot"] != nested_bindings["language_matrix"]
    ):
        raise LovelaceError(
            f"{label} boot/language evidence bindings differ"
        )
    boot_measured = verification["boot"] == VALIDATION_CONTRACT["boot"][
        "measured_status"
    ]
    if boot_measured != (present_boot_fields == boot_fields):
        raise LovelaceError(f"{label} boot evidence status is inconsistent")
    ghidra_measured = verification["ghidra_headless"] == (
        VALIDATION_CONTRACT["ghidra_headless"]["measured_status"]
    )
    if ghidra_measured != ("ghidra_headless" in nested_bindings):
        raise LovelaceError(
            f"{label} Ghidra evidence status is inconsistent"
        )
    for field, binding in nested_bindings.items():
        _validate_evidence_binding_shape(
            binding,
            VALIDATION_CONTRACT[field],
            vector,
            f"{label} validation evidence {field}",
        )
    if nested_bindings:
        raise LovelaceError(
            f"{label} input verification must exclude nested runtime "
            "validation evidence"
        )


def evidence_input_verification_snapshot(
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Keep runtime evidence acyclic and bound only by the outer manifest."""
    snapshot = copy.deepcopy(verification)
    snapshot["boot"] = "NOT_MEASURED"
    snapshot["ghidra_headless"] = "NOT_MEASURED"
    snapshot["validation_evidence"] = {}
    return snapshot


def _complete_console_line_spans(
    output: bytes,
) -> list[tuple[int, int, bytes]]:
    records: list[tuple[int, int, bytes]] = []
    start = 0
    while True:
        newline = output.find(b"\n", start)
        if newline < 0:
            break
        line = output[start:newline]
        records.append(
            (start, newline + 1, line.removesuffix(b"\r"))
        )
        start = newline + 1
    return records


def _functional_console_record(
    output: bytes,
    *,
    console_ready_line_end_offset: int,
    command_dispatch_offset: int,
) -> dict[str, Any]:
    text = output.decode("utf-8", errors="replace")
    return {
        "console_bytes": len(output),
        "console_transcript_base64": base64.b64encode(output).decode(
            "ascii"
        ),
        "console_sha256": hashlib.sha256(output).hexdigest(),
        "console_tail": text[-12000:],
        "console_ready_line_end_offset": console_ready_line_end_offset,
        "command_dispatch_offset": command_dispatch_offset,
    }


def _validated_functional_console(
    runtime: dict[str, Any],
    expected_markers: Sequence[str],
    label: str,
) -> bytes:
    encoded = runtime["console_transcript_base64"]
    maximum_encoded = ((MAX_FUNCTIONAL_CONSOLE_BYTES + 2) // 3) * 4
    _require_evidence(
        isinstance(encoded, str)
        and len(encoded) <= maximum_encoded,
        f"{label} console transcript encoding is invalid or oversized",
    )
    try:
        encoded_bytes = encoded.encode("ascii")
        output = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise LovelaceError(
            f"{label} console transcript is not strict base64"
        ) from exc
    _require_evidence(
        base64.b64encode(output) == encoded_bytes
        and len(output) <= MAX_FUNCTIONAL_CONSOLE_BYTES
        and type(runtime["console_bytes"]) is int
        and runtime["console_bytes"] == len(output)
        and hashlib.sha256(output).hexdigest()
        == runtime["console_sha256"],
        f"{label} console transcript byte binding differs",
    )
    text = output.decode("utf-8", errors="replace")
    _require_evidence(
        runtime["console_tail"] == text[-12000:],
        f"{label} console tail does not match the complete transcript",
    )
    reject_forbidden_tcg_diagnostics(text)

    if (
        not isinstance(expected_markers, Sequence)
        or isinstance(expected_markers, (str, bytes))
        or len(expected_markers) < 3
        or expected_markers[0]
        not in {OFFLINE_BOOT_LINE, INTERNET_BOOT_LINE}
        or expected_markers[1] != CONSOLE_MARKER
        or len(set(expected_markers)) != len(expected_markers)
        or not all(
            isinstance(marker, str)
            and marker
            and "\r" not in marker
            and "\n" not in marker
            for marker in expected_markers
        )
    ):
        raise LovelaceError(
            f"{label} expected functional marker contract is invalid"
        )
    spans = _complete_console_line_spans(output)
    boot_lines = [
        record
        for record in spans
        if record[2].startswith((BOOT_MARKER + " ").encode("ascii"))
    ]
    _require_evidence(
        len(boot_lines) == 1
        and boot_lines[0][2] == expected_markers[0].encode("ascii"),
        f"{label} contains a missing, duplicate, or conflicting boot line",
    )
    marker_spans: list[tuple[int, int, bytes]] = []
    for marker in expected_markers:
        matches = [
            record
            for record in spans
            if record[2] == marker.encode("ascii")
        ]
        _require_evidence(
            len(matches) == 1,
            f"{label} does not contain each exact marker once: {marker}",
        )
        marker_spans.append(matches[0])
    _require_evidence(
        [record[0] for record in marker_spans]
        == sorted(record[0] for record in marker_spans),
        f"{label} exact markers are out of order",
    )
    ready_end = runtime["console_ready_line_end_offset"]
    dispatch_offset = runtime["command_dispatch_offset"]
    _require_evidence(
        type(ready_end) is int
        and ready_end == marker_spans[1][1]
        and type(dispatch_offset) is int
        and ready_end <= dispatch_offset <= len(output)
        and marker_spans[0][0] < marker_spans[1][0]
        and marker_spans[1][1] <= dispatch_offset
        and all(
            record[0] >= dispatch_offset for record in marker_spans[2:]
        ),
        f"{label} console-ready or post-dispatch marker binding differs",
    )
    return output


def _validate_runtime_result(
    runtime: Any, expected_markers: Sequence[str], label: str
) -> None:
    require_exact_keys(
        runtime,
        {
            "status",
            "qemu_exit",
            "markers",
            "console_bytes",
            "console_transcript_base64",
            "console_sha256",
            "console_tail",
            "console_ready_line_end_offset",
            "command_dispatch_offset",
            "console_eof_observed",
            "console_drain_timeout_seconds",
            "functional_accelerator",
            "functional_cpu_model",
            "functional_kernel_arguments",
            "forbidden_diagnostics_absent",
            "isolation_claim",
        },
        label,
    )
    _require_evidence(
        runtime["status"] == "pass"
        and type(runtime["qemu_exit"]) is int
        and runtime["qemu_exit"] == 0
        and runtime["markers"] == list(expected_markers)
        and type(runtime["console_bytes"]) is int
        and runtime["console_bytes"] >= 0
        and isinstance(runtime["console_transcript_base64"], str)
        and is_lower_hex(runtime["console_sha256"], 64)
        and isinstance(runtime["console_tail"], str)
        and len(runtime["console_tail"]) <= 12000
        and runtime["functional_accelerator"] == "tcg"
        and runtime["functional_cpu_model"] == TCG_CPU_MODEL
        and runtime["functional_kernel_arguments"]
        == expected_functional_kernel_arguments()
        and runtime["console_eof_observed"] is True
        and runtime["console_drain_timeout_seconds"]
        == FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS
        and runtime["forbidden_diagnostics_absent"] is True
        and runtime["isolation_claim"] is False,
        f"{label} runtime invariants differ",
    )
    _validated_functional_console(runtime, expected_markers, label)


def _require_exclusive_console_line_prefix(
    output: bytes,
    prefix: str,
    expected_line: str,
    label: str,
) -> None:
    prefix_bytes = prefix.encode("ascii")
    expected_bytes = expected_line.encode("ascii")
    matching = [
        line
        for _start, _end, line in _complete_console_line_spans(output)
        if line.startswith(prefix_bytes)
    ]
    _require_evidence(
        matching == [expected_bytes],
        f"{label} has a missing or conflicting {prefix} line",
    )


def _validate_ghidra_runtime_result(
    runtime: Any, label: str
) -> None:
    expected_markers = [
        OFFLINE_BOOT_LINE,
        CONSOLE_MARKER,
        GHIDRA_SEMANTIC_MARKER,
        GHIDRA_EXIT_SUCCESS_MARKER,
        GHIDRA_PASS_MARKER,
    ]
    _validate_runtime_result(runtime, expected_markers, label)
    output = _validated_functional_console(
        runtime, expected_markers, label
    )
    _require_exclusive_console_line_prefix(
        output,
        GHIDRA_SEMANTIC_MARKER,
        GHIDRA_SEMANTIC_MARKER,
        label,
    )
    _require_exclusive_console_line_prefix(
        output,
        GHIDRA_EXIT_LINE_PREFIX,
        GHIDRA_EXIT_SUCCESS_MARKER,
        label,
    )


def _validate_noxframe_runtime_result(
    runtime: Any, label: str
) -> None:
    expected_markers = [
        OFFLINE_BOOT_LINE,
        CONSOLE_MARKER,
        NOXFRAME_GHIDRA_SEMANTIC_MARKER,
        NOXFRAME_GHIDRA_MARKER,
        HOSTILE_NOXFRAME_MARKER,
    ]
    _validate_runtime_result(runtime, expected_markers, label)
    output = _validated_functional_console(runtime, expected_markers, label)
    _require_exclusive_console_line_prefix(
        output,
        NOXFRAME_GHIDRA_SEMANTIC_MARKER,
        NOXFRAME_GHIDRA_SEMANTIC_MARKER,
        label,
    )


def _validate_immutable_base(
    evidence: dict[str, Any], vector: dict[str, Any], label: str
) -> None:
    base_sha256 = vector["artifacts"]["base_image"]["sha256"]
    _require_evidence(
        evidence["base_image_sha256"] == base_sha256
        and evidence["base_image_sha256_before"] == base_sha256
        and evidence["base_image_sha256_after"] == base_sha256
        and evidence["base_image_unchanged"] is True,
        f"{label} immutable base-image proof differs",
    )


def hostile_resource_limits(vector: dict[str, Any]) -> dict[str, int]:
    base_size = vector["artifacts"]["base_image"]["size"]
    guest_memory = HOSTILE_MEMORY_MIB * 1024 * 1024
    return {
        "address_space_bytes": (
            guest_memory * 2 + HOSTILE_ADDRESS_SPACE_OVERHEAD_BYTES
        ),
        "locked_memory_bytes": 8 * 1024 * 1024,
        "file_size_bytes": base_size + HOSTILE_FILE_SIZE_OVERHEAD_BYTES,
        "open_files": 256,
        "processes": 2048,
        "core_bytes": 0,
    }


def _hostile_serialized_absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise LovelaceError(f"{label} must be a non-empty path string")
    if len(value) > 4096:
        raise LovelaceError(f"{label} is too long")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise LovelaceError(f"{label} contains a control character")
    if "\\" in value:
        raise LovelaceError(f"{label} contains a backslash")
    if "," in value:
        raise LovelaceError(f"{label} contains a QEMU option separator")
    if not value.startswith("/") or value.startswith("//"):
        raise LovelaceError(f"{label} is not an unambiguous absolute path")
    components = value.split("/")
    if any(
        component in {"", ".", ".."}
        for component in components[1:]
    ):
        raise LovelaceError(f"{label} contains an empty, dot, or traversal component")
    path = Path(value)
    if str(path) != value or Path(os.path.abspath(value)) != path:
        raise LovelaceError(f"{label} is not canonical")
    return path


def _validate_hostile_executable_record(
    record: Any, expected_path: str, label: str
) -> None:
    require_exact_keys(
        record,
        {
            "path",
            "size",
            "sha256",
            "mode",
            "uid",
            "gid",
            "device",
            "inode",
            "links",
            "mtime_ns",
            "ctime_ns",
            "setuid",
            "setgid",
            "executable",
            "version",
        },
        label,
    )
    mode_value = (
        int(record["mode"], 8)
        if isinstance(record["mode"], str)
        and re.fullmatch(r"[0-7]{4}", record["mode"]) is not None
        else -1
    )
    _require_evidence(
        record["path"] == expected_path
        and type(record["size"]) is int
        and record["size"] > 0
        and is_lower_hex(record["sha256"], 64)
        and isinstance(record["mode"], str)
        and re.fullmatch(r"[0-7]{4}", record["mode"]) is not None
        and type(record["uid"]) is int
        and record["uid"] == 0
        and type(record["gid"]) is int
        and record["gid"] >= 0
        and type(record["device"]) is int
        and record["device"] >= 0
        and type(record["inode"]) is int
        and record["inode"] > 0
        and type(record["links"]) is int
        and record["links"] >= 1
        and type(record["mtime_ns"]) is int
        and record["mtime_ns"] >= 0
        and type(record["ctime_ns"]) is int
        and record["ctime_ns"] >= 0
        and record["setuid"] is False
        and record["setgid"] is False
        and record["executable"] is True
        and mode_value & 0o022 == 0
        and mode_value & 0o111 != 0
        and isinstance(record["version"], str)
        and 0 < len(record["version"]) <= 300,
        f"{label} trust record is invalid",
    )


def _validate_hostile_evidence(
    evidence: dict[str, Any],
    manifest: dict[str, Any],
    vector: dict[str, Any],
    label: str,
) -> None:
    immutable_keys = {
        "base_image_sha256",
        "base_image_sha256_before",
        "base_image_sha256_after",
        "base_image_unchanged",
    }
    require_exact_keys(
        evidence,
        {
            "schema",
            "status",
            "artifact_vector",
            *immutable_keys,
            "profile",
            "execution_class",
            "storage",
            "network",
            "functional_accelerator",
            "isolation_claim",
            "claim_scope",
            "required_layers",
            "layers",
            "input_verification",
            "host",
            "launch_plan",
            "cleanup",
            "runtime",
            "claims",
            "non_claims",
        },
        label,
    )
    _validate_immutable_base(evidence, vector, label)
    _validate_input_verification(
        evidence["input_verification"], manifest, vector, label
    )
    expected_layers = list(HOSTILE_REQUIRED_LAYERS)
    _require_evidence(
        evidence["profile"] == "hostile"
        and evidence["execution_class"]
        == "defensive-untrusted-system-code"
        and evidence["storage"] == "volatile"
        and evidence["network"] == "none"
        and evidence["functional_accelerator"] == "kvm"
        and evidence["isolation_claim"] is True
        and evidence["claim_scope"]
        == "local-kvm-bwrap-layered-control-presence"
        and evidence["required_layers"] == expected_layers,
        f"{label} hostile execution identity differs",
    )
    require_exact_keys(evidence["layers"], HOSTILE_REQUIRED_LAYERS, label)
    _require_evidence(
        all(evidence["layers"][layer] is True for layer in HOSTILE_REQUIRED_LAYERS),
        f"{label} does not validate every required hostile layer",
    )

    host = evidence["host"]
    require_exact_keys(
        host,
        {
            "effective_uid",
            "kvm_device",
            "executables",
            "executables_stable_before_after",
        },
        f"{label} host",
    )
    _require_evidence(
        type(host["effective_uid"]) is int
        and host["effective_uid"] > 0
        and host["executables_stable_before_after"] is True,
        f"{label} hostile producer did not run unprivileged",
    )
    kvm = host["kvm_device"]
    require_exact_keys(
        kvm,
        {
            "path",
            "character_device",
            "root_owned",
            "device_major",
            "device_minor",
            "mode",
            "world_readable",
            "world_writable",
            "readable",
            "writable",
        },
        f"{label} KVM device",
    )
    _require_evidence(
        kvm["path"] == "/dev/kvm"
        and kvm["character_device"] is True
        and kvm["root_owned"] is True
        and kvm["device_major"] == 10
        and kvm["device_minor"] == 232
        and isinstance(kvm["mode"], str)
        and re.fullmatch(r"[0-7]{4}", kvm["mode"]) is not None
        and kvm["world_readable"] is False
        and kvm["world_writable"] is False
        and kvm["readable"] is True
        and kvm["writable"] is True,
        f"{label} KVM device record is invalid",
    )
    executables = host["executables"]
    require_exact_keys(
        executables,
        {"qemu", "qemu_img", "bubblewrap"},
        f"{label} host executables",
    )
    for name, path in {
        "qemu": "/usr/bin/qemu-system-x86_64",
        "qemu_img": "/usr/bin/qemu-img",
        "bubblewrap": "/usr/bin/bwrap",
    }.items():
        _validate_hostile_executable_record(
            executables[name], path, f"{label} {name}"
        )

    plan = evidence["launch_plan"]
    require_exact_keys(
        plan,
        {
            "schema",
            "source_plan_sha256",
            "profile",
            "storage",
            "network",
            "acceleration",
            "memory_mib",
            "cpus",
            "qemu_sandbox",
            "supervisor_paths",
            "artifact_digests",
            "namespace_flags",
            "outer_boundary",
            "empty_private_root",
            "root_read_only_after_setup",
            "host_network_namespace_unshared",
            "read_only_binding_count",
            "read_only_bindings_sha256",
            "writable_binding_purpose",
            "device_bindings",
            "host_resource_limits",
            "qemu_argv_sha256",
            "outer_argv_sha256",
            "materialized_plan",
            "network_device_absent",
            "persistent_disk_absent",
            "host_shares_absent",
            "host_device_passthrough_absent",
        },
        f"{label} launch plan",
    )
    expected_digests = {
        name: vector["artifacts"][name]["sha256"]
        for name in ("base_image", "kernel", "initramfs")
    }
    materialized = plan["materialized_plan"]
    require_exact_keys(
        materialized,
        {
            "schema",
            "decision",
            "argv_materialized",
            "profile",
            "supervisor",
            "inputs",
            "payload_ingress",
            "storage",
            "network",
            "acceleration",
            "resources",
            "controls",
            "outer_boundary",
            "host_resource_limits",
            "qemu_argv",
            "argv",
            "environment",
            "claims",
            "nonclaims",
        },
        f"{label} materialized plan",
    )
    materialized_outer = materialized["outer_boundary"]
    _require_evidence(
        isinstance(materialized_outer, dict)
        and isinstance(materialized.get("qemu_argv"), list)
        and isinstance(materialized.get("argv"), list)
        and isinstance(materialized_outer.get("read_only_bindings"), list),
        f"{label} materialized plan collections are invalid",
    )
    materialized_digests: dict[str, Any] = {}
    materialized_inputs = materialized.get("inputs")
    if isinstance(materialized_inputs, dict):
        for artifact_name, input_name in (
            ("base_image", "base_image"),
            ("kernel", "kernel"),
            ("initramfs", "initrd"),
        ):
            record = materialized_inputs.get(input_name)
            materialized_digests[artifact_name] = (
                record.get("sha256") if isinstance(record, dict) else None
            )
    _require_evidence(
        plan["schema"] == "wuci.lab.launch-plan.v1"
        and is_lower_hex(plan["source_plan_sha256"], 64)
        and plan["profile"] == "hostile"
        and plan["storage"] == "volatile"
        and plan["network"] == "none"
        and plan["acceleration"] == "kvm"
        and plan["memory_mib"] == HOSTILE_MEMORY_MIB
        and plan["cpus"] == HOSTILE_CPUS
        and plan["qemu_sandbox"]
        == (
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,"
            "resourcecontrol=deny"
        )
        and plan["supervisor_paths"]
        == {
            "qemu": "/usr/bin/qemu-system-x86_64",
            "qemu_img": "/usr/bin/qemu-img",
            "bubblewrap": "/usr/bin/bwrap",
        }
        and plan["artifact_digests"] == expected_digests
        and plan["namespace_flags"] == list(HOSTILE_BWRAP_FLAGS)
        and plan["outer_boundary"] == "bubblewrap"
        and plan["empty_private_root"] is True
        and plan["root_read_only_after_setup"] is True
        and plan["host_network_namespace_unshared"] is True
        and type(plan["read_only_binding_count"]) is int
        and plan["read_only_binding_count"] == 10
        and is_lower_hex(plan["read_only_bindings_sha256"], 64)
        and plan["writable_binding_purpose"]
        == "private volatile qcow2 overlay only"
        and plan["device_bindings"]
        == [{"source": "/dev/kvm", "destination": "/dev/kvm"}]
        and plan["host_resource_limits"] == hostile_resource_limits(vector)
        and is_lower_hex(plan["qemu_argv_sha256"], 64)
        and is_lower_hex(plan["outer_argv_sha256"], 64)
        and plan["network_device_absent"] is True
        and plan["persistent_disk_absent"] is True
        and plan["host_shares_absent"] is True
        and plan["host_device_passthrough_absent"] is True,
        f"{label} launch-plan controls differ",
    )
    _require_evidence(
        plan["source_plan_sha256"]
        == hashlib.sha256(canonical_json(materialized)).hexdigest()
        and plan["read_only_bindings_sha256"]
        == hashlib.sha256(
            canonical_json(materialized_outer["read_only_bindings"])
        ).hexdigest()
        and plan["qemu_argv_sha256"]
        == hashlib.sha256(
            canonical_json(materialized["qemu_argv"])
        ).hexdigest()
        and plan["outer_argv_sha256"]
        == hashlib.sha256(canonical_json(materialized["argv"])).hexdigest()
        and materialized["schema"] == plan["schema"]
        and materialized["decision"] == "launch-plan-valid"
        and materialized["argv_materialized"] is True
        and materialized["profile"] == plan["profile"]
        and isinstance(materialized["storage"], dict)
        and materialized["storage"].get("mode") == plan["storage"]
        and isinstance(materialized["network"], dict)
        and materialized["network"].get("mode") == plan["network"]
        and isinstance(materialized["acceleration"], dict)
        and materialized["acceleration"].get("selected")
        == plan["acceleration"]
        and isinstance(materialized["resources"], dict)
        and materialized["resources"].get("memory_mib")
        == plan["memory_mib"]
        and materialized["resources"].get("cpus") == plan["cpus"]
        and materialized_digests == plan["artifact_digests"]
        and isinstance(materialized["controls"], dict)
        and materialized["controls"].get("qemu_sandbox")
        == plan["qemu_sandbox"]
        and materialized_outer.get("supervisor")
        == plan["outer_boundary"]
        and materialized_outer.get("namespace_flags")
        == plan["namespace_flags"]
        and materialized_outer.get("empty_private_root")
        == plan["empty_private_root"]
        and materialized_outer.get("root_read_only_after_setup")
        == plan["root_read_only_after_setup"]
        and materialized_outer.get("host_network_namespace_unshared")
        == plan["host_network_namespace_unshared"]
        and len(materialized_outer["read_only_bindings"])
        == plan["read_only_binding_count"]
        and materialized_outer.get("device_bindings")
        == plan["device_bindings"]
        and materialized["host_resource_limits"]
        == plan["host_resource_limits"],
        f"{label} materialized plan does not match its summary",
    )
    qemu_binding = materialized_outer["read_only_bindings"][0]
    _require_evidence(
        isinstance(qemu_binding, dict),
        f"{label} QEMU read-only binding is invalid",
    )
    require_exact_keys(
        qemu_binding,
        {
            "source",
            "destination",
            "kind",
            "device",
            "inode",
            "links",
            "size",
            "mtime_ns",
            "ctime_ns",
            "mode",
        },
        f"{label} QEMU read-only binding",
    )
    host_qemu = host["executables"]["qemu"]
    _require_evidence(
        all(
            qemu_binding[field] == host_qemu[field]
            for field in (
                "device",
                "inode",
                "links",
                "size",
                "mtime_ns",
                "ctime_ns",
                "mode",
            )
        ),
        f"{label} QEMU process binding differs from the trusted executable",
    )

    _require_evidence(
        isinstance(materialized_inputs, dict),
        f"{label} materialized plan inputs are invalid",
    )
    try:
        serialized_paths = {
            "kernel": _hostile_serialized_absolute_path(
                materialized_inputs["kernel"]["path"],
                f"{label} serialized kernel",
            ),
            "initramfs": _hostile_serialized_absolute_path(
                materialized_inputs["initrd"]["path"],
                f"{label} serialized initrd",
            ),
            "base_image": _hostile_serialized_absolute_path(
                materialized_inputs["base_image"]["path"],
                f"{label} serialized base image",
            ),
        }
        reconstructed, _root_disk = hostile_plan_summary(
            materialized,
            serialized_paths,
            vector,
            REPO / "build/wuci-lab",
            inspect_artifacts=False,
        )
    except (KeyError, TypeError, LovelaceError) as exc:
        raise LovelaceError(
            f"{label} does not contain an exact canonical hostile launch "
            f"plan: {exc}"
        ) from exc
    reconstructed_summary = {
        key: value
        for key, value in reconstructed.items()
        if key != "materialized_plan"
    }
    recorded_summary = {
        key: value
        for key, value in plan.items()
        if key != "materialized_plan"
    }
    _require_evidence(
        reconstructed_summary == recorded_summary,
        f"{label} launch-plan summary was not independently reconstructed",
    )

    cleanup = evidence["cleanup"]
    require_exact_keys(
        cleanup,
        {
            "materialized_overlay_absent",
            "volatile_directory_unchanged",
            "entries_before_sha256",
            "entries_after_sha256",
            "normal_supervisor_unwind",
            "cleanup_after_sigkill_or_host_crash_claimed",
        },
        f"{label} cleanup",
    )
    _require_evidence(
        cleanup["materialized_overlay_absent"] is True
        and cleanup["volatile_directory_unchanged"] is True
        and is_lower_hex(cleanup["entries_before_sha256"], 64)
        and cleanup["entries_after_sha256"]
        == cleanup["entries_before_sha256"]
        and cleanup["normal_supervisor_unwind"] is True
        and cleanup["cleanup_after_sigkill_or_host_crash_claimed"] is False,
        f"{label} volatile cleanup proof differs",
    )

    runtime = evidence["runtime"]
    require_exact_keys(
        runtime,
        {
            "status",
            "supervisor_exit",
            "markers",
            "challenge",
            "command_results",
            "command_results_after_dispatch",
            "command_dispatch_offset",
            "challenge_generated_after_predispatch_validation",
            "challenge_absent_before_dispatch",
            "exact_boot_line_validated",
            "complete_result_lines_validated",
            "console_sha256",
            "console_transcript",
            "console_transcript_bytes",
            "console_transcript_complete",
            "console_tail",
            "forbidden_diagnostics_absent",
            "console_ready_timeout_seconds",
            "console_rendering",
            "console_forwarded_byte_allowlist",
            "non_allowlisted_console_bytes_forwarded",
            "console_sha256_scope",
            "plan_emitted_before_guest_console",
            "plan_validated_before_guest_command_dispatch",
            "qemu_process",
            "qemu_process_absent_after_supervisor_exit",
        },
        f"{label} runtime",
    )
    expected_markers = [BOOT_MARKER, CONSOLE_MARKER]
    challenge = runtime["challenge"]
    result_markers = [
        HOSTILE_NETWORK_MARKER,
        HOSTILE_WUCIJI_MARKER,
        HOSTILE_NOXFRAME_RESULT_MARKER,
        GHIDRA_SEMANTIC_MARKER,
        HOSTILE_GHIDRA_MARKER,
        HOSTILE_CELL_MARKER,
    ]
    expected_results = (
        [f"{marker} {challenge}" for marker in result_markers]
        if is_lower_hex(challenge, 64)
        else []
    )
    challenge_bytes = (
        challenge.encode("ascii")
        if is_lower_hex(challenge, 64)
        else b""
    )
    transcript = runtime["console_transcript"]
    _require_evidence(
        isinstance(transcript, str),
        f"{label} hostile transcript is not text",
    )
    reject_forbidden_hostile_transcript_text(transcript)
    transcript_bytes = transcript.encode("ascii")
    dispatch_offset = runtime["command_dispatch_offset"]
    _require_evidence(
        type(runtime["console_transcript_bytes"]) is int
        and runtime["console_transcript_bytes"] == len(transcript_bytes)
        and len(transcript_bytes) <= MAX_HOSTILE_CONSOLE_BYTES
        and runtime["console_transcript_complete"] is True
        and hashlib.sha256(transcript_bytes).hexdigest()
        == runtime["console_sha256"]
        and runtime["console_tail"] == transcript[-12000:]
        and type(dispatch_offset) is int
        and 0 < dispatch_offset <= len(transcript_bytes),
        f"{label} hostile complete transcript binding differs",
    )
    parsed_plan, emitted_before_console = (
        _parse_materialized_hostile_plan(transcript_bytes)
    )
    _require_evidence(
        emitted_before_console
        and parsed_plan == plan["materialized_plan"]
        and challenge_bytes
        and challenge_bytes not in transcript_bytes[:dispatch_offset]
        and challenge_bytes not in canonical_json(plan["materialized_plan"]),
        f"{label} hostile pre-dispatch transcript binding differs",
    )
    transcript_records = _hostile_complete_console_line_records(
        transcript_bytes
    )
    status_records = [
        (offset, line)
        for offset, line in transcript_records
        if line.startswith(GHIDRA_EXIT_LINE_PREFIX.encode("ascii"))
    ]
    semantic_records = [
        (offset, line)
        for offset, line in transcript_records
        if line.startswith(GHIDRA_SEMANTIC_MARKER.encode("ascii"))
    ]
    expected_semantic_line = (
        f"{GHIDRA_SEMANTIC_MARKER} {challenge}".encode("ascii")
        if is_lower_hex(challenge, 64)
        else b""
    )
    _require_evidence(
        [line for _offset, line in status_records]
        == [GHIDRA_EXIT_SUCCESS_MARKER.encode("ascii")]
        and [line for _offset, line in semantic_records]
        == [expected_semantic_line],
        f"{label} hostile Ghidra status or semantic line conflicts",
    )
    boot_records = [
        (offset, line)
        for offset, line in transcript_records
        if line == HOSTILE_BOOT_LINE.encode("ascii")
    ]
    ready_records = [
        (offset, line)
        for offset, line in transcript_records
        if line == CONSOLE_MARKER.encode("ascii")
    ]
    result_offsets = [
        [
            offset
            for offset, line in transcript_records
            if line == result.encode("ascii")
        ]
        for result in expected_results
    ]
    _require_evidence(
        len(boot_records) == 1
        and len(ready_records) == 1
        and (
            ready_records[0][0]
            + len(ready_records[0][1])
            + 1
            <= dispatch_offset
        )
        and all(
            len(offsets) == 1 and offsets[0] >= dispatch_offset
            for offsets in result_offsets
        )
        and [offsets[0] for offsets in result_offsets]
        == sorted(offsets[0] for offsets in result_offsets)
        and semantic_records[0][0]
        < status_records[0][0]
        < result_offsets[4][0],
        f"{label} hostile complete result-line binding differs",
    )
    reject_forbidden_guest_runtime_diagnostics(
        transcript, "hostile guest console"
    )
    process = runtime["qemu_process"]
    require_exact_keys(
        process,
        {
            "observed",
            "executable",
            "host_pid",
            "process_group_id",
            "session_id",
            "start_time_ticks",
            "executable_device",
            "executable_inode",
            "cmdline_sha256",
            "host_uids",
            "all_host_uids_equal_nonzero",
            "effective_capabilities_hex",
            "capabilities_empty",
            "no_new_privileges",
            "seccomp_mode",
            "seccomp_filters",
            "namespaces",
        },
        f"{label} QEMU process",
    )
    _require_evidence(
        runtime["status"] == "pass"
        and type(runtime["supervisor_exit"]) is int
        and runtime["supervisor_exit"] == 0
        and runtime["markers"] == expected_markers
        and is_lower_hex(challenge, 64)
        and runtime["command_results"] == expected_results
        and runtime["command_results_after_dispatch"] is True
        and runtime[
            "challenge_generated_after_predispatch_validation"
        ]
        is True
        and runtime["challenge_absent_before_dispatch"] is True
        and runtime["exact_boot_line_validated"] is True
        and runtime["complete_result_lines_validated"] is True
        and is_lower_hex(runtime["console_sha256"], 64)
        and isinstance(runtime["console_tail"], str)
        and len(runtime["console_tail"]) <= 12000
        and runtime["forbidden_diagnostics_absent"] is True
        and runtime["console_ready_timeout_seconds"]
        == HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS
        and runtime["console_rendering"] == "escaped-ascii"
        and runtime["console_forwarded_byte_allowlist"]
        == list(HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST)
        and runtime["non_allowlisted_console_bytes_forwarded"] is False
        and runtime["console_sha256_scope"]
        == "escaped-ascii-supervisor-transcript"
        and runtime["plan_emitted_before_guest_console"] is True
        and runtime["plan_validated_before_guest_command_dispatch"] is True
        and runtime["qemu_process_absent_after_supervisor_exit"] is True
        and process["observed"] is True
        and process["executable"] == "/usr/bin/qemu-system-x86_64"
        and type(process["host_pid"]) is int
        and process["host_pid"] > 0
        and type(process["process_group_id"]) is int
        and process["process_group_id"] > 0
        and type(process["session_id"]) is int
        and process["session_id"] > 0
        and type(process["start_time_ticks"]) is int
        and process["start_time_ticks"] > 0
        and process["executable_device"]
        == host["executables"]["qemu"]["device"]
        and process["executable_inode"]
        == host["executables"]["qemu"]["inode"]
        and process["cmdline_sha256"] == plan["qemu_argv_sha256"]
        and isinstance(process["host_uids"], list)
        and len(process["host_uids"]) == 4
        and all(type(uid) is int and uid > 0 for uid in process["host_uids"])
        and len(set(process["host_uids"])) == 1
        and process["all_host_uids_equal_nonzero"] is True
        and process["effective_capabilities_hex"] == "0000000000000000"
        and process["capabilities_empty"] is True
        and process["no_new_privileges"] is True
        and process["seccomp_mode"] == 2
        and type(process["seccomp_filters"]) is int
        and process["seccomp_filters"] >= 1,
        f"{label} hostile runtime observation differs",
    )
    namespaces = process["namespaces"]
    require_exact_keys(
        namespaces,
        {"mnt", "user", "pid", "ipc", "uts", "cgroup", "net"},
        f"{label} QEMU namespaces",
    )
    for name, record in namespaces.items():
        require_exact_keys(
            record,
            {"producer", "qemu", "different"},
            f"{label} QEMU {name} namespace",
        )
        _require_evidence(
            isinstance(record["producer"], str)
            and isinstance(record["qemu"], str)
            and _namespace_inode(name, record["producer"]) is not None
            and _namespace_inode(name, record["qemu"]) is not None
            and record["producer"] != record["qemu"]
            and record["different"] is True,
            f"{label} QEMU {name} namespace was not separated",
        )

    claims = evidence["claims"]
    _require_evidence(
        claims
        == {
            "authoritative_for_release": False,
            "production_ready_claimed": False,
            "perfect_isolation_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
            "hypervisor_escape_impossible_claimed": False,
            "side_channel_confidentiality_claimed": False,
        }
        and evidence["non_claims"] == list(HOSTILE_EVIDENCE_NONCLAIMS),
        f"{label} claim boundary differs",
    )


def _validate_hostile_payload_evidence(
    evidence: dict[str, Any],
    manifest: dict[str, Any],
    vector: dict[str, Any],
    label: str,
) -> None:
    immutable_keys = {
        "base_image_sha256",
        "base_image_sha256_before",
        "base_image_sha256_after",
        "base_image_unchanged",
    }
    require_exact_keys(
        evidence,
        {
            "schema",
            "status",
            "artifact_vector",
            *immutable_keys,
            "profile",
            "execution_class",
            "storage",
            "network",
            "functional_accelerator",
            "isolation_claim",
            "claim_scope",
            "required_layers",
            "layers",
            "input_verification",
            "host",
            "launch_plan",
            "guest_command_contract",
            "cleanup",
            "runtime",
            "claims",
            "non_claims",
        },
        label,
    )
    _validate_immutable_base(evidence, vector, label)
    _validate_input_verification(
        evidence["input_verification"], manifest, vector, label
    )
    expected_layers = list(HOSTILE_PAYLOAD_REQUIRED_LAYERS)
    _require_evidence(
        evidence["profile"] == "hostile"
        and evidence["execution_class"]
        == "fixed-benign-hostile-payload-ingress"
        and evidence["storage"] == "volatile"
        and evidence["network"] == "none"
        and evidence["functional_accelerator"] == "kvm"
        and evidence["isolation_claim"] is False
        and evidence["claim_scope"]
        == "local-kvm-bwrap-fixed-benign-read-only-payload-ingress"
        and evidence["required_layers"] == expected_layers,
        f"{label} hostile payload execution identity differs",
    )
    require_exact_keys(
        evidence["layers"], HOSTILE_PAYLOAD_REQUIRED_LAYERS, label
    )
    _require_evidence(
        all(
            evidence["layers"][layer] is True
            for layer in HOSTILE_PAYLOAD_REQUIRED_LAYERS
        ),
        f"{label} does not validate every hostile payload layer",
    )

    host = evidence["host"]
    require_exact_keys(
        host,
        {
            "effective_uid",
            "effective_gid",
            "kvm_device",
            "executables",
            "payload_tools",
            "executables_stable_before_after",
        },
        f"{label} host",
    )
    _require_evidence(
        type(host["effective_uid"]) is int
        and host["effective_uid"] > 0
        and type(host["effective_gid"]) is int
        and host["effective_gid"] >= 0
        and host["executables_stable_before_after"] is True,
        f"{label} hostile payload producer did not run unprivileged",
    )
    kvm = host["kvm_device"]
    require_exact_keys(
        kvm,
        {
            "path",
            "character_device",
            "root_owned",
            "device_major",
            "device_minor",
            "mode",
            "world_readable",
            "world_writable",
            "readable",
            "writable",
        },
        f"{label} KVM device",
    )
    _require_evidence(
        kvm["path"] == "/dev/kvm"
        and kvm["character_device"] is True
        and kvm["root_owned"] is True
        and kvm["device_major"] == 10
        and kvm["device_minor"] == 232
        and isinstance(kvm["mode"], str)
        and re.fullmatch(r"[0-7]{4}", kvm["mode"]) is not None
        and kvm["world_readable"] is False
        and kvm["world_writable"] is False
        and kvm["readable"] is True
        and kvm["writable"] is True,
        f"{label} KVM device record is invalid",
    )
    executables = host["executables"]
    require_exact_keys(
        executables,
        {"qemu", "qemu_img", "bubblewrap"},
        f"{label} host executables",
    )
    for name, path in {
        "qemu": "/usr/bin/qemu-system-x86_64",
        "qemu_img": "/usr/bin/qemu-img",
        "bubblewrap": "/usr/bin/bwrap",
    }.items():
        _validate_hostile_executable_record(
            executables[name], path, f"{label} {name}"
        )
    payload_tools = host["payload_tools"]
    require_exact_keys(
        payload_tools,
        {"mke2fs", "debugfs"},
        f"{label} payload tools",
    )
    for name, path in {
        "mke2fs": "/usr/sbin/mke2fs",
        "debugfs": "/usr/sbin/debugfs",
    }.items():
        _validate_hostile_executable_record(
            payload_tools[name], path, f"{label} payload {name}"
        )
        _require_evidence(
            payload_tools[name]["version"]
            == f"{name} {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)",
            f"{label} payload {name} version differs",
        )

    plan = evidence["launch_plan"]
    _require_evidence(
        isinstance(plan, dict)
        and isinstance(plan.get("materialized_plan"), dict),
        f"{label} launch plan is invalid",
    )
    materialized = plan["materialized_plan"]
    inputs = materialized.get("inputs")
    try:
        if not isinstance(inputs, dict):
            raise LovelaceError("materialized input map is invalid")
        serialized_paths = {
            "kernel": _hostile_serialized_absolute_path(
                inputs["kernel"]["path"], f"{label} serialized kernel"
            ),
            "initramfs": _hostile_serialized_absolute_path(
                inputs["initrd"]["path"], f"{label} serialized initrd"
            ),
            "base_image": _hostile_serialized_absolute_path(
                inputs["base_image"]["path"],
                f"{label} serialized base image",
            ),
        }
        reconstructed, _root_disk, _media_path = (
            hostile_payload_plan_summary(
                materialized,
                serialized_paths,
                vector,
                REPO / "build/wuci-lab",
                payload_tools,
                payload_uid=host["effective_uid"],
                payload_gid=host["effective_gid"],
                inspect_artifacts=False,
            )
        )
    except (KeyError, TypeError, LovelaceError) as exc:
        raise LovelaceError(
            f"{label} does not contain an exact canonical hostile payload "
            f"launch plan: {exc}"
        ) from exc
    _require_evidence(
        plan == reconstructed,
        f"{label} hostile payload launch-plan summary was not independently "
        "reconstructed",
    )
    qemu_binding = materialized["outer_boundary"]["read_only_bindings"][0]
    trusted_qemu = executables["qemu"]
    _require_evidence(
        all(
            qemu_binding[field] == trusted_qemu[field]
            for field in (
                "device",
                "inode",
                "links",
                "size",
                "mtime_ns",
                "ctime_ns",
                "mode",
            )
        ),
        f"{label} QEMU process binding differs from the trusted executable",
    )

    cleanup = evidence["cleanup"]
    require_exact_keys(
        cleanup,
        {
            "materialized_overlay_absent",
            "payload_media_absent",
            "volatile_directory_unchanged",
            "payload_directory_unchanged",
            "volatile_entries_before_sha256",
            "volatile_entries_after_sha256",
            "payload_entries_before_sha256",
            "payload_entries_after_sha256",
            "normal_supervisor_unwind",
            "cleanup_after_sigkill_or_host_crash_claimed",
        },
        f"{label} cleanup",
    )
    empty_snapshot = hashlib.sha256(canonical_json([])).hexdigest()
    _require_evidence(
        cleanup["materialized_overlay_absent"] is True
        and cleanup["payload_media_absent"] is True
        and cleanup["volatile_directory_unchanged"] is True
        and cleanup["payload_directory_unchanged"] is True
        and cleanup["volatile_entries_before_sha256"] == empty_snapshot
        and cleanup["volatile_entries_after_sha256"] == empty_snapshot
        and cleanup["payload_entries_before_sha256"] == empty_snapshot
        and cleanup["payload_entries_after_sha256"] == empty_snapshot
        and cleanup["normal_supervisor_unwind"] is True
        and cleanup["cleanup_after_sigkill_or_host_crash_claimed"] is False,
        f"{label} hostile payload cleanup proof differs",
    )

    runtime = evidence["runtime"]
    require_exact_keys(
        runtime,
        {
            "status",
            "supervisor_exit",
            "markers",
            "challenge",
            "command_results",
            "command_results_after_dispatch",
            "command_dispatch_offset",
            "challenge_generated_after_predispatch_validation",
            "challenge_absent_before_dispatch",
            "exact_boot_line_validated",
            "complete_result_lines_validated",
            "console_sha256",
            "console_transcript",
            "console_transcript_bytes",
            "console_transcript_complete",
            "console_tail",
            "forbidden_diagnostics_absent",
            "console_ready_timeout_seconds",
            "console_rendering",
            "console_forwarded_byte_allowlist",
            "non_allowlisted_console_bytes_forwarded",
            "console_sha256_scope",
            "plan_emitted_before_guest_console",
            "plan_validated_before_guest_command_dispatch",
            "qemu_process",
            "qemu_process_absent_after_supervisor_exit",
        },
        f"{label} runtime",
    )
    challenge = runtime["challenge"]
    expected_results = (
        [
            f"{marker} {challenge}"
            for marker in (
                HOSTILE_PAYLOAD_BYTES_MARKER,
                HOSTILE_PAYLOAD_MANIFEST_MARKER,
                HOSTILE_PAYLOAD_MARKER,
            )
        ]
        if is_lower_hex(challenge, 64)
        else []
    )
    _require_evidence(
        is_lower_hex(challenge, 64)
        and evidence["guest_command_contract"]
        == hostile_payload_guest_command_contract(challenge),
        f"{label} hostile payload guest-command contract differs",
    )
    transcript = runtime["console_transcript"]
    _require_evidence(
        isinstance(transcript, str),
        f"{label} hostile payload transcript is not text",
    )
    reject_forbidden_hostile_transcript_text(transcript)
    try:
        transcript_bytes = transcript.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LovelaceError(
            f"{label} hostile payload transcript is not escaped ASCII"
        ) from exc
    dispatch_offset = runtime["command_dispatch_offset"]
    _require_evidence(
        type(runtime["console_transcript_bytes"]) is int
        and runtime["console_transcript_bytes"] == len(transcript_bytes)
        and len(transcript_bytes) <= MAX_HOSTILE_CONSOLE_BYTES
        and runtime["console_transcript_complete"] is True
        and hashlib.sha256(transcript_bytes).hexdigest()
        == runtime["console_sha256"]
        and runtime["console_tail"] == transcript[-12000:]
        and type(dispatch_offset) is int
        and 0 < dispatch_offset <= len(transcript_bytes),
        f"{label} hostile payload complete transcript binding differs",
    )
    parsed_plan, emitted_before_console = _parse_materialized_hostile_plan(
        transcript_bytes
    )
    challenge_bytes = challenge.encode("ascii")
    _require_evidence(
        emitted_before_console
        and parsed_plan == materialized
        and challenge_bytes not in transcript_bytes[:dispatch_offset]
        and challenge_bytes not in canonical_json(materialized),
        f"{label} hostile payload pre-dispatch transcript binding differs",
    )
    records = _hostile_complete_console_line_records(transcript_bytes)
    boot_records = [
        (offset, line)
        for offset, line in records
        if line == HOSTILE_BOOT_LINE.encode("ascii")
    ]
    ready_records = [
        (offset, line)
        for offset, line in records
        if line == CONSOLE_MARKER.encode("ascii")
    ]
    result_offsets = [
        [
            offset
            for offset, line in records
            if line == result.encode("ascii")
        ]
        for result in expected_results
    ]
    payload_prefix = b"LOVELACE_HOSTILE_PAYLOAD_"
    payload_lines = [
        line for _offset, line in records if line.startswith(payload_prefix)
    ]
    _require_evidence(
        len(boot_records) == 1
        and len(ready_records) == 1
        and (
            ready_records[0][0] + len(ready_records[0][1]) + 1
            <= dispatch_offset
        )
        and all(
            len(offsets) == 1 and offsets[0] >= dispatch_offset
            for offsets in result_offsets
        )
        and [offsets[0] for offsets in result_offsets]
        == sorted(offsets[0] for offsets in result_offsets)
        and payload_lines
        == [result.encode("ascii") for result in expected_results],
        f"{label} hostile payload complete result-line binding differs",
    )
    reject_forbidden_guest_runtime_diagnostics(
        transcript, "hostile payload guest console"
    )

    process = runtime["qemu_process"]
    require_exact_keys(
        process,
        {
            "observed",
            "executable",
            "host_pid",
            "process_group_id",
            "session_id",
            "start_time_ticks",
            "executable_device",
            "executable_inode",
            "cmdline_sha256",
            "host_uids",
            "all_host_uids_equal_nonzero",
            "effective_capabilities_hex",
            "capabilities_empty",
            "no_new_privileges",
            "seccomp_mode",
            "seccomp_filters",
            "namespaces",
        },
        f"{label} QEMU process",
    )
    expected_markers = [BOOT_MARKER, CONSOLE_MARKER]
    _require_evidence(
        runtime["status"] == "pass"
        and type(runtime["supervisor_exit"]) is int
        and runtime["supervisor_exit"] == 0
        and runtime["markers"] == expected_markers
        and runtime["command_results"] == expected_results
        and runtime["command_results_after_dispatch"] is True
        and runtime[
            "challenge_generated_after_predispatch_validation"
        ]
        is True
        and runtime["challenge_absent_before_dispatch"] is True
        and runtime["exact_boot_line_validated"] is True
        and runtime["complete_result_lines_validated"] is True
        and is_lower_hex(runtime["console_sha256"], 64)
        and isinstance(runtime["console_tail"], str)
        and len(runtime["console_tail"]) <= 12000
        and runtime["forbidden_diagnostics_absent"] is True
        and runtime["console_ready_timeout_seconds"]
        == HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS
        and runtime["console_rendering"] == "escaped-ascii"
        and runtime["console_forwarded_byte_allowlist"]
        == list(HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST)
        and runtime["non_allowlisted_console_bytes_forwarded"] is False
        and runtime["console_sha256_scope"]
        == "escaped-ascii-supervisor-transcript"
        and runtime["plan_emitted_before_guest_console"] is True
        and runtime["plan_validated_before_guest_command_dispatch"] is True
        and runtime["qemu_process_absent_after_supervisor_exit"] is True
        and process["observed"] is True
        and process["executable"] == "/usr/bin/qemu-system-x86_64"
        and type(process["host_pid"]) is int
        and process["host_pid"] > 0
        and type(process["process_group_id"]) is int
        and process["process_group_id"] > 0
        and type(process["session_id"]) is int
        and process["session_id"] > 0
        and type(process["start_time_ticks"]) is int
        and process["start_time_ticks"] > 0
        and process["executable_device"] == executables["qemu"]["device"]
        and process["executable_inode"] == executables["qemu"]["inode"]
        and process["cmdline_sha256"] == plan["qemu_argv_sha256"]
        and process["host_uids"] == [host["effective_uid"]] * 4
        and process["all_host_uids_equal_nonzero"] is True
        and process["effective_capabilities_hex"] == "0000000000000000"
        and process["capabilities_empty"] is True
        and process["no_new_privileges"] is True
        and process["seccomp_mode"] == 2
        and type(process["seccomp_filters"]) is int
        and process["seccomp_filters"] >= 1,
        f"{label} hostile payload runtime observation differs",
    )
    namespaces = process["namespaces"]
    require_exact_keys(
        namespaces,
        {"mnt", "user", "pid", "ipc", "uts", "cgroup", "net"},
        f"{label} QEMU namespaces",
    )
    for name, record in namespaces.items():
        require_exact_keys(
            record,
            {"producer", "qemu", "different"},
            f"{label} QEMU {name} namespace",
        )
        _require_evidence(
            isinstance(record["producer"], str)
            and isinstance(record["qemu"], str)
            and _namespace_inode(name, record["producer"]) is not None
            and _namespace_inode(name, record["qemu"]) is not None
            and record["producer"] != record["qemu"]
            and record["different"] is True,
            f"{label} QEMU {name} namespace was not separated",
        )

    _require_evidence(
        evidence["claims"]
        == {
            "authoritative_for_release": False,
            "production_ready_claimed": False,
            "perfect_isolation_claimed": False,
            "safe_for_arbitrary_malware_claimed": False,
            "hypervisor_escape_impossible_claimed": False,
            "side_channel_confidentiality_claimed": False,
        }
        and evidence["non_claims"] == list(HOSTILE_EVIDENCE_NONCLAIMS),
        f"{label} hostile payload claim boundary differs",
    )


def validate_evidence_document(
    evidence: dict[str, Any],
    expected_schema: str,
    manifest: dict[str, Any],
    label: str,
) -> None:
    if not isinstance(evidence, dict):
        raise LovelaceError(f"{label} must be a JSON object")
    vector = canonical_artifact_vector(manifest)
    if evidence.get("schema") != expected_schema:
        raise LovelaceError(f"{label} schema differs from its contract")
    if evidence.get("status") != "pass":
        raise LovelaceError(f"{label} status is not pass")
    if evidence.get("artifact_vector") != vector:
        raise LovelaceError(f"{label} artifact vector differs")
    if expected_schema == VALIDATION_CONTRACT["hostile_kvm_cell"][
        "evidence_schema"
    ]:
        _validate_hostile_evidence(evidence, manifest, vector, label)
        return
    if expected_schema == VALIDATION_CONTRACT["hostile_payload_ingress"][
        "evidence_schema"
    ]:
        _validate_hostile_payload_evidence(
            evidence, manifest, vector, label
        )
        return

    immutable_keys = {
        "base_image_sha256",
        "base_image_sha256_before",
        "base_image_sha256_after",
        "base_image_unchanged",
    }
    common_runtime_keys = {
        "schema",
        "status",
        "artifact_vector",
        *immutable_keys,
        "functional_accelerator",
        "isolation_claim",
        "input_verification",
    }
    if expected_schema == "wucios.lovelace.boot_evidence.v1":
        require_exact_keys(
            evidence,
            common_runtime_keys | {"storage", "network", "runtime"},
            label,
        )
        _validate_immutable_base(evidence, vector, label)
        _require_evidence(
            evidence["storage"] == "volatile"
            and evidence["network"] == "none"
            and evidence["functional_accelerator"] == "tcg"
            and evidence["isolation_claim"] is False,
            f"{label} execution mode differs",
        )
        _validate_input_verification(
            evidence["input_verification"], manifest, vector, label
        )
        _validate_runtime_result(
            evidence["runtime"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                LANGUAGE_MARKER,
                WUCIJI_MARKER,
                NOXFRAME_MARKER,
                GHIDRA_PRESENT_MARKER,
            ],
            label,
        )
        return
    if expected_schema == "wucios.lovelace.ghidra_headless_evidence.v1":
        require_exact_keys(
            evidence,
            common_runtime_keys
            | {"storage", "network", "fixture", "ghidra", "runtime"},
            label,
        )
        _validate_immutable_base(evidence, vector, label)
        ghidra_lock = load_object(RELEASE_ROOT / "ghidra-lock.json")
        validate_ghidra_manifest_records(manifest, ghidra_lock)
        _require_evidence(
            evidence["storage"] == "volatile"
            and evidence["network"] == "none"
            and evidence["functional_accelerator"] == "tcg"
            and evidence["isolation_claim"] is False
            and evidence["fixture"] == manifest.get("ghidra_fixture")
            and evidence["ghidra"] == manifest.get("ghidra"),
            f"{label} Ghidra identity or execution mode differs",
        )
        _validate_input_verification(
            evidence["input_verification"], manifest, vector, label
        )
        _validate_ghidra_runtime_result(evidence["runtime"], label)
        return
    if expected_schema == "wucios.lovelace.noxframe_guest_evidence.v1":
        require_exact_keys(
            evidence,
            common_runtime_keys
            | {
                "storage",
                "network",
                "languages",
                "analysis_tools",
                "runtime",
            },
            label,
        )
        _validate_immutable_base(evidence, vector, label)
        _require_evidence(
            evidence["storage"] == "volatile"
            and evidence["network"] == "none"
            and evidence["languages"]
            == ["python3", "c", "cpp", "assembly", "rust", "go"]
            and evidence["analysis_tools"] == ["ghidra-headless"]
            and evidence["functional_accelerator"] == "tcg"
            and evidence["isolation_claim"] is False,
            f"{label} NOXFRAME identity or execution mode differs",
        )
        _validate_input_verification(
            evidence["input_verification"], manifest, vector, label
        )
        _validate_noxframe_runtime_result(evidence["runtime"], label)
        return
    if expected_schema == "wucios.lovelace.persistence_evidence.v1":
        require_exact_keys(
            evidence,
            common_runtime_keys
            | {
                "storage",
                "network",
                "proof_token_sha256",
                "first_boot",
                "second_boot",
            },
            label,
        )
        _validate_immutable_base(evidence, vector, label)
        token = hashlib.sha256(
            (
                "wucios-lovelace-persistent-round-trip-v1:"
                + evidence["base_image_sha256"]
            ).encode("ascii")
        ).hexdigest()
        _require_evidence(
            evidence["storage"] == "temporary-qcow2-round-trip-overlay"
            and evidence["network"] == "none"
            and evidence["proof_token_sha256"]
            == hashlib.sha256(token.encode("ascii")).hexdigest()
            and evidence["functional_accelerator"] == "tcg"
            and evidence["isolation_claim"] is False,
            f"{label} persistence identity or execution mode differs",
        )
        _validate_input_verification(
            evidence["input_verification"], manifest, vector, label
        )
        _validate_runtime_result(
            evidence["first_boot"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                "LOVELACE_PERSISTENT_WRITE_PASS",
            ],
            label,
        )
        _validate_runtime_result(
            evidence["second_boot"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                "LOVELACE_PERSISTENT_ROUND_TRIP_PASS",
            ],
            label,
        )
        return
    if expected_schema == "wucios.lovelace.network_evidence.v1":
        require_exact_keys(
            evidence,
            common_runtime_keys
            | {
                "storage",
                "network",
                "inbound_host_forwarding",
                "guest_listening_sockets",
                "guest_topology",
                "launch_contract",
                "https_probe",
                "timeouts",
                "runtime",
            },
            label,
        )
        _validate_immutable_base(evidence, vector, label)
        release, _seeds, _ghidra = configuration()
        expected_probe = network_probe_binding(release)
        expected_listener_observation = {
            "command": "ss -H -lntup",
            "command_succeeded": True,
            "observed": [],
            "scope": (
                "TCP/UDP listening sockets visible to the guest lab user"
            ),
        }
        expected_launch_contract = {
            "machine": "q35,accel=tcg",
            "accelerator": "tcg",
            "netdev": QEMU_USER_NETDEV,
            "network_device": QEMU_USER_NETWORK_DEVICE,
            "host_forwarding": False,
            "root_disk_format": "qcow2",
            "temporary_overlay": True,
            "base_image_directly_writable": False,
            "qemu_snapshot_flag": False,
        }
        _require_evidence(
            evidence["storage"] == "volatile"
            and evidence["network"] == "explicit-qemu-user-nat"
            and evidence["inbound_host_forwarding"] is False
            and evidence["guest_listening_sockets"]
            == expected_listener_observation
            and evidence["guest_topology"] == network_guest_topology()
            and evidence["launch_contract"] == expected_launch_contract
            and evidence["https_probe"] == expected_probe
            and evidence["timeouts"]
            == {
                "connect_seconds": NETWORK_CONNECT_TIMEOUT_SECONDS,
                "transfer_seconds": NETWORK_TRANSFER_TIMEOUT_SECONDS,
                "vm_seconds": NETWORK_VM_TIMEOUT_SECONDS,
            }
            and evidence["functional_accelerator"] == "tcg"
            and evidence["isolation_claim"] is False,
            f"{label} network identity or execution mode differs",
        )
        _validate_input_verification(
            evidence["input_verification"], manifest, vector, label
        )
        _validate_runtime_result(
            evidence["runtime"],
            [
                INTERNET_BOOT_LINE,
                CONSOLE_MARKER,
                "LOVELACE_EXPLICIT_INTERNET_PASS",
            ],
            label,
        )
        return
    if expected_schema == "wucios.lovelace.reproducibility_evidence.v1":
        require_exact_keys(
            evidence,
            {
                "schema",
                "status",
                "artifact_vector",
                "release_id",
                "independent_build_roots",
                "network_used",
                "source_inputs_unchanged_during_test",
                "byte_for_byte_equal",
                "base_image_sha256",
                "isolation_claim",
                "artifacts",
                "first_verification",
                "second_verification",
                "authoritative_for_release",
                "non_claims",
            },
            label,
        )
        comparisons = evidence["artifacts"]
        require_exact_keys(
            comparisons,
            {"base_image", "kernel", "initramfs", "manifest"},
            f"{label} artifact comparisons",
        )
        for name, comparison in comparisons.items():
            require_exact_keys(
                comparison,
                {"size", "sha256", "byte_for_byte_equal"},
                f"{label} {name} comparison",
            )
            _require_evidence(
                type(comparison["size"]) is int
                and comparison["size"] > 0
                and is_lower_hex(comparison["sha256"], 64)
                and comparison["byte_for_byte_equal"] is True,
                f"{label} {name} comparison is invalid",
            )
            if name != "manifest":
                artifact = vector["artifacts"][name]
                _require_evidence(
                    comparison["size"] == artifact["size"]
                    and comparison["sha256"] == artifact["sha256"],
                    f"{label} {name} comparison differs from artifact vector",
                )
        _require_evidence(
            evidence["release_id"] == vector["release_id"]
            and type(evidence["independent_build_roots"]) is int
            and evidence["independent_build_roots"] == 2
            and evidence["network_used"] is False
            and evidence["source_inputs_unchanged_during_test"] is True
            and evidence["byte_for_byte_equal"] is True
            and evidence["base_image_sha256"]
            == vector["artifacts"]["base_image"]["sha256"]
            and evidence["isolation_claim"] is False
            and evidence["authoritative_for_release"] is False
            and evidence["non_claims"] == manifest.get("non_claims"),
            f"{label} reproducibility invariants differ",
        )
        _validate_input_verification(
            evidence["first_verification"], manifest, vector, label
        )
        _validate_input_verification(
            evidence["second_verification"], manifest, vector, label
        )
        return
    raise LovelaceError(f"unsupported validation evidence schema: {expected_schema}")


def verify_validation_evidence(
    manifest: dict[str, Any], paths: dict[str, Path]
) -> dict[str, dict[str, Any]]:
    validation = manifest.get("validation")
    bindings = manifest.get("validation_evidence")
    if not isinstance(validation, dict) or not isinstance(bindings, dict):
        raise LovelaceError("validation and validation-evidence objects required")
    require_exact_keys(
        validation, set(VALIDATION_CONTRACT), "validation status"
    )
    require_exact_keys(
        bindings, set(VALIDATION_CONTRACT), "validation evidence bindings"
    )
    evidence_groups: dict[str, list[str]] = {}
    for field, contract in VALIDATION_CONTRACT.items():
        evidence_groups.setdefault(contract["evidence_path"], []).append(field)
    for evidence_path, fields in evidence_groups.items():
        measured = [validation[field] != "NOT_MEASURED" for field in fields]
        if any(measured) and not all(measured):
            raise LovelaceError(
                "validation fields sharing evidence must be promoted together: "
                f"{evidence_path}"
            )
    vector = canonical_artifact_vector(manifest)
    vector_sha256 = canonical_object_sha256(vector)
    expected_files: dict[str, dict[str, Any]] = {}
    verified: dict[str, dict[str, Any]] = {}
    for field, contract in VALIDATION_CONTRACT.items():
        status = validation.get(field)
        binding = bindings.get(field)
        if status == "NOT_MEASURED":
            if binding is not None:
                raise LovelaceError(
                    f"NOT_MEASURED validation field has evidence: {field}"
                )
            continue
        if status != contract["measured_status"]:
            raise LovelaceError(
                f"validation field has an unsupported status: {field}"
            )
        if not isinstance(binding, dict):
            raise LovelaceError(
                f"measured validation field lacks evidence binding: {field}"
            )
        _validate_evidence_binding_shape(
            binding,
            contract,
            vector,
            f"validation evidence binding {field}",
        )
        if binding["artifact_vector_sha256"] != vector_sha256:
            raise LovelaceError(
                f"validation evidence artifact vector differs: {field}"
            )
        previous = expected_files.get(contract["evidence_path"])
        if previous is not None and previous != binding:
            raise LovelaceError(
                "validation fields sharing evidence have inconsistent bindings"
            )
        expected_files[contract["evidence_path"]] = binding
        verified[field] = dict(binding)

    evidence_directory = paths["evidence"]
    observed_files: set[str] = set()
    if evidence_directory.exists() or evidence_directory.is_symlink():
        try:
            info = evidence_directory.lstat()
        except OSError as exc:
            raise LovelaceError(
                f"cannot inspect validation evidence directory: {exc}"
            ) from exc
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise LovelaceError(
                "validation evidence path must be a real directory"
            )
        for child in evidence_directory.iterdir():
            child_info = child.lstat()
            if (
                not stat.S_ISREG(child_info.st_mode)
                or stat.S_ISLNK(child_info.st_mode)
                or child_info.st_nlink != 1
            ):
                raise LovelaceError(
                    f"unexpected validation evidence entry: {child}"
                )
            observed_files.add(f"evidence/{child.name}")
    if observed_files != set(expected_files):
        raise LovelaceError(
            "validation evidence file set differs from manifest bindings"
        )
    for relative, binding in expected_files.items():
        evidence_path = paths["manifest"].parent / relative
        evidence_limit = validation_evidence_size_limit(binding["schema"])
        snapshot = _transaction_file_snapshot(
            evidence_path,
            "validation evidence",
            max_bytes=evidence_limit,
        )
        if snapshot["sha256"] != binding["sha256"]:
            raise LovelaceError(
                f"validation evidence digest differs: {relative}"
            )
        evidence = parse_json_object(
            snapshot["data"], os.fspath(evidence_path)
        )
        validate_evidence_document(
            evidence, binding["schema"], manifest, relative
        )
    return verified


def validate_static_build_records(manifest: dict[str, Any]) -> None:
    expected_overlay = overlay_source_manifest()
    if manifest["overlay"] != expected_overlay:
        raise LovelaceError(
            "build manifest overlay record differs from current sources"
        )

    native = manifest["native_wuci_ji"]
    require_exact_keys(
        native,
        {"path", "size", "sha256", "source", "sources", "host_tools"},
        "native Wuci-Ji build record",
    )
    if (
        native["path"] != "/usr/local/bin/wuci-ji"
        or type(native["size"]) is not int
        or native["size"] <= 0
        or native["size"] > MAX_NATIVE_WUCIJI_BYTES
        or not is_lower_hex(native["sha256"], 64)
        or native["source"]
        != "isolated direct GNU as/ld build from the working source tree"
        or native["sources"] != native_source_records()
        or native["host_tools"] != native_host_tool_records()
    ):
        raise LovelaceError("native Wuci-Ji build record differs")

    if manifest["java_home"] != EXPECTED_JAVA_HOME:
        raise LovelaceError("build manifest Java home differs")
    if manifest["busybox_runtime_links"] != [
        path for path, _target in BUSYBOX_RUNTIME_LINKS
    ]:
        raise LovelaceError("build manifest BusyBox links differ")
    expected_privileged = {
        "suid_sgid_removed": [],
        "single_justified_suid": DOAS_PATH,
        "final_setid_inventory": [{"path": DOAS_PATH, "mode": DOAS_MODE}],
        "justification": DOAS_JUSTIFICATION,
    }
    if manifest["privileged_files"] != expected_privileged:
        raise LovelaceError("build manifest privileged-file record differs")


def validate_embedded_runtime_source_inventory(
    manifest: dict[str, Any],
    inventory: dict[str, dict[str, Any]],
) -> tuple[PurePosixPath, str]:
    source_prefix = PurePosixPath("/opt/wuci-ji")
    expected_source_paths: dict[str, str] = {
        source_prefix.as_posix(): "directory"
    }
    for record in manifest["source_tree"]["files"]:
        guest = source_prefix / record["path"]
        for parent in guest.parents:
            if (
                parent == source_prefix
                or parent.as_posix().startswith(
                    source_prefix.as_posix() + "/"
                )
            ):
                if expected_source_paths.get(parent.as_posix()) not in {
                    None,
                    "directory",
                }:
                    raise LovelaceError(
                        "embedded runtime source parent collides with a leaf"
                    )
                expected_source_paths[parent.as_posix()] = "directory"
        guest_path = guest.as_posix()
        if guest_path in expected_source_paths:
            raise LovelaceError(
                f"embedded runtime source path collision: {guest_path}"
            )
        expected_source_paths[guest_path] = record["type"]
    native_guest_path = "/opt/wuci-ji/build/wuci-ji"
    for parent in PurePosixPath(native_guest_path).parents:
        if (
            parent == source_prefix
            or parent.as_posix().startswith(source_prefix.as_posix() + "/")
        ):
            if expected_source_paths.get(parent.as_posix()) not in {
                None,
                "directory",
            }:
                raise LovelaceError(
                    "embedded native parent collides with a source leaf"
                )
            expected_source_paths[parent.as_posix()] = "directory"
    if native_guest_path in expected_source_paths:
        raise LovelaceError("embedded native Wuci-Ji path collision")
    expected_source_paths[native_guest_path] = "regular"
    observed_source_paths = {
        path: record
        for path, record in inventory.items()
        if path == source_prefix.as_posix()
        or path.startswith(source_prefix.as_posix() + "/")
    }
    if set(observed_source_paths) != set(expected_source_paths):
        raise LovelaceError(
            "embedded runtime source subtree path set differs"
        )
    global_inode_paths: dict[int, list[str]] = {}
    for path, record in inventory.items():
        inode = record["inode"]
        global_inode_paths.setdefault(inode, []).append(path)
    observed_source_inodes: set[int] = set()
    for path, expected_type in expected_source_paths.items():
        embedded = observed_source_paths[path]
        if (
            embedded["type"] != expected_type
            or embedded["uid"] != 0
            or embedded["gid"] != 0
            or embedded["inode"] in observed_source_inodes
            or len(global_inode_paths.get(embedded["inode"], ())) != 1
            or (
                expected_type == "directory"
                and (
                    stat.S_IMODE(int(embedded["mode"], 8)) != 0o755
                    or embedded["size"] is not None
                )
            )
        ):
            raise LovelaceError(
                f"embedded runtime source subtree entry differs: {path}"
            )
        observed_source_inodes.add(embedded["inode"])
    return source_prefix, native_guest_path


def embedded_contract_bindings() -> list[dict[str, Any]]:
    release, _seeds, ghidra_lock = configuration()
    values = {
        "release.json": release,
        "profile.json": load_object(PROFILE_PATH),
        "package-lock.json": load_object(PACKAGE_LOCK_PATH),
        "ghidra-lock.json": ghidra_lock,
        "lovelace-runtime.json": runtime_marker(),
    }
    records: list[dict[str, Any]] = []
    for name in sorted(values):
        payload = canonical_json(values[name])
        records.append(
            {
                "path": f"/usr/share/wucios/{name}",
                "mode": 0o644,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return records


def validate_embedded_contract_bindings(
    image: Path | PinnedExt4Image,
    debugfs: Path,
    inventory: dict[str, dict[str, Any]],
    *,
    deadline: float | int | None = None,
) -> None:
    for record in embedded_contract_bindings():
        validate_ext4_regular_binding(
            image,
            debugfs,
            inventory,
            record["path"],
            expected_mode=record["mode"],
            expected_size=record["size"],
            expected_sha256=record["sha256"],
            label=f"embedded Lovelace contract {record['path']}",
            deadline=deadline,
        )


def validate_embedded_build_records(
    manifest: dict[str, Any],
    image: Path | PinnedExt4Image,
    debugfs: Path,
    path_inventory: Sequence[dict[str, Any]],
) -> None:
    inventory = ext4_inventory_by_path(path_inventory)
    debugfs_deadline = (
        time.monotonic() + MAX_EMBEDDED_DEBUGFS_VERIFICATION_SECONDS
    )
    for record in manifest["overlay"]["files"]:
        source = RELEASE_ROOT / "overlay" / record["path"]
        info = ensure_regular(
            source, "Lovelace overlay source", single_link=True
        )
        validate_ext4_regular_binding(
            image,
            debugfs,
            inventory,
            "/" + record["path"],
            expected_mode=int(record["mode"], 8),
            expected_size=info.st_size,
            expected_sha256=record["sha256"],
            label=f"embedded overlay file {record['path']}",
            deadline=debugfs_deadline,
        )

    source_prefix, native_guest_path = (
        validate_embedded_runtime_source_inventory(manifest, inventory)
    )

    for record in manifest["source_tree"]["files"]:
        guest_path = (source_prefix / record["path"]).as_posix()
        if record["type"] == "regular":
            validate_ext4_regular_binding(
                image,
                debugfs,
                inventory,
                guest_path,
                expected_mode=int(record["mode"], 8),
                expected_size=record["size"],
                expected_sha256=record["sha256"],
                label=f"embedded runtime source {record['path']}",
                deadline=debugfs_deadline,
            )
        elif record["type"] == "symlink":
            validate_ext4_symlink_binding(
                image,
                debugfs,
                inventory,
                guest_path,
                expected_target=record["target"],
                label=f"embedded runtime source {record['path']}",
                deadline=debugfs_deadline,
            )
        else:
            raise LovelaceError(
                "embedded runtime source record type is unsupported"
            )

    native = manifest["native_wuci_ji"]
    for guest_path in (
        native["path"],
        native_guest_path,
    ):
        validate_ext4_regular_binding(
            image,
            debugfs,
            inventory,
            guest_path,
            expected_mode=0o755,
            expected_size=native["size"],
            expected_sha256=native["sha256"],
            label=f"embedded native Wuci-Ji {guest_path}",
            deadline=debugfs_deadline,
        )

    validate_ext4_symlink_binding(
        image,
        debugfs,
        inventory,
        "/usr/lib/jvm/default-jvm",
        expected_target=PurePosixPath(EXPECTED_JAVA_HOME).name,
        label="embedded default Java home",
        deadline=debugfs_deadline,
    )
    java_binary = inventory.get(f"{EXPECTED_JAVA_HOME}/bin/java")
    if (
        java_binary is None
        or java_binary["type"] != "regular"
        or java_binary["uid"] != 0
        or java_binary["gid"] != 0
        or type(java_binary["size"]) is not int
        or java_binary["size"] <= 0
        or stat.S_IMODE(int(java_binary["mode"], 8)) & 0o111 == 0
    ):
        raise LovelaceError("embedded Java executable differs")

    for guest_path, target in BUSYBOX_RUNTIME_LINKS:
        validate_ext4_symlink_binding(
            image,
            debugfs,
            inventory,
            guest_path,
            expected_target=target,
            label=f"embedded BusyBox link {guest_path}",
            deadline=debugfs_deadline,
        )

    validate_embedded_contract_bindings(
        image,
        debugfs,
        inventory,
        deadline=debugfs_deadline,
    )

    fixture = manifest["ghidra_fixture"]
    validate_ext4_regular_binding(
        image,
        debugfs,
        inventory,
        fixture["source"],
        expected_mode=0o644,
        expected_size=fixture["source_size"],
        expected_sha256=fixture["source_sha256"],
        label="embedded Ghidra fixture source",
        deadline=debugfs_deadline,
    )
    validate_ext4_regular_binding(
        image,
        debugfs,
        inventory,
        fixture["binary"],
        expected_mode=0o755,
        expected_size=fixture["binary_size"],
        expected_sha256=fixture["binary_sha256"],
        label="embedded Ghidra fixture binary",
        deadline=debugfs_deadline,
    )
    final_setid = validate_final_setid_inventory(path_inventory)
    if final_setid != manifest["privileged_files"]["final_setid_inventory"]:
        raise LovelaceError(
            "embedded set-ID inventory differs from build manifest"
        )
    require_embedded_debugfs_deadline(debugfs_deadline)


def inspect_pinned_ext4_artifact(
    manifest: dict[str, Any],
    paths: dict[str, Path],
    release: dict[str, Any],
    ghidra: dict[str, Any],
    *,
    qemu_img: Path,
    e2fsck: Path,
    debugfs: Path,
) -> dict[str, Any]:
    """Read every ext4 verification fact through one immutable open fd."""
    with pinned_ext4_image(
        paths["base_image"], manifest["artifacts"]["base_image"]
    ) as pinned:
        qemu_info_result = run_bounded(
            [qemu_img, "info", "--output=json", pinned.child_path],
            timeout=120,
            pass_fds=pinned.pass_fds,
            max_stdout_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
            max_stderr_bytes=MAX_DEBUGFS_COMMAND_OUTPUT_BYTES,
        )
        try:
            qemu_info = json.loads(qemu_info_result.stdout)
        except json.JSONDecodeError as exc:
            raise LovelaceError("qemu-img returned invalid JSON") from exc
        check = run_bounded(
            [e2fsck, "-fn", pinned.child_path],
            timeout=600,
            check=False,
            pass_fds=pinned.pass_fds,
            max_stdout_bytes=8 * 1024 * 1024,
            max_stderr_bytes=8 * 1024 * 1024,
        )
        metadata_readback = ext4_metadata_readback(pinned)
        path_inventory = ext4_path_inventory(pinned, debugfs)
        reachable_inodes = sorted(
            {record["inode"] for record in path_inventory}
        )
        normalized_inodes = sorted(
            set(reachable_inodes) | set(range(1, 11))
        )
        timestamp_readback = ext4_inode_timestamp_readback(
            pinned,
            normalized_inodes,
            expected_epoch=release["source_date_epoch"],
        )
        inventory = ext4_inventory_by_path(path_inventory)
        if "/var/log/apk.log" in inventory:
            raise LovelaceError(
                "forbidden transient path is present: /var/log/apk.log"
            )
        required_executable_paths = (
            "/usr/local/bin/wuci-ji",
            "/usr/local/bin/noxframe",
            "/usr/local/bin/wuci-lab-run",
            "/opt/wucios/ghidra/support/analyzeHeadless",
            "/usr/bin/python3",
            "/usr/bin/cc",
            "/usr/bin/c++",
            "/usr/bin/rustc",
            "/usr/bin/go",
            "/usr/bin/java",
        )
        semantic_script_path = (
            f"{GHIDRA_SEMANTIC_SCRIPT_PATH}/"
            f"{GHIDRA_SEMANTIC_SCRIPT_NAME}"
        )
        if semantic_script_path not in inventory:
            raise LovelaceError(
                "required Ghidra semantic script is missing from image"
            )
        validate_required_runtime_executable_paths(
            pinned,
            debugfs,
            inventory,
            required_executable_paths,
        )
        validate_embedded_build_records(
            manifest,
            pinned,
            debugfs,
            path_inventory,
        )
        return {
            "qemu_info": qemu_info,
            "e2fsck_status": check.returncode,
            "metadata_readback": metadata_readback,
            "path_inventory": path_inventory,
            "reachable_inodes": reachable_inodes,
            "normalized_inodes": normalized_inodes,
            "timestamp_readback": timestamp_readback,
            "runtime_marker": runtime_marker(),
        }


def validated_root_tree_entry_count(value: Any) -> int:
    require_exact_keys(
        value,
        {"regular", "directory", "symlink", "owner_read_added"},
        "build manifest root tree counts",
    )
    if not (
        all(
            type(value[field]) is int and value[field] >= 0
            for field in (
                "regular",
                "directory",
                "symlink",
                "owner_read_added",
            )
        )
        and value["regular"] > 0
        and value["directory"] > 0
        and value["owner_read_added"] <= value["regular"]
    ):
        raise LovelaceError("build manifest root tree counts are invalid")
    staged_entries = (
        value["regular"] + value["directory"] + value["symlink"] - 1
    )
    if staged_entries > MAX_ROOT_TREE_ENTRIES:
        raise LovelaceError(
            "build manifest root tree counts exceed the entry ceiling"
        )
    return staged_entries


def validate_serialized_ext4_staged_tree_counts(
    path_inventory: Sequence[dict[str, Any]],
    root_counts: Any,
    staged_entry_count: Any,
) -> None:
    expected_staged_entry_count = validated_root_tree_entry_count(root_counts)
    if (
        type(staged_entry_count) is not int
        or staged_entry_count != expected_staged_entry_count
    ):
        raise LovelaceError(
            "serialized ext4 staged-entry count differs from root-tree counts"
        )
    lost_found_records = [
        record
        for record in path_inventory
        if isinstance(record, dict)
        and record.get("path") == "/lost+found"
    ]
    if len(lost_found_records) != 1:
        raise LovelaceError(
            "serialized ext4 inventory must contain exactly one canonical "
            "/lost+found directory"
        )
    inventory = ext4_inventory_by_path(path_inventory)
    validate_ext4_root_inventory_record(inventory.get("/"))
    expected_lost_found = {
        "path": "/lost+found",
        "inode": 11,
        "mode": "040700",
        "type": "directory",
        "uid": 0,
        "gid": 0,
        "size": None,
    }
    if lost_found_records[0] != expected_lost_found:
        raise LovelaceError(
            "serialized ext4 /lost+found metadata differs from the "
            "canonical mke2fs directory"
        )
    if any(path.startswith("/lost+found/") for path in inventory):
        raise LovelaceError(
            "serialized ext4 /lost+found directory is not empty"
        )
    staged_records = [
        record
        for path, record in inventory.items()
        if path != "/lost+found"
    ]
    observed_tree_counts = {
        entry_type: sum(
            record["type"] == entry_type for record in staged_records
        )
        for entry_type in ("regular", "directory", "symlink")
    }
    if (
        observed_tree_counts
        != {
            "regular": root_counts["regular"],
            "directory": root_counts["directory"],
            "symlink": root_counts["symlink"],
        }
        or len(staged_records) - 1 != staged_entry_count
    ):
        raise LovelaceError(
            "serialized ext4 path counts differ from the staged root tree"
        )


def _verify_build_locked(output: Path) -> dict[str, Any]:
    release, seeds, ghidra = configuration()
    qemu_img = trusted_host_tool("qemu-img")
    e2fsck = trusted_host_tool("e2fsck")
    debugfs = trusted_host_tool("debugfs")
    manifest, paths = artifact_paths(output)
    required_manifest = {
        "schema",
        "status",
        "builder",
        "release_id",
        "profile",
        "authoritative_for_release",
        "artifacts",
        "package_install",
        "input_snapshot",
        "package_lock_sha256",
        "overlay",
        "source_tree",
        "native_wuci_ji",
        "java_home",
        "busybox_runtime_links",
        "ghidra",
        "ghidra_fixture",
        "root_tree_counts",
        "privileged_files",
        "filesystem",
        "source_inputs",
        "defaults",
        "hostile_cell",
        "validation",
        "validation_evidence",
        "non_claims",
    }
    require_exact_keys(manifest, required_manifest, "build manifest")
    require_exact_keys(
        manifest["artifacts"],
        {"base_image", "kernel", "initramfs"},
        "build manifest artifacts",
    )
    require_exact_keys(
        manifest["validation"],
        set(VALIDATION_CONTRACT),
        "build manifest validation",
    )
    require_exact_keys(
        manifest["validation_evidence"],
        set(VALIDATION_CONTRACT),
        "build manifest validation evidence",
    )
    expected_staged_entry_count = validated_root_tree_entry_count(
        manifest["root_tree_counts"]
    )
    if (
        manifest["schema"] != "wucios.lovelace.build_manifest.v1"
        or manifest["status"] != "locally-built-non-authoritative"
        or manifest["builder"] != BUILDER_VERSION
        or manifest["release_id"] != release["release_id"]
        or manifest["profile"] != "lovelace-laboratory"
        or manifest["authoritative_for_release"] is not False
        or manifest["defaults"]
        != {
            "storage": "volatile",
            "network": "none",
            "noxframe": "metadata-only",
        }
        or manifest["hostile_cell"]
        != {
            "requires_kvm": True,
            "software_emulation_fallback": False,
            "network": "none",
            "storage": "volatile",
            "persistent_storage": False,
            "host_shares": False,
        }
        or manifest["non_claims"] != release["non_claims"]
    ):
        raise LovelaceError("build manifest identity or defaults are invalid")
    validate_manifest_artifact_locks(manifest, release)
    lock = load_object(PACKAGE_LOCK_PATH)
    validate_package_lock(lock, seeds)
    require_exact_keys(
        manifest["input_snapshot"],
        {
            "schema",
            "private_build_root",
            "network_used",
            "package_count",
            "package_bytes",
            "ghidra_bytes",
            "all_sizes_and_sha256_verified_while_copying",
            "transient_path_scan",
        },
        "build input snapshot",
    )
    transient_path_scan = manifest["input_snapshot"]["transient_path_scan"]
    require_exact_keys(
        transient_path_scan,
        {
            "schema",
            "status",
            "coverage",
            "regular_files_scanned",
            "directories_scanned",
            "symlinks_scanned",
            "xattrs_scanned",
            "bytes_scanned",
            "exact_plain_work_path_bytes_found",
        },
        "build transient-path scan",
    )
    expected_input_snapshot = {
        "schema": "wucios.lovelace.input_snapshot.v1",
        "private_build_root": True,
        "network_used": False,
        "package_count": lock["package_count"],
        "package_bytes": sum(record["size"] for record in lock["packages"]),
        "ghidra_bytes": ghidra["size"],
        "all_sizes_and_sha256_verified_while_copying": True,
        "transient_path_scan": transient_path_scan,
    }
    if (
        manifest["input_snapshot"] != expected_input_snapshot
        or transient_path_scan["schema"]
        != "wucios.lovelace.transient_path_scan.v2"
        or transient_path_scan["status"] != "pass"
        or transient_path_scan["coverage"]
        != [
            "regular-file-bytes",
            "symlink-target-bytes",
            "xattr-name-bytes",
            "xattr-value-bytes",
        ]
        or type(transient_path_scan["regular_files_scanned"]) is not int
        or transient_path_scan["regular_files_scanned"] <= 0
        or transient_path_scan["regular_files_scanned"]
        != manifest["root_tree_counts"]["regular"]
        or type(transient_path_scan["directories_scanned"]) is not int
        or transient_path_scan["directories_scanned"] <= 0
        or transient_path_scan["directories_scanned"]
        != manifest["root_tree_counts"]["directory"]
        or type(transient_path_scan["symlinks_scanned"]) is not int
        or transient_path_scan["symlinks_scanned"] < 0
        or transient_path_scan["symlinks_scanned"]
        != manifest["root_tree_counts"]["symlink"]
        or type(transient_path_scan["xattrs_scanned"]) is not int
        or transient_path_scan["xattrs_scanned"] < 0
        or type(transient_path_scan["bytes_scanned"]) is not int
        or transient_path_scan["bytes_scanned"] <= 0
        or transient_path_scan["bytes_scanned"]
        > MAX_TRANSIENT_PATH_SCAN_BYTES
        or transient_path_scan["exact_plain_work_path_bytes_found"] is not False
    ):
        raise LovelaceError("build input snapshot record is invalid")
    package_install = manifest["package_install"]
    require_exact_keys(
        package_install,
        {
            "package_count",
            "installed_identities_exact",
            "network_used",
            "package_scripts_executed",
            "apk_build_log_embedded",
            "stdout_tail",
        },
        "build manifest package install",
    )
    if not (
        package_install["package_count"] == lock["package_count"]
        and package_install["installed_identities_exact"] is True
        and package_install["network_used"] is False
        and package_install["package_scripts_executed"] is False
        and package_install["apk_build_log_embedded"] is False
        and isinstance(package_install["stdout_tail"], str)
        and len(package_install["stdout_tail"]) <= 2000
    ):
        raise LovelaceError("build manifest package install record is invalid")
    if manifest["package_lock_sha256"] != digest_file(PACKAGE_LOCK_PATH):
        raise LovelaceError("build manifest package lock binding drift")
    if manifest["source_inputs"] != source_inputs_manifest():
        raise LovelaceError(
            "build manifest source-input binding differs from the current tree"
        )
    if manifest["source_tree"] != runtime_source_manifest():
        raise LovelaceError(
            "embedded runtime source binding differs from the current tree"
        )
    validate_static_build_records(manifest)
    validate_ghidra_manifest_records(manifest, ghidra)
    for name in ("kernel", "initramfs"):
        record = manifest["artifacts"][name]
        verify_locked_file(paths[name], record, f"built {name}")
    ext4_observation = inspect_pinned_ext4_artifact(
        manifest,
        paths,
        release,
        ghidra,
        qemu_img=qemu_img,
        e2fsck=e2fsck,
        debugfs=debugfs,
    )
    qemu_info = ext4_observation["qemu_info"]
    check_status = ext4_observation["e2fsck_status"]
    if (
        not isinstance(qemu_info, dict)
        or qemu_info.get("format") != "raw"
        or qemu_info.get("virtual-size")
        != manifest["artifacts"]["base_image"]["size"]
    ):
        raise LovelaceError("base image is not the expected raw image")
    if check_status not in {0, 1}:
        raise LovelaceError("base image failed read-only e2fsck")
    filesystem = manifest["filesystem"]
    require_exact_keys(
        filesystem,
        {
            "format",
            "logical_size",
            "sha256",
            "label",
            "uuid",
            "block_size",
            "blocks_count",
            "inode_size",
            "inode_count",
            "features",
            "journal_size_mib",
            "staged_entry_count",
            "mke2fs_config",
            "host_tools",
            "metadata_normalization",
            "serialized_exact_path_scan",
            "mke2fs_stdout",
            "mke2fs_stderr",
            "e2fsck_status",
        },
        "build filesystem record",
    )
    require_exact_keys(
        filesystem["mke2fs_config"],
        {"path", "sha256"},
        "build mke2fs configuration record",
    )
    require_exact_keys(
        filesystem["host_tools"],
        {"mke2fs", "debugfs", "e2fsck", "fakeroot"},
        "build filesystem host tools",
    )
    expected_features = [
        "has_journal",
        "ext_attr",
        "resize_inode",
        "dir_index",
        "filetype",
        "extent",
        "64bit",
        "flex_bg",
        "sparse_super",
        "large_file",
        "huge_file",
        "dir_nlink",
        "extra_isize",
        "metadata_csum",
    ]
    expected_host_tools = {
        "mke2fs": host_tool_record(
            trusted_host_tool("mke2fs"),
            f"mke2fs {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)",
        ),
        "debugfs": host_tool_record(
            debugfs,
            f"debugfs {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)",
        ),
        "e2fsck": host_tool_record(
            e2fsck,
            f"e2fsck {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)",
        ),
        "fakeroot": host_tool_record(
            trusted_host_tool("fakeroot"),
            f"fakeroot version {EXPECTED_FAKEROOT_VERSION}",
        ),
    }
    root_counts = manifest["root_tree_counts"]
    if not (
        filesystem["format"] == "ext4"
        and filesystem["logical_size"]
        == release["filesystem"]["size_mib"] * 1024 * 1024
        == manifest["artifacts"]["base_image"]["size"]
        and filesystem["sha256"]
        == manifest["artifacts"]["base_image"]["sha256"]
        and filesystem["label"] == release["filesystem"]["label"]
        and filesystem["uuid"] == release["filesystem"]["uuid"]
        and filesystem["block_size"] == 4096
        and filesystem["blocks_count"]
        == filesystem["logical_size"] // 4096
        and filesystem["inode_size"] == 256
        and filesystem["inode_count"] == 524288
        and filesystem["features"] == expected_features
        and filesystem["journal_size_mib"] == 64
        and filesystem["staged_entry_count"]
        == expected_staged_entry_count
        and filesystem["mke2fs_config"]
        == {
            "path": MKE2FS_CONFIG_PATH.relative_to(REPO).as_posix(),
            "sha256": digest_file(MKE2FS_CONFIG_PATH),
        }
        and filesystem["host_tools"] == expected_host_tools
        and filesystem["mke2fs_stdout"] == ""
        and filesystem["mke2fs_stderr"] == ""
        and filesystem["e2fsck_status"] == check_status
    ):
        raise LovelaceError("build filesystem record differs")
    serialized_path_scan = manifest["filesystem"][
        "serialized_exact_path_scan"
    ]
    require_exact_keys(
        serialized_path_scan,
        {
            "schema",
            "bytes_scanned",
            "sha256",
            "exact_plain_work_path_bytes_found",
        },
        "serialized exact transient-path scan",
    )
    if serialized_path_scan != {
        "schema": "wucios.lovelace.serialized_exact_path_scan.v1",
        "bytes_scanned": manifest["artifacts"]["base_image"]["size"],
        "sha256": manifest["artifacts"]["base_image"]["sha256"],
        "exact_plain_work_path_bytes_found": False,
    }:
        raise LovelaceError(
            "serialized exact transient-path scan record is invalid"
        )
    normalization = manifest["filesystem"]["metadata_normalization"]
    require_exact_keys(
        normalization,
        {
            "normalized_inode_count",
            "reachable_inode_count",
            "reserved_inode_count",
            "timestamp_epoch",
            "directory_hash_seed",
            "allocated_inode_timestamp_fields_normalized",
            "extra_timestamp_bits_zeroed_where_present",
            "superblock_readback",
            "inode_timestamp_readback",
            "debugfs_stdout_tail",
        },
        "build ext4 metadata normalization",
    )
    metadata_readback = ext4_observation["metadata_readback"]
    path_inventory = ext4_observation["path_inventory"]
    validate_serialized_ext4_staged_tree_counts(
        path_inventory,
        root_counts,
        filesystem["staged_entry_count"],
    )
    reachable_inodes = ext4_observation["reachable_inodes"]
    normalized_inodes = ext4_observation["normalized_inodes"]
    timestamp_readback = ext4_observation["timestamp_readback"]
    expected_readback = {
        "filesystem_uuid": release["filesystem"]["uuid"],
        "directory_hash_seed": release["filesystem"]["uuid"],
        "mtime": 0,
        "wtime": release["source_date_epoch"],
        "lastcheck": release["source_date_epoch"],
        "mkfs_time": release["source_date_epoch"],
        "timestamp_high_bytes_zero": True,
        "allocated_inode_count": normalization["normalized_inode_count"],
    }
    if not (
        metadata_readback == expected_readback
        and normalization["superblock_readback"] == metadata_readback
        and type(normalization["normalized_inode_count"]) is int
        and normalization["normalized_inode_count"] > 10
        and type(normalization["reachable_inode_count"]) is int
        and normalization["reachable_inode_count"] > 0
        and normalization["reserved_inode_count"] == 10
        and normalization["normalized_inode_count"]
        == normalization["reachable_inode_count"] + 9
        and normalization["normalized_inode_count"] == len(normalized_inodes)
        and normalization["reachable_inode_count"] == len(reachable_inodes)
        and normalization["timestamp_epoch"] == release["source_date_epoch"]
        and normalization["directory_hash_seed"]
        == release["filesystem"]["uuid"]
        and normalization[
            "allocated_inode_timestamp_fields_normalized"
        ]
        is True
        and normalization[
            "extra_timestamp_bits_zeroed_where_present"
        ]
        is True
        and normalization["inode_timestamp_readback"]
        == timestamp_readback
        and isinstance(normalization["debugfs_stdout_tail"], str)
        and len(normalization["debugfs_stdout_tail"]) <= 1000
    ):
        raise LovelaceError(
            "build ext4 metadata normalization readback differs"
        )
    marker = ext4_observation["runtime_marker"]
    verified_evidence = verify_validation_evidence(manifest, paths)
    return {
        "schema": "wucios.lovelace.build_verification.v1",
        "status": "pass",
        "release_id": release["release_id"],
        "artifacts": manifest["artifacts"],
        "package_count": lock["package_count"],
        "offline_package_install": True,
        "base_image_read_only": True,
        "ext4_check": "pass",
        "runtime_marker": marker,
        "required_runtime_paths": "pass",
        "boot": manifest["validation"]["boot"],
        "ghidra_headless": manifest["validation"]["ghidra_headless"],
        "validation_evidence": verified_evidence,
        "authoritative_for_release": False,
        "non_claims": release["non_claims"],
    }


def verify_build(output: Path) -> dict[str, Any]:
    with output_lock(output):
        return _verify_build_locked(output)


def expected_release_kernel_arguments() -> list[str]:
    arguments = load_object(RELEASE_ROOT / "release.json")["boot"][
        "kernel_arguments"
    ]
    if (
        not isinstance(arguments, list)
        or not arguments
        or not all(
            isinstance(argument, str)
            and argument
            and " " not in argument
            for argument in arguments
        )
    ):
        raise LovelaceError(
            "release kernel arguments are invalid"
        )
    return list(arguments)


def expected_functional_kernel_arguments() -> list[str]:
    return [
        *expected_release_kernel_arguments(),
        *FUNCTIONAL_TCG_EXTRA_KERNEL_ARGUMENTS,
    ]


def qemu_argv(
    paths: dict[str, Path],
    manifest: dict[str, Any],
    *,
    disk: Path | None = None,
    disk_format: str = "raw",
    snapshot: bool = True,
    network: str = "none",
    memory_mib: int = 4096,
) -> list[str]:
    if disk_format not in {"raw", "qcow2"}:
        raise LovelaceError("QEMU disk format must be raw or qcow2")
    if network not in {"none", "internet"}:
        raise LovelaceError("QEMU network mode must be none or internet")
    root_disk = disk or paths["base_image"]
    drive = (
        f"file={root_disk},if=none,id=wuci-root,format={disk_format},"
        "cache=writeback,aio=threads"
    )
    if snapshot:
        drive += ",snapshot=on"
    argv = [
        str(trusted_host_tool("qemu-system-x86_64")),
        "-nodefaults",
        "-no-user-config",
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        TCG_CPU_MODEL,
        "-m",
        str(memory_mib),
        "-smp",
        "2",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-monitor",
        "none",
        "-nographic",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-kernel",
        str(paths["kernel"]),
        "-initrd",
        str(paths["initramfs"]),
        "-append",
        " ".join(expected_functional_kernel_arguments()),
        "-drive",
        drive,
        "-device",
        "virtio-blk-pci,drive=wuci-root,bootindex=1",
    ]
    if snapshot:
        argv.append("-snapshot")
    if network == "none":
        argv.extend(["-nic", "none"])
    else:
        argv.extend(
            [
                "-netdev",
                QEMU_USER_NETDEV,
                "-device",
                QEMU_USER_NETWORK_DEVICE,
            ]
        )
    return argv


def functional_qemu_cpu_model(argv: Sequence[str]) -> str:
    if (
        list(argv).count("-machine") != 1
        or list(argv).count("-cpu") != 1
    ):
        raise LovelaceError(
            "functional QEMU argv must bind one machine and one CPU model"
        )
    machine_index = list(argv).index("-machine")
    cpu_index = list(argv).index("-cpu")
    if (
        machine_index + 1 >= len(argv)
        or argv[machine_index + 1] != "q35,accel=tcg"
        or cpu_index + 1 >= len(argv)
        or argv[cpu_index + 1] != TCG_CPU_MODEL
    ):
        raise LovelaceError(
            "functional QEMU argv does not bind the pinned TCG CPU model"
        )
    return argv[cpu_index + 1]


def functional_qemu_kernel_arguments(argv: Sequence[str]) -> list[str]:
    if list(argv).count("-append") != 1:
        raise LovelaceError(
            "functional QEMU argv must bind one kernel argument vector"
        )
    append_index = list(argv).index("-append")
    if append_index + 1 >= len(argv):
        raise LovelaceError(
            "functional QEMU argv lacks its kernel argument vector"
        )
    arguments = argv[append_index + 1].split(" ")
    expected = expected_functional_kernel_arguments()
    if arguments != expected:
        raise LovelaceError(
            "functional QEMU argv does not bind the exact kernel arguments"
        )
    return arguments


def reject_forbidden_guest_runtime_diagnostics(
    console: str, context: str
) -> None:
    guest_diagnostics = [
        diagnostic
        for diagnostic in FORBIDDEN_GUEST_RUNTIME_DIAGNOSTICS
        if diagnostic in console
    ]
    if guest_diagnostics:
        raise LovelaceError(
            f"{context} emitted a forbidden kernel or storage diagnostic: "
            f"{guest_diagnostics}; console_tail={ascii(console[-12000:])}"
        )


def reject_forbidden_hostile_transcript_bytes(block: bytes) -> None:
    forbidden: list[dict[str, Any]] = []
    for index, value in enumerate(block):
        if value in {0x09, 0x0A} or 0x20 <= value <= 0x7E:
            continue
        forbidden.append({"offset": index, "byte": f"{value:02x}"})
        if len(forbidden) == 16:
            break
    if forbidden:
        raise LovelaceError(
            "hostile supervisor transcript contains raw terminal-control "
            f"or non-ASCII bytes: {forbidden}"
        )


def reject_forbidden_hostile_transcript_text(
    transcript: str,
) -> None:
    forbidden: list[dict[str, Any]] = []
    for index, value in enumerate(transcript):
        if value in {"\t", "\n"} or " " <= value <= "~":
            continue
        forbidden.append(
            {"offset": index, "codepoint": f"{ord(value):04x}"}
        )
        if len(forbidden) == 16:
            break
    if forbidden:
        raise LovelaceError(
            "hostile evidence transcript contains raw terminal-control "
            f"or non-ASCII characters: {forbidden}"
        )


def _hostile_complete_console_line_records(
    output: bytes,
) -> list[tuple[int, bytes]]:
    lines = output.split(b"\n")
    if not output.endswith(b"\n"):
        lines.pop()
    records: list[tuple[int, bytes]] = []
    offset = 0
    for line in lines:
        records.append((offset, line.removesuffix(b"\r")))
        offset += len(line) + 1
    return records


def _hostile_complete_console_lines(output: bytes) -> list[bytes]:
    return [
        line
        for _offset, line in _hostile_complete_console_line_records(output)
    ]


def _hostile_exact_console_line_present(
    output: bytes, marker: str
) -> bool:
    return marker.encode("ascii") in _hostile_complete_console_lines(output)


def reject_forbidden_tcg_diagnostics(console: str) -> None:
    qemu_diagnostics = [
        diagnostic
        for diagnostic in FORBIDDEN_TCG_DIAGNOSTICS
        if diagnostic in console
    ]
    if qemu_diagnostics:
        raise LovelaceError(
            "QEMU filtered the pinned functional TCG CPU model: "
            f"{qemu_diagnostics}; console_tail={ascii(console[-12000:])}"
        )
    reject_forbidden_guest_runtime_diagnostics(
        console, "functional guest"
    )


def _append_hostile_console_block(
    output: bytearray, block: bytes
) -> None:
    if not block:
        return
    reject_forbidden_hostile_transcript_bytes(block)
    overlap_bytes = max(
        len(diagnostic.encode("ascii"))
        for diagnostic in FORBIDDEN_GUEST_RUNTIME_DIAGNOSTICS
    ) - 1
    scan_start = max(0, len(output) - overlap_bytes)
    output.extend(block)
    if len(output) > MAX_HOSTILE_CONSOLE_BYTES:
        raise LovelaceError("hostile supervisor output exceeds 32 MiB")
    reject_forbidden_guest_runtime_diagnostics(
        output[scan_start:].decode("utf-8", errors="replace"),
        "hostile guest console",
    )


def _materialize_hostile_challenge_commands(
    command_factory: Callable[
        [str], tuple[Sequence[str], Sequence[str]]
    ],
    challenge: str,
) -> tuple[list[str], list[str]]:
    if not is_lower_hex(challenge, 64):
        raise LovelaceError("hostile dispatch challenge is invalid")
    value = command_factory(challenge)
    if not isinstance(value, tuple) or len(value) != 2:
        raise LovelaceError(
            "hostile command factory must return (commands, results)"
        )
    commands_value, results_value = value
    if (
        not isinstance(commands_value, Sequence)
        or isinstance(commands_value, (str, bytes))
        or not isinstance(results_value, Sequence)
        or isinstance(results_value, (str, bytes))
    ):
        raise LovelaceError(
            "hostile command factory returned invalid sequences"
        )
    commands = list(commands_value)
    results = list(results_value)
    if (
        not commands
        or len(commands) > 64
        or not all(
            isinstance(command, str)
            and command
            and len(command.encode("utf-8")) <= 65536
            and "\x00" not in command
            and "\r" not in command
            and "\n" not in command
            for command in commands
        )
        or sum(len(command.encode("utf-8")) + 1 for command in commands)
        > 1024 * 1024
    ):
        raise LovelaceError(
            "hostile command factory returned invalid or oversized commands"
        )
    if (
        not results
        or len(results) > 64
        or len(set(results)) != len(results)
        or not all(
            isinstance(result, str)
            and re.fullmatch(
                r"[A-Z0-9_]+ [0-9a-f]{64}", result
            )
            is not None
            and result.endswith(" " + challenge)
            for result in results
        )
    ):
        raise LovelaceError(
            "hostile command factory returned invalid challenge results"
        )
    payload = "\n".join(commands) + "\n"
    if challenge in payload or any(result in payload for result in results):
        raise LovelaceError(
            "hostile command payload discloses a complete challenge or "
            "acceptance result before guest processing"
        )
    return commands, results


def _append_functional_console_block(
    output: bytearray, block: bytes
) -> None:
    if not block:
        return
    output.extend(block)
    if len(output) > MAX_FUNCTIONAL_CONSOLE_BYTES:
        raise LovelaceError(
            "QEMU console output exceeds the functional "
            f"{MAX_FUNCTIONAL_CONSOLE_BYTES}-byte limit"
        )


def _drain_functional_console_to_eof(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    output: bytearray,
) -> None:
    if process.stdout is None:
        raise LovelaceError("QEMU stdout pipe is unavailable during drain")
    deadline = (
        time.monotonic() + FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS
    )
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        events = selector.select(timeout=min(0.1, max(0.0, remaining)))
        if not events:
            continue
        for key, _mask in events:
            block = os.read(key.fileobj.fileno(), 65536)
            if not block:
                return
            _append_functional_console_block(output, block)
    raise LovelaceError(
        "QEMU console did not reach EOF within the bounded "
        f"{FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS}-second drain"
    )


def run_qemu_commands(
    argv: list[str],
    commands: list[str],
    expected_markers: Sequence[str],
    *,
    timeout_seconds: int,
) -> dict[str, Any]:
    if (
        not isinstance(expected_markers, Sequence)
        or isinstance(expected_markers, (str, bytes))
        or len(expected_markers) < 3
        or expected_markers[0]
        not in {OFFLINE_BOOT_LINE, INTERNET_BOOT_LINE}
        or expected_markers[1] != CONSOLE_MARKER
        or len(set(expected_markers)) != len(expected_markers)
    ):
        raise LovelaceError("invalid functional QEMU marker contract")
    functional_cpu_model = functional_qemu_cpu_model(argv)
    functional_kernel_arguments = functional_qemu_kernel_arguments(argv)
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": "/tmp",
        "XDG_CONFIG_HOME": "/nonexistent",
    }
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    sent = False
    dispatch_offset: int | None = None
    console_ready_line_end_offset: int | None = None
    runtime_failure: Exception | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            cwd=REPO,
            env=environment,
            close_fds=True,
        )
    except OSError as exc:
        raise LovelaceError(
            "QEMU process launch failed: "
            f"{ascii(str(exc))}; console_tail=''"
        ) from exc
    try:
        if process.stdout is None or process.stdin is None:
            raise LovelaceError("QEMU stdio pipes were not created")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _mask in selector.select(timeout=1):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    break
                _append_functional_console_block(output, block)
            spans = _complete_console_line_spans(bytes(output))
            ready_matches = [
                record
                for record in spans
                if record[2] == CONSOLE_MARKER.encode("ascii")
            ]
            if len(ready_matches) > 1:
                raise LovelaceError(
                    "QEMU emitted the exact console-ready line more than once"
                )
            if not sent and ready_matches:
                boot_lines = [
                    record
                    for record in spans
                    if record[2].startswith(
                        (BOOT_MARKER + " ").encode("ascii")
                    )
                ]
                if (
                    len(boot_lines) != 1
                    or boot_lines[0][2]
                    != expected_markers[0].encode("ascii")
                    or boot_lines[0][0] >= ready_matches[0][0]
                ):
                    raise LovelaceError(
                        "QEMU reached console-ready without the exact "
                        "ordered functional boot line"
                    )
                premature = [
                    marker
                    for marker in expected_markers[2:]
                    if any(
                        record[2] == marker.encode("ascii")
                        for record in spans
                    )
                ]
                if premature:
                    raise LovelaceError(
                        "QEMU emitted command acceptance markers before "
                        f"host dispatch: {premature}"
                    )
                payload = ("\n".join(commands) + "\n").encode("utf-8")
                console_ready_line_end_offset = ready_matches[0][1]
                dispatch_offset = len(output)
                process.stdin.write(payload)
                process.stdin.flush()
                sent = True
            returncode = process.poll()
            if returncode is not None:
                _drain_functional_console_to_eof(
                    process, selector, output
                )
                break
        else:
            raise LovelaceError(
                f"QEMU boot test timed out after {timeout_seconds} seconds"
            )
    except (LovelaceError, OSError) as exc:
        runtime_failure = exc
    finally:
        try:
            if selector is not None:
                selector.close()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    text = output.decode("utf-8", errors="replace")
    try:
        if runtime_failure is not None:
            if isinstance(runtime_failure, LovelaceError):
                raise runtime_failure
            raise LovelaceError(
                "QEMU console I/O failed: "
                f"{ascii(str(runtime_failure))}"
            ) from runtime_failure
        reject_forbidden_tcg_diagnostics(text)
        if not sent:
            raise LovelaceError(
                "QEMU guest never reached the Lovelace boot marker; "
                f"qemu_exit={process.returncode}"
            )
        if dispatch_offset is None or console_ready_line_end_offset is None:
            raise LovelaceError("QEMU command dispatch was not recorded")
        if type(process.returncode) is not int or process.returncode != 0:
            raise LovelaceError(
                f"QEMU exited with status {process.returncode}"
            )
        result = {
            "status": "pass",
            "qemu_exit": process.returncode,
            "markers": list(expected_markers),
            **_functional_console_record(
                bytes(output),
                console_ready_line_end_offset=(
                    console_ready_line_end_offset
                ),
                command_dispatch_offset=dispatch_offset,
            ),
            "console_eof_observed": True,
            "console_drain_timeout_seconds": (
                FUNCTIONAL_CONSOLE_DRAIN_TIMEOUT_SECONDS
            ),
            "functional_accelerator": "tcg",
            "functional_cpu_model": functional_cpu_model,
            "functional_kernel_arguments": functional_kernel_arguments,
            "forbidden_diagnostics_absent": True,
            "isolation_claim": False,
        }
        _validate_runtime_result(
            result, expected_markers, "functional QEMU runtime"
        )
        return result
    except LovelaceError as exc:
        raise LovelaceError(
            f"{exc}; console_tail={ascii(text[-12000:])}"
        ) from exc


def _transaction_file_snapshot(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_INDEX_SIZE,
) -> dict[str, Any]:
    if type(max_bytes) is not int or max_bytes <= 0:
        raise LovelaceError(f"{label} has an invalid size limit")
    before = ensure_regular(path, label, single_link=True)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
            or opened.st_size > max_bytes
        ):
            raise LovelaceError(f"{label} changed or is too large")
        data = bytearray()
        while block := os.read(descriptor, 1024 * 1024):
            data.extend(block)
            if len(data) > max_bytes:
                raise LovelaceError(f"{label} exceeds the transaction limit")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} changed while snapshotting") from exc
    identity = lambda info: (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    opened_identity = identity(opened)
    if (
        len(data) != opened.st_size
        or opened_identity != identity(after)
        or opened_identity != identity(final)
    ):
        raise LovelaceError(f"{label} changed while snapshotting")
    raw = bytes(data)
    return {
        "data": raw,
        "identity": opened_identity,
        "mode": stat.S_IMODE(opened.st_mode),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _same_transaction_file(
    left: dict[str, Any], right: dict[str, Any]
) -> bool:
    return (
        left["identity"] == right["identity"]
        and left["mode"] == right["mode"]
        and left["sha256"] == right["sha256"]
        and left["data"] == right["data"]
    )


def _rollback_transaction_file(
    path: Path,
    previous: dict[str, Any] | None,
    written: dict[str, Any],
    label: str,
    *,
    max_bytes: int = MAX_INDEX_SIZE,
) -> None:
    current = _transaction_file_snapshot(
        path, f"current {label}", max_bytes=max_bytes
    )
    if not _same_transaction_file(current, written):
        raise LovelaceError(
            f"refusing {label} rollback because the committed file changed"
        )
    if previous is None:
        path.unlink()
        fsync_directory(path.parent)
        return
    try:
        noether_forge.atomic_write(
            path, previous["data"], mode=previous["mode"]
        )
    except noether_forge.NoetherForgeError as exc:
        raise LovelaceError(f"cannot restore prior {label}: {exc}") from exc
    restored = _transaction_file_snapshot(
        path, f"restored {label}", max_bytes=max_bytes
    )
    if (
        restored["data"] != previous["data"]
        or restored["sha256"] != previous["sha256"]
        or restored["mode"] != previous["mode"]
    ):
        raise LovelaceError(f"restored {label} differs from its snapshot")


def _commit_validation_transaction(
    output: Path,
    paths: dict[str, Path],
    manifest: dict[str, Any],
    evidence_path: Path,
    evidence: dict[str, Any],
) -> None:
    manifest_path = paths["manifest"]
    evidence_schema = evidence.get("schema")
    if not isinstance(evidence_schema, str):
        raise LovelaceError("validation evidence schema is required")
    evidence_limit = validation_evidence_size_limit(evidence_schema)
    desired_evidence = canonical_json(evidence)
    if len(desired_evidence) > evidence_limit:
        raise LovelaceError(
            "validation evidence exceeds its serialized size limit"
        )
    prior_manifest = _transaction_file_snapshot(
        manifest_path, "prior validation manifest"
    )
    if prior_manifest["data"] != canonical_json(
        parse_json_object(
            prior_manifest["data"], os.fspath(manifest_path)
        )
    ):
        raise LovelaceError("prior validation manifest is not canonical JSON")
    prior_evidence: dict[str, Any] | None = None
    if evidence_path.exists() or evidence_path.is_symlink():
        prior_evidence = _transaction_file_snapshot(
            evidence_path,
            "prior validation evidence",
            max_bytes=evidence_limit,
        )
    desired_manifest = canonical_json(manifest)
    written_evidence: dict[str, Any] | None = None
    written_manifest: dict[str, Any] | None = None
    try:
        write_json(evidence_path, evidence)
        written_evidence = _transaction_file_snapshot(
            evidence_path,
            "committed validation evidence",
            max_bytes=evidence_limit,
        )
        if written_evidence["data"] != desired_evidence:
            raise LovelaceError("committed validation evidence bytes differ")
        write_json(manifest_path, manifest)
        written_manifest = _transaction_file_snapshot(
            manifest_path, "committed validation manifest"
        )
        if written_manifest["data"] != desired_manifest:
            raise LovelaceError("committed validation manifest bytes differ")
        _verify_build_locked(output)
    except BaseException as primary:
        rollback_errors: list[str] = []
        if written_manifest is None:
            try:
                current_manifest = _transaction_file_snapshot(
                    manifest_path, "failed validation manifest"
                )
                if _same_transaction_file(current_manifest, prior_manifest):
                    current_manifest = None
                elif current_manifest["data"] == desired_manifest:
                    written_manifest = current_manifest
                else:
                    rollback_errors.append(
                        "validation manifest changed outside this transaction"
                    )
            except LovelaceError as exc:
                rollback_errors.append(str(exc))
        if written_manifest is not None:
            try:
                _rollback_transaction_file(
                    manifest_path,
                    prior_manifest,
                    written_manifest,
                    "validation manifest",
                )
            except (OSError, LovelaceError) as exc:
                rollback_errors.append(str(exc))
        if written_evidence is None:
            try:
                if evidence_path.exists() or evidence_path.is_symlink():
                    current_evidence = _transaction_file_snapshot(
                        evidence_path,
                        "failed validation evidence",
                        max_bytes=evidence_limit,
                    )
                    if prior_evidence is not None and _same_transaction_file(
                        current_evidence, prior_evidence
                    ):
                        current_evidence = None
                    elif current_evidence["data"] == desired_evidence:
                        written_evidence = current_evidence
                    else:
                        rollback_errors.append(
                            "validation evidence changed outside this transaction"
                        )
                elif prior_evidence is not None:
                    rollback_errors.append(
                        "prior validation evidence disappeared during transaction"
                    )
            except LovelaceError as exc:
                rollback_errors.append(str(exc))
        if written_evidence is not None:
            try:
                _rollback_transaction_file(
                    evidence_path,
                    prior_evidence,
                    written_evidence,
                    "validation evidence",
                    max_bytes=evidence_limit,
                )
            except (OSError, LovelaceError) as exc:
                rollback_errors.append(str(exc))
        if rollback_errors:
            raise LovelaceError(
                "validation update failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from primary
        raise


def _update_validation_unlocked(
    output: Path,
    updates: dict[str, str],
    evidence_name: str,
    evidence: dict[str, Any],
) -> None:
    manifest, paths = artifact_paths(output)
    verify_validation_evidence(manifest, paths)
    candidate_vector = canonical_artifact_vector(manifest)
    unknown = set(updates) - set(manifest["validation"])
    if unknown:
        raise LovelaceError(f"unknown validation fields: {sorted(unknown)}")
    if not updates:
        raise LovelaceError("validation update must not be empty")
    relative_evidence = f"evidence/{evidence_name}"
    expected_fields = {
        field
        for field, contract in VALIDATION_CONTRACT.items()
        if contract["evidence_path"] == relative_evidence
    }
    if set(updates) != expected_fields:
        raise LovelaceError(
            "validation update fields differ from the evidence contract"
        )
    schemas = {
        VALIDATION_CONTRACT[field]["evidence_schema"]
        for field in updates
    }
    if len(schemas) != 1:
        raise LovelaceError("validation evidence schema contract is ambiguous")
    evidence_schema = next(iter(schemas))
    validate_evidence_document(
        evidence, evidence_schema, manifest, relative_evidence
    )
    serialized_evidence = canonical_json(evidence)
    if len(serialized_evidence) > validation_evidence_size_limit(
        evidence_schema
    ):
        raise LovelaceError(
            "validation evidence exceeds its serialized size limit"
        )
    for field, status in updates.items():
        if status != VALIDATION_CONTRACT[field]["measured_status"]:
            raise LovelaceError(
                f"validation status differs from contract: {field}"
            )

    # This is the final artifact boundary before evidence and manifest commit.
    # Re-read and fully verify the release so a runtime result cannot promote a
    # kernel, initramfs, base image, package lock, or source tree that changed
    # after the runtime lane captured its artifact vector.
    verification = _verify_build_locked(output)
    manifest, paths = artifact_paths(output)
    current_vector = canonical_artifact_vector(manifest)
    if (
        current_vector != candidate_vector
        or verification["artifacts"] != current_vector["artifacts"]
    ):
        raise LovelaceError(
            "build artifacts changed before validation evidence commit"
        )
    validate_evidence_document(
        evidence, evidence_schema, manifest, relative_evidence
    )
    base_sha256 = current_vector["artifacts"]["base_image"]["sha256"]
    manifest["validation"].update(updates)
    paths["evidence"].mkdir(parents=True, exist_ok=True)
    evidence_path = paths["evidence"] / evidence_name
    binding = {
        "path": relative_evidence,
        "sha256": hashlib.sha256(serialized_evidence).hexdigest(),
        "schema": evidence_schema,
        "base_image_sha256": base_sha256,
        "artifact_vector_sha256": canonical_object_sha256(current_vector),
    }
    for field in updates:
        manifest["validation_evidence"][field] = dict(binding)
    _commit_validation_transaction(
        output, paths, manifest, evidence_path, evidence
    )


def update_validation(
    output: Path,
    updates: dict[str, str],
    evidence_name: str,
    evidence: dict[str, Any],
) -> None:
    with output_lock(output):
        _update_validation_unlocked(
            output, updates, evidence_name, evidence
        )


def compare_reproducible_files(
    first: Path, second: Path, label: str
) -> dict[str, Any]:
    first_info = ensure_regular(first, f"first {label}", single_link=False)
    second_info = ensure_regular(second, f"second {label}", single_link=False)
    if first_info.st_size != second_info.st_size:
        raise LovelaceError(
            f"independent {label} sizes differ: "
            f"{first_info.st_size} != {second_info.st_size}"
        )
    first_sha256 = digest_file(first)
    second_sha256 = digest_file(second)
    if first_sha256 != second_sha256:
        raise LovelaceError(
            f"independent {label} SHA-256 digests differ: "
            f"{first_sha256} != {second_sha256}"
        )
    comparison = run(
        [trusted_host_tool("cmp"), "-s", "--", first, second],
        timeout=3600,
        check=False,
    )
    if comparison.returncode != 0:
        raise LovelaceError(
            f"independent {label} bytes differ despite digest comparison"
        )
    return {
        "size": first_info.st_size,
        "sha256": first_sha256,
        "byte_for_byte_equal": True,
    }


def _reproducibility_test_unlocked(
    cache: Path, output: Path
) -> dict[str, Any]:
    source_inputs_before = source_inputs_manifest()
    runtime_sources_before = runtime_source_manifest()
    _build_unlocked(cache, output)
    first_verification = evidence_input_verification_snapshot(
        _verify_build_locked(output)
    )
    first_manifest, first_paths = artifact_paths(output)
    first_vector = canonical_artifact_vector(first_manifest)
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-reproducibility.", dir="/tmp"
    ) as temporary:
        second_output = Path(temporary) / "second"
        build(cache, second_output)
        second_verification = evidence_input_verification_snapshot(
            verify_build(second_output)
        )
        second_manifest, second_paths = artifact_paths(second_output)
        second_vector = canonical_artifact_vector(second_manifest)
        if second_vector != first_vector:
            raise LovelaceError(
                "independent build artifact vectors differ"
            )
        if (
            source_inputs_manifest() != source_inputs_before
            or runtime_source_manifest() != runtime_sources_before
        ):
            raise LovelaceError(
                "source inputs changed during independent rebuilds"
            )
        comparisons = {
            name: compare_reproducible_files(
                first_paths[name],
                second_paths[name],
                name.replace("_", " "),
            )
            for name in ("base_image", "kernel", "initramfs", "manifest")
        }
    evidence = {
        "schema": "wucios.lovelace.reproducibility_evidence.v1",
        "status": "pass",
        "artifact_vector": first_vector,
        "release_id": first_manifest["release_id"],
        "independent_build_roots": 2,
        "network_used": False,
        "source_inputs_unchanged_during_test": True,
        "byte_for_byte_equal": True,
        "base_image_sha256": comparisons["base_image"]["sha256"],
        "isolation_claim": False,
        "artifacts": comparisons,
        "first_verification": first_verification,
        "second_verification": second_verification,
        "authoritative_for_release": False,
        "non_claims": first_manifest["non_claims"],
    }
    _update_validation_unlocked(
        output,
        {"reproducible_build": "locally-validated-byte-for-byte"},
        "reproducibility.json",
        evidence,
    )
    return evidence


def reproducibility_test(cache: Path, output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    require_real_directory(output, "Lovelace output root")
    with output_lock(output):
        return _reproducibility_test_unlocked(cache, output)


def create_temporary_overlay(
    base_image: Path, directory: Path
) -> Path:
    qemu_img = trusted_host_tool("qemu-img")
    require_real_directory(directory, "temporary overlay directory")
    base_before = ensure_regular(
        base_image, "temporary overlay base image", single_link=True
    )
    try:
        canonical_base = base_image.resolve(strict=True)
    except OSError as exc:
        raise LovelaceError(
            "temporary overlay base image cannot be resolved"
        ) from exc
    base_after = ensure_regular(
        canonical_base, "resolved temporary overlay base image", single_link=True
    )
    if (
        (base_before.st_dev, base_before.st_ino)
        != (base_after.st_dev, base_after.st_ino)
    ):
        raise LovelaceError(
            "temporary overlay base image changed while resolving"
        )
    overlay = directory / "volatile-root.qcow2"
    run(
        [
            qemu_img,
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            "raw",
            "-b",
            canonical_base,
            overlay,
        ],
        timeout=120,
    )
    ensure_regular(overlay, "temporary volatile overlay")
    os.chmod(overlay, 0o600)
    info = run(
        [qemu_img, "info", "--output=json", overlay], timeout=120
    )
    try:
        value = json.loads(info.stdout)
    except json.JSONDecodeError as exc:
        raise LovelaceError("temporary overlay qemu-img output invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("format") != "qcow2"
        or value.get("full-backing-filename") != str(canonical_base)
        or value.get("backing-filename-format") != "raw"
    ):
        raise LovelaceError("temporary overlay backing binding is invalid")
    return overlay


def _boot_test_unlocked(output: Path) -> dict[str, Any]:
    verification = evidence_input_verification_snapshot(
        _verify_build_locked(output)
    )
    manifest, paths = artifact_paths(output)
    vector = canonical_artifact_vector(manifest)
    before = digest_file(paths["base_image"])
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-boot.", dir="/tmp"
    ) as temporary:
        overlay = create_temporary_overlay(
            paths["base_image"], Path(temporary)
        )
        argv = qemu_argv(
            paths,
            manifest,
            disk=overlay,
            disk_format="qcow2",
            snapshot=False,
            network="none",
        )
        result = run_qemu_commands(
            argv,
            ["wuci-lab-smoke", "doas poweroff -f"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                LANGUAGE_MARKER,
                WUCIJI_MARKER,
                NOXFRAME_MARKER,
                GHIDRA_PRESENT_MARKER,
            ],
            timeout_seconds=1200,
        )
    after = digest_file(paths["base_image"])
    if after != before:
        raise LovelaceError("volatile boot changed the immutable base image")
    evidence = {
        "schema": "wucios.lovelace.boot_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": before,
        "base_image_sha256_before": before,
        "base_image_sha256_after": after,
        "base_image_unchanged": True,
        "storage": "volatile",
        "network": "none",
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "input_verification": verification,
        "runtime": result,
    }
    _update_validation_unlocked(
        output,
        {
            "boot": "locally-validated-tcg-functional-only",
            "language_matrix": "locally-validated",
        },
        "boot-test.json",
        evidence,
    )
    return evidence


def boot_test(output: Path) -> dict[str, Any]:
    with output_lock(output):
        return _boot_test_unlocked(output)


def ghidra_smoke_command(
    *,
    project_name: str,
    temporary_prefix: str,
    timeout_seconds: int,
    success_marker: str,
    challenge: str | None = None,
) -> str:
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", project_name) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", temporary_prefix)
        is None
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 3600
        or re.fullmatch(r"[A-Z0-9_]+", success_marker) is None
        or (
            challenge is not None
            and not is_lower_hex(challenge, 64)
        )
    ):
        raise LovelaceError("invalid Ghidra smoke command binding")
    if challenge is None:
        split = len(success_marker) // 2
        success_command = (
            "printf '\\n%s%s\\n' "
            f"'{success_marker[:split]}' '{success_marker[split:]}'"
        )
        semantic_arguments = ""
    else:
        success_command = _challenge_result_command(
            success_marker, challenge
        )
        challenge_split = len(challenge) // 2
        semantic_arguments = (
            f" '{challenge[:challenge_split]}' "
            f"'{challenge[challenge_split:]}'"
        )
    return (
        "(set -eu; umask 077; "
        f"work=$(mktemp -d /tmp/{temporary_prefix}.XXXXXX); "
        "trap 'rm -rf -- \"$work\"' EXIT HUP INT TERM; "
        "mkdir -m 700 \"$work/projects\" \"$work/home\" "
        "\"$work/config\" \"$work/cache\" \"$work/tmp\"; "
        "test ! -e /home/lab/.config/ghidra; "
        "test ! -e /var/tmp/lab-ghidra; "
        "set +e; "
        "timeout --signal=TERM "
        f"--kill-after={GHIDRA_PROCESS_KILL_GRACE_SECONDS} "
        f"{timeout_seconds} env "
        "HOME=\"$work/home\" XDG_CONFIG_HOME=\"$work/config\" "
        "XDG_CACHE_HOME=\"$work/cache\" TMPDIR=\"$work/tmp\" "
        f"GHIDRA_HEADLESS_MAXMEM={GHIDRA_HEADLESS_MAXMEM} "
        f"JAVA_TOOL_OPTIONS=\"{GHIDRA_JAVA_COMPILER_OPTION} "
        "-Duser.home=$work/home "
        "-Djava.io.tmpdir=$work/tmp\" ghidra-headless "
        f"\"$work/projects\" {project_name} "
        "-import /usr/share/wucios/fixtures/ghidra/ghidra-smoke "
        f"-overwrite -scriptPath {GHIDRA_SEMANTIC_SCRIPT_PATH} "
        f"-postScript {GHIDRA_SEMANTIC_SCRIPT_NAME}"
        f"{semantic_arguments} -deleteProject </dev/null; "
        "status=$?; set -e; "
        "printf '\\n%s%s%s\\n' 'LOVELACE_GHIDRA_' "
        "'HEADLESS_EXIT status=' \"$status\"; "
        "test \"$status\" -eq 0; "
        "test ! -e /home/lab/.config/ghidra; "
        "test ! -e /var/tmp/lab-ghidra; "
        "find \"$work/projects\" -mindepth 1 -print -quit "
        "> \"$work/project-remnants\"; "
        "test ! -s \"$work/project-remnants\"; "
        "rm -f -- \"$work/project-remnants\"; "
        "rm -rf -- \"$work\"; test ! -e \"$work\"; "
        "trap - EXIT HUP INT TERM; "
        f"{success_command})"
    )


def _ghidra_test_unlocked(output: Path) -> dict[str, Any]:
    verification = evidence_input_verification_snapshot(
        _verify_build_locked(output)
    )
    manifest, paths = artifact_paths(output)
    vector = canonical_artifact_vector(manifest)
    before = digest_file(paths["base_image"])
    command = ghidra_smoke_command(
        project_name="lovelace-smoke",
        temporary_prefix="wuci-ghidra",
        timeout_seconds=GHIDRA_PROCESS_TIMEOUT_SECONDS,
        success_marker=GHIDRA_PASS_MARKER,
    )
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-ghidra.", dir="/tmp"
    ) as temporary:
        overlay = create_temporary_overlay(
            paths["base_image"], Path(temporary)
        )
        argv = qemu_argv(
            paths,
            manifest,
            disk=overlay,
            disk_format="qcow2",
            snapshot=False,
            network="none",
            memory_mib=GHIDRA_VM_MEMORY_MIB,
        )
        result = run_qemu_commands(
            argv,
            [command, "doas poweroff -f"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                GHIDRA_SEMANTIC_MARKER,
                GHIDRA_EXIT_SUCCESS_MARKER,
                GHIDRA_PASS_MARKER,
            ],
            timeout_seconds=GHIDRA_VM_TIMEOUT_SECONDS,
        )
    after = digest_file(paths["base_image"])
    if before != after:
        raise LovelaceError("Ghidra test changed the immutable base image")
    evidence = {
        "schema": "wucios.lovelace.ghidra_headless_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": before,
        "base_image_sha256_before": before,
        "base_image_sha256_after": after,
        "network": "none",
        "storage": "volatile",
        "base_image_unchanged": True,
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "fixture": manifest["ghidra_fixture"],
        "ghidra": manifest["ghidra"],
        "input_verification": verification,
        "runtime": result,
    }
    _update_validation_unlocked(
        output,
        {"ghidra_headless": "locally-validated"},
        "ghidra-headless.json",
        evidence,
    )
    return evidence


def ghidra_test(output: Path) -> dict[str, Any]:
    with output_lock(output):
        return _ghidra_test_unlocked(output)


def _noxframe_test_unlocked(output: Path) -> dict[str, Any]:
    verification = evidence_input_verification_snapshot(
        _verify_build_locked(output)
    )
    manifest, paths = artifact_paths(output)
    vector = canonical_artifact_vector(manifest)
    before = vector["artifacts"]["base_image"]["sha256"]
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-noxframe.", dir="/tmp"
    ) as temporary:
        overlay = create_temporary_overlay(
            paths["base_image"], Path(temporary)
        )
        argv = qemu_argv(
            paths,
            manifest,
            disk=overlay,
            disk_format="qcow2",
            snapshot=False,
            network="none",
            memory_mib=GHIDRA_VM_MEMORY_MIB,
        )
        result = run_qemu_commands(
            argv,
            ["wuci-noxframe-smoke", "doas poweroff -f"],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                NOXFRAME_GHIDRA_SEMANTIC_MARKER,
                NOXFRAME_GHIDRA_MARKER,
                HOSTILE_NOXFRAME_MARKER,
            ],
            timeout_seconds=2400,
        )
    after = digest_file(paths["base_image"])
    if after != before:
        raise LovelaceError(
            "NOXFRAME guest-broker test changed the immutable base image"
        )
    evidence = {
        "schema": "wucios.lovelace.noxframe_guest_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": before,
        "storage": "volatile",
        "network": "none",
        "languages": ["python3", "c", "cpp", "assembly", "rust", "go"],
        "analysis_tools": ["ghidra-headless"],
        "base_image_sha256_before": before,
        "base_image_sha256_after": after,
        "base_image_unchanged": True,
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "input_verification": verification,
        "runtime": result,
    }
    _update_validation_unlocked(
        output,
        {"noxframe_guest_broker": "locally-validated"},
        "noxframe-guest.json",
        evidence,
    )
    return evidence


def noxframe_test(output: Path) -> dict[str, Any]:
    with output_lock(output):
        return _noxframe_test_unlocked(output)


def _standalone_guest_result_command(marker: str) -> str:
    if re.fullmatch(r"[A-Z0-9_]+", marker) is None:
        raise LovelaceError("invalid standalone guest result marker")
    split = len(marker) // 2
    return (
        "printf '\\n%s%s\\n' "
        f"'{marker[:split]}' '{marker[split:]}'"
    )


def _persistent_round_trip_test_unlocked(output: Path) -> dict[str, Any]:
    verification = evidence_input_verification_snapshot(
        _verify_build_locked(output)
    )
    manifest, paths = artifact_paths(output)
    vector = canonical_artifact_vector(manifest)
    before = vector["artifacts"]["base_image"]["sha256"]
    token = hashlib.sha256(
        (
            "wucios-lovelace-persistent-round-trip-v1:"
            + before
        ).encode("ascii")
    ).hexdigest()
    proof_path = "/work/.lovelace-persistent-round-trip"
    with tempfile.TemporaryDirectory(
        prefix="wuci-lovelace-persistent.", dir="/tmp"
    ) as temporary:
        overlay = create_temporary_overlay(
            paths["base_image"], Path(temporary)
        )
        argv = qemu_argv(
            paths,
            manifest,
            disk=overlay,
            disk_format="qcow2",
            snapshot=False,
            network="none",
        )
        write_result = run_qemu_commands(
            argv,
            [
                f"umask 077 && printf '%s\\n' '{token}' > {proof_path} "
                "&& sync && "
                + _standalone_guest_result_command(
                    "LOVELACE_PERSISTENT_WRITE_PASS"
                ),
                "doas poweroff -f",
            ],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                "LOVELACE_PERSISTENT_WRITE_PASS",
            ],
            timeout_seconds=1200,
        )
        check = run(
            [trusted_host_tool("qemu-img"), "check", "-q", overlay],
            timeout=300,
            check=False,
        )
        if check.returncode != 0:
            raise LovelaceError(
                "persistent round-trip overlay failed qemu-img check"
            )
        read_result = run_qemu_commands(
            argv,
            [
                f"test \"$(cat {proof_path})\" = '{token}' && "
                + _standalone_guest_result_command(
                    "LOVELACE_PERSISTENT_ROUND_TRIP_PASS"
                ),
                "doas poweroff -f",
            ],
            [
                OFFLINE_BOOT_LINE,
                CONSOLE_MARKER,
                "LOVELACE_PERSISTENT_ROUND_TRIP_PASS",
            ],
            timeout_seconds=1200,
        )
    after = digest_file(paths["base_image"])
    if after != before:
        raise LovelaceError(
            "persistent round-trip changed the immutable base image"
        )
    evidence = {
        "schema": "wucios.lovelace.persistence_evidence.v1",
        "status": "pass",
        "artifact_vector": vector,
        "base_image_sha256": before,
        "storage": "temporary-qcow2-round-trip-overlay",
        "network": "none",
        "proof_token_sha256": hashlib.sha256(
            token.encode("ascii")
        ).hexdigest(),
        "base_image_sha256_before": before,
        "base_image_sha256_after": after,
        "base_image_unchanged": True,
        "functional_accelerator": "tcg",
        "isolation_claim": False,
        "input_verification": verification,
        "first_boot": write_result,
        "second_boot": read_result,
    }
    _update_validation_unlocked(
        output,
        {"persistent_round_trip": "locally-validated"},
        "persistent-round-trip.json",
        evidence,
    )
    return evidence


def persistent_round_trip_test(output: Path) -> dict[str, Any]:
    with output_lock(output):
        return _persistent_round_trip_test_unlocked(output)


def network_probe_binding(release: dict[str, Any]) -> dict[str, Any]:
    alpine_lock = shared_alpine_lock(release)
    try:
        media = alpine_lock["boot_media"]
        iso = media["iso"]
        sidecars = media["sidecars"]
    except (KeyError, TypeError) as exc:
        raise LovelaceError(
            "authenticated Alpine lock cannot define the network probe"
        ) from exc
    require_exact_keys(
        media, {"role", "iso", "sidecars"}, "Alpine boot media"
    )
    require_exact_keys(
        iso,
        {"filename", "url", "size", "sha256", "sha512"},
        "Alpine boot ISO",
    )
    if not isinstance(sidecars, list):
        raise LovelaceError("Alpine boot sidecars must be a list")
    matches = [
        record
        for record in sidecars
        if isinstance(record, dict)
        and record.get("role") == "sha256-digest"
    ]
    if len(matches) != 1:
        raise LovelaceError(
            "Alpine boot media requires exactly one sha256-digest sidecar"
        )
    sidecar = matches[0]
    require_exact_keys(
        sidecar,
        {"filename", "role", "sha256", "size", "suffix", "url"},
        "Alpine SHA-256 sidecar",
    )
    expected_line = f"{iso['sha256']}  {iso['filename']}"
    try:
        expected_body = (expected_line + "\n").encode("ascii")
    except (UnicodeEncodeError, TypeError) as exc:
        raise LovelaceError(
            "Alpine SHA-256 sidecar line is not ASCII"
        ) from exc
    if (
        not isinstance(iso["filename"], str)
        or not iso["filename"]
        or not isinstance(iso["url"], str)
        or not iso["url"].startswith("https://")
        or not is_lower_hex(iso["sha256"], 64)
        or sidecar["role"] != "sha256-digest"
        or sidecar["suffix"] != ".sha256"
        or sidecar["filename"] != iso["filename"] + ".sha256"
        or sidecar["url"] != iso["url"] + ".sha256"
        or not isinstance(sidecar["url"], str)
        or not sidecar["url"].startswith("https://")
        or "'" in sidecar["url"]
        or "\r" in sidecar["url"]
        or "\n" in sidecar["url"]
        or type(sidecar["size"]) is not int
        or not 1 <= sidecar["size"] <= 4096
        or sidecar["size"] != len(expected_body)
        or not is_lower_hex(sidecar["sha256"], 64)
        or sidecar["sha256"]
        != hashlib.sha256(expected_body).hexdigest()
    ):
        raise LovelaceError(
            "authenticated Alpine SHA-256 sidecar binding is invalid"
        )
    return {
        "url": sidecar["url"],
        "expected_exact_line": expected_line,
        "expected_response_bytes": sidecar["size"],
        "expected_response_sha256": sidecar["sha256"],
        "maximum_response_bytes": sidecar["size"],
        "connect_timeout_seconds": NETWORK_CONNECT_TIMEOUT_SECONDS,
        "transfer_timeout_seconds": NETWORK_TRANSFER_TIMEOUT_SECONDS,
    }


def network_guest_topology() -> dict[str, Any]:
    resolv = GUEST_RESOLV_CONF.encode("ascii")
    return {
        "qemu_netdev": QEMU_USER_NETDEV,
        "ipv4_cidr": QEMU_USER_GUEST_IPV4_CIDR,
        "gateway_ipv4": QEMU_USER_GATEWAY_IPV4,
        "dns_proxy_ipv4": QEMU_USER_DNS_PROXY_IPV4,
        "resolv_conf_bytes": len(resolv),
        "resolv_conf_sha256": hashlib.sha256(resolv).hexdigest(),
    }


def network_qemu_launch_contract(
    argv: Sequence[str], paths: dict[str, Path], overlay: Path
) -> dict[str, Any]:
    values = list(argv)
    overlay_path = overlay.resolve(strict=True)
    base_path = paths["base_image"].resolve(strict=True)
    expected = qemu_argv(
        paths,
        {},
        disk=overlay_path,
        disk_format="qcow2",
        snapshot=False,
        network="internet",
    )
    if (
        overlay_path == base_path
        or values != expected
        or any("hostfwd" in value for value in values)
    ):
        raise LovelaceError(
            "network QEMU argv differs from the volatile user-NAT contract"
        )
    functional_qemu_cpu_model(values)
    functional_qemu_kernel_arguments(values)
    return {
        "machine": "q35,accel=tcg",
        "accelerator": "tcg",
        "netdev": QEMU_USER_NETDEV,
        "network_device": QEMU_USER_NETWORK_DEVICE,
        "host_forwarding": False,
        "root_disk_format": "qcow2",
        "temporary_overlay": True,
        "base_image_directly_writable": False,
        "qemu_snapshot_flag": False,
    }


def explicit_network_probe_command(
    sidecar_url: str, expected_line: str
) -> str:
    if (
        not isinstance(sidecar_url, str)
        or not sidecar_url.startswith("https://")
        or "'" in sidecar_url
        or "\r" in sidecar_url
        or "\n" in sidecar_url
        or not isinstance(expected_line, str)
        or "'" in expected_line
        or "\r" in expected_line
        or "\n" in expected_line
    ):
        raise LovelaceError("invalid explicit-network probe binding")
    try:
        response = (expected_line + "\n").encode("ascii")
    except UnicodeEncodeError as exc:
        raise LovelaceError(
            "invalid explicit-network probe binding"
        ) from exc
    if not 1 <= len(response) <= 4096:
        raise LovelaceError("invalid explicit-network probe binding")
    response_sha256 = hashlib.sha256(response).hexdigest()
    resolv = GUEST_RESOLV_CONF.encode("ascii")
    resolv_sha256 = hashlib.sha256(resolv).hexdigest()
    success_command = _standalone_guest_result_command(
        "LOVELACE_EXPLICIT_INTERNET_PASS"
    )
    return (
        "(set -efu; umask 077; "
        "work=$(mktemp -d /tmp/wuci-lovelace-network.XXXXXX); "
        "trap 'rm -rf -- \"$work\"' EXIT HUP INT TERM; "
        "test -d /sys/class/net/eth0; "
        "ip -o -4 address show dev eth0 scope global > \"$work/address\"; "
        "test \"$(wc -l < \"$work/address\")\" -eq 1; "
        "address_line=$(cat \"$work/address\"); set -- $address_line; "
        "test \"$#\" -ge 4; test \"$2\" = 'eth0'; "
        "test \"$3\" = 'inet'; "
        f"test \"$4\" = '{QEMU_USER_GUEST_IPV4_CIDR}'; "
        "ip -4 route show default > \"$work/default-route\"; "
        "test \"$(wc -l < \"$work/default-route\")\" -eq 1; "
        "route_line=$(cat \"$work/default-route\"); "
        "set -- $route_line; test \"$#\" -eq 5; "
        "test \"$1\" = 'default'; test \"$2\" = 'via'; "
        f"test \"$3\" = '{QEMU_USER_GATEWAY_IPV4}'; "
        "test \"$4\" = 'dev'; test \"$5\" = 'eth0'; "
        f"test \"$(wc -c < /etc/resolv.conf)\" -eq {len(resolv)}; "
        "resolv_digest=$(sha256sum /etc/resolv.conf); "
        "resolv_digest=${resolv_digest%% *}; "
        f"test \"$resolv_digest\" = '{resolv_sha256}'; "
        "command -v ss >/dev/null; "
        "ss -H -lntup > \"$work/listeners\" 2> \"$work/ss.stderr\"; "
        "test ! -s \"$work/listeners\"; "
        "curl --disable --noproxy '*' --proto '=https' --fail "
        "--silent --show-error "
        f"--connect-timeout {NETWORK_CONNECT_TIMEOUT_SECONDS} "
        f"--max-time {NETWORK_TRANSFER_TIMEOUT_SECONDS} "
        f"--max-filesize {len(response)} --output \"$work/response\" "
        f"'{sidecar_url}'; "
        f"test \"$(wc -c < \"$work/response\")\" -eq {len(response)}; "
        "response_digest=$(sha256sum \"$work/response\"); "
        "response_digest=${response_digest%% *}; "
        f"test \"$response_digest\" = '{response_sha256}'; "
        "rm -rf -- \"$work\"; trap - EXIT HUP INT TERM; "
        f"{success_command})"
    )


def network_test(output: Path) -> dict[str, Any]:
    with output_lock(output):
        verification = evidence_input_verification_snapshot(
            _verify_build_locked(output)
        )
        manifest, paths = artifact_paths(output)
        vector = canonical_artifact_vector(manifest)
        release, _seeds, _ghidra = configuration()
        probe = network_probe_binding(release)
        before = digest_file(paths["base_image"])
        if before != vector["artifacts"]["base_image"]["sha256"]:
            raise LovelaceError(
                "explicit-network base image differs before launch"
            )
        result: dict[str, Any]
        launch_contract: dict[str, Any]
        after: str | None = None
        try:
            command = explicit_network_probe_command(
                probe["url"], probe["expected_exact_line"]
            )
            with tempfile.TemporaryDirectory(
                prefix="wuci-lovelace-network.", dir="/tmp"
            ) as temporary:
                overlay = create_temporary_overlay(
                    paths["base_image"], Path(temporary)
                )
                argv = qemu_argv(
                    paths,
                    manifest,
                    disk=overlay,
                    disk_format="qcow2",
                    snapshot=False,
                    network="internet",
                )
                launch_contract = network_qemu_launch_contract(
                    argv, paths, overlay
                )
                result = run_qemu_commands(
                    argv,
                    [command, "doas poweroff -f"],
                    [
                        INTERNET_BOOT_LINE,
                        CONSOLE_MARKER,
                        "LOVELACE_EXPLICIT_INTERNET_PASS",
                    ],
                    timeout_seconds=NETWORK_VM_TIMEOUT_SECONDS,
                )
        finally:
            after = digest_file(paths["base_image"])
            if after != before:
                raise LovelaceError(
                    "explicit-network test changed the immutable base image"
                )
        evidence = {
            "schema": "wucios.lovelace.network_evidence.v1",
            "status": "pass",
            "artifact_vector": vector,
            "base_image_sha256": before,
            "storage": "volatile",
            "network": "explicit-qemu-user-nat",
            "inbound_host_forwarding": False,
            "guest_listening_sockets": {
                "command": "ss -H -lntup",
                "command_succeeded": True,
                "observed": [],
                "scope": (
                    "TCP/UDP listening sockets visible to the guest lab user"
                ),
            },
            "guest_topology": network_guest_topology(),
            "launch_contract": launch_contract,
            "https_probe": probe,
            "timeouts": {
                "connect_seconds": NETWORK_CONNECT_TIMEOUT_SECONDS,
                "transfer_seconds": NETWORK_TRANSFER_TIMEOUT_SECONDS,
                "vm_seconds": NETWORK_VM_TIMEOUT_SECONDS,
            },
            "base_image_sha256_before": before,
            "base_image_sha256_after": after,
            "base_image_unchanged": True,
            "functional_accelerator": "tcg",
            "isolation_claim": False,
            "input_verification": verification,
            "runtime": result,
        }
        _update_validation_unlocked(
            output,
            {"network_internet": "locally-validated-explicit-mode"},
            "network-internet.json",
            evidence,
        )
        return evidence


def _hostile_executable_snapshot(
    path: Path,
    label: str,
    version_argv: Sequence[str],
) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} is missing: {path}") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022)
        or before.st_mode & 0o111 == 0
    ):
        raise LovelaceError(
            f"{label} must be root-owned, executable, non-set-ID, and "
            f"not group/world writable: {path}"
        )
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino)
            != (before.st_dev, before.st_ino)
        ):
            raise LovelaceError(f"{label} changed while being opened")
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > 1024 * 1024 * 1024:
                raise LovelaceError(f"{label} exceeds the 1 GiB limit")
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as exc:
        raise LovelaceError(f"{label} changed after hashing") from exc
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if total != opened.st_size or not (
        identity(before) == identity(after) == identity(final)
    ):
        raise LovelaceError(f"{label} changed while being hashed")
    version_result = run(version_argv, timeout=15)
    version_lines = (
        version_result.stdout + "\n" + version_result.stderr
    ).strip().splitlines()
    if not version_lines:
        raise LovelaceError(f"{label} did not report a version")
    return {
        "path": str(path),
        "size": total,
        "sha256": digest.hexdigest(),
        "mode": f"{stat.S_IMODE(after.st_mode):04o}",
        "uid": after.st_uid,
        "gid": after.st_gid,
        "device": after.st_dev,
        "inode": after.st_ino,
        "links": after.st_nlink,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
        "setuid": bool(after.st_mode & stat.S_ISUID),
        "setgid": bool(after.st_mode & stat.S_ISGID),
        "executable": bool(after.st_mode & 0o111),
        "version": version_lines[0][:300],
    }


def hostile_host_executable_records() -> dict[str, Any]:
    paths = {
        "qemu": Path("/usr/bin/qemu-system-x86_64"),
        "qemu_img": Path("/usr/bin/qemu-img"),
        "bubblewrap": Path("/usr/bin/bwrap"),
    }
    return {
        name: _hostile_executable_snapshot(
            path,
            f"hostile {name}",
            [str(path), "--version"],
        )
        for name, path in paths.items()
    }


def hostile_payload_tool_records() -> dict[str, Any]:
    paths = {
        "mke2fs": Path("/usr/sbin/mke2fs"),
        "debugfs": Path("/usr/sbin/debugfs"),
    }
    records = {
        name: _hostile_executable_snapshot(
            path,
            f"hostile payload {name}",
            [str(path), "-V"],
        )
        for name, path in paths.items()
    }
    for name, record in records.items():
        if record["version"] != (
            f"{name} {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)"
        ):
            raise LovelaceError(
                f"hostile payload {name} version differs"
            )
    return records


def hostile_kvm_device_record() -> dict[str, Any]:
    path = Path("/dev/kvm")
    try:
        info = path.lstat()
    except OSError as exc:
        raise LovelaceError(
            "hostile evidence requires usable exact /dev/kvm"
        ) from exc
    character = stat.S_ISCHR(info.st_mode)
    major = os.major(info.st_rdev) if character else -1
    minor = os.minor(info.st_rdev) if character else -1
    mode = stat.S_IMODE(info.st_mode)
    record = {
        "path": str(path),
        "character_device": character,
        "root_owned": info.st_uid == 0,
        "device_major": major,
        "device_minor": minor,
        "mode": f"{mode:04o}",
        "world_readable": bool(mode & stat.S_IROTH),
        "world_writable": bool(mode & stat.S_IWOTH),
        "readable": character and os.access(path, os.R_OK),
        "writable": character and os.access(path, os.W_OK),
    }
    if record != {
        "path": "/dev/kvm",
        "character_device": True,
        "root_owned": True,
        "device_major": 10,
        "device_minor": 232,
        "mode": record["mode"],
        "world_readable": False,
        "world_writable": False,
        "readable": True,
        "writable": True,
    }:
        raise LovelaceError(
            "hostile evidence requires root-owned /dev/kvm character device "
            "10:232, no world access, and current-user read/write access"
        )
    return record


def _hostile_state_directories() -> tuple[Path, Path]:
    state = REPO / "build/wuci-lab"
    volatile = state / "volatile"
    for path, label in (
        (state, "hostile supervisor state root"),
        (volatile, "hostile volatile state directory"),
    ):
        if path.exists() or path.is_symlink():
            require_real_directory(path, label)
        else:
            try:
                path.mkdir(mode=0o700)
            except OSError as exc:
                raise LovelaceError(f"cannot create {label}: {path}") from exc
        info = path.lstat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise LovelaceError(f"{label} must be private and operator-owned")
    return state, volatile


def _hostile_payload_state_directories() -> tuple[Path, Path, Path]:
    state, volatile = _hostile_state_directories()
    payloads = state / "payloads"
    label = "hostile payload state directory"
    if payloads.exists() or payloads.is_symlink():
        require_real_directory(payloads, label)
    else:
        try:
            payloads.mkdir(mode=0o700)
        except OSError as exc:
            raise LovelaceError(f"cannot create {label}: {payloads}") from exc
    info = payloads.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise LovelaceError(f"{label} must be private and operator-owned")
    return state, volatile, payloads


def _empty_volatile_snapshot(directory: Path, label: str) -> str:
    require_real_directory(directory, label)
    entries = sorted(path.name for path in directory.iterdir())
    if entries:
        raise LovelaceError(
            f"{label} must be empty for an exact cleanup observation: {entries}"
        )
    return hashlib.sha256(canonical_json([])).hexdigest()


def _proc_parent_map() -> dict[int, int]:
    parents: dict[int, int] = {}
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return parents
    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_bytes()
        except OSError:
            continue
        if len(raw) > 65536:
            continue
        close = raw.rfind(b") ")
        if close < 0:
            continue
        fields = raw[close + 2 :].split()
        if len(fields) < 2 or not fields[1].isascii():
            continue
        try:
            parents[int(entry.name)] = int(fields[1])
        except ValueError:
            continue
    return parents


def _descendant_pids(root_pid: int) -> set[int]:
    parents = _proc_parent_map()
    descendants: set[int] = set()
    frontier = {root_pid}
    while frontier:
        children = {
            pid
            for pid, parent in parents.items()
            if parent in frontier and pid not in descendants
        }
        descendants.update(children)
        frontier = children
    return descendants


def _proc_stat_identity(raw: bytes) -> tuple[int, int, int] | None:
    """Return stable pgrp/session/start-time fields from one proc stat record."""
    if len(raw) > 65536:
        return None
    close = raw.rfind(b") ")
    fields = raw[close + 2 :].split() if close >= 0 else []
    if len(fields) < 20:
        return None
    try:
        process_group = int(fields[2])
        session = int(fields[3])
        start_time = int(fields[19])
    except ValueError:
        return None
    return process_group, session, start_time


def _namespace_inode(name: str, value: str) -> int | None:
    """Parse the exact kernel namespace-link representation."""
    if not isinstance(name, str) or not isinstance(value, str):
        return None
    match = re.fullmatch(
        rf"{re.escape(name)}:\[([0-9]+)\]",
        value,
    )
    if match is None:
        return None
    token = match.group(1)
    inode = int(token)
    if inode <= 0 or str(inode) != token:
        return None
    return inode


def _qemu_teardown_identity(
    pid: int,
    executable: str,
    executable_info: os.stat_result,
    proc_identity: tuple[int, int, int],
) -> dict[str, Any]:
    return {
        "host_pid": pid,
        "start_time_ticks": proc_identity[2],
        "executable": executable,
        "executable_device": executable_info.st_dev,
        "executable_inode": executable_info.st_ino,
    }


def _qemu_process_observation(
    root_pid: int,
    expected_qemu: dict[str, Any],
) -> dict[str, Any] | None:
    expected_path = expected_qemu.get("path")
    expected_device = expected_qemu.get("device")
    expected_inode = expected_qemu.get("inode")
    if (
        expected_path != "/usr/bin/qemu-system-x86_64"
        or type(expected_device) is not int
        or expected_device < 0
        or type(expected_inode) is not int
        or expected_inode <= 0
    ):
        raise LovelaceError(
            "hostile QEMU observation lacks an exact trusted executable "
            "identity"
        )
    for pid in sorted(_descendant_pids(root_pid)):
        proc = Path("/proc") / str(pid)
        try:
            executable_before = os.readlink(proc / "exe")
        except OSError:
            continue
        if executable_before != expected_path:
            continue
        try:
            executable_info_before = os.stat(proc / "exe")
            stat_before = (proc / "stat").read_bytes()
            cmdline_raw = (proc / "cmdline").read_bytes()
            raw = (proc / "status").read_bytes()
        except OSError:
            continue
        if (
            len(raw) > 128 * 1024
            or len(stat_before) > 65536
            or len(cmdline_raw) > 1024 * 1024
        ):
            continue
        identity_before = _proc_stat_identity(stat_before)
        if identity_before is None:
            continue
        teardown_identity = _qemu_teardown_identity(
            pid,
            executable_before,
            executable_info_before,
            identity_before,
        )
        try:
            text = raw.decode("ascii", errors="strict")
            cmdline = [
                item.decode("utf-8", errors="strict")
                for item in cmdline_raw.rstrip(b"\0").split(b"\0")
                if item
            ]
        except UnicodeDecodeError:
            continue
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            fields[name] = value.strip()
        try:
            uids = [int(value) for value in fields["Uid"].split()]
            no_new_privileges = int(fields["NoNewPrivs"])
            seccomp_mode = int(fields["Seccomp"])
            seccomp_filters = int(fields["Seccomp_filters"])
        except (KeyError, ValueError):
            continue
        capabilities = fields.get("CapEff", "").lower()
        namespaces: dict[str, dict[str, Any]] = {}
        namespace_error = False
        for name in ("mnt", "user", "pid", "ipc", "uts", "cgroup", "net"):
            try:
                producer_value = os.readlink(Path("/proc/self/ns") / name)
                qemu_value = os.readlink(proc / "ns" / name)
            except OSError:
                namespace_error = True
                break
            if (
                _namespace_inode(name, producer_value) is None
                or _namespace_inode(name, qemu_value) is None
            ):
                raise _HostileProcessObservationError(
                    f"hostile QEMU {name} namespace identity is malformed",
                    teardown_identity,
                )
            namespaces[name] = {
                "producer": producer_value,
                "qemu": qemu_value,
                "different": producer_value != qemu_value,
            }
        if namespace_error:
            continue
        try:
            stat_after = (proc / "stat").read_bytes()
            executable_after = os.readlink(proc / "exe")
            executable_info_after = os.stat(proc / "exe")
        except OSError:
            continue
        identity_after = _proc_stat_identity(stat_after)
        if (
            identity_after is None
            or identity_after != identity_before
            or executable_after != executable_before
            or (
                executable_info_after.st_dev,
                executable_info_after.st_ino,
            )
            != (
                executable_info_before.st_dev,
                executable_info_before.st_ino,
            )
        ):
            continue
        process_group, session, start_time = identity_before
        teardown_identity = _qemu_teardown_identity(
            pid,
            executable_before,
            executable_info_before,
            identity_before,
        )
        if (
            executable_info_before.st_dev != expected_device
            or executable_info_before.st_ino != expected_inode
        ):
            raise _HostileProcessObservationError(
                "hostile QEMU process executable identity differs from the "
                "trusted pre-launch snapshot",
                teardown_identity,
            )
        if not cmdline:
            continue
        if (
            no_new_privileges in {0, 1}
            and seccomp_mode in {0, 1, 2}
            and seccomp_filters >= 0
            and (
                no_new_privileges != 1
                or seccomp_mode != 2
                or seccomp_filters < 1
            )
        ):
            # QEMU installs these monotonic process controls during startup.
            # Never dispatch guest commands until all three are observed.
            continue
        if (
            len(uids) != 4
            or any(uid <= 0 for uid in uids)
            or len(set(uids)) != 1
            or re.fullmatch(r"[0-9a-f]{16}", capabilities) is None
            or capabilities != "0000000000000000"
            or process_group <= 0
            or session <= 0
            or start_time <= 0
            or no_new_privileges != 1
            or seccomp_mode != 2
            or seccomp_filters < 1
            or not all(
                record["different"] is True
                for record in namespaces.values()
            )
        ):
            raise _HostileProcessObservationError(
                "hostile QEMU process did not match the exact unprivileged, "
                "capability-empty, seccomp-filtered namespace boundary",
                teardown_identity,
            )
        return {
            "observed": True,
            "executable": executable_before,
            "host_pid": pid,
            "process_group_id": process_group,
            "session_id": session,
            "start_time_ticks": start_time,
            "executable_device": executable_info_before.st_dev,
            "executable_inode": executable_info_before.st_ino,
            "cmdline_sha256": hashlib.sha256(
                canonical_json(cmdline)
            ).hexdigest(),
            "host_uids": uids,
            "all_host_uids_equal_nonzero": True,
            "effective_capabilities_hex": capabilities,
            "capabilities_empty": True,
            "no_new_privileges": True,
            "seccomp_mode": seccomp_mode,
            "seccomp_filters": seccomp_filters,
            "namespaces": namespaces,
            "_cmdline": cmdline,
        }
    return None


def _observed_qemu_identity_present(
    observation: dict[str, Any],
) -> bool | None:
    """Return whether the exact observed process still exists.

    ``None`` means the proc record still exists but could not be read
    consistently, so callers must not treat that as successful teardown.
    """
    pid = observation.get("host_pid")
    start_time = observation.get("start_time_ticks")
    executable = observation.get("executable")
    executable_device = observation.get("executable_device")
    executable_inode = observation.get("executable_inode")
    if (
        type(pid) is not int
        or pid <= 0
        or type(start_time) is not int
        or start_time <= 0
        or executable != "/usr/bin/qemu-system-x86_64"
        or type(executable_device) is not int
        or executable_device < 0
        or type(executable_inode) is not int
        or executable_inode <= 0
    ):
        raise LovelaceError(
            "hostile QEMU teardown observation has an invalid identity"
        )
    proc = Path("/proc") / str(pid)
    if not proc.exists():
        return False
    try:
        raw = (proc / "stat").read_bytes()
    except OSError:
        return None if proc.exists() else False
    identity = _proc_stat_identity(raw)
    if identity is None:
        return None if proc.exists() else False
    if identity[2] != start_time:
        return False
    try:
        current_executable = os.readlink(proc / "exe")
        current_info = os.stat(proc / "exe")
    except OSError:
        return None if proc.exists() else False
    if (
        current_executable != executable
        or current_info.st_dev != executable_device
        or current_info.st_ino != executable_inode
    ):
        # The start time still identifies the observed process.  An executable
        # transition is not process disappearance.
        return True
    return True


def _wait_for_observed_qemu_absence(
    observation: dict[str, Any],
    *,
    timeout_seconds: float = 5.0,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _observed_qemu_identity_present(observation) is False:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _terminate_hostile_process_group(
    process: subprocess.Popen[bytes],
) -> None:
    process.poll()
    if not _hostile_process_group_exists(process):
        if process.poll() is None:
            process.wait(timeout=5)
        return
    for selected_signal, timeout in (
        (signal.SIGINT, 15),
        (signal.SIGTERM, 5),
        (signal.SIGKILL, 5),
    ):
        try:
            os.killpg(process.pid, selected_signal)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            process.poll()
            if not _hostile_process_group_exists(process):
                if process.poll() is None:
                    process.wait(timeout=max(0.1, deadline - time.monotonic()))
                return
            time.sleep(0.05)
    raise LovelaceError(
        "cannot terminate every hostile supervisor process-group member"
    )


def _hostile_process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is None:
        return True
    for pid in _proc_parent_map():
        try:
            raw = (Path("/proc") / str(pid) / "stat").read_bytes()
        except OSError:
            continue
        if len(raw) > 65536:
            continue
        close = raw.rfind(b") ")
        fields = raw[close + 2 :].split() if close >= 0 else []
        if len(fields) < 4:
            continue
        try:
            state = fields[0]
            process_group = int(fields[2])
            session = int(fields[3])
        except ValueError:
            continue
        if (
            process_group == process.pid
            and session == process.pid
            and state != b"Z"
        ):
            return True
    return False


def _parse_materialized_hostile_plan(
    output: bytes,
) -> tuple[dict[str, Any], bool]:
    text = output.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder(
        object_pairs_hook=reject_duplicate_json_keys,
        parse_constant=lambda token: (_ for _ in ()).throw(
            LovelaceError(
                f"hostile launch plan contains non-finite number: {token}"
            )
        ),
    )
    try:
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, LovelaceError) as exc:
        raise LovelaceError(
            "hostile supervisor did not emit a valid materialized plan"
        ) from exc
    if not isinstance(value, dict):
        raise LovelaceError("hostile materialized plan must be an object")
    encoded = canonical_json(value)
    if output[: len(encoded)] != encoded:
        raise LovelaceError(
            "hostile supervisor plan bytes are not canonical JSON"
        )
    records = _hostile_complete_console_line_records(output)
    hostile_boot_line = HOSTILE_BOOT_LINE.encode("ascii")
    boot_offsets = [
        offset for offset, line in records if line == hostile_boot_line
    ]
    console_marker = CONSOLE_MARKER.encode("ascii")
    console_offsets = [
        offset for offset, line in records if line == console_marker
    ]
    ordered_exact_markers = (
        len(boot_offsets) == 1
        and len(console_offsets) == 1
        and len(encoded) <= boot_offsets[0] < console_offsets[0]
    )
    return value, ordered_exact_markers and end < boot_offsets[0]


def run_hostile_supervisor_commands(
    argv: Sequence[str],
    expected_markers: Sequence[str],
    expected_qemu: dict[str, Any],
    *,
    command_factory: Callable[
        [str], tuple[Sequence[str], Sequence[str]]
    ],
    validate_plan: Callable[[dict[str, Any]], object],
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": "/tmp",
        "XDG_CONFIG_HOME": "/nonexistent",
    }
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    sent = False
    dispatch_offset: int | None = None
    observation: dict[str, Any] | None = None
    rejected_observation: dict[str, Any] | None = None
    predispatch_plan: dict[str, Any] | None = None
    predispatch_plan_bytes: bytes | None = None
    challenge: str | None = None
    commands: list[str] | None = None
    command_results: list[str] | None = None
    surviving_group_after_leader_exit = False
    qemu_process_absent_after_supervisor_exit = False
    deadline = time.monotonic() + timeout_seconds
    # Artifact verification and private-overlay materialization happen in the
    # supervisor before QEMU exists.  Bound that work with the overall
    # deadline, but start the guest boot deadline only once the exact QEMU
    # process has been observed.  Otherwise large, deliberately re-hashed
    # images can consume the guest's entire boot allowance before a vCPU has
    # started.
    console_ready_deadline: float | None = None
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=False,
        cwd=REPO,
        env=environment,
        close_fds=True,
        start_new_session=True,
    )
    try:
        if process.stdin is None or process.stdout is None:
            raise LovelaceError(
                "hostile supervisor stdio pipes were not created"
            )
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            for key, _mask in selector.select(timeout=0.5):
                try:
                    block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    block = b""
                if block:
                    _append_hostile_console_block(output, block)
            if observation is None:
                try:
                    candidate_observation = _qemu_process_observation(
                        process.pid, expected_qemu
                    )
                except _HostileProcessObservationError as exc:
                    rejected_observation = dict(exc.teardown_identity)
                    raise
                if candidate_observation is not None:
                    observation = candidate_observation
                    console_ready_deadline = min(
                        deadline,
                        time.monotonic()
                        + HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS,
                    )
            console_ready = _hostile_exact_console_line_present(
                bytes(output), CONSOLE_MARKER
            )
            if (
                not console_ready
                and console_ready_deadline is not None
                and time.monotonic() >= console_ready_deadline
            ):
                raise LovelaceError(
                    "hostile guest did not reach its console-ready marker "
                    f"within {HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS} seconds; "
                    "console_tail="
                    f"{ascii(output.decode('utf-8', errors='replace')[-12000:])}"
                )
            if console_ready and observation is not None and not sent:
                while True:
                    try:
                        block = os.read(
                            process.stdout.fileno(), 65536
                        )
                    except BlockingIOError:
                        break
                    if not block:
                        break
                    _append_hostile_console_block(output, block)
                candidate_plan, emitted_before_console = (
                    _parse_materialized_hostile_plan(bytes(output))
                )
                if not emitted_before_console:
                    raise LovelaceError(
                        "hostile materialized plan was not emitted before "
                        "guest output"
                    )
                observed_cmdline = observation.get("_cmdline")
                if observed_cmdline != candidate_plan.get("qemu_argv"):
                    raise LovelaceError(
                        "observed hostile QEMU command line differs from the "
                        "materialized canonical plan before guest-command "
                        "dispatch"
                    )
                candidate_plan_bytes = canonical_json(candidate_plan)
                validate_plan(candidate_plan)
                if canonical_json(candidate_plan) != candidate_plan_bytes:
                    raise LovelaceError(
                        "hostile pre-dispatch plan validator mutated the "
                        "materialized plan"
                    )
                challenge = secrets.token_hex(32)
                commands, command_results = (
                    _materialize_hostile_challenge_commands(
                        command_factory, challenge
                    )
                )
                challenge_bytes = challenge.encode("ascii")
                dispatch_context = canonical_json(
                    {
                        "argv": list(argv),
                        "environment": environment,
                        "materialized_plan": candidate_plan,
                    }
                )
                if (
                    challenge_bytes in output
                    or challenge_bytes in dispatch_context
                ):
                    raise LovelaceError(
                        "hostile challenge was disclosed before dispatch"
                    )
                if any(
                    result.encode("ascii") in output
                    for result in command_results
                ):
                    raise LovelaceError(
                        "hostile challenge result appeared before dispatch"
                    )
                payload = ("\n".join(commands) + "\n").encode("utf-8")
                predispatch_plan = candidate_plan
                predispatch_plan_bytes = candidate_plan_bytes
                dispatch_offset = len(output)
                process.stdin.write(payload)
                process.stdin.flush()
                sent = True
            if process.poll() is not None:
                while True:
                    try:
                        block = os.read(process.stdout.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not block:
                        break
                    _append_hostile_console_block(output, block)
                break
        else:
            raise LovelaceError(
                f"hostile KVM-cell test timed out after {timeout_seconds} "
                "seconds; console_tail="
                f"{ascii(output.decode('utf-8', errors='replace')[-12000:])}"
            )
    finally:
        try:
            if selector is not None:
                selector.close()
        finally:
            group_exists = _hostile_process_group_exists(process)
            surviving_group_after_leader_exit = (
                process.poll() is not None and group_exists
            )
            try:
                if process.poll() is None or group_exists:
                    _terminate_hostile_process_group(process)
            finally:
                teardown_observation = observation or rejected_observation
                if teardown_observation is not None:
                    qemu_process_absent_after_supervisor_exit = (
                        _wait_for_observed_qemu_absence(
                            teardown_observation
                        )
                    )
                    if not qemu_process_absent_after_supervisor_exit:
                        raise LovelaceError(
                            "the exact observed hostile QEMU process identity "
                            "remained after supervisor termination"
                        )
    text = output.decode("utf-8", errors="replace")
    reject_forbidden_guest_runtime_diagnostics(
        text, "hostile guest console"
    )
    if not sent:
        console_ready = _hostile_exact_console_line_present(
            bytes(output), CONSOLE_MARKER
        )
        raise LovelaceError(
            "hostile supervisor exited before guest-command acceptance "
            f"(supervisor_exit={process.returncode}, "
            f"console_ready={str(console_ready).lower()}, "
            f"qemu_observed={str(observation is not None).lower()}): "
            f"{ascii(text[-12000:])}"
        )
    if surviving_group_after_leader_exit:
        raise LovelaceError(
            "hostile supervisor exited while a process-group member remained"
        )
    console_lines = [line.rstrip("\r") for line in text.splitlines()]
    def marker_line_count(marker: str) -> int:
        if marker == BOOT_MARKER:
            return console_lines.count(HOSTILE_BOOT_LINE)
        return console_lines.count(marker)

    missing = [
        marker
        for marker in expected_markers
        if marker_line_count(marker) != 1
    ]
    if missing:
        raise LovelaceError(
            "hostile guest console does not contain each acceptance marker "
            f"exactly once: {missing}"
        )
    marker_positions = [
        next(
            index
            for index, line in enumerate(console_lines)
            if (
                line == HOSTILE_BOOT_LINE
                if marker == BOOT_MARKER
                else line == marker
            )
        )
        for marker in expected_markers
    ]
    if marker_positions != sorted(marker_positions):
        raise LovelaceError(
            "hostile guest acceptance markers are out of order"
        )
    if process.returncode != 0:
        raise LovelaceError(
            f"hostile supervisor exited with status {process.returncode}: "
            f"{ascii(text[-12000:])}"
        )
    if observation is None:
        raise LovelaceError("hostile QEMU process was not observed")
    if predispatch_plan is None or predispatch_plan_bytes is None:
        raise LovelaceError(
            "hostile materialized plan was not validated before dispatch"
        )
    if dispatch_offset is None:
        raise LovelaceError("hostile command dispatch was not recorded")
    if (
        challenge is None
        or commands is None
        or command_results is None
    ):
        raise LovelaceError(
            "hostile challenge commands were not materialized at dispatch"
        )
    complete_records = _hostile_complete_console_line_records(bytes(output))
    result_offsets: list[int] = []
    missing_results = [
        result
        for result in command_results
        if len(
            offsets := [
                offset
                for offset, line in complete_records
                if line == result.encode("ascii")
            ]
        )
        != 1
        or offsets[0] < dispatch_offset
    ]
    if missing_results:
        raise LovelaceError(
            "hostile guest did not emit each challenge-bound command result "
            f"exactly once after dispatch: {missing_results}; console_tail="
            f"{ascii(text[-12000:])}"
        )
    for result in command_results:
        result_offsets.append(
            next(
                offset
                for offset, line in complete_records
                if line == result.encode("ascii")
            )
        )
    if result_offsets != sorted(result_offsets):
        raise LovelaceError(
            "hostile challenge-bound command results are out of order"
        )
    plan, emitted_before_console = _parse_materialized_hostile_plan(
        bytes(output)
    )
    if not emitted_before_console:
        raise LovelaceError(
            "hostile materialized plan was not emitted before guest output"
        )
    if (
        plan != predispatch_plan
        or canonical_json(plan) != predispatch_plan_bytes
    ):
        raise LovelaceError(
            "hostile materialized plan changed after guest-command dispatch"
        )
    observed_cmdline = observation.pop("_cmdline", None)
    if observed_cmdline != plan.get("qemu_argv"):
        raise LovelaceError(
            "observed hostile QEMU command line differs from the "
            "materialized canonical plan"
        )
    return plan, {
        "status": "pass",
        "supervisor_exit": process.returncode,
        "markers": list(expected_markers),
        "challenge": challenge,
        "command_results": list(command_results),
        "command_results_after_dispatch": True,
        "command_dispatch_offset": dispatch_offset,
        "challenge_generated_after_predispatch_validation": True,
        "challenge_absent_before_dispatch": True,
        "exact_boot_line_validated": True,
        "complete_result_lines_validated": True,
        "console_sha256": hashlib.sha256(output).hexdigest(),
        "console_transcript": text,
        "console_transcript_bytes": len(output),
        "console_transcript_complete": True,
        "console_tail": text[-12000:],
        "forbidden_diagnostics_absent": True,
        "console_ready_timeout_seconds": (
            HOSTILE_CONSOLE_READY_TIMEOUT_SECONDS
        ),
        "console_rendering": "escaped-ascii",
        "console_forwarded_byte_allowlist": list(
            HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST
        ),
        "non_allowlisted_console_bytes_forwarded": False,
        "console_sha256_scope": "escaped-ascii-supervisor-transcript",
        "plan_emitted_before_guest_console": True,
        "plan_validated_before_guest_command_dispatch": True,
        "qemu_process": observation,
        "qemu_process_absent_after_supervisor_exit": (
            qemu_process_absent_after_supervisor_exit
        ),
    }


def hostile_payload_fixture_record() -> dict[str, Any]:
    info = ensure_regular(
        HOSTILE_PAYLOAD_FIXTURE_PATH,
        "fixed hostile payload fixture",
        size=HOSTILE_PAYLOAD_FIXTURE_SIZE,
        single_link=True,
    )
    record = {
        "path": str(HOSTILE_PAYLOAD_FIXTURE_PATH),
        "sha256": digest_file(HOSTILE_PAYLOAD_FIXTURE_PATH),
        "size": info.st_size,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
    }
    if record != {
        "path": str(HOSTILE_PAYLOAD_FIXTURE_PATH),
        "sha256": HOSTILE_PAYLOAD_FIXTURE_SHA256,
        "size": HOSTILE_PAYLOAD_FIXTURE_SIZE,
        "mode": "0644",
    }:
        raise LovelaceError("fixed hostile payload fixture binding differs")
    return record


def hostile_payload_manifest(source: dict[str, Any]) -> dict[str, Any]:
    require_exact_keys(
        source,
        {"path", "sha256", "size", "mode"},
        "fixed hostile payload source",
    )
    if source != hostile_payload_fixture_record():
        raise LovelaceError("hostile payload source is not the fixed fixture")
    manifest = {
        "schema": HOSTILE_PAYLOAD_SCHEMA,
        "source": {
            "sha256": HOSTILE_PAYLOAD_FIXTURE_SHA256,
            "size": HOSTILE_PAYLOAD_FIXTURE_SIZE,
        },
        "guest": {
            "payload_path": "/payload/payload.bin",
            "manifest_path": "/payload/manifest.json",
            "secondary_device": HOSTILE_PAYLOAD_GUEST_DEVICE,
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
    encoded = canonical_json(manifest)
    if (
        len(encoded) != HOSTILE_PAYLOAD_MANIFEST_SIZE
        or hashlib.sha256(encoded).hexdigest()
        != HOSTILE_PAYLOAD_MANIFEST_SHA256
    ):
        raise LovelaceError(
            "canonical hostile payload manifest binding differs"
        )
    return manifest


def hostile_payload_filesystem_uuid() -> str:
    raw = bytearray.fromhex(HOSTILE_PAYLOAD_FIXTURE_SHA256[:32])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    value = raw.hex()
    return (
        f"{value[:8]}-{value[8:12]}-{value[12:16]}-"
        f"{value[16:20]}-{value[20:]}"
    )


def hostile_payload_media_size() -> int:
    quantum = 4 * 1024 * 1024
    requested = HOSTILE_PAYLOAD_FIXTURE_SIZE + 16 * 1024 * 1024
    return max(
        16 * 1024 * 1024,
        ((requested + quantum - 1) // quantum) * quantum,
    )


def hostile_payload_semantic_readback(
    source: dict[str, Any], debugfs_path: Path
) -> dict[str, Any]:
    hostile_payload_manifest(source)
    return {
        "filesystem": "ext4",
        "debugfs_path": str(debugfs_path),
        "debugfs_version": EXPECTED_E2FSPROGS_VERSION,
        "payload": {
            "guest_path": "/payload.bin",
            "size": HOSTILE_PAYLOAD_FIXTURE_SIZE,
            "sha256": HOSTILE_PAYLOAD_FIXTURE_SHA256,
        },
        "manifest": {
            "guest_path": "/manifest.json",
            "size": HOSTILE_PAYLOAD_MANIFEST_SIZE,
            "sha256": HOSTILE_PAYLOAD_MANIFEST_SHA256,
        },
        "exact_guest_file_bytes_verified": True,
    }


def validate_hostile_payload_media_report(
    report: Any,
    *,
    source: dict[str, Any],
    state_root: Path,
    debugfs_path: Path,
    payload_uid: int,
    payload_gid: int,
    inspect_media: bool,
) -> dict[str, Any]:
    require_exact_keys(
        report,
        {
            "schema",
            "source",
            "manifest",
            "semantic_readback",
            "media",
            "cleanup_on_supervisor_unwind",
            "cleanup_after_sigkill_or_host_crash_claimed",
        },
        "hostile payload media report",
    )
    expected_manifest = hostile_payload_manifest(source)
    expected_readback = hostile_payload_semantic_readback(
        source, debugfs_path
    )
    media = report["media"]
    require_exact_keys(
        media,
        {
            "path",
            "sha256",
            "size",
            "mode",
            "format",
            "filesystem_uuid",
            "guest_device",
            "qemu_read_only",
            "host_mode",
        },
        "hostile payload media binding",
    )
    media_path = _hostile_serialized_absolute_path(
        media["path"], "hostile payload media"
    )
    payload_root = state_root / "payloads"
    if (
        media_path.name != "payload.ext4"
        or media_path.parent.parent != payload_root
        or re.fullmatch(
            r"\.wuci-payload\.[A-Za-z0-9_-]{6,64}",
            media_path.parent.name,
        )
        is None
    ):
        raise LovelaceError(
            "hostile payload media escaped its private state directory"
        )
    if (
        report["schema"] != HOSTILE_PAYLOAD_SCHEMA
        or report["source"] != source
        or report["manifest"] != expected_manifest
        or report["semantic_readback"] != expected_readback
        or report["cleanup_on_supervisor_unwind"] is not True
        or report["cleanup_after_sigkill_or_host_crash_claimed"] is not False
        or not is_lower_hex(media["sha256"], 64)
        or media["size"] != hostile_payload_media_size()
        or media["mode"] != "0400"
        or media["format"] != "raw-ext4"
        or media["filesystem_uuid"] != hostile_payload_filesystem_uuid()
        or media["guest_device"] != HOSTILE_PAYLOAD_GUEST_DEVICE
        or media["qemu_read_only"] is not True
        or media["host_mode"] != "0400"
        or type(payload_uid) is not int
        or payload_uid <= 0
        or type(payload_gid) is not int
        or payload_gid < 0
    ):
        raise LovelaceError("hostile payload media contract differs")

    normalized_inventory = [
        {
            "path": "/",
            "type": "directory",
            "mode": "0755",
            "uid": 0,
            "gid": 0,
            "size": None,
        },
        {
            "path": "/lost+found",
            "type": "directory",
            "mode": "0700",
            "uid": 0,
            "gid": 0,
            "size": None,
        },
        {
            "path": "/manifest.json",
            "type": "regular",
            "mode": "0400",
            "uid": payload_uid,
            "gid": payload_gid,
            "size": expected_readback["manifest"]["size"],
        },
        {
            "path": "/payload.bin",
            "type": "regular",
            "mode": "0400",
            "uid": payload_uid,
            "gid": payload_gid,
            "size": HOSTILE_PAYLOAD_FIXTURE_SIZE,
        },
    ]
    if inspect_media:
        info = ensure_regular(
            media_path,
            "hostile payload media",
            size=media["size"],
            single_link=True,
        )
        if (
            stat.S_IMODE(info.st_mode) != 0o400
            or info.st_uid != payload_uid
            or info.st_gid != payload_gid
        ):
            raise LovelaceError(
                "hostile payload media host metadata differs"
            )
        deadline = time.monotonic() + 120
        with pinned_ext4_image(media_path) as pinned:
            if (
                _digest_descriptor(pinned.descriptor, pinned.opened.st_size)
                != media["sha256"]
            ):
                raise LovelaceError("hostile payload media SHA-256 differs")
            inventory_records = ext4_path_inventory(pinned, debugfs_path)
            inventory = ext4_inventory_by_path(inventory_records)
            if set(inventory) != {
                "/",
                "/lost+found",
                "/manifest.json",
                "/payload.bin",
            }:
                raise LovelaceError(
                    "hostile payload media path inventory differs"
                )
            observed_normalized = [
                {
                    "path": path,
                    "type": record["type"],
                    "mode": f"{stat.S_IMODE(int(record['mode'], 8)):04o}",
                    "uid": record["uid"],
                    "gid": record["gid"],
                    "size": record["size"],
                }
                for path, record in sorted(inventory.items())
            ]
            if (
                observed_normalized != normalized_inventory
                or len({record["inode"] for record in inventory.values()})
                != len(inventory)
            ):
                raise LovelaceError(
                    "hostile payload media metadata inventory differs"
                )
            validate_ext4_regular_binding(
                pinned,
                debugfs_path,
                inventory,
                "/payload.bin",
                expected_mode=0o400,
                expected_size=HOSTILE_PAYLOAD_FIXTURE_SIZE,
                expected_sha256=HOSTILE_PAYLOAD_FIXTURE_SHA256,
                expected_uid=payload_uid,
                expected_gid=payload_gid,
                label="hostile payload media source",
                deadline=deadline,
            )
            validate_ext4_regular_binding(
                pinned,
                debugfs_path,
                inventory,
                "/manifest.json",
                expected_mode=0o400,
                expected_size=expected_readback["manifest"]["size"],
                expected_sha256=expected_readback["manifest"]["sha256"],
                expected_uid=payload_uid,
                expected_gid=payload_gid,
                label="hostile payload media manifest",
                deadline=deadline,
            )
            require_embedded_debugfs_deadline(deadline)
    return {
        "source": source,
        "manifest": expected_manifest,
        "semantic_readback": expected_readback,
        "media": dict(media),
        "media_inventory": normalized_inventory,
        "exact_media_bytes_independently_verified": True,
    }


def hostile_plan_summary(
    plan: dict[str, Any],
    paths: dict[str, Path],
    vector: dict[str, Any],
    state_root: Path,
    *,
    inspect_artifacts: bool = True,
) -> tuple[dict[str, Any], Path]:
    require_exact_keys(
        plan,
        {
            "schema",
            "decision",
            "argv_materialized",
            "profile",
            "supervisor",
            "inputs",
            "payload_ingress",
            "storage",
            "network",
            "acceleration",
            "resources",
            "controls",
            "outer_boundary",
            "host_resource_limits",
            "qemu_argv",
            "argv",
            "environment",
            "claims",
            "nonclaims",
        },
        "hostile materialized launch plan",
    )
    if (
        plan["schema"] != "wuci.lab.launch-plan.v1"
        or plan["decision"] != "launch-plan-valid"
        or plan["argv_materialized"] is not True
        or plan["profile"] != "hostile"
    ):
        raise LovelaceError("hostile materialized plan identity differs")

    if (
        _hostile_serialized_absolute_path(
            str(state_root), "hostile state root"
        )
        != state_root
    ):
        raise LovelaceError("hostile state root is not canonical and absolute")

    supervisor = plan["supervisor"]
    expected_supervisor = {
        "state_root": str(state_root),
        "qemu_path": "/usr/bin/qemu-system-x86_64",
        "qemu_img_path": "/usr/bin/qemu-img",
        "mke2fs_path": None,
        "mke2fs_version": None,
        "debugfs_path": None,
        "debugfs_version": None,
        "bubblewrap_path": "/usr/bin/bwrap",
    }
    if supervisor != expected_supervisor:
        raise LovelaceError("hostile supervisor executable bindings differ")
    if plan["payload_ingress"] is not None:
        raise LovelaceError(
            "canonical hostile isolation evidence does not accept a payload"
        )

    inputs = plan["inputs"]
    require_exact_keys(
        inputs, {"kernel", "initrd", "base_image"}, "hostile plan inputs"
    )
    input_artifacts = (
        ("kernel", "kernel", "0644"),
        ("initrd", "initramfs", "0644"),
        ("base_image", "base_image", "0444"),
    )
    artifact_parents: set[Path] = set()
    for input_name, artifact_name, required_mode in input_artifacts:
        record = inputs[input_name]
        require_exact_keys(
            record,
            {"path", "sha256", "size", "mode"},
            f"hostile plan {input_name}",
        )
        artifact_path = paths[artifact_name]
        if (
            _hostile_serialized_absolute_path(
                str(artifact_path), f"hostile plan {input_name}"
            )
            != artifact_path
        ):
            raise LovelaceError(f"hostile plan {input_name} path differs")
        artifact_parents.add(artifact_path.parent)
        if artifact_path.name != vector["artifacts"][artifact_name]["filename"]:
            raise LovelaceError(
                f"hostile plan {input_name} filename differs from the "
                "artifact vector"
            )
        mode_value = record.get("mode")
        if (
            not isinstance(mode_value, str)
            or re.fullmatch(r"[0-7]{4}", mode_value) is None
            or mode_value != required_mode
        ):
            raise LovelaceError(
                f"hostile plan {input_name} mode is invalid"
            )
        if inspect_artifacts:
            info = ensure_regular(
                artifact_path,
                f"hostile plan {input_name}",
                single_link=True,
            )
            expected_mode = f"{stat.S_IMODE(info.st_mode):04o}"
        else:
            expected_mode = mode_value
        expected = {
            "path": str(artifact_path),
            "sha256": vector["artifacts"][artifact_name]["sha256"],
            "size": vector["artifacts"][artifact_name]["size"],
            "mode": expected_mode,
        }
        if record != expected:
            raise LovelaceError(
                f"hostile plan {input_name} differs from the artifact vector"
            )
    if len(artifact_parents) != 1:
        raise LovelaceError(
            "hostile plan inputs do not share one release directory"
        )

    storage = plan["storage"]
    require_exact_keys(
        storage,
        {
            "mode",
            "root_disk",
            "deferred_root_disk_token",
            "root_format",
            "base_image_mutated",
            "qemu_temporary_snapshot",
            "explicit_private_volatile_overlay",
            "volatile_overlay_deferred_until_real_launch",
            "volatile_overlay_cleanup_on_supervisor_unwind",
            "volatile_overlay_cleanup_after_sigkill_or_host_crash",
            "guest_writes_persist",
            "overlay",
        },
        "hostile plan storage",
    )
    root_value = storage["root_disk"]
    if not isinstance(root_value, str):
        raise LovelaceError("hostile plan lacks a materialized root overlay")
    root_disk = _hostile_serialized_absolute_path(
        root_value, "hostile materialized overlay"
    )
    volatile = state_root / "volatile"
    if (
        not root_disk.is_absolute()
        or Path(os.path.abspath(root_value)) != root_disk
        or root_disk.parent != volatile
    ):
        raise LovelaceError(
            "hostile materialized overlay escaped the volatile state root"
        )
    overlay = storage["overlay"]
    require_exact_keys(
        overlay,
        {
            "path",
            "format",
            "allocated_file_size",
            "virtual_size",
            "base_path",
            "base_sha256",
            "single_link_regular_file",
            "private_permissions",
            "cleanup_on_supervisor_unwind",
            "cleanup_after_sigkill_or_host_crash_claimed",
        },
        "hostile plan overlay",
    )
    if (
        storage
        != {
            "mode": "volatile",
            "root_disk": root_value,
            "deferred_root_disk_token": None,
            "root_format": "qcow2",
            "base_image_mutated": False,
            "qemu_temporary_snapshot": False,
            "explicit_private_volatile_overlay": True,
            "volatile_overlay_deferred_until_real_launch": False,
            "volatile_overlay_cleanup_on_supervisor_unwind": True,
            "volatile_overlay_cleanup_after_sigkill_or_host_crash": False,
            "guest_writes_persist": False,
            "overlay": overlay,
        }
        or overlay["path"] != root_value
        or overlay["format"] != "qcow2"
        or type(overlay["allocated_file_size"]) is not int
        or overlay["allocated_file_size"] <= 0
        or overlay["virtual_size"]
        != vector["artifacts"]["base_image"]["size"]
        or overlay["base_path"] != str(paths["base_image"])
        or overlay["base_sha256"]
        != vector["artifacts"]["base_image"]["sha256"]
        or overlay["single_link_regular_file"] is not True
        or overlay["private_permissions"] is not True
        or overlay["cleanup_on_supervisor_unwind"] is not True
        or overlay["cleanup_after_sigkill_or_host_crash_claimed"] is not False
    ):
        raise LovelaceError("hostile volatile-overlay record differs")

    if plan["network"] != {
        "mode": "none",
        "guest_internet_enabled": False,
        "inbound_host_forwarding": False,
        "host_shares": False,
    }:
        raise LovelaceError("hostile plan attached a network or host share")
    if plan["acceleration"] != {
        "selected": "kvm",
        "tcg_fallback": False,
        "label": "KVM REQUIRED (hostile fail-closed profile)",
    }:
        raise LovelaceError("hostile plan did not select fail-closed KVM")
    if plan["resources"] != {
        "memory_mib": HOSTILE_MEMORY_MIB,
        "cpus": HOSTILE_CPUS,
        "limits": {
            "memory_mib": [512, 16384],
            "cpus": [1, 8],
        },
    }:
        raise LovelaceError("hostile plan resource selection differs")
    expected_sandbox = (
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,"
        "resourcecontrol=deny"
    )
    expected_controls = {
        "direct_kernel_boot": True,
        "q35_machine": True,
        "nodefaults": True,
        "no_user_config": True,
        "monitor_disabled": True,
        "serial_stdio": True,
        "hostile_console_rendering": "escaped-ascii",
        "hostile_console_forwarded_byte_allowlist": list(
            HOSTILE_CONSOLE_FORWARDED_BYTE_ALLOWLIST
        ),
        "hostile_non_allowlisted_console_bytes_forwarded": False,
        "hostile_console_stderr_merged": True,
        "hostile_console_byte_limit": MAX_HOSTILE_CONSOLE_BYTES,
        "hostile_console_input_buffer_byte_limit": (
            MAX_HOSTILE_CONSOLE_INPUT_BUFFER_BYTES
        ),
        "hostile_stdin_one_way_pipe": True,
        "hostile_tty_restoration_on_handled_exit": True,
        "hostile_tty_input_flushed_before_handoff": True,
        "hostile_process_group_absence_checked": True,
        "hostile_handled_signals": [
            "SIGHUP",
            "SIGINT",
            "SIGQUIT",
            "SIGTERM",
            "SIGTSTP",
        ],
        "hostile_console_descendant_drain_timeout_seconds": 5,
        "hostile_console_leader_exit_confirm_timeout_seconds": (
            HOSTILE_CONSOLE_LEADER_EXIT_CONFIRM_TIMEOUT_SECONDS
        ),
        "qemu_sandbox": expected_sandbox,
        "host_shares": False,
        "shell": False,
        "sanitized_environment": True,
        "hostile_requires_kvm": True,
        "hostile_requires_non_root": True,
        "hostile_outer_bubblewrap": True,
        "empty_private_host_root": True,
        "host_network_namespace_unshared": True,
        "exact_read_only_host_bindings": True,
        "volatile_overlay_only_read_write_binding": True,
        "exact_kvm_device_binding": True,
        "hostile_payload_read_only_secondary_media": False,
        "hostile_payload_host_source_shared": False,
        "hostile_payload_host_execution": False,
        "explicit_host_resource_limits": True,
        "implicit_qemu_snapshot": False,
        "explicit_private_volatile_overlay": True,
    }
    if plan["controls"] != expected_controls:
        raise LovelaceError("hostile launch controls differ")

    outer = plan["outer_boundary"]
    require_exact_keys(
        outer,
        {
            "supervisor",
            "path",
            "empty_private_root",
            "root_read_only_after_setup",
            "namespace_flags",
            "private_tmpfs",
            "read_only_bindings",
            "read_write_bindings",
            "device_bindings",
            "directory_skeleton",
            "environment",
            "host_network_namespace_unshared",
            "host_resource_limits",
        },
        "hostile outer boundary",
    )
    expected_binding_triples = [
        (
            "/usr/bin/qemu-system-x86_64",
            "/usr/bin/qemu-system-x86_64",
            "file",
        ),
        (
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "directory",
        ),
        ("/usr/share/qemu", "/usr/share/qemu", "directory"),
        ("/usr/share/seabios", "/usr/share/seabios", "directory"),
        (
            "/usr/lib/x86_64-linux-gnu",
            "/lib/x86_64-linux-gnu",
            "directory",
        ),
        (
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib64/ld-linux-x86-64.so.2",
            "file",
        ),
        ("/etc/ld.so.cache", "/etc/ld.so.cache", "file"),
        *(
            (
                str(paths[artifact_name]),
                str(paths[artifact_name]),
                "file",
            )
            for _input_name, artifact_name, _required_mode in input_artifacts
        ),
    ]
    bindings = outer["read_only_bindings"]
    if not isinstance(bindings, list):
        raise LovelaceError("hostile read-only binding list is invalid")
    for record in bindings:
        require_exact_keys(
            record,
            {
                "source",
                "destination",
                "kind",
                "device",
                "inode",
                "links",
                "size",
                "mtime_ns",
                "ctime_ns",
                "mode",
            },
            "hostile read-only binding",
        )
        mode_value = record["mode"]
        if not (
            _hostile_serialized_absolute_path(
                record["source"], "hostile binding source"
            )
            == Path(record["source"])
            and _hostile_serialized_absolute_path(
                record["destination"], "hostile binding destination"
            )
            == Path(record["destination"])
            and record["kind"] in {"file", "directory"}
            and type(record["device"]) is int
            and record["device"] >= 0
            and type(record["inode"]) is int
            and record["inode"] > 0
            and type(record["links"]) is int
            and record["links"] >= 1
            and type(record["size"]) is int
            and record["size"] >= 0
            and type(record["mtime_ns"]) is int
            and record["mtime_ns"] >= 0
            and type(record["ctime_ns"]) is int
            and record["ctime_ns"] >= 0
            and isinstance(mode_value, str)
            and re.fullmatch(r"[0-7]{4}", mode_value) is not None
        ):
            raise LovelaceError(
                "hostile read-only binding metadata is invalid"
            )
    observed_triples = [
        (record["source"], record["destination"], record["kind"])
        for record in bindings
    ]
    for offset, (input_name, _artifact_name, _required_mode) in enumerate(
        input_artifacts
    ):
        binding = bindings[7 + offset]
        input_record = inputs[input_name]
        if (
            binding["size"] != input_record["size"]
            or binding["mode"] != input_record["mode"]
        ):
            raise LovelaceError(
                f"hostile {input_name} binding metadata differs"
            )
    expected_limits = hostile_resource_limits(vector)
    expected_outer_environment = {
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin",
        "XDG_CONFIG_HOME": "/tmp",
    }
    if (
        outer["supervisor"] != "bubblewrap"
        or outer["path"] != "/usr/bin/bwrap"
        or outer["empty_private_root"] is not True
        or outer["root_read_only_after_setup"] is not True
        or outer["namespace_flags"] != list(HOSTILE_BWRAP_FLAGS)
        or outer["private_tmpfs"] != ["/tmp", "/run", "/var/tmp"]
        or len(bindings) != 10
        or observed_triples != expected_binding_triples
        or outer["read_write_bindings"]
        != [
            {
                "source": root_value,
                "destination": root_value,
                "purpose": "private volatile qcow2 overlay only",
                "materialized": True,
            }
        ]
        or outer["device_bindings"]
        != [{"source": "/dev/kvm", "destination": "/dev/kvm"}]
        or outer["environment"] != expected_outer_environment
        or outer["host_network_namespace_unshared"] is not True
        or outer["host_resource_limits"]
        != {
            "applied_before_bubblewrap_exec": True,
            "inherited_by_qemu": True,
            "limits": expected_limits,
        }
        or plan["host_resource_limits"] != expected_limits
    ):
        raise LovelaceError("hostile outer-boundary policy differs")

    expected_directories = {
        Path("/dev"),
        Path("/proc"),
        Path("/run"),
        Path("/sys"),
        Path("/tmp"),
        Path("/var"),
        Path("/var/tmp"),
        volatile,
    }
    for _source, destination_value, kind in expected_binding_triples:
        destination = Path(destination_value)
        current = destination if kind == "directory" else destination.parent
        while current != Path("/"):
            expected_directories.add(current)
            current = current.parent
    current = volatile
    while current != Path("/"):
        expected_directories.add(current)
        current = current.parent
    expected_skeleton = [
        str(path)
        for path in sorted(
            expected_directories,
            key=lambda item: (len(item.parts), str(item)),
        )
    ]
    if outer["directory_skeleton"] != expected_skeleton:
        raise LovelaceError("hostile outer directory skeleton differs")

    qemu_argv = [
        "/usr/bin/qemu-system-x86_64",
        "-nodefaults",
        "-no-user-config",
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        str(HOSTILE_MEMORY_MIB),
        "-smp",
        str(HOSTILE_CPUS),
        "-name",
        "wuci-lab-hostile,debug-threads=on",
        "-sandbox",
        expected_sandbox,
        "-monitor",
        "none",
        "-nographic",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
        "-kernel",
        str(paths["kernel"]),
        "-initrd",
        str(paths["initramfs"]),
        "-append",
        " ".join(expected_release_kernel_arguments()),
        "-drive",
        (
            f"file={root_value},if=none,id=wuci-root,format=qcow2,"
            "cache=writeback,aio=threads"
        ),
        "-device",
        "virtio-blk-pci,drive=wuci-root,bootindex=1",
        "-nic",
        "none",
    ]
    expected_outer_argv = [
        "/usr/bin/bwrap",
        *HOSTILE_BWRAP_FLAGS,
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
    for directory in expected_skeleton:
        expected_outer_argv.extend(["--dir", directory])
    expected_outer_argv.extend(
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
        expected_outer_argv.extend(
            ["--perms", "0700", "--tmpfs", destination]
        )
    for record in bindings:
        expected_outer_argv.extend(
            ["--ro-bind", record["source"], record["destination"]]
        )
    expected_outer_argv.extend(
        [
            "--bind",
            root_value,
            root_value,
            "--remount-ro",
            "/",
            "--chdir",
            "/tmp",
        ]
    )
    for key, value in expected_outer_environment.items():
        expected_outer_argv.extend(["--setenv", key, value])
    expected_outer_argv.extend(["--", *qemu_argv])
    outer_argv = plan["argv"]
    if (
        plan["qemu_argv"] != qemu_argv
        or outer_argv != expected_outer_argv
    ):
        raise LovelaceError("hostile executed argument vector differs")
    if plan["environment"] != {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "XDG_CONFIG_HOME": "/nonexistent",
    }:
        raise LovelaceError("hostile supervisor environment differs")
    if plan["claims"] != {
        "production_ready_claimed": False,
        "runtime_sandbox_claimed": False,
        "safe_for_arbitrary_malware_claimed": False,
        "hypervisor_escape_impossible_claimed": False,
    }:
        raise LovelaceError("hostile supervisor claim boundary differs")
    if plan["nonclaims"] != list(HOSTILE_SUPERVISOR_NONCLAIMS):
        raise LovelaceError("hostile supervisor nonclaims are invalid")

    return {
        "schema": plan["schema"],
        "source_plan_sha256": hashlib.sha256(
            canonical_json(plan)
        ).hexdigest(),
        "profile": "hostile",
        "storage": "volatile",
        "network": "none",
        "acceleration": "kvm",
        "memory_mib": HOSTILE_MEMORY_MIB,
        "cpus": HOSTILE_CPUS,
        "qemu_sandbox": expected_sandbox,
        "supervisor_paths": {
            "qemu": supervisor["qemu_path"],
            "qemu_img": supervisor["qemu_img_path"],
            "bubblewrap": supervisor["bubblewrap_path"],
        },
        "artifact_digests": {
            name: vector["artifacts"][name]["sha256"]
            for name in ("base_image", "kernel", "initramfs")
        },
        "namespace_flags": list(HOSTILE_BWRAP_FLAGS),
        "outer_boundary": "bubblewrap",
        "empty_private_root": True,
        "root_read_only_after_setup": True,
        "host_network_namespace_unshared": True,
        "read_only_binding_count": len(bindings),
        "read_only_bindings_sha256": hashlib.sha256(
            canonical_json(bindings)
        ).hexdigest(),
        "writable_binding_purpose": "private volatile qcow2 overlay only",
        "device_bindings": outer["device_bindings"],
        "host_resource_limits": expected_limits,
        "qemu_argv_sha256": hashlib.sha256(
            canonical_json(qemu_argv)
        ).hexdigest(),
        "outer_argv_sha256": hashlib.sha256(
            canonical_json(outer_argv)
        ).hexdigest(),
        "materialized_plan": plan,
        "network_device_absent": True,
        "persistent_disk_absent": True,
        "host_shares_absent": True,
        "host_device_passthrough_absent": True,
    }, root_disk


def hostile_payload_plan_summary(
    plan: dict[str, Any],
    paths: dict[str, Path],
    vector: dict[str, Any],
    state_root: Path,
    payload_tools: dict[str, Any],
    *,
    payload_uid: int,
    payload_gid: int,
    inspect_artifacts: bool = True,
) -> tuple[dict[str, Any], Path, Path]:
    require_exact_keys(
        payload_tools,
        {"mke2fs", "debugfs"},
        "hostile payload host tools",
    )
    for name, path in {
        "mke2fs": "/usr/sbin/mke2fs",
        "debugfs": "/usr/sbin/debugfs",
    }.items():
        _validate_hostile_executable_record(
            payload_tools[name], path, f"hostile payload {name}"
        )
        if payload_tools[name]["version"] != (
            f"{name} {EXPECTED_E2FSPROGS_VERSION} (5-Feb-2023)"
        ):
            raise LovelaceError(
                f"hostile payload {name} version binding differs"
            )

    supervisor = plan.get("supervisor")
    if not isinstance(supervisor, dict):
        raise LovelaceError("hostile payload plan lacks a supervisor record")
    expected_tool_supervisor = {
        "mke2fs_path": payload_tools["mke2fs"]["path"],
        "mke2fs_version": EXPECTED_E2FSPROGS_VERSION,
        "debugfs_path": payload_tools["debugfs"]["path"],
        "debugfs_version": EXPECTED_E2FSPROGS_VERSION,
    }
    if any(
        supervisor.get(key) != value
        for key, value in expected_tool_supervisor.items()
    ):
        raise LovelaceError(
            "hostile payload supervisor tool bindings differ"
        )

    source = hostile_payload_fixture_record()
    ingress = plan.get("payload_ingress")
    require_exact_keys(
        ingress,
        {
            "schema",
            "source",
            "media",
            "deferred_media_token",
            "guest_device",
            "guest_media_path",
            "guest_read_only",
            "host_source_shared",
            "host_execution",
            "bounded_source_bytes",
            "cleanup_on_supervisor_unwind",
            "cleanup_after_sigkill_or_host_crash_claimed",
        },
        "hostile payload ingress",
    )
    if (
        ingress["schema"] != HOSTILE_PAYLOAD_SCHEMA
        or ingress["source"] != source
        or ingress["deferred_media_token"] is not None
        or ingress["guest_device"] != HOSTILE_PAYLOAD_GUEST_DEVICE
        or ingress["guest_media_path"] != HOSTILE_PAYLOAD_GUEST_MEDIA
        or ingress["guest_read_only"] is not True
        or ingress["host_source_shared"] is not False
        or ingress["host_execution"] is not False
        or ingress["bounded_source_bytes"] != MAX_HOSTILE_PAYLOAD_BYTES
        or ingress["cleanup_on_supervisor_unwind"] is not True
        or ingress["cleanup_after_sigkill_or_host_crash_claimed"] is not False
    ):
        raise LovelaceError("hostile payload ingress policy differs")
    validated_payload = validate_hostile_payload_media_report(
        ingress["media"],
        source=source,
        state_root=state_root,
        debugfs_path=Path(payload_tools["debugfs"]["path"]),
        payload_uid=payload_uid,
        payload_gid=payload_gid,
        inspect_media=inspect_artifacts,
    )
    media = validated_payload["media"]
    media_path = Path(media["path"])

    controls = plan.get("controls")
    if not isinstance(controls, dict) or (
        controls.get("hostile_payload_read_only_secondary_media") is not True
        or controls.get("hostile_payload_host_source_shared") is not False
        or controls.get("hostile_payload_host_execution") is not False
    ):
        raise LovelaceError("hostile payload launch controls differ")
    outer = plan.get("outer_boundary")
    bindings = (
        outer.get("read_only_bindings")
        if isinstance(outer, dict)
        else None
    )
    if not isinstance(bindings, list) or len(bindings) != 11:
        raise LovelaceError(
            "hostile payload plan lacks its exact read-only binding"
        )
    payload_binding = bindings[-1]
    require_exact_keys(
        payload_binding,
        {
            "source",
            "destination",
            "kind",
            "device",
            "inode",
            "links",
            "size",
            "mtime_ns",
            "ctime_ns",
            "mode",
            "purpose",
            "materialized",
        },
        "hostile payload bwrap binding",
    )
    if (
        payload_binding["source"] != str(media_path)
        or payload_binding["destination"] != HOSTILE_PAYLOAD_GUEST_MEDIA
        or payload_binding["kind"] != "file"
        or type(payload_binding["device"]) is not int
        or payload_binding["device"] < 0
        or type(payload_binding["inode"]) is not int
        or payload_binding["inode"] <= 0
        or payload_binding["links"] != 1
        or payload_binding["size"] != media["size"]
        or type(payload_binding["mtime_ns"]) is not int
        or payload_binding["mtime_ns"] < 0
        or type(payload_binding["ctime_ns"]) is not int
        or payload_binding["ctime_ns"] < 0
        or payload_binding["mode"] != "0400"
        or payload_binding["purpose"]
        != "guest-read-only hostile payload media"
        or payload_binding["materialized"] is not True
    ):
        raise LovelaceError("hostile payload bwrap binding differs")
    if inspect_artifacts:
        media_info = media_path.lstat()
        if any(
            payload_binding[field] != observed
            for field, observed in {
                "device": media_info.st_dev,
                "inode": media_info.st_ino,
                "links": media_info.st_nlink,
                "size": media_info.st_size,
                "mtime_ns": media_info.st_mtime_ns,
                "ctime_ns": media_info.st_ctime_ns,
                "mode": f"{stat.S_IMODE(media_info.st_mode):04o}",
            }.items()
        ):
            raise LovelaceError(
                "hostile payload bwrap binding changed from the media inode"
            )

    payload_drive = (
        f"file={HOSTILE_PAYLOAD_GUEST_MEDIA},if=none,id=wuci-payload,"
        "format=raw,readonly=on,cache=writeback,aio=threads"
    )
    payload_qemu_tokens = [
        "-drive",
        payload_drive,
        "-device",
        "virtio-blk-pci,drive=wuci-payload",
    ]
    qemu_argv = plan.get("qemu_argv")
    if not isinstance(qemu_argv, list) or not all(
        isinstance(item, str) for item in qemu_argv
    ):
        raise LovelaceError("hostile payload QEMU argv is invalid")
    payload_offsets = [
        index
        for index in range(len(qemu_argv) - len(payload_qemu_tokens) + 1)
        if qemu_argv[index : index + len(payload_qemu_tokens)]
        == payload_qemu_tokens
    ]
    if len(payload_offsets) != 1:
        raise LovelaceError(
            "hostile payload QEMU attachment differs"
        )
    payload_offset = payload_offsets[0]
    stripped_qemu = [
        *qemu_argv[:payload_offset],
        *qemu_argv[payload_offset + len(payload_qemu_tokens) :],
    ]
    if (
        str(HOSTILE_PAYLOAD_FIXTURE_PATH)
        in canonical_json(qemu_argv).decode("ascii")
        or str(media_path) in canonical_json(qemu_argv).decode("ascii")
    ):
        raise LovelaceError(
            "hostile payload QEMU argv exposes a host source path"
        )

    outer_argv = plan.get("argv")
    payload_bwrap_tokens = [
        "--ro-bind",
        str(media_path),
        HOSTILE_PAYLOAD_GUEST_MEDIA,
    ]
    if not isinstance(outer_argv, list) or not all(
        isinstance(item, str) for item in outer_argv
    ):
        raise LovelaceError("hostile payload outer argv is invalid")
    bwrap_offsets = [
        index
        for index in range(len(outer_argv) - 2)
        if outer_argv[index : index + 3] == payload_bwrap_tokens
    ]
    separator = len(outer_argv) - len(qemu_argv) - 1
    if (
        len(bwrap_offsets) != 1
        or not 0 <= separator < len(outer_argv)
        or outer_argv[separator] != "--"
        or outer_argv[separator + 1 :] != qemu_argv
        or bwrap_offsets[0] >= separator
        or str(HOSTILE_PAYLOAD_FIXTURE_PATH)
        in canonical_json(outer_argv).decode("ascii")
    ):
        raise LovelaceError(
            "hostile payload outer attachment differs"
        )
    bwrap_offset = bwrap_offsets[0]
    stripped_outer_prefix = [
        *outer_argv[:bwrap_offset],
        *outer_argv[bwrap_offset + 3 : separator],
    ]
    stripped_outer = [*stripped_outer_prefix, "--", *stripped_qemu]

    ordinary_plan = copy.deepcopy(plan)
    ordinary_plan["supervisor"].update(
        {
            "mke2fs_path": None,
            "mke2fs_version": None,
            "debugfs_path": None,
            "debugfs_version": None,
        }
    )
    ordinary_plan["payload_ingress"] = None
    ordinary_plan["controls"][
        "hostile_payload_read_only_secondary_media"
    ] = False
    ordinary_plan["outer_boundary"]["read_only_bindings"] = copy.deepcopy(
        bindings[:-1]
    )
    ordinary_plan["qemu_argv"] = stripped_qemu
    ordinary_plan["argv"] = stripped_outer
    ordinary_summary, root_disk = hostile_plan_summary(
        ordinary_plan,
        paths,
        vector,
        state_root,
        inspect_artifacts=inspect_artifacts,
    )
    summary = dict(ordinary_summary)
    summary.update(
        {
            "source_plan_sha256": hashlib.sha256(
                canonical_json(plan)
            ).hexdigest(),
            "supervisor_paths": {
                **ordinary_summary["supervisor_paths"],
                "mke2fs": payload_tools["mke2fs"]["path"],
                "debugfs": payload_tools["debugfs"]["path"],
            },
            "read_only_binding_count": len(bindings),
            "read_only_bindings_sha256": hashlib.sha256(
                canonical_json(bindings)
            ).hexdigest(),
            "qemu_argv_sha256": hashlib.sha256(
                canonical_json(qemu_argv)
            ).hexdigest(),
            "outer_argv_sha256": hashlib.sha256(
                canonical_json(outer_argv)
            ).hexdigest(),
            "materialized_plan": plan,
            "payload": {
                **validated_payload,
                "trusted_tools": copy.deepcopy(payload_tools),
                "bwrap_binding": copy.deepcopy(payload_binding),
                "qemu_attachment": {
                    "drive": payload_drive,
                    "device": "virtio-blk-pci,drive=wuci-payload",
                    "guest_device": HOSTILE_PAYLOAD_GUEST_DEVICE,
                    "read_only": True,
                },
            },
        }
    )
    return summary, root_disk, media_path


def _challenge_result_command(marker: str, challenge: str) -> str:
    if (
        re.fullmatch(r"[A-Z0-9_]+", marker) is None
        or not is_lower_hex(challenge, 64)
    ):
        raise LovelaceError("invalid hostile challenge result")
    marker_split = len(marker) // 2
    challenge_split = len(challenge) // 2
    return (
        "printf '\\n%s%s%s%s\\n' "
        f"'{marker[:marker_split]}' '{marker[marker_split:]}' "
        f"' {challenge[:challenge_split]}' "
        f"'{challenge[challenge_split:]}'"
    )


def hostile_payload_guest_commands(
    challenge: str,
) -> tuple[list[str], list[str]]:
    if not is_lower_hex(challenge, 64):
        raise LovelaceError("invalid hostile payload challenge")
    source = hostile_payload_fixture_record()
    manifest = hostile_payload_manifest(source)
    manifest_bytes = canonical_json(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    payload_path = f"{HOSTILE_PAYLOAD_MOUNTPOINT}/payload.bin"
    manifest_path = f"{HOSTILE_PAYLOAD_MOUNTPOINT}/manifest.json"
    payload_check = (
        f"doas mkdir -p {HOSTILE_PAYLOAD_MOUNTPOINT} && "
        "doas mount -t ext4 -o ro,nodev,nosuid,noexec "
        f"{HOSTILE_PAYLOAD_GUEST_DEVICE} {HOSTILE_PAYLOAD_MOUNTPOINT} && "
        "doas sh -c 'set -eu; "
        f"test \"$(wc -c < {payload_path})\" = "
        f"\"{HOSTILE_PAYLOAD_FIXTURE_SIZE}\"; "
        f"observed=$(sha256sum {payload_path}); "
        f"test \"${{observed%% *}}\" = "
        f"\"{HOSTILE_PAYLOAD_FIXTURE_SHA256}\"' && "
        f"{_challenge_result_command(HOSTILE_PAYLOAD_BYTES_MARKER, challenge)}"
    )
    manifest_check = (
        "doas sh -c 'set -eu; "
        f"test \"$(wc -c < {manifest_path})\" = "
        f"\"{len(manifest_bytes)}\"; "
        f"observed=$(sha256sum {manifest_path}); "
        f"test \"${{observed%% *}}\" = \"{manifest_sha256}\"' && "
        f"{_challenge_result_command(HOSTILE_PAYLOAD_MANIFEST_MARKER, challenge)}"
    )
    read_only_check = (
        "doas sh -c 'set -eu; "
        f"line=$(grep \"^{HOSTILE_PAYLOAD_GUEST_DEVICE} "
        f"{HOSTILE_PAYLOAD_MOUNTPOINT} ext4 \" /proc/mounts); "
        "test -n \"$line\"; options=${line#* ext4 }; "
        "options=${options%% *}; "
        "for option in ro nodev nosuid noexec; do "
        "case \",$options,\" in *,\"$option\",*) ;; *) exit 1 ;; esac; "
        "done; "
        f"if printf x 2>/dev/null >> {payload_path}; then exit 1; fi; "
        f"test \"$(wc -c < {payload_path})\" = "
        f"\"{HOSTILE_PAYLOAD_FIXTURE_SIZE}\"; "
        f"observed=$(sha256sum {payload_path}); "
        f"test \"${{observed%% *}}\" = "
        f"\"{HOSTILE_PAYLOAD_FIXTURE_SHA256}\"; "
        f"probe={HOSTILE_PAYLOAD_MOUNTPOINT}/root-write-probe; "
        "if touch \"$probe\" 2>/dev/null; then exit 1; fi; "
        "test ! -e \"$probe\"' && "
        f"doas umount {HOSTILE_PAYLOAD_MOUNTPOINT} && "
        f"doas rmdir {HOSTILE_PAYLOAD_MOUNTPOINT} && "
        f"{_challenge_result_command(HOSTILE_PAYLOAD_MARKER, challenge)}"
    )
    result_markers = [
        HOSTILE_PAYLOAD_BYTES_MARKER,
        HOSTILE_PAYLOAD_MANIFEST_MARKER,
        HOSTILE_PAYLOAD_MARKER,
    ]
    return (
        [
            payload_check,
            manifest_check,
            read_only_check,
            "doas poweroff -f",
        ],
        [f"{marker} {challenge}" for marker in result_markers],
    )


def hostile_payload_guest_command_contract(
    challenge: str,
) -> dict[str, Any]:
    commands, results = hostile_payload_guest_commands(challenge)
    source = hostile_payload_fixture_record()
    manifest_bytes = canonical_json(hostile_payload_manifest(source))
    return {
        "guest_device": HOSTILE_PAYLOAD_GUEST_DEVICE,
        "mountpoint": HOSTILE_PAYLOAD_MOUNTPOINT,
        "mount_options": ["ro", "nodev", "nosuid", "noexec"],
        "payload": {
            "path": f"{HOSTILE_PAYLOAD_MOUNTPOINT}/payload.bin",
            "size": HOSTILE_PAYLOAD_FIXTURE_SIZE,
            "sha256": HOSTILE_PAYLOAD_FIXTURE_SHA256,
        },
        "manifest": {
            "path": f"{HOSTILE_PAYLOAD_MOUNTPOINT}/manifest.json",
            "size": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
        "root_write_attempts_must_fail": [
            f"{HOSTILE_PAYLOAD_MOUNTPOINT}/payload.bin",
            f"{HOSTILE_PAYLOAD_MOUNTPOINT}/root-write-probe",
        ],
        "payload_reverified_after_write_rejection": True,
        "guest_root_write_rejected_and_probe_absent": True,
        "unmount_required_before_success": True,
        "poweroff_command": "doas poweroff -f",
        "result_markers": [
            HOSTILE_PAYLOAD_BYTES_MARKER,
            HOSTILE_PAYLOAD_MANIFEST_MARKER,
            HOSTILE_PAYLOAD_MARKER,
        ],
        "commands_sha256": hashlib.sha256(
            canonical_json(commands)
        ).hexdigest(),
        "command_results_sha256": hashlib.sha256(
            canonical_json(results)
        ).hexdigest(),
    }


def hostile_test(output: Path) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise LovelaceError("hostile KVM-cell evidence refuses to run as root")
    with output_lock(output):
        verification = evidence_input_verification_snapshot(
            _verify_build_locked(output)
        )
        manifest, paths = artifact_paths(output)
        vector = canonical_artifact_vector(manifest)
        before = digest_file(paths["base_image"])
        state_root, volatile = _hostile_state_directories()
        entries_before = _empty_volatile_snapshot(
            volatile, "hostile volatile state directory before launch"
        )
        expected_markers = [BOOT_MARKER, CONSOLE_MARKER]
        result_markers = [
            HOSTILE_NETWORK_MARKER,
            HOSTILE_WUCIJI_MARKER,
            HOSTILE_NOXFRAME_RESULT_MARKER,
            GHIDRA_SEMANTIC_MARKER,
            HOSTILE_GHIDRA_MARKER,
            HOSTILE_CELL_MARKER,
        ]

        def hostile_command_factory(
            challenge: str,
        ) -> tuple[list[str], list[str]]:
            command_results = [
                f"{marker} {challenge}" for marker in result_markers
            ]
            ghidra_command = ghidra_smoke_command(
                project_name="lovelace-hostile-smoke",
                temporary_prefix="wuci-hostile-ghidra",
                timeout_seconds=GHIDRA_PROCESS_TIMEOUT_SECONDS,
                success_marker=HOSTILE_GHIDRA_MARKER,
                challenge=challenge,
            )
            commands = [
                (
                    "test -d /sys/class/net/lo; "
                    "for iface in /sys/class/net/*; do "
                    "test \"${iface##*/}\" = lo || exit 1; done; "
                    "command -v ss >/dev/null || exit 1; "
                    "test -z \"$(ss -H -lntup 2>/dev/null)\" && "
                    f"{_challenge_result_command(HOSTILE_NETWORK_MARKER, challenge)}"
                ),
                (
                    "wuci-ji selftest >/dev/null && "
                    f"{_challenge_result_command(HOSTILE_WUCIJI_MARKER, challenge)}"
                ),
                (
                    "wuci-noxframe-smoke && "
                    f"{_challenge_result_command(HOSTILE_NOXFRAME_RESULT_MARKER, challenge)}"
                ),
                ghidra_command,
                _challenge_result_command(
                    HOSTILE_CELL_MARKER, challenge
                ),
                "doas poweroff -f",
            ]
            return commands, command_results

        command = [
            sys.executable,
            str(REPO / "tools/wuci_lab.py"),
            "launch",
            "--kernel",
            str(paths["kernel"]),
            "--kernel-sha256",
            vector["artifacts"]["kernel"]["sha256"],
            "--initrd",
            str(paths["initramfs"]),
            "--initrd-sha256",
            vector["artifacts"]["initramfs"]["sha256"],
            "--base-image",
            str(paths["base_image"]),
            "--base-sha256",
            vector["artifacts"]["base_image"]["sha256"],
            "--state-root",
            str(state_root),
            "--profile",
            "hostile",
            "--storage",
            "volatile",
            "--network",
            "none",
            "--accel",
            "kvm",
            "--memory-mib",
            str(HOSTILE_MEMORY_MIB),
            "--cpus",
            str(HOSTILE_CPUS),
        ]
        host_executables_before = hostile_host_executable_records()
        plan, runtime = run_hostile_supervisor_commands(
            command,
            expected_markers,
            host_executables_before["qemu"],
            command_factory=hostile_command_factory,
            validate_plan=lambda candidate: hostile_plan_summary(
                candidate, paths, vector, state_root
            ),
            timeout_seconds=1800,
        )
        plan_summary, root_disk = hostile_plan_summary(
            plan, paths, vector, state_root
        )
        entries_after = _empty_volatile_snapshot(
            volatile, "hostile volatile state directory after launch"
        )
        if root_disk.exists() or root_disk.is_symlink():
            raise LovelaceError(
                "hostile materialized volatile overlay remains after unwind"
            )
        after = digest_file(paths["base_image"])
        if after != before:
            raise LovelaceError(
                "hostile KVM-cell test changed the immutable base image"
            )
        host_executables_after = hostile_host_executable_records()
        if host_executables_after != host_executables_before:
            raise LovelaceError(
                "hostile host executables changed across the runtime test"
            )
        host = {
            "effective_uid": os.geteuid(),
            "kvm_device": hostile_kvm_device_record(),
            "executables": host_executables_before,
            "executables_stable_before_after": True,
        }
        evidence = {
            "schema": "wucios.lovelace.hostile_kvm_cell_evidence.v1",
            "status": "pass",
            "artifact_vector": vector,
            "base_image_sha256": before,
            "base_image_sha256_before": before,
            "base_image_sha256_after": after,
            "base_image_unchanged": True,
            "profile": "hostile",
            "execution_class": "defensive-untrusted-system-code",
            "storage": "volatile",
            "network": "none",
            "functional_accelerator": "kvm",
            "isolation_claim": True,
            "claim_scope": "local-kvm-bwrap-layered-control-presence",
            "required_layers": list(HOSTILE_REQUIRED_LAYERS),
            "layers": {layer: True for layer in HOSTILE_REQUIRED_LAYERS},
            "input_verification": verification,
            "host": host,
            "launch_plan": plan_summary,
            "cleanup": {
                "materialized_overlay_absent": True,
                "volatile_directory_unchanged": (
                    entries_after == entries_before
                ),
                "entries_before_sha256": entries_before,
                "entries_after_sha256": entries_after,
                "normal_supervisor_unwind": True,
                "cleanup_after_sigkill_or_host_crash_claimed": False,
            },
            "runtime": runtime,
            "claims": {
                "authoritative_for_release": False,
                "production_ready_claimed": False,
                "perfect_isolation_claimed": False,
                "safe_for_arbitrary_malware_claimed": False,
                "hypervisor_escape_impossible_claimed": False,
                "side_channel_confidentiality_claimed": False,
            },
            "non_claims": list(HOSTILE_EVIDENCE_NONCLAIMS),
        }
        _update_validation_unlocked(
            output,
            {
                "hostile_kvm_cell": (
                    "locally-validated-kvm-layered-control-presence"
                )
            },
            "hostile-kvm-cell.json",
            evidence,
        )
        return evidence


def hostile_payload_test(output: Path) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise LovelaceError(
            "hostile payload evidence refuses to run as root"
        )
    with output_lock(output):
        verification = evidence_input_verification_snapshot(
            _verify_build_locked(output)
        )
        manifest, paths = artifact_paths(output)
        vector = canonical_artifact_vector(manifest)
        base_before = digest_file(paths["base_image"])
        source_before = hostile_payload_fixture_record()
        state_root, volatile, payloads = (
            _hostile_payload_state_directories()
        )
        volatile_before = _empty_volatile_snapshot(
            volatile,
            "hostile payload volatile state directory before launch",
        )
        payloads_before = _empty_volatile_snapshot(
            payloads,
            "hostile payload state directory before launch",
        )
        host_executables_before = hostile_host_executable_records()
        payload_tools_before = hostile_payload_tool_records()
        expected_markers = [BOOT_MARKER, CONSOLE_MARKER]
        command = [
            sys.executable,
            str(REPO / "tools/wuci_lab.py"),
            "launch",
            "--kernel",
            str(paths["kernel"]),
            "--kernel-sha256",
            vector["artifacts"]["kernel"]["sha256"],
            "--initrd",
            str(paths["initramfs"]),
            "--initrd-sha256",
            vector["artifacts"]["initramfs"]["sha256"],
            "--base-image",
            str(paths["base_image"]),
            "--base-sha256",
            vector["artifacts"]["base_image"]["sha256"],
            "--state-root",
            str(state_root),
            "--profile",
            "hostile",
            "--storage",
            "volatile",
            "--network",
            "none",
            "--accel",
            "kvm",
            "--memory-mib",
            str(HOSTILE_MEMORY_MIB),
            "--cpus",
            str(HOSTILE_CPUS),
            "--hostile-payload",
            str(HOSTILE_PAYLOAD_FIXTURE_PATH),
            "--hostile-payload-sha256",
            HOSTILE_PAYLOAD_FIXTURE_SHA256,
        ]
        predispatch_validations: list[
            tuple[dict[str, Any], Path, Path]
        ] = []

        def validate_payload_plan(candidate: dict[str, Any]) -> None:
            if predispatch_validations:
                raise LovelaceError(
                    "hostile payload plan validation ran more than once"
                )
            summary, root_disk, media_path = (
                hostile_payload_plan_summary(
                    candidate,
                    paths,
                    vector,
                    state_root,
                    payload_tools_before,
                    payload_uid=os.geteuid(),
                    payload_gid=os.getegid(),
                )
            )
            predispatch_validations.append(
                (copy.deepcopy(summary), root_disk, media_path)
            )

        plan, runtime = run_hostile_supervisor_commands(
            command,
            expected_markers,
            host_executables_before["qemu"],
            command_factory=hostile_payload_guest_commands,
            validate_plan=validate_payload_plan,
            timeout_seconds=1800,
        )
        if len(predispatch_validations) != 1:
            raise LovelaceError(
                "hostile payload plan lacked one pre-dispatch validation"
            )
        plan_summary, root_disk, media_path = predispatch_validations[0]
        reconstructed, reconstructed_root, reconstructed_media = (
            hostile_payload_plan_summary(
                plan,
                paths,
                vector,
                state_root,
                payload_tools_before,
                payload_uid=os.geteuid(),
                payload_gid=os.getegid(),
                inspect_artifacts=False,
            )
        )
        if (
            reconstructed != plan_summary
            or reconstructed_root != root_disk
            or reconstructed_media != media_path
        ):
            raise LovelaceError(
                "hostile payload plan changed after pre-dispatch validation"
            )
        volatile_after = _empty_volatile_snapshot(
            volatile,
            "hostile payload volatile state directory after launch",
        )
        payloads_after = _empty_volatile_snapshot(
            payloads,
            "hostile payload state directory after launch",
        )
        if root_disk.exists() or root_disk.is_symlink():
            raise LovelaceError(
                "hostile payload volatile overlay remains after unwind"
            )
        if media_path.exists() or media_path.is_symlink():
            raise LovelaceError(
                "hostile payload media remains after unwind"
            )
        base_after = digest_file(paths["base_image"])
        if base_after != base_before:
            raise LovelaceError(
                "hostile payload test changed the immutable base image"
            )
        source_after = hostile_payload_fixture_record()
        if source_after != source_before:
            raise LovelaceError(
                "fixed hostile payload fixture changed across the test"
            )
        host_executables_after = hostile_host_executable_records()
        payload_tools_after = hostile_payload_tool_records()
        if (
            host_executables_after != host_executables_before
            or payload_tools_after != payload_tools_before
        ):
            raise LovelaceError(
                "hostile payload host executables changed across the test"
            )
        challenge = runtime.get("challenge")
        if not is_lower_hex(challenge, 64):
            raise LovelaceError(
                "hostile payload runtime challenge is invalid"
            )
        evidence = {
            "schema": (
                "wucios.lovelace.hostile_payload_ingress_evidence.v1"
            ),
            "status": "pass",
            "artifact_vector": vector,
            "base_image_sha256": base_before,
            "base_image_sha256_before": base_before,
            "base_image_sha256_after": base_after,
            "base_image_unchanged": True,
            "profile": "hostile",
            "execution_class": "fixed-benign-hostile-payload-ingress",
            "storage": "volatile",
            "network": "none",
            "functional_accelerator": "kvm",
            "isolation_claim": False,
            "claim_scope": (
                "local-kvm-bwrap-fixed-benign-read-only-payload-ingress"
            ),
            "required_layers": list(HOSTILE_PAYLOAD_REQUIRED_LAYERS),
            "layers": {
                layer: True for layer in HOSTILE_PAYLOAD_REQUIRED_LAYERS
            },
            "input_verification": verification,
            "host": {
                "effective_uid": os.geteuid(),
                "effective_gid": os.getegid(),
                "kvm_device": hostile_kvm_device_record(),
                "executables": host_executables_before,
                "payload_tools": payload_tools_before,
                "executables_stable_before_after": True,
            },
            "launch_plan": plan_summary,
            "guest_command_contract": (
                hostile_payload_guest_command_contract(challenge)
            ),
            "cleanup": {
                "materialized_overlay_absent": True,
                "payload_media_absent": True,
                "volatile_directory_unchanged": (
                    volatile_after == volatile_before
                ),
                "payload_directory_unchanged": (
                    payloads_after == payloads_before
                ),
                "volatile_entries_before_sha256": volatile_before,
                "volatile_entries_after_sha256": volatile_after,
                "payload_entries_before_sha256": payloads_before,
                "payload_entries_after_sha256": payloads_after,
                "normal_supervisor_unwind": True,
                "cleanup_after_sigkill_or_host_crash_claimed": False,
            },
            "runtime": runtime,
            "claims": {
                "authoritative_for_release": False,
                "production_ready_claimed": False,
                "perfect_isolation_claimed": False,
                "safe_for_arbitrary_malware_claimed": False,
                "hypervisor_escape_impossible_claimed": False,
                "side_channel_confidentiality_claimed": False,
            },
            "non_claims": list(HOSTILE_EVIDENCE_NONCLAIMS),
        }
        _update_validation_unlocked(
            output,
            {
                "hostile_payload_ingress": (
                    "locally-validated-kvm-fixed-benign-read-only-"
                    "payload-ingress"
                )
            },
            "hostile-payload-ingress.json",
            evidence,
        )
        return evidence


def launch_command(
    output: Path,
    *,
    profile: str,
    storage: str,
    overlay: str | None,
    network: str,
    accel: str,
    memory_mib: int,
    cpus: int,
    hostile_payload: str | None,
    hostile_payload_sha256: str | None,
    dry_run: bool,
) -> list[str]:
    verification = verify_build(output)
    _manifest, paths = artifact_paths(output)
    artifacts = verification["artifacts"]
    command = [
        sys.executable,
        str(REPO / "tools/wuci_lab.py"),
        "launch",
        "--kernel",
        str(paths["kernel"]),
        "--kernel-sha256",
        artifacts["kernel"]["sha256"],
        "--initrd",
        str(paths["initramfs"]),
        "--initrd-sha256",
        artifacts["initramfs"]["sha256"],
        "--base-image",
        str(paths["base_image"]),
        "--base-sha256",
        artifacts["base_image"]["sha256"],
        "--profile",
        profile,
        "--storage",
        storage,
        "--network",
        network,
        "--accel",
        accel,
        "--memory-mib",
        str(memory_mib),
        "--cpus",
        str(cpus),
    ]
    if overlay is not None:
        command.extend(["--overlay", overlay])
    if hostile_payload is not None:
        command.extend(["--hostile-payload", hostile_payload])
    if hostile_payload_sha256 is not None:
        command.extend(
            ["--hostile-payload-sha256", hostile_payload_sha256]
        )
    if dry_run:
        command.append("--dry-run")
    return command


def parser() -> argparse.ArgumentParser:
    value = LovelaceArgumentParser(
        description="Build and validate WuciOS Lovelace Laboratory"
    )
    value.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    value.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "fetch", help="explicitly fetch and lock Alpine/Ghidra inputs"
    )
    commands.add_parser(
        "verify-inputs", help="verify exact local inputs without network"
    )
    commands.add_parser("build", help="build raw ext4 image without network")
    commands.add_parser("verify", help="verify built artifacts without boot")
    commands.add_parser(
        "boot-test", help="functional TCG boot and language matrix"
    )
    commands.add_parser(
        "ghidra-test", help="functional TCG headless Ghidra smoke"
    )
    commands.add_parser(
        "noxframe-test",
        help="functional TCG NOXFRAME broker and language matrix",
    )
    commands.add_parser(
        "persistent-test",
        help="two-boot persistent qcow2 round-trip",
    )
    commands.add_parser(
        "network-test",
        help="explicit Internet-NAT HTTPS reachability test",
    )
    commands.add_parser(
        "hostile-test",
        help="KVM-only hostile-cell layered-control smoke",
    )
    commands.add_parser(
        "hostile-payload-test",
        help="KVM-only fixed benign read-only payload-ingress smoke",
    )
    commands.add_parser(
        "reproducibility-test",
        help="build twice independently and compare exact output bytes",
    )
    launch = commands.add_parser(
        "launch", help="launch through the digest-bound host supervisor"
    )
    launch.add_argument(
        "--profile",
        choices=LAUNCH_CHOICES["profile"],
        default=os.environ.get("LOVELACE_PROFILE", "developer"),
    )
    launch.add_argument(
        "--storage",
        choices=LAUNCH_CHOICES["storage"],
        default=os.environ.get("LOVELACE_STORAGE", "volatile"),
    )
    launch.add_argument(
        "--overlay", default=os.environ.get("LOVELACE_OVERLAY") or None
    )
    launch.add_argument(
        "--network",
        choices=LAUNCH_CHOICES["network"],
        default=os.environ.get("LOVELACE_NETWORK", "none"),
    )
    launch.add_argument(
        "--accel",
        choices=LAUNCH_CHOICES["accel"],
        default=os.environ.get("LOVELACE_ACCEL", "auto"),
    )
    launch.add_argument(
        "--memory-mib",
        type=int,
        default=os.environ.get("LOVELACE_MEMORY_MIB", "4096"),
    )
    launch.add_argument(
        "--cpus",
        type=int,
        default=os.environ.get("LOVELACE_CPUS", "2"),
    )
    launch.add_argument(
        "--hostile-payload",
        default=os.environ.get("LOVELACE_HOSTILE_PAYLOAD") or None,
    )
    launch.add_argument(
        "--hostile-payload-sha256",
        default=os.environ.get("LOVELACE_HOSTILE_PAYLOAD_SHA256") or None,
    )
    launch.add_argument("--dry-run", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "fetch":
            result = fetch_inputs(args.cache)
        elif args.command == "verify-inputs":
            with tempfile.TemporaryDirectory(
                prefix=".lovelace-verify.",
                dir=args.output.parent,
            ) as temporary:
                (
                    release,
                    _seeds,
                    ghidra,
                    lock,
                    kernel,
                    initramfs,
                    _bootstrap,
                ) = verify_inputs(args.cache, Path(temporary))
                result = {
                    "schema": "wucios.lovelace.input_verification.v1",
                    "status": "pass",
                    "release_id": release["release_id"],
                    "package_count": lock["package_count"],
                    "kernel_sha256": digest_file(kernel),
                    "initramfs_sha256": digest_file(initramfs),
                    "ghidra_sha256": ghidra["sha256"],
                    "all_apk_signatures_valid": True,
                    "network_used": False,
                }
        elif args.command == "build":
            result = build(args.cache, args.output)
        elif args.command == "verify":
            result = verify_build(args.output)
        elif args.command == "boot-test":
            result = boot_test(args.output)
        elif args.command == "ghidra-test":
            result = ghidra_test(args.output)
        elif args.command == "noxframe-test":
            result = noxframe_test(args.output)
        elif args.command == "persistent-test":
            result = persistent_round_trip_test(args.output)
        elif args.command == "network-test":
            result = network_test(args.output)
        elif args.command == "hostile-test":
            result = hostile_test(args.output)
        elif args.command == "hostile-payload-test":
            result = hostile_payload_test(args.output)
        elif args.command == "reproducibility-test":
            result = reproducibility_test(args.cache, args.output)
        elif args.command == "launch":
            command = launch_command(
                args.output,
                profile=args.profile,
                storage=args.storage,
                overlay=args.overlay,
                network=args.network,
                accel=args.accel,
                memory_mib=args.memory_mib,
                cpus=args.cpus,
                hostile_payload=args.hostile_payload,
                hostile_payload_sha256=args.hostile_payload_sha256,
                dry_run=args.dry_run,
            )
            completed = subprocess.run(command, shell=False, check=False)
            return completed.returncode
        else:
            raise LovelaceError(f"unsupported command: {args.command}")
        sys.stdout.buffer.write(canonical_json(result))
        return 0
    except (
        LovelaceError,
        noether_forge.NoetherForgeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        sys.stderr.write(f"lovelace-builder: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
