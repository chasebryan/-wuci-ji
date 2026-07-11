#!/usr/bin/env python3
"""Build and verify the Alpine-based WuciOS Noether Forge ISO.

Only the explicit ``fetch`` command performs network operations. Build,
inspection, boot verification, and readiness reporting consume pinned local
inputs; this is a workflow boundary, not OS-level network isolation.
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


REPO = Path(__file__).resolve().parents[2]
RELEASE_ROOT = REPO / "wucios/releases/noether-forge-v2.4.0"
DEFAULT_CACHE = REPO / "build/wucios/inputs/alpine/3.24.1/x86_64"
DEFAULT_OUTPUT = REPO / "build/wucios/noether-forge-v2.4.0"
BUILDER_VERSION = "wucios-noether-forge-builder-v1"
OVERLAY_FILENAME = "wucios-noether-forge.apkovl.tar.gz"
RUNTIME_SCHEMA = "wucios.noether.runtime.v1"
PASS_MARKER = (
    "NOETHER_FORGE_RUNTIME_PASS schema=wucios.noether.runtime.v1 "
    "release=2.4.0 profile=noether-core substrate=alpine-3.24.1 arch=x86_64"
)
BOOT_MEDIA_MARKER = "NOETHER_FORGE_BOOT_MEDIA_SHA256 "
SHUTDOWN_MARKER = "NOETHER_FORGE_SHUTDOWN_REQUESTED"
APK_SHA256_PASS_MARKER = "NOETHER_FORGE_APK_SHA256_PASS"
HOST_PASS_MARKER = "NOETHER_FORGE_HOST_INTERACTIVE_PASS"
HOME_PASS_MARKER = "NOETHER_FORGE_HOME_WRITABLE_PASS"
DOAS_DENY_PASS_MARKER = "NOETHER_FORGE_DOAS_ARBITRARY_ROOT_DENIED"
LOW_UID_MARKER = "NOETHER_FORGE_LOW_UID=1001"
RUNTIME_JSON_BEGIN = "NOETHER_FORGE_RUNTIME_JSON_BEGIN"
RUNTIME_JSON_END = "NOETHER_FORGE_RUNTIME_JSON_END"

DENIED_BOOT_LOG_FRAGMENTS = (
    "login: can't change directory",
    "Operation not permitted (you must be root)",
    "netlink: Error: cache initialization failed",
    "error: can't find command `serial'",
    "error: terminal `serial' isn't found",
)

STATIC_PRIVACY_PATTERNS = (
    (b"BEGIN OPENSSH PRIVATE KEY", "openssh-private-key-marker"),
    (b"BEGIN PRIVATE KEY", "private-key-marker"),
    (b"VOID_LIVE", "legacy-void-volume"),
    (b"voidlinux", "legacy-void-identity"),
    (b"WuciA/OS", "legacy-wucia-identity"),
    (b"Aperture Bastion", "legacy-aperture-identity"),
)

NEWC_HEADER_SIZE = 110
NEWC_MAX_NAME_SIZE = 4096
NEWC_MAX_ENTRY_SIZE = 8 * 1024 * 1024
NEWC_MAX_ENTRIES = 4096
NEWC_MAX_ARCHIVE_SIZE = 128 * 1024 * 1024
GZIP_CHUNK_SIZE = 1024 * 1024

EXPECTED_LOCK_SECTION_SHA256 = {
    "release_signer": "ff13cf8c63c7a081f9132cf767af2f1d19bfc750b665ffe95a550c6aed20a656",
    "boot_media": "119073981ac3cadfa5a89dd77838301728eb5ecb60c92a7204077fb4770e831b",
    "package_source_media": "1d795d5eefed841c719641a563c85890730764cbffd9b2bb80aed15f61f243bf",
    "post_release_overlay": "f22b6b436c956fbf2ab552e1e155a57d67e2f871a2b96a8080e46b7e30908870",
    "bootstrap": "7fbff6e29a077f27855c3cb84968bc5e87d0095ff07c5ae7cf659b80cd0bb00e",
    "upstream_layout": "22611a90fddd9b8caea2262cddcdd52decc63887ee0d3be3059def7065b3ae7c",
    "required_host_tools": "d2fcda2bc9be60102f6e0c00f73165015fc154c73069a2d1f319fa720e882561",
}
EXPECTED_INPUT_LOCK_SHA256 = "06b6714a23715f5d4df2786d289a5f6930a6172703145285cc4cacdcacad42ce"
EXPECTED_PACKAGE_LOCK_SHA256 = "cb1cb6149c4d8b8cd840ed31917cb53b1d8d3179d5c0c880572ba9506f3756b2"
EXPECTED_RELEASE_BASE_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/"
EXPECTED_OVERLAY_BASE_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/"
INITRAMFS_PATCH_SPEC = RELEASE_ROOT / "initramfs-patch-spec.json"
INITRAMFS_PATCH_LICENSE = RELEASE_ROOT / "LICENSES/GPL-2.0-only.txt"
INITRAMFS_PATCH_NOTICE = RELEASE_ROOT / "PATCH-NOTICE.md"
EXPECTED_INITRAMFS_PATCH_SPEC_SHA256 = "b95d22cf33e879b01085dea8bd3a6b8580df8f94cac1cfe6791ea425c3ec7e1b"
EXPECTED_GPL2_ONLY_TEXT_SHA256 = "b3c87315aae4c9f276c37168f2655dd8bd990544d7a0bbfb929664155c7ab257"


class NoetherForgeError(RuntimeError):
    pass


def privacy_patterns() -> tuple[tuple[bytes, str], ...]:
    """Return public markers plus non-generic identifiers of this build host."""
    dynamic: list[tuple[bytes, str]] = []
    home = os.environ.get("HOME", "").strip().rstrip("/")
    if home.startswith("/home/") and len(home.split("/")) == 3:
        username = home.rsplit("/", 1)[1]
        dynamic.append((home.encode("utf-8"), "workstation-home-path"))
        if len(username) >= 4 and username not in {"build", "builder", "nobody", "runner"}:
            dynamic.append((username.encode("utf-8"), "workstation-user-name"))
    return tuple(dynamic) + STATIC_PRIVACY_PATTERNS


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NoetherForgeError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise NoetherForgeError(f"JSON object required: {path}")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def ensure_regular(path: Path, label: str, *, expected_size: int | None = None) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise NoetherForgeError(f"{label} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise NoetherForgeError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise NoetherForgeError(f"{label} hardlink rejected: {path}")
    if expected_size is not None and info.st_size != expected_size:
        raise NoetherForgeError(f"{label} size mismatch: expected {expected_size}, got {info.st_size}")
    return info


def digest_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def initramfs_replacements(patch_spec: dict[str, Any]) -> dict[str, bytes]:
    records = patch_spec.get("replacements")
    if not isinstance(records, list) or len(records) != 4:
        raise NoetherForgeError("initramfs patch specification must contain exactly four replacements")
    replacements: dict[str, bytes] = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"label", "encoding", "content"}:
            raise NoetherForgeError("initramfs replacement record is structurally invalid")
        label = record.get("label")
        content = record.get("content")
        if (
            not isinstance(label, str)
            or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", label) is None
            or label in replacements
            or record.get("encoding") != "utf-8"
            or not isinstance(content, str)
            or not content
            or "\0" in content
        ):
            raise NoetherForgeError("initramfs replacement identity or content is invalid")
        replacements[label] = content.encode("utf-8")
    values = list(replacements.values())
    if len(values) != len(set(values)) or any(
        index != other_index and value in other
        for index, value in enumerate(values)
        for other_index, other in enumerate(values)
    ):
        raise NoetherForgeError("initramfs replacement markers must be unique and non-overlapping")
    return replacements


def load_initramfs_patch_spec(input_lock: dict[str, Any]) -> dict[str, Any]:
    ensure_regular(INITRAMFS_PATCH_SPEC, "initramfs patch specification")
    patch_spec = load_json(INITRAMFS_PATCH_SPEC)
    if hashlib.sha256(canonical_json(patch_spec)).hexdigest() != EXPECTED_INITRAMFS_PATCH_SPEC_SHA256:
        raise NoetherForgeError("exact canonical initramfs patch specification drift")
    if set(patch_spec) != {
        "schema", "license", "license_file", "notice_file", "copyright",
        "modification_notice", "upstream", "replacements",
    }:
        raise NoetherForgeError("initramfs patch specification fields are invalid")
    if (
        patch_spec.get("schema") != "wucios.noether_forge.initramfs_patch_spec.v1"
        or patch_spec.get("license") != "GPL-2.0-only"
        or patch_spec.get("license_file") != "LICENSES/GPL-2.0-only.txt"
        or patch_spec.get("notice_file") != "PATCH-NOTICE.md"
        or not isinstance(patch_spec.get("copyright"), str)
        or not isinstance(patch_spec.get("modification_notice"), str)
    ):
        raise NoetherForgeError("initramfs patch licensing metadata is invalid")
    upstream = patch_spec.get("upstream")
    if not isinstance(upstream, dict) or set(upstream) != {
        "project", "project_url", "source_file", "version", "distribution",
        "aports_commit", "provenance_basis", "source_archive", "authenticated_source",
    }:
        raise NoetherForgeError("initramfs patch upstream provenance is invalid")
    expected_binding = {
        "boot_media_filename": input_lock["boot_media"]["iso"]["filename"],
        "boot_media_sha256": input_lock["boot_media"]["iso"]["sha256"],
        "initramfs_iso_path": input_lock["bootstrap"]["initramfs"]["iso_path"],
        "initramfs_sha256": input_lock["bootstrap"]["initramfs"]["sha256"],
        "member": input_lock["bootstrap"]["patch"]["member"],
        "member_size": input_lock["bootstrap"]["patch"]["source_member_size"],
        "member_sha256": input_lock["bootstrap"]["patch"]["source_member_sha256"],
    }
    expected_source_archive = {
        "url": "https://gitlab.alpinelinux.org/alpine/mkinitfs/-/archive/3.14.0/mkinitfs-3.14.0.tar.gz",
        "size": 43617,
        "sha256": "7fae5c06d13f701c7a1578198fd7b92551ad53a747a607748b0753e31f003c0e",
        "sha512": "1cb5639347706b49c520f3b25ca19a1494601163b5b9117ffcd55b07c977a9e736303b050743bcd433958f6041bffec8d3b72177c5e507192e7d651bc013f01a",
        "template_path": "mkinitfs-3.14.0/initramfs-init.in",
        "template_sha256": "033bfaee121e0d294b0d15cdc7a789e450136323240c1aed3c96ce6a2eeecd80",
        "instantiation": {
            "token": "@VERSION@",
            "value": "3.14.0-r0",
            "result_size": input_lock["bootstrap"]["patch"]["source_member_size"],
            "result_sha256": input_lock["bootstrap"]["patch"]["source_member_sha256"],
        },
    }
    if (
        upstream.get("project") != "Alpine mkinitfs"
        or upstream.get("project_url") != "https://gitlab.alpinelinux.org/alpine/mkinitfs"
        or upstream.get("source_file") != "initramfs-init.in"
        or upstream.get("version") != "3.14.0-r0"
        or upstream.get("distribution") != "Alpine Linux 3.24.1"
        or upstream.get("aports_commit") != "ae535315a7cea5b415c834cc81ba68f03a3aae17"
        or not isinstance(upstream.get("provenance_basis"), str)
        or upstream.get("source_archive") != expected_source_archive
        or upstream.get("authenticated_source") != expected_binding
    ):
        raise NoetherForgeError("initramfs patch provenance differs from the authenticated member lock")
    ensure_regular(INITRAMFS_PATCH_LICENSE, "GPL-2.0-only license text")
    if digest_file(INITRAMFS_PATCH_LICENSE) != EXPECTED_GPL2_ONLY_TEXT_SHA256:
        raise NoetherForgeError("release-scoped GPL-2.0-only license text drift")
    ensure_regular(INITRAMFS_PATCH_NOTICE, "initramfs patch notice")
    try:
        notice = INITRAMFS_PATCH_NOTICE.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise NoetherForgeError("initramfs patch notice is unreadable") from exc
    if not all(marker in notice for marker in ("GPL-2.0-only", "source-only", "does not provide legal clearance")):
        raise NoetherForgeError("initramfs patch notice omits required licensing or non-clearance language")
    replacements = initramfs_replacements(patch_spec)
    span_labels = [record.get("label") for record in input_lock["bootstrap"]["patch"].get("source_spans", [])]
    if list(replacements) != span_labels:
        raise NoetherForgeError("initramfs replacement labels differ from the ordered source-span lock")
    return patch_spec


def digest_vector(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha384", "sha512")}
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            for digest in digests.values():
                digest.update(block)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def atomic_write(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise NoetherForgeError(f"refusing symlink output: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, canonical_json(value))


def run(
    argv: Sequence[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = [os.fspath(item) for item in argv]
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
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-4000:]
        raise NoetherForgeError(f"command failed ({result.returncode}): {command[0]}: {detail}")
    return result


def safe_reset_directory(path: Path, allowed_parent: Path) -> None:
    if path.name in {"", ".", ".."}:
        raise NoetherForgeError(f"generated directory leaf name is unsafe: {path}")
    try:
        resolved_parent = allowed_parent.resolve(strict=True)
        resolved_path_parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise NoetherForgeError(f"generated directory parent is missing or unresolved: {path.parent}") from exc
    parent_info = allowed_parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
        raise NoetherForgeError(f"generated directory allowed parent must be a real directory: {allowed_parent}")
    if resolved_path_parent != resolved_parent:
        raise NoetherForgeError(f"generated directory must be a direct child of its resolved output root: {path}")
    try:
        leaf_info = path.lstat()
    except FileNotFoundError:
        leaf_info = None
    except OSError as exc:
        raise NoetherForgeError(f"cannot inspect generated directory leaf: {path}") from exc
    if leaf_info is not None:
        if not stat.S_ISDIR(leaf_info.st_mode) or stat.S_ISLNK(leaf_info.st_mode):
            raise NoetherForgeError(f"generated directory leaf must be a real directory: {path}")
        os.chmod(path, stat.S_IRWXU)
        for current, directories, _files in os.walk(path, topdown=True, followlinks=False):
            os.chmod(current, stat.S_IRWXU)
            for name in directories:
                child = Path(current) / name
                if not child.is_symlink():
                    os.chmod(child, stat.S_IRWXU)
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=False)


def relative_repo_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO.resolve()).as_posix()
    except ValueError as exc:
        raise NoetherForgeError(f"source path outside repository: {path}") from exc


def validated_basename(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise NoetherForgeError(f"{label} must be a non-empty POSIX basename")
    path = PurePosixPath(value)
    if path.is_absolute() or len(path.parts) != 1 or path.name != value or value in {".", ".."}:
        raise NoetherForgeError(f"{label} must not contain path traversal or separators: {value!r}")
    return value


def validated_relative_posix(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise NoetherForgeError(f"{label} must be a non-empty relative POSIX path")
    path = PurePosixPath(value)
    if not path.parts or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != value:
        raise NoetherForgeError(f"{label} contains an absolute, non-canonical, or traversal path: {value!r}")
    return path


def validate_trust_locks(input_lock: dict[str, Any], package_lock: dict[str, Any]) -> None:
    if hashlib.sha256(canonical_json(input_lock)).hexdigest() != EXPECTED_INPUT_LOCK_SHA256:
        raise NoetherForgeError("exact canonical Alpine input lock drift")
    for name, expected in EXPECTED_LOCK_SECTION_SHA256.items():
        if name not in input_lock or hashlib.sha256(canonical_json(input_lock[name])).hexdigest() != expected:
            raise NoetherForgeError(f"exact Alpine trust-lock section drift: {name}")
    if hashlib.sha256(canonical_json(package_lock)).hexdigest() != EXPECTED_PACKAGE_LOCK_SHA256:
        raise NoetherForgeError("exact Noether package lock drift")
    signer = input_lock["release_signer"]
    if signer != {
        "key_url": "https://www.alpinelinux.org/keys/ncopa.asc",
        "key_filename": "ncopa.asc",
        "key_size": 3092,
        "key_sha256": "75a9a7e0cc35bfa946ce40c26133b3ed29a204fbd98a3b33331b659d927b3027",
        "fingerprint": "0482D84022F52DF1C4E7CD43293ACD0907D9495A",
    }:
        raise NoetherForgeError("Alpine release signer tuple drift")
    exact_media = {
        "boot_media": ("boot-base", "alpine-standard-3.24.1-x86_64.iso"),
        "package_source_media": ("package-source", "alpine-extended-3.24.1-x86_64.iso"),
    }
    for name, (role, filename) in exact_media.items():
        media = input_lock[name]
        if media["role"] != role or media["iso"]["filename"] != filename:
            raise NoetherForgeError(f"exact Alpine media role drift: {name}")
        if media["iso"]["url"] != EXPECTED_RELEASE_BASE_URL + filename:
            raise NoetherForgeError(f"exact Alpine media URL drift: {name}")
        for sidecar in media["sidecars"]:
            if sidecar["url"] != EXPECTED_RELEASE_BASE_URL + sidecar["filename"]:
                raise NoetherForgeError(f"exact Alpine sidecar URL drift: {sidecar.get('filename')}")
    overlay = input_lock["post_release_overlay"]
    expected_overlay_names = [
        "libexpat-2.8.2-r0.apk",
        "openrc-0.63.2-r0.apk",
        "openrc-user-0.63.2-r0.apk",
    ]
    if [item["filename"] for item in overlay] != expected_overlay_names:
        raise NoetherForgeError("post-release overlay order or identity drift")
    if package_lock["post_release_overlay"] != expected_overlay_names:
        raise NoetherForgeError("package lock post-release overlay binding drift")
    package_by_name = {item["filename"]: item for item in package_lock["packages"]}
    for record in overlay:
        if record["url"] != EXPECTED_OVERLAY_BASE_URL + record["filename"]:
            raise NoetherForgeError(f"post-release overlay URL drift: {record['filename']}")
        package = package_by_name.get(record["filename"])
        if package is None or package["size"] != record["size"] or package["sha256"] != record["sha256"]:
            raise NoetherForgeError(f"post-release overlay package-lock mismatch: {record['filename']}")
    expat = package_by_name.get("libexpat-2.8.2-r0.apk")
    if expat is None or not expat["filename"].startswith("libexpat-2.8.2-"):
        raise NoetherForgeError("release blocker: libexpat must be at least 2.8.2")


def ensure_no_symlink_parents(path: Path, root: Path, label: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise NoetherForgeError(f"{label} escapes its root: {path}") from exc
    current = root
    if current.is_symlink():
        raise NoetherForgeError(f"{label} root symlink rejected: {root}")
    for part in relative.parts[:-1]:
        current /= part
        if current.is_symlink():
            raise NoetherForgeError(f"{label} symlinked parent rejected: {current}")


def validate_configuration() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    release = load_json(RELEASE_ROOT / "release.json")
    input_lock = load_json(RELEASE_ROOT / "alpine-input-lock.json")
    package_lock = load_json(RELEASE_ROOT / "package-lock.json")
    validate_trust_locks(input_lock, package_lock)
    expected = {
        "release": "wucios.noether_forge.release.v1",
        "input": "wucios.noether_forge.alpine_input_lock.v2",
        "packages": "wucios.noether_forge.package_lock.v2",
    }
    observed = {
        "release": release.get("schema"),
        "input": input_lock.get("schema"),
        "packages": package_lock.get("schema"),
    }
    if observed != expected:
        raise NoetherForgeError(f"configuration schema mismatch: {observed}")
    if release.get("version") != "2.4.0" or release.get("codename") != "Noether Forge":
        raise NoetherForgeError("release identity is not Noether Forge 2.4.0")
    if release.get("volume_id") != "WuciOS 2.4 Noether Forge" or len(release["volume_id"].encode("ascii")) != 24:
        raise NoetherForgeError("volume ID must be the fixed 24-byte Noether Forge label")
    artifact_filename = validated_basename(release.get("artifact_filename"), "release artifact filename")
    if not artifact_filename.endswith(".iso"):
        raise NoetherForgeError("release artifact filename must end in .iso")
    expected_media = {
        "boot_media": ("boot-base", "alpine-standard-3.24.1-x86_64.iso"),
        "package_source_media": ("package-source", "alpine-extended-3.24.1-x86_64.iso"),
    }
    for media_name, (role, filename) in expected_media.items():
        media = input_lock.get(media_name)
        if not isinstance(media, dict) or media.get("role") != role or not isinstance(media.get("iso"), dict):
            raise NoetherForgeError(f"Alpine {media_name} identity is invalid")
        iso_record = media["iso"]
        if validated_basename(iso_record.get("filename"), f"{media_name} ISO filename") != filename:
            raise NoetherForgeError(f"Alpine {media_name} filename is invalid")
        sidecars = media.get("sidecars")
        if not isinstance(sidecars, list) or len(sidecars) != 3 or any(not isinstance(item, dict) for item in sidecars):
            raise NoetherForgeError(f"Alpine {media_name} sidecar set is invalid")
        expected_suffixes = {
            "sha256-digest": ".sha256",
            "sha512-digest": ".sha512",
            "detached-signature": ".asc",
        }
        observed_roles = [item.get("role") for item in sidecars]
        if set(observed_roles) != set(expected_suffixes) or len(observed_roles) != len(set(observed_roles)):
            raise NoetherForgeError(f"Alpine {media_name} sidecar roles are not exact and unique")
        iso_url = iso_record.get("url")
        if not isinstance(iso_url, str) or not iso_url.endswith("/" + filename):
            raise NoetherForgeError(f"Alpine {media_name} URL does not bind its filename")
        for sidecar in sidecars:
            suffix = expected_suffixes[sidecar["role"]]
            if (
                sidecar.get("suffix") != suffix
                or sidecar.get("filename") != filename + suffix
                or sidecar.get("url") != iso_url + suffix
            ):
                raise NoetherForgeError(f"Alpine {media_name} sidecar does not bind its parent ISO")
    if input_lock.get("alpine_release") != package_lock.get("alpine_release"):
        raise NoetherForgeError("input and package locks identify different Alpine releases")
    package_media = input_lock["package_source_media"]
    if (
        package_lock.get("source_media") != package_media["iso"]["filename"]
        or package_lock.get("repository_path") != package_media["repository"]["path"]
    ):
        raise NoetherForgeError("package lock source does not bind the package-source release media")
    bootstrap = input_lock.get("bootstrap")
    if not isinstance(bootstrap, dict) or not isinstance(bootstrap.get("initramfs"), dict):
        raise NoetherForgeError("Alpine bootstrap lock is missing")
    members = bootstrap.get("members")
    if not isinstance(members, list) or len(members) != 11 or any(not isinstance(item, dict) for item in members):
        raise NoetherForgeError("Alpine bootstrap must pin exactly 11 members")
    member_paths = [validated_relative_posix(item.get("path"), "bootstrap member path").as_posix() for item in members]
    if member_paths != sorted(member_paths) or len(member_paths) != len(set(member_paths)):
        raise NoetherForgeError("Alpine bootstrap member paths must be unique and sorted")
    packages = package_lock.get("packages")
    if not isinstance(packages, list) or len(packages) != 52:
        raise NoetherForgeError("package lock must contain exactly 52 packages")
    if any(not isinstance(item, dict) for item in packages):
        raise NoetherForgeError("package lock entries must be objects")
    filenames = [validated_basename(item.get("filename"), "package filename") for item in packages]
    if filenames != sorted(filenames) or len(set(filenames)) != len(filenames):
        raise NoetherForgeError("package lock filenames must be unique and sorted")
    if package_lock.get("world") != [
        "alpine-base=3.24.1-r0",
        "doas=6.8.2-r8",
        "nftables=1.1.6-r1",
        "openssl=3.5.7-r0",
        "python3=3.14.5-r0",
    ]:
        raise NoetherForgeError("package world does not match the frozen runtime contract")
    records = cache_records(input_lock)
    record_filenames = [validated_basename(item.get("filename"), f"{item.get('kind', 'input')} filename") for item in records]
    if len(record_filenames) != len(set(record_filenames)):
        raise NoetherForgeError("Alpine cache filenames must be unique")
    payload_map = load_json(RELEASE_ROOT / "payload-map.json")
    if payload_map.get("schema") != "wucios.noether_forge.payload_map.v1" or not isinstance(payload_map.get("payloads"), list):
        raise NoetherForgeError("payload map schema mismatch")
    destinations: list[str] = []
    for payload in payload_map["payloads"]:
        if not isinstance(payload, dict):
            raise NoetherForgeError("payload map entries must be objects")
        source_path = validated_relative_posix(payload.get("source"), "payload source")
        destination_path = validated_relative_posix(payload.get("destination"), "payload destination")
        mode = payload.get("mode")
        if not isinstance(mode, str) or not re.fullmatch(r"0[0-7]{3}", mode):
            raise NoetherForgeError("payload mode must be a four-digit octal string")
        source_parent = (REPO / source_path).parent.resolve()
        try:
            source_parent.relative_to(REPO.resolve())
        except ValueError as exc:
            raise NoetherForgeError(f"payload source parent escapes repository: {source_path}") from exc
        destinations.append(destination_path.as_posix())
    if len(destinations) != len(set(destinations)):
        raise NoetherForgeError("payload destinations must be unique")
    runlevels = load_json(RELEASE_ROOT / "runlevels.json")
    if runlevels.get("schema") != "wucios.noether_forge.runlevels.v1" or not isinstance(runlevels.get("runlevels"), dict):
        raise NoetherForgeError("runlevel map schema mismatch")
    if set(runlevels["runlevels"]) != {"sysinit", "boot", "default", "shutdown"}:
        raise NoetherForgeError("runlevel map has an unexpected runlevel set")
    for runlevel, services in runlevels["runlevels"].items():
        validated_basename(runlevel, "runlevel name")
        if not isinstance(services, list) or len(services) != len(set(services)):
            raise NoetherForgeError(f"runlevel services must be a unique list: {runlevel}")
        for service in services:
            validated_basename(service, f"{runlevel} service")
    overlay_metadata = load_json(RELEASE_ROOT / "overlay-metadata.json")
    if overlay_metadata.get("schema") != "wucios.noether_forge.overlay_metadata.v1" or not isinstance(overlay_metadata.get("paths"), dict):
        raise NoetherForgeError("overlay metadata schema mismatch")
    for name, metadata in overlay_metadata["paths"].items():
        validated_relative_posix(name, "overlay metadata path")
        if not isinstance(metadata, dict) or not set(metadata) <= {"mode", "uid", "gid"}:
            raise NoetherForgeError(f"overlay metadata record is invalid: {name}")
        if "mode" in metadata and (not isinstance(metadata["mode"], str) or not re.fullmatch(r"0[0-7]{3}", metadata["mode"])):
            raise NoetherForgeError(f"overlay metadata mode is invalid: {name}")
        if any(key in metadata and (not isinstance(metadata[key], int) or metadata[key] < 0) for key in ("uid", "gid")):
            raise NoetherForgeError(f"overlay metadata ownership is invalid: {name}")
    load_initramfs_patch_spec(input_lock)
    return release, input_lock, package_lock


def cache_records(input_lock: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for media_name in ("boot_media", "package_source_media"):
        media = input_lock[media_name]
        records.append({**media["iso"], "kind": media["role"] + "-iso"})
        records.extend({**item, "kind": media["role"] + "-sidecar"} for item in media["sidecars"])
    records.append({
        "filename": input_lock["release_signer"]["key_filename"],
        "url": input_lock["release_signer"]["key_url"],
        "size": input_lock["release_signer"]["key_size"],
        "sha256": input_lock["release_signer"]["key_sha256"],
        "kind": "release-key",
    })
    records.extend({**item, "kind": "post-release-overlay-apk"} for item in input_lock["post_release_overlay"])
    return records


def verify_locked_file(path: Path, record: dict[str, Any], label: str) -> None:
    ensure_regular(path, label, expected_size=record.get("size"))
    observed = digest_file(path)
    if observed != record["sha256"]:
        raise NoetherForgeError(f"{label} SHA-256 mismatch: expected {record['sha256']}, got {observed}")


def download_locked(record: dict[str, Any], cache: Path) -> None:
    destination = cache / record["filename"]
    if destination.is_file():
        try:
            verify_locked_file(destination, record, record["kind"])
            return
        except NoetherForgeError:
            pass
    cache.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=cache)
    os.close(fd)
    try:
        request = urllib.request.Request(record["url"], headers={"User-Agent": f"{BUILDER_VERSION}/1"})
        with urllib.request.urlopen(request, timeout=90) as response, open(temporary, "wb") as stream:
            received = 0
            expected_size = record.get("size")
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                received += len(block)
                if isinstance(expected_size, int) and received > expected_size:
                    raise NoetherForgeError(f"{record['kind']} download exceeds locked size {expected_size}")
                stream.write(block)
            if isinstance(expected_size, int) and received != expected_size:
                raise NoetherForgeError(f"{record['kind']} download size mismatch: expected {expected_size}, got {received}")
        os.chmod(temporary, 0o644)
        verify_locked_file(Path(temporary), record, record["kind"])
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def xorriso_extract(iso: Path, iso_path: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    run(["xorriso", "-osirrox", "on", "-indev", iso, "-extract", iso_path, destination])
    ensure_regular(destination, f"extracted ISO file {iso_path}")


def read_locked_gzip(path: Path, record: dict[str, Any], label: str) -> bytes:
    """Read one digest-pinned gzip while bounding compressed and expanded bytes."""
    verify_locked_file(path, record, label)
    expected_size = record.get("uncompressed_size")
    expected_sha256 = record.get("uncompressed_sha256")
    if not isinstance(expected_size, int) or expected_size < 1 or not isinstance(expected_sha256, str):
        raise NoetherForgeError(f"{label} lacks an exact expanded-size and digest lock")
    expanded = bytearray()
    try:
        with path.open("rb") as source, gzip.GzipFile(fileobj=source, mode="rb") as stream:
            while len(expanded) <= expected_size:
                remaining = expected_size + 1 - len(expanded)
                block = stream.read(min(GZIP_CHUNK_SIZE, remaining))
                if not block:
                    break
                expanded.extend(block)
    except (EOFError, OSError) as exc:
        raise NoetherForgeError(f"{label} is not a complete valid gzip stream: {exc}") from exc
    if len(expanded) != expected_size:
        relation = "exceeds" if len(expanded) > expected_size else "does not reach"
        raise NoetherForgeError(f"{label} expanded data {relation} locked size {expected_size}")
    observed = hashlib.sha256(expanded).hexdigest()
    if observed != expected_sha256:
        raise NoetherForgeError(f"{label} expanded SHA-256 mismatch: expected {expected_sha256}, got {observed}")
    return bytes(expanded)


def locate_newc_regular_member(
    archive: bytes,
    member_name: str,
    *,
    expected_entry_count: int,
) -> tuple[int, int]:
    target = validated_relative_posix(member_name, "newc patch member").as_posix()
    offset = 0
    entry_count = 0
    match: tuple[int, int] | None = None
    seen: set[str] = set()
    while offset < len(archive):
        if entry_count >= NEWC_MAX_ENTRIES or len(archive) - offset < NEWC_HEADER_SIZE:
            raise NoetherForgeError("newc patch scan is truncated or exceeds its entry ceiling")
        header = archive[offset:offset + NEWC_HEADER_SIZE]
        if header[:6] != b"070701" or re.fullmatch(rb"[0-9A-Fa-f]{104}", header[6:]) is None:
            raise NoetherForgeError("newc patch scan found a malformed header")
        fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
        mode, filesize, namesize = fields[1], fields[6], fields[11]
        offset += NEWC_HEADER_SIZE
        if namesize < 2 or namesize > NEWC_MAX_NAME_SIZE or offset + namesize > len(archive):
            raise NoetherForgeError("newc patch scan found an invalid member name length")
        encoded_name = archive[offset:offset + namesize]
        if encoded_name[-1:] != b"\0" or b"\0" in encoded_name[:-1]:
            raise NoetherForgeError("newc patch scan found a malformed member name")
        try:
            name = encoded_name[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NoetherForgeError("newc patch scan found a non-UTF-8 member name") from exc
        offset += namesize
        offset += (-offset) % 4
        data_start = offset
        data_end = data_start + filesize
        if filesize > NEWC_MAX_ENTRY_SIZE or data_end > len(archive):
            raise NoetherForgeError("newc patch scan found oversized or truncated member data")
        offset = data_end
        offset += (-offset) % 4
        if name == "TRAILER!!!":
            if fields != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0] or any(archive[offset:]):
                raise NoetherForgeError("newc patch scan found a malformed trailer")
            break
        _newc_path(name)
        if name in seen:
            raise NoetherForgeError(f"duplicate newc member rejected during patch scan: {name}")
        seen.add(name)
        entry_count += 1
        if name == target:
            if match is not None or stat.S_IFMT(mode) != stat.S_IFREG:
                raise NoetherForgeError("newc patch member is duplicate or not regular")
            match = (data_start, data_end)
    if entry_count != expected_entry_count or match is None:
        raise NoetherForgeError("newc patch member or archive entry count differs from its lock")
    return match


def patch_initramfs_payload(
    payload: bytes,
    patch_lock: dict[str, Any],
    patch_spec: dict[str, Any],
    *,
    expected_entry_count: int,
) -> bytes:
    replacements = initramfs_replacements(patch_spec)
    member_start, member_end = locate_newc_regular_member(
        payload,
        patch_lock["member"],
        expected_entry_count=expected_entry_count,
    )
    member = payload[member_start:member_end]
    if (
        len(member) != patch_lock.get("source_member_size")
        or hashlib.sha256(member).hexdigest() != patch_lock.get("source_member_sha256")
    ):
        raise NoetherForgeError("initramfs patch source member digest drift")
    raw_spans = patch_lock.get("source_spans")
    if not isinstance(raw_spans, list) or len(raw_spans) != len(replacements):
        raise NoetherForgeError("initramfs source-span count differs from the replacement specification")
    spans: list[dict[str, Any]] = []
    labels: set[str] = set()
    for record in raw_spans:
        if (
            not isinstance(record, dict)
            or set(record) != {
                "label", "offset", "length", "sha256", "replacement_length", "replacement_sha256",
            }
            or not isinstance(record.get("label"), str)
            or type(record.get("offset")) is not int
            or type(record.get("length")) is not int
            or type(record.get("replacement_length")) is not int
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
            or not isinstance(record.get("replacement_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["replacement_sha256"]) is None
        ):
            raise NoetherForgeError("initramfs source-span record is structurally invalid")
        label = record["label"]
        if label in labels or label not in replacements:
            raise NoetherForgeError("initramfs source-span labels are duplicate or unbound")
        labels.add(label)
        replacement = replacements[label]
        if (
            record["replacement_length"] != len(replacement)
            or record["replacement_sha256"] != hashlib.sha256(replacement).hexdigest()
        ):
            raise NoetherForgeError(f"initramfs replacement binding drift: {label}")
        spans.append(record)
    if labels != set(replacements):
        raise NoetherForgeError("initramfs source-span labels do not exactly cover replacements")
    spans.sort(key=lambda item: (item["offset"], item["label"]))
    previous_end = 0
    source_total = 0
    replacement_total = 0
    chunks: list[bytes] = []
    for record in spans:
        label = record["label"]
        offset = record["offset"]
        length = record["length"]
        end = offset + length
        if offset < 0 or length <= 0 or end > len(member):
            raise NoetherForgeError(f"initramfs source span is out of range: {label}")
        if offset < previous_end:
            raise NoetherForgeError(f"initramfs source spans overlap: {label}")
        source_slice = member[offset:end]
        if hashlib.sha256(source_slice).hexdigest() != record["sha256"]:
            raise NoetherForgeError(f"initramfs source-slice digest drift: {label}")
        replacement = replacements[label]
        if payload.count(replacement) != 0:
            raise NoetherForgeError(f"initramfs replacement marker already exists before patch: {label}")
        chunks.extend((member[previous_end:offset], replacement))
        source_total += length
        replacement_total += len(replacement)
        previous_end = end
    chunks.append(member[previous_end:])
    expected_member_size = len(member) - source_total + replacement_total
    if (
        expected_member_size != patch_lock.get("output_member_size")
        or expected_member_size != len(member)
    ):
        raise NoetherForgeError("initramfs replacement length accounting does not preserve the locked member size")
    patched_member = b"".join(chunks)
    if (
        len(patched_member) != patch_lock["output_member_size"]
        or hashlib.sha256(patched_member).hexdigest() != patch_lock.get("output_member_sha256")
    ):
        raise NoetherForgeError("initramfs patched member length or digest differs from its exact lock")
    patched = payload[:member_start] + patched_member + payload[member_end:]
    if (
        len(patched) != len(payload)
        or patched[:member_start] != payload[:member_start]
        or patched[member_end:] != payload[member_end:]
    ):
        raise NoetherForgeError("initramfs patch changed bytes outside its exact member")
    for label, replacement in replacements.items():
        if patched.count(replacement) != 1:
            raise NoetherForgeError(f"initramfs replacement marker count drift after patch: {label}")
    return patched


def verify_patched_initramfs_payload(
    payload: bytes,
    patch_lock: dict[str, Any],
    patch_spec: dict[str, Any],
    *,
    expected_entry_count: int,
) -> dict[str, Any]:
    if len(payload) != patch_lock["output_uncompressed_size"]:
        raise NoetherForgeError("patched initramfs expanded size differs from its exact lock")
    observed = hashlib.sha256(payload).hexdigest()
    if observed != patch_lock["output_uncompressed_sha256"]:
        raise NoetherForgeError("patched initramfs expanded digest differs from its exact lock")
    member_start, member_end = locate_newc_regular_member(
        payload,
        patch_lock["member"],
        expected_entry_count=expected_entry_count,
    )
    member = payload[member_start:member_end]
    if (
        len(member) != patch_lock["output_member_size"]
        or hashlib.sha256(member).hexdigest() != patch_lock["output_member_sha256"]
    ):
        raise NoetherForgeError("patched initramfs member differs from its exact output lock")
    marker_counts: dict[str, int] = {}
    for label, replacement in initramfs_replacements(patch_spec).items():
        if payload.count(replacement) != 1:
            raise NoetherForgeError(f"patched initramfs marker verification failed: {label}")
        marker_counts[label] = 1
    return {
        "expanded_size": len(payload),
        "expanded_sha256": observed,
        "marker_counts": marker_counts,
    }


def write_patched_initramfs(
    source: Path,
    destination: Path,
    initramfs_lock: dict[str, Any],
    patch_lock: dict[str, Any],
    patch_spec: dict[str, Any],
) -> dict[str, Any]:
    source_payload = read_locked_gzip(source, initramfs_lock, "authenticated boot-media initramfs")
    patched_payload = patch_initramfs_payload(
        source_payload,
        patch_lock,
        patch_spec,
        expected_entry_count=initramfs_lock["entry_count"],
    )
    evidence = verify_patched_initramfs_payload(
        patched_payload,
        patch_lock,
        patch_spec,
        expected_entry_count=initramfs_lock["entry_count"],
    )
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=compressed,
        mtime=patch_lock["gzip_mtime"],
        compresslevel=9,
    ) as stream:
        stream.write(patched_payload)
    output = compressed.getvalue()
    if len(output) != patch_lock["output_size"] or hashlib.sha256(output).hexdigest() != patch_lock["output_sha256"]:
        raise NoetherForgeError("deterministic patched initramfs compressed bytes differ from their exact lock")
    atomic_write(destination, output)
    return {
        **evidence,
        "filename": destination.name,
        "size": len(output),
        "sha256": hashlib.sha256(output).hexdigest(),
        "gzip_mtime": patch_lock["gzip_mtime"],
    }


def read_patched_initramfs(
    path: Path,
    patch_lock: dict[str, Any],
    patch_spec: dict[str, Any],
    *,
    expected_entry_count: int,
) -> tuple[bytes, dict[str, Any]]:
    verify_locked_file(
        path,
        {"size": patch_lock["output_size"], "sha256": patch_lock["output_sha256"]},
        "patched ISO initramfs",
    )
    expanded = bytearray()
    try:
        with path.open("rb") as source, gzip.GzipFile(fileobj=source, mode="rb") as stream:
            while len(expanded) <= patch_lock["output_uncompressed_size"]:
                remaining = patch_lock["output_uncompressed_size"] + 1 - len(expanded)
                block = stream.read(min(GZIP_CHUNK_SIZE, remaining))
                if not block:
                    break
                expanded.extend(block)
    except (EOFError, OSError) as exc:
        raise NoetherForgeError(f"patched ISO initramfs gzip is malformed: {exc}") from exc
    payload = bytes(expanded)
    return payload, verify_patched_initramfs_payload(
        payload,
        patch_lock,
        patch_spec,
        expected_entry_count=expected_entry_count,
    )


def _newc_path(name: str) -> PurePosixPath:
    if name == ".":
        return PurePosixPath(name)
    if not name or "\\" in name:
        raise NoetherForgeError(f"newc member path is empty or non-POSIX: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != name:
        raise NoetherForgeError(f"newc member path is non-canonical or traversing: {name!r}")
    return path


def parse_newc_bootstrap(
    archive: bytes,
    member_specs: Sequence[dict[str, Any]],
    *,
    expected_entry_count: int,
) -> dict[str, dict[str, Any]]:
    """Strictly parse a newc archive and return only the exact bootstrap allowlist."""
    if len(archive) > NEWC_MAX_ARCHIVE_SIZE:
        raise NoetherForgeError("newc archive exceeds the hard expanded-size ceiling")
    specs = {item["path"]: item for item in member_specs}
    if len(specs) != len(member_specs):
        raise NoetherForgeError("newc bootstrap allowlist contains duplicate paths")
    found: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    offset = 0
    entry_count = 0
    trailer_seen = False
    while offset < len(archive):
        if entry_count >= NEWC_MAX_ENTRIES or len(archive) - offset < NEWC_HEADER_SIZE:
            raise NoetherForgeError("newc archive is truncated or exceeds the entry-count ceiling")
        header = archive[offset:offset + NEWC_HEADER_SIZE]
        if header[:6] != b"070701" or re.fullmatch(rb"[0-9A-Fa-f]{104}", header[6:]) is None:
            raise NoetherForgeError("newc header magic or hexadecimal fields are malformed")
        fields = [int(header[6 + index * 8:14 + index * 8], 16) for index in range(13)]
        mode, uid, gid, nlink, filesize, namesize, checksum = (
            fields[1], fields[2], fields[3], fields[4], fields[6], fields[11], fields[12]
        )
        trailer_shape = mode == 0 and nlink == 0 and filesize == 0 and namesize == 11
        if uid != 0 or gid != 0 or checksum != 0 or (nlink < 1 and not trailer_shape):
            raise NoetherForgeError("newc entry ownership, link count, or checksum field is outside the locked format")
        if namesize < 2 or namesize > NEWC_MAX_NAME_SIZE:
            raise NoetherForgeError("newc member name length is outside the allowed bounds")
        offset += NEWC_HEADER_SIZE
        name_end = offset + namesize
        if name_end > len(archive):
            raise NoetherForgeError("newc member name is truncated")
        encoded_name = archive[offset:name_end]
        if encoded_name[-1:] != b"\0" or b"\0" in encoded_name[:-1]:
            raise NoetherForgeError("newc member name must contain one terminal NUL")
        try:
            name = encoded_name[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NoetherForgeError("newc member name is not valid UTF-8") from exc
        offset = name_end
        name_padding = (-offset) % 4
        if archive[offset:offset + name_padding] != b"\0" * name_padding:
            raise NoetherForgeError("newc member name padding is malformed")
        offset += name_padding
        if filesize > NEWC_MAX_ENTRY_SIZE:
            raise NoetherForgeError(f"newc member exceeds the entry-size ceiling: {name!r}")
        data_end = offset + filesize
        if data_end > len(archive):
            raise NoetherForgeError(f"newc member data is truncated: {name!r}")
        data = archive[offset:data_end]
        offset = data_end
        data_padding = (-offset) % 4
        if archive[offset:offset + data_padding] != b"\0" * data_padding:
            raise NoetherForgeError("newc member data padding is malformed")
        offset += data_padding
        if name == "TRAILER!!!":
            if fields != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0] or trailer_seen:
                raise NoetherForgeError("newc trailer is duplicated or carries data")
            trailer_seen = True
            if any(archive[offset:]):
                raise NoetherForgeError("newc archive has non-zero bytes after its trailer")
            break
        _newc_path(name)
        if name in seen:
            raise NoetherForgeError(f"duplicate newc member rejected: {name}")
        seen.add(name)
        entry_count += 1
        file_type = stat.S_IFMT(mode)
        if file_type not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
            raise NoetherForgeError(f"newc member has an unsupported type: {name}")
        if file_type != stat.S_IFDIR and nlink != 1:
            raise NoetherForgeError(f"newc non-directory member link count is not one: {name}")
        if file_type == stat.S_IFDIR and filesize != 0:
            raise NoetherForgeError(f"newc directory carries data: {name}")
        if file_type == stat.S_IFLNK and (b"\0" in data or len(data) > NEWC_MAX_NAME_SIZE):
            raise NoetherForgeError(f"newc symlink target is malformed: {name}")
        spec = specs.get(name)
        if spec is None:
            continue
        expected_type = stat.S_IFREG if spec["type"] == "regular" else stat.S_IFLNK
        if file_type != expected_type or stat.S_IMODE(mode) != int(spec["mode"], 8):
            raise NoetherForgeError(f"bootstrap member type or mode drift: {name}")
        if spec["type"] == "regular":
            if len(data) != spec["size"] or hashlib.sha256(data).hexdigest() != spec["sha256"]:
                raise NoetherForgeError(f"bootstrap member size or digest drift: {name}")
            found[name] = {"type": "regular", "mode": stat.S_IMODE(mode), "data": bytes(data)}
        else:
            try:
                target = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise NoetherForgeError(f"bootstrap symlink target is not UTF-8: {name}") from exc
            if len(data) != len(spec["target"].encode("utf-8")) or target != spec["target"]:
                raise NoetherForgeError(f"bootstrap symlink target drift: {name}")
            found[name] = {"type": "symlink", "mode": stat.S_IMODE(mode), "target": target}
    if not trailer_seen:
        raise NoetherForgeError("newc archive trailer is missing")
    if entry_count != expected_entry_count:
        raise NoetherForgeError(f"newc entry count mismatch: expected {expected_entry_count}, got {entry_count}")
    missing = sorted(set(specs) - set(found))
    if missing:
        raise NoetherForgeError(f"newc bootstrap members are missing: {missing}")
    return found


def materialize_bootstrap(root: Path, members: dict[str, dict[str, Any]]) -> list[Path]:
    root.mkdir(parents=True, exist_ok=False)
    regular = [(name, item) for name, item in members.items() if item["type"] == "regular"]
    links = [(name, item) for name, item in members.items() if item["type"] == "symlink"]
    for name, item in sorted(regular):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(destination, item["data"], mode=item["mode"])
    for name, item in sorted(links):
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise NoetherForgeError(f"duplicate bootstrap output: {destination}")
        os.symlink(item["target"], destination)
    keys = sorted((root / "etc/apk/keys").glob("*.rsa.pub"))
    if len(keys) != 3:
        raise NoetherForgeError("bootstrap did not materialize exactly three Alpine public keys")
    return keys


def bootstrap_apk_command(root: Path) -> list[str | os.PathLike[str]]:
    return [
        root / "usr/lib/ld-musl-x86_64.so.1",
        "--library-path",
        root / "usr/lib",
        root / "usr/sbin/apk",
    ]


def extract_locked_repository(
    media_iso: Path,
    destination: Path,
    repository_lock: dict[str, Any],
    package_lock: dict[str, Any],
    overlay_cache: Path,
) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    overlay_names = set(package_lock["post_release_overlay"])
    media_packages = [item for item in package_lock["packages"] if item["filename"] not in overlay_names]
    media_names = [repository_lock["index_filename"], *[item["filename"] for item in media_packages]]
    command: list[str | os.PathLike[str]] = ["xorriso", "-osirrox", "on", "-indev", media_iso]
    repository_path = package_lock["repository_path"].rstrip("/")
    for filename in media_names:
        command.extend(["-extract", f"{repository_path}/{filename}", destination / filename])
    run(command, timeout=600)
    for filename in package_lock["post_release_overlay"]:
        source = overlay_cache / filename
        locked = next(item for item in package_lock["packages"] if item["filename"] == filename)
        verify_locked_file(source, locked, "post-release overlay APK")
        shutil.copyfile(source, destination / filename)
    expected_names = [repository_lock["index_filename"], *[item["filename"] for item in package_lock["packages"]]]
    observed_names = sorted(path.name for path in destination.iterdir())
    if observed_names != sorted(expected_names):
        raise NoetherForgeError("extracted package repository has missing or extra members")
    verify_locked_file(
        destination / repository_lock["index_filename"],
        {
            "size": repository_lock["index_size"],
            "sha256": repository_lock["index_sha256"],
        },
        "extended-media signed APK index",
    )
    for package in package_lock["packages"]:
        source_label = "post-release overlay APK" if package["filename"] in overlay_names else "extended-media APK member"
        verify_locked_file(destination / package["filename"], package, source_label)
    return destination


def normalize_xorriso_report(report: str, iso: Path) -> str:
    normalized = report.replace(str(iso), iso.name)
    normalized = re.sub(
        r"(?m)^(Media summary:.*?,\s+)[0-9]+(?:\.[0-9]+)?[kmgt] free$",
        r"\1<host-free-space> free",
        normalized,
    )
    return re.sub(
        r"(?m)^(xorriso : UPDATE :\s+[0-9]+ nodes read in )[0-9]+ seconds$",
        r"\1<host-elapsed-time> seconds",
        normalized,
    )


def tool_version(command: str, *args: str) -> str:
    path = shutil.which(command)
    if not path:
        raise NoetherForgeError(f"required host tool not found: {command}")
    result = run([path, *args])
    return (result.stdout or result.stderr).splitlines()[0].strip()


def media_sidecar(media: dict[str, Any], role: str) -> dict[str, Any]:
    matches = [item for item in media["sidecars"] if item.get("role") == role]
    if len(matches) != 1:
        raise NoetherForgeError(f"release media requires exactly one {role} sidecar")
    return matches[0]


def verify_release_media(
    media: dict[str, Any],
    cache: Path,
    gpg_home: Path,
    fingerprint: str,
) -> dict[str, Any]:
    iso_record = media["iso"]
    iso = cache / iso_record["filename"]
    if digest_file(iso, "sha512") != iso_record["sha512"]:
        raise NoetherForgeError(f"{media['role']} ISO SHA-512 mismatch")
    for role, algorithm in (("sha256-digest", "sha256"), ("sha512-digest", "sha512")):
        record = media_sidecar(media, role)
        text = (cache / record["filename"]).read_text(encoding="ascii").strip()
        if text.split() != [iso_record[algorithm], iso.name]:
            raise NoetherForgeError(f"published Alpine {media['role']} {algorithm} sidecar does not bind the locked ISO")
    signature_record = media_sidecar(media, "detached-signature")
    signature_result = run([
        "gpg",
        "--no-autostart",
        "--batch",
        "--homedir",
        gpg_home,
        "--status-fd",
        "1",
        "--verify",
        cache / signature_record["filename"],
        iso,
    ])
    if f"[GNUPG:] VALIDSIG {fingerprint} " not in signature_result.stdout:
        raise NoetherForgeError(f"Alpine {media['role']} detached signature did not produce the pinned fingerprint")
    return {
        "role": media["role"],
        "filename": iso.name,
        "size": iso.stat().st_size,
        "sha256": digest_file(iso),
        "sha512": digest_file(iso, "sha512"),
        "sidecars_match": True,
        "detached_signature_valid": True,
        "signer_fingerprint": fingerprint,
    }


def verify_inputs(cache: Path, work: Path) -> dict[str, Any]:
    release, input_lock, package_lock = validate_configuration()
    records = cache_records(input_lock)
    for record in records:
        verify_locked_file(cache / record["filename"], record, record["kind"])
    for record in input_lock["post_release_overlay"]:
        if digest_file(cache / record["filename"], "sha512") != record["sha512"]:
            raise NoetherForgeError(f"post-release overlay APK SHA-512 mismatch: {record['filename']}")

    gpg_home = work / "gnupg"
    gpg_home.mkdir(mode=0o700)
    key = cache / input_lock["release_signer"]["key_filename"]
    run(["gpg", "--no-autostart", "--batch", "--homedir", gpg_home, "--import", key])
    fingerprint = input_lock["release_signer"]["fingerprint"]
    boot_media = verify_release_media(input_lock["boot_media"], cache, gpg_home, fingerprint)
    package_source_media = verify_release_media(input_lock["package_source_media"], cache, gpg_home, fingerprint)
    iso = cache / input_lock["boot_media"]["iso"]["filename"]
    package_source_iso = cache / input_lock["package_source_media"]["iso"]["filename"]

    extracted = work / "upstream"
    extracted.mkdir()
    layout = input_lock["upstream_layout"]
    syslinux = extracted / "syslinux.cfg"
    grub = extracted / "grub.cfg"
    bootx64 = extracted / "bootx64.efi"
    efi_image = extracted / "efi.img"
    initramfs = extracted / "initramfs-lts"
    xorriso_extract(iso, "/boot/syslinux/syslinux.cfg", syslinux)
    xorriso_extract(iso, "/boot/grub/grub.cfg", grub)
    xorriso_extract(iso, "/efi/boot/bootx64.efi", bootx64)
    xorriso_extract(iso, "/boot/grub/efi.img", efi_image)
    xorriso_extract(iso, input_lock["bootstrap"]["initramfs"]["iso_path"], initramfs)
    for path, expected in (
        (syslinux, layout["syslinux_config_sha256"]),
        (grub, layout["grub_config_sha256"]),
        (bootx64, layout["bootx64_efi_sha256"]),
    ):
        if digest_file(path) != expected:
            raise NoetherForgeError(f"upstream boot layout drift: {path.name}")
    original_label = layout["volume_id"].encode("ascii")
    if bootx64.read_bytes().count(original_label) != layout["efi_embedded_volume_label_occurrences"]:
        raise NoetherForgeError("unexpected EFI executable volume-label occurrence count")
    if efi_image.read_bytes().count(original_label) != layout["efi_image_embedded_volume_label_occurrences"]:
        raise NoetherForgeError("unexpected EFI image volume-label occurrence count")

    initramfs_record = input_lock["bootstrap"]["initramfs"]
    archive = read_locked_gzip(initramfs, initramfs_record, "authenticated boot-media initramfs")
    bootstrap_members = parse_newc_bootstrap(
        archive,
        input_lock["bootstrap"]["members"],
        expected_entry_count=initramfs_record["entry_count"],
    )
    bootstrap_root = work / "apk-bootstrap"
    keys = materialize_bootstrap(bootstrap_root, bootstrap_members)
    keys_dir = bootstrap_root / "etc/apk/keys"
    overlay_keys_dir = work / "post-release-overlay-keys"
    overlay_keys_dir.mkdir()
    overlay_key = keys_dir / "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
    if digest_file(overlay_key) != "207e4696d3c05f7cb05966aee557307151f1f00217af4143c1bcaf33b8df733f":
        raise NoetherForgeError("authenticated post-release overlay signer key digest drift")
    shutil.copyfile(overlay_key, overlay_keys_dir / overlay_key.name)
    apk_home = work / "apk-home"
    apk_home.mkdir()
    apk_environment = {
        "HOME": str(apk_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    apk_command = bootstrap_apk_command(bootstrap_root)
    version_result = run([*apk_command, "--version"], env=apk_environment)
    if version_result.stdout.strip() != input_lock["bootstrap"]["apk_version"]:
        raise NoetherForgeError(f"authenticated bootstrap apk version drift: {version_result.stdout.strip()}")

    local_repo = extract_locked_repository(
        package_source_iso,
        work / "package-source/x86_64",
        input_lock["package_source_media"]["repository"],
        package_lock,
        cache,
    )
    index = local_repo / input_lock["package_source_media"]["repository"]["index_filename"]
    run([*apk_command, "verify", "--keys-dir", keys_dir, index], env=apk_environment)
    overlay_records = {item["filename"]: item for item in input_lock["post_release_overlay"]}
    for package in package_lock["packages"]:
        package_path = local_repo / package["filename"]
        signature_keys = keys_dir
        if package["filename"] in overlay_records:
            verify_post_release_overlay_metadata(package_path, overlay_records[package["filename"]])
            signature_keys = overlay_keys_dir
        run([*apk_command, "verify", "--keys-dir", signature_keys, package_path], env=apk_environment)

    root = work / "closure-root"
    root.mkdir()
    empty_repositories = work / "empty-repositories"
    atomic_write(empty_repositories, b"")
    closure_result = run([
        *apk_command,
        "add",
        "--root",
        root,
        "--initdb",
        "--usermode",
        "--no-cache",
        "--no-network",
        "--force-non-repository",
        "--repositories-file",
        empty_repositories,
        "--arch",
        "x86_64",
        "--keys-dir",
        keys_dir,
        "--no-scripts",
        *[local_repo / package["filename"] for package in package_lock["packages"]],
        *package_lock["world"],
    ], env=apk_environment)
    installed = root / "lib/apk/db/installed"
    ensure_regular(installed, "rootless closure database")
    installed_count = sum(1 for line in installed.read_text(encoding="utf-8").splitlines() if line.startswith("P:"))
    if installed_count != len(package_lock["packages"]):
        raise NoetherForgeError(f"APK closure installed {installed_count} packages, expected {len(package_lock['packages'])}")
    expected_identities = sorted(
        (info["pkgname"], info["pkgver"], info["arch"])
        for info in (apk_pkginfo(local_repo / package["filename"]) for package in package_lock["packages"])
    )
    observed_identities = installed_apk_identities(installed)
    if observed_identities != expected_identities:
        raise NoetherForgeError("rootless direct-file closure installed identities differ from the exact 52 APK inputs")

    xorriso_version = tool_version("xorriso", "-version")
    qemu_version = tool_version("qemu-system-x86_64", "--version")
    gpg_version = tool_version("gpg", "--version")
    if "1.5.8.pl02" not in xorriso_version:
        raise NoetherForgeError(f"unlocked xorriso version: {xorriso_version}")
    return {
        "schema": "wucios.noether_forge.input_verification.v1",
        "status": "pass",
        "release": release["release_id"],
        "media": {
            "boot": boot_media,
            "package_source": package_source_media,
        },
        "apk": {
            "signed_index_sha256": digest_file(index),
            "source_media": package_source_iso.name,
            "release_media_member_count": 49,
            "post_release_overlay_count": 3,
            "post_release_overlay": list(package_lock["post_release_overlay"]),
            "package_count": installed_count,
            "all_package_signatures_valid": True,
            "rootless_offline_closure_install": "pass",
            "closure_mode": "52-absolute-files-force-non-repository",
            "installed_identities_exact": True,
            "signing_keys": [{"filename": item.name, "sha256": digest_file(item)} for item in keys],
            "world": list(package_lock["world"]),
            "stdout_tail": closure_result.stdout[-2000:],
        },
        "bootstrap": {
            "source": "GPG-authenticated boot-media initramfs",
            "initramfs_sha256": digest_file(initramfs),
            "initramfs_uncompressed_sha256": hashlib.sha256(archive).hexdigest(),
            "member_count": len(bootstrap_members),
            "apk_version": version_result.stdout.strip(),
        },
        "host_tools": {
            "gpg": gpg_version,
            "qemu": qemu_version,
            "xorriso": xorriso_version,
        },
        "non_claims": list(release["non_claims"]),
    }


def git_metadata() -> dict[str, Any]:
    head = run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip()
    branch = run(["git", "branch", "--show-current"], cwd=REPO).stdout.strip()
    status_lines = run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=REPO).stdout.splitlines()
    paths = sorted(line[3:] for line in status_lines if len(line) >= 4 and not line[3:].startswith("build/"))
    return {
        "head": head,
        "branch": branch,
        "clean": not paths,
        "dirty_path_count": len(paths),
        "dirty_paths": paths,
        "public_release_source_gate": "blocked" if paths or branch != "main" else "eligible-for-later-review",
    }


def source_manifest() -> dict[str, Any]:
    payload_map = load_json(RELEASE_ROOT / "payload-map.json")
    sources: set[Path] = {
        Path(__file__),
        REPO / "Makefile",
        REPO / "NOTICE",
        REPO / "include/wuci.inc",
        REPO / "tools/wucios/noether_runtime.py",
        REPO / "tools/wucios/noether_obligations.py",
        REPO / "wucios/sets/cantor-denied-noether-packages.txt",
        REPO / "wucios/components/component-register.json",
        REPO / "wucios/profiles/noether-core.json",
        REPO / "wucios/schemas/noether-forge-alpine-input-lock.schema.json",
        REPO / "wucios/schemas/noether-forge-initramfs-patch-spec.schema.json",
        REPO / "wucios/schemas/noether-forge-package-lock.schema.json",
        REPO / "wucios/substrates/alpine.json",
    }
    sources.update((REPO / "src").glob("*.s"))
    for path in RELEASE_ROOT.rglob("*"):
        if path.is_file():
            sources.add(path)
    for payload in payload_map["payloads"]:
        sources.add(REPO / payload["source"])
    records: list[dict[str, Any]] = []
    for path in sorted(sources, key=lambda item: relative_repo_path(item)):
        info = ensure_regular(path, "release source input")
        records.append({
            "path": relative_repo_path(path),
            "size": info.st_size,
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "sha256": digest_file(path),
        })
    payload_digest = hashlib.sha256(canonical_json(records)).hexdigest()
    release = load_json(RELEASE_ROOT / "release.json")
    return {
        "schema": "wucios.noether_forge.source_manifest.v1",
        "builder": BUILDER_VERSION,
        "release_id": release["release_id"],
        "source_date_epoch": release["source_date_epoch"],
        "source_payload_sha256": payload_digest,
        "git": git_metadata(),
        "files": records,
        "boundary": "Only listed build inputs are bound into the ISO-specific build; unrelated dirty paths remain publication blockers.",
    }


def apk_pkginfo(path: Path) -> dict[str, str]:
    with tarfile.open(path, "r:gz") as archive:
        try:
            stream = archive.extractfile(".PKGINFO")
        except KeyError as exc:
            raise NoetherForgeError(f"APK metadata missing: {path.name}") from exc
        if stream is None:
            raise NoetherForgeError(f"APK metadata unreadable: {path.name}")
        text = stream.read().decode("utf-8")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key not in fields:
            fields[key] = value
    return fields


def verify_post_release_overlay_metadata(path: Path, record: dict[str, Any]) -> dict[str, str]:
    expected_signer = ".SIGN.RSA.alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
    with tarfile.open(path, "r:gz") as archive:
        signatures = [member for member in archive.getmembers() if member.name.startswith(".SIGN")]
        if len(signatures) != 1 or signatures[0].name != expected_signer or not signatures[0].isfile():
            raise NoetherForgeError(f"post-release overlay signer member drift: {path.name}")
        pkginfo_members = [member for member in archive.getmembers() if member.name == ".PKGINFO"]
        if len(pkginfo_members) != 1 or not pkginfo_members[0].isfile():
            raise NoetherForgeError(f"post-release overlay .PKGINFO member drift: {path.name}")
        stream = archive.extractfile(pkginfo_members[0])
        if stream is None:
            raise NoetherForgeError(f"post-release overlay .PKGINFO unreadable: {path.name}")
        text = stream.read().decode("utf-8")
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values.setdefault(key, []).append(value)
    expected = {
        "pkgname": record["package"],
        "pkgver": record["version"],
        "arch": record["architecture"],
        "origin": record["origin"],
    }
    for key, value in expected.items():
        if values.get(key) != [value]:
            raise NoetherForgeError(f"post-release overlay .PKGINFO {key} drift: {path.name}")
    return expected


def installed_apk_identities(path: Path) -> list[tuple[str, str, str]]:
    identities: list[tuple[str, str, str]] = []
    for paragraph in path.read_text(encoding="utf-8").strip().split("\n\n"):
        fields: dict[str, list[str]] = {}
        for line in paragraph.splitlines():
            if len(line) >= 3 and line[1] == ":":
                fields.setdefault(line[0], []).append(line[2:])
        if any(len(fields.get(key, [])) != 1 for key in ("P", "V", "A")):
            raise NoetherForgeError("installed APK database has ambiguous package identity fields")
        identities.append((fields["P"][0], fields["V"][0], fields["A"][0]))
    if len(identities) != len(set(identities)):
        raise NoetherForgeError("installed APK database contains duplicate package identities")
    return sorted(identities)


def generate_runtime_package_contract(cache: Path, package_lock: dict[str, Any]) -> dict[str, Any]:
    packages: list[dict[str, str]] = []
    for locked in package_lock["packages"]:
        path = cache / locked["filename"]
        verify_locked_file(path, locked, f"runtime contract APK {locked['filename']}")
        info = apk_pkginfo(path)
        required = ("pkgname", "pkgver", "arch")
        if any(not info.get(name) for name in required):
            raise NoetherForgeError(f"APK lacks runtime identity metadata: {locked['filename']}")
        packages.append({
            "name": info["pkgname"],
            "version": info["pkgver"],
            "package_architecture": info["arch"],
            "installed_architecture": info["arch"],
            "apk_sha256": locked["sha256"],
        })
    packages.sort(key=lambda item: (item["name"], item["version"], item["installed_architecture"]))
    identities = [(item["name"], item["version"], item["installed_architecture"]) for item in packages]
    if len(packages) != 52 or len(identities) != len(set(identities)):
        raise NoetherForgeError("runtime package contract must contain 52 unique installed package identities")
    return {
        "schema": "wucios.noether_forge.runtime_package_contract.v1",
        "release": "noether-forge-v2.4.0",
        "package_count": len(packages),
        "packages": packages,
    }


def spdx_id(name: str) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", name)


def validate_spdx_sbom(sbom: dict[str, Any], package_lock: dict[str, Any], source: dict[str, Any]) -> None:
    allowed_top_level = {
        "SPDXID", "annotations", "comment", "creationInfo", "dataLicense", "documentDescribes",
        "documentNamespace", "files", "name", "packages", "relationships", "spdxVersion",
    }
    if set(sbom) != allowed_top_level:
        raise NoetherForgeError(f"SPDX document has unsupported or missing top-level fields: {sorted(set(sbom) ^ allowed_top_level)}")
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("SPDXID") != "SPDXRef-DOCUMENT" or sbom.get("dataLicense") != "CC0-1.0":
        raise NoetherForgeError("SPDX document identity fields are invalid")
    creation = sbom.get("creationInfo")
    if (
        not isinstance(creation, dict)
        or set(creation) != {"created", "creators"}
        or not isinstance(creation.get("created"), str)
        or not isinstance(creation.get("creators"), list)
        or not creation["creators"]
        or any(not isinstance(item, str) or not item for item in creation["creators"])
    ):
        raise NoetherForgeError("SPDX creationInfo is structurally invalid")
    annotations = sbom.get("annotations")
    if not isinstance(annotations, list) or not annotations:
        raise NoetherForgeError("SPDX document must contain a scope annotation")
    for annotation in annotations:
        if (
            not isinstance(annotation, dict)
            or set(annotation) != {"annotationDate", "annotationType", "annotator", "comment"}
            or annotation.get("annotationType") not in {"OTHER", "REVIEW"}
            or any(not isinstance(annotation.get(key), str) or not annotation.get(key) for key in ("annotationDate", "annotator", "comment"))
        ):
            raise NoetherForgeError("SPDX annotation is structurally invalid")
    packages = sbom.get("packages")
    files = sbom.get("files")
    relationships = sbom.get("relationships")
    if not isinstance(packages, list) or len(packages) != len(package_lock["packages"]) + 2:
        raise NoetherForgeError("SPDX package scope must cover both Alpine release media plus every locked APK member")
    if not isinstance(files, list) or len(files) != len(source["files"]):
        raise NoetherForgeError("SPDX file scope must cover every bound first-party build input")
    package_allowed = {
        "SPDXID", "checksums", "comment", "downloadLocation", "externalRefs", "filesAnalyzed",
        "licenseConcluded", "licenseDeclared", "name", "packageFileName", "primaryPackagePurpose",
        "supplier", "versionInfo",
    }
    file_allowed = {"SPDXID", "checksums", "fileName", "fileTypes", "licenseConcluded"}
    identifiers = {"SPDXRef-DOCUMENT"}
    checksum_algorithms = {
        "ADLER32", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512", "BLAKE3", "MD2", "MD4", "MD5", "MD6",
        "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512",
    }

    def check_checksums(value: Any, label: str) -> None:
        if not isinstance(value, list) or not value:
            raise NoetherForgeError(f"{label} must include at least one checksum")
        for checksum in value:
            if (
                not isinstance(checksum, dict)
                or set(checksum) != {"algorithm", "checksumValue"}
                or checksum.get("algorithm") not in checksum_algorithms
                or not isinstance(checksum.get("checksumValue"), str)
                or not re.fullmatch(r"[0-9a-f]+", checksum["checksumValue"])
            ):
                raise NoetherForgeError(f"{label} has an invalid checksum")

    for package in packages:
        if not isinstance(package, dict) or not {"SPDXID", "downloadLocation", "name"} <= set(package) or not set(package) <= package_allowed:
            raise NoetherForgeError("SPDX package record is structurally invalid")
        if "primaryPackagePurpose" in package and package["primaryPackagePurpose"] not in {
            "APPLICATION", "CONTAINER", "DEVICE", "FIRMWARE", "FILE", "FRAMEWORK",
            "INSTALL", "LIBRARY", "OPERATING_SYSTEM", "OTHER", "SOURCE", "ARCHIVE",
        }:
            raise NoetherForgeError("SPDX package primaryPackagePurpose is invalid")
        check_checksums(package.get("checksums"), "SPDX package")
        if package.get("filesAnalyzed") is not False:
            raise NoetherForgeError("SPDX package records must explicitly state filesAnalyzed=false")
        external_refs = package.get("externalRefs", [])
        if not isinstance(external_refs, list) or any(
            not isinstance(item, dict)
            or not {"referenceCategory", "referenceLocator", "referenceType"} <= set(item)
            or not set(item) <= {"comment", "referenceCategory", "referenceLocator", "referenceType"}
            for item in external_refs
        ):
            raise NoetherForgeError("SPDX package externalRefs are structurally invalid")
        identifiers.add(str(package["SPDXID"]))
    for file_record in files:
        if not isinstance(file_record, dict) or not {"SPDXID", "checksums", "fileName"} <= set(file_record) or not set(file_record) <= file_allowed:
            raise NoetherForgeError("SPDX file record is structurally invalid")
        check_checksums(file_record["checksums"], "SPDX file")
        if not isinstance(file_record.get("fileTypes", []), list) or any(
            value not in {"APPLICATION", "ARCHIVE", "AUDIO", "BINARY", "DOCUMENTATION", "IMAGE", "OTHER", "SOURCE", "SPDX", "TEXT", "VIDEO"}
            for value in file_record.get("fileTypes", [])
        ):
            raise NoetherForgeError("SPDX fileTypes are invalid")
        identifiers.add(str(file_record["SPDXID"]))
    if len(identifiers) != 1 + len(packages) + len(files):
        raise NoetherForgeError("SPDX identifiers are not unique")
    described = sbom.get("documentDescribes")
    expected_described = sorted(identifiers - {"SPDXRef-DOCUMENT"})
    if described != expected_described:
        raise NoetherForgeError("SPDX documentDescribes does not exactly cover packages and first-party files")
    expected_relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": identifier}
        for identifier in expected_described
    ]
    if relationships != expected_relationships:
        raise NoetherForgeError("SPDX DESCRIBES relationships are incomplete or contain extras")


def generate_sbom(package_source: Path, package_lock: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    packages: list[dict[str, Any]] = []
    input_lock = load_json(RELEASE_ROOT / "alpine-input-lock.json")
    overlay_records = {item["filename"]: item for item in input_lock["post_release_overlay"]}
    for locked in package_lock["packages"]:
        path = package_source / locked["filename"]
        info = apk_pkginfo(path)
        identifier = spdx_id(info["pkgname"])
        alpine_license = info.get("license", "not reported")
        overlay_record = overlay_records.get(locked["filename"])
        checksums = [{"algorithm": "SHA256", "checksumValue": locked["sha256"]}]
        if overlay_record is not None:
            checksums.append({"algorithm": "SHA512", "checksumValue": overlay_record["sha512"]})
        source_comment = (
            f"Post-release Alpine-signed package fetched from an exact official versioned URL, whole-file "
            f"SHA-256/SHA-512 locked, and verified only with the authenticated 6165 signing key. Its mutable "
            f"repository locator creates future rebuild-availability risk. Inclusion reason: {overlay_record['reason']}. "
            if overlay_record is not None
            else f"Signed APK member {package_lock['repository_path']}/{locked['filename']} is extracted from "
                 f"locked container {package_lock['source_media']}. "
        )
        packages.append({
            "SPDXID": identifier,
            "name": info["pkgname"],
            "versionInfo": info["pkgver"],
            "packageFileName": locked["filename"],
            "downloadLocation": overlay_record["url"] if overlay_record is not None else "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "checksums": checksums,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:apk/alpine/{info['pkgname']}@{info['pkgver']}?arch={info.get('arch', 'noarch')}",
            }],
            "supplier": "Organization: Alpine Linux",
            "comment": (
                source_comment + "The package is selected into the diskless runtime closure. "
                f"Raw Alpine package metadata reports license: {alpine_license}. This SBOM does not independently "
                "normalize that expression or make a license conclusion."
            ),
        })
    alpine_iso = input_lock["boot_media"]["iso"]
    package_source_iso = input_lock["package_source_media"]["iso"]
    packages.append({
        "SPDXID": "SPDXRef-Package-Alpine-Standard-ISO",
        "name": "alpine-standard",
        "versionInfo": input_lock["alpine_release"],
        "packageFileName": alpine_iso["filename"],
        "downloadLocation": alpine_iso["url"],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": alpine_iso["sha256"]},
            {"algorithm": "SHA512", "checksumValue": alpine_iso["sha512"]},
        ],
        "primaryPackagePurpose": "OPERATING_SYSTEM",
        "supplier": "Organization: Alpine Linux",
        "comment": "Authenticated upstream ISO substrate supplying the kernel, initramfs, and BIOS/UEFI boot equipment.",
    })
    packages.append({
        "SPDXID": "SPDXRef-Alpine-Extended-ISO",
        "name": "Alpine Linux extended ISO package-source media",
        "versionInfo": input_lock["alpine_release"],
        "packageFileName": package_source_iso["filename"],
        "primaryPackagePurpose": "OPERATING_SYSTEM",
        "downloadLocation": package_source_iso["url"],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": package_source_iso["sha256"]},
            {"algorithm": "SHA512", "checksumValue": package_source_iso["sha512"]},
        ],
        "supplier": "Organization: Alpine Linux",
        "comment": "Authenticated release media supplying the signed APK index and 49 locked APK members; the three post-release overlay APKs are not members of this ISO.",
    })
    files: list[dict[str, Any]] = []
    for record in source["files"]:
        path = record["path"]
        identifier = "SPDXRef-File-" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:24]
        if path == "build/wuci-ji":
            file_type = "BINARY"
        elif Path(path).suffix in {".py", ".s", ".inc"} or path == "Makefile":
            file_type = "SOURCE"
        else:
            file_type = "TEXT"
        files.append({
            "SPDXID": identifier,
            "fileName": "./" + path,
            "checksums": [{"algorithm": "SHA256", "checksumValue": record["sha256"]}],
            "fileTypes": [file_type],
            "licenseConcluded": "NOASSERTION",
        })
    described = sorted([item["SPDXID"] for item in packages] + [item["SPDXID"] for item in files])
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": identifier}
        for identifier in described
    ]
    namespace_seed = hashlib.sha256(canonical_json({
        "package_lock": package_lock,
        "source_payload_sha256": source["source_payload_sha256"],
        "alpine_boot_iso_sha256": alpine_iso["sha256"],
        "alpine_package_source_iso_sha256": package_source_iso["sha256"],
    })).hexdigest()
    timestamp = datetime.fromtimestamp(load_json(RELEASE_ROOT / "release.json")["source_date_epoch"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "WuciOS-2.4.0-Noether-Forge-x86_64-build-and-runtime-closure",
        "documentNamespace": f"https://nosuchmachine.net/spdx/wucios/noether-forge/{namespace_seed}",
        "creationInfo": {
            "created": timestamp,
            "creators": [f"Tool: {BUILDER_VERSION}"],
        },
        "comment": (
            "Scope: the authenticated Alpine ISO boot substrate, all 52 signed APK runtime payloads, and every "
            f"first-party source/configuration/binary input bound by source manifest {source['source_payload_sha256']}."
        ),
        "packages": packages,
        "files": files,
        "documentDescribes": described,
        "relationships": relationships,
        "annotations": [{
            "annotationType": "OTHER",
            "annotator": f"Tool: {BUILDER_VERSION}",
            "annotationDate": timestamp,
            "comment": (
                "The signed APKINDEX and 49 APK payloads are members of the locked, GPG-authenticated Alpine extended "
                "release ISO and serve source verification only; APKINDEX is absent from the final WuciOS ISO. Three "
                "post-release official Alpine APKs use exact mutable repository locators, whole-file SHA-256/SHA-512 "
                "locks, and exact 6165-key verification. APK v2 RSA signatures cover a SHA-1 control stream, so signature "
                "verification alone is not represented as modern collision-resistant whole-file integrity; the exact "
                "whole-file digest locks are security-critical. QEMU evidence records the installed 52-package set."
            ),
        }],
    }
    validate_spdx_sbom(sbom, package_lock, source)
    return sbom


def copy_regular(source: Path, destination: Path, label: str) -> None:
    ensure_regular(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise NoetherForgeError(f"duplicate overlay destination: {destination}")
    shutil.copyfile(source, destination)


def prepare_overlay(
    work: Path,
    source: dict[str, Any],
    sbom: dict[str, Any],
    input_verification: dict[str, Any],
    runtime_package_contract: dict[str, Any],
) -> tuple[Path, dict[str, dict[str, int]], dict[str, Any]]:
    overlay = work / "overlay"
    overlay.mkdir()
    source_overlay = RELEASE_ROOT / "overlay"
    for path in sorted(source_overlay.rglob("*")):
        relative = path.relative_to(source_overlay)
        destination = overlay / relative
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            destination.mkdir(parents=True, exist_ok=True)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise NoetherForgeError(f"overlay source hardlink rejected: {path}")
            copy_regular(path, destination, "overlay source")
        else:
            raise NoetherForgeError(f"unsupported tracked overlay source type: {path}")

    metadata_raw = load_json(RELEASE_ROOT / "overlay-metadata.json")
    metadata: dict[str, dict[str, int]] = {}
    for name, value in metadata_raw["paths"].items():
        metadata[name] = {
            "mode": int(value.get("mode", metadata_raw["defaults"]["file_mode"]), 8),
            "uid": int(value.get("uid", metadata_raw["defaults"]["uid"])),
            "gid": int(value.get("gid", metadata_raw["defaults"]["gid"])),
        }

    payload_map = load_json(RELEASE_ROOT / "payload-map.json")
    for payload in payload_map["payloads"]:
        source_path = REPO / payload["source"]
        destination = overlay / payload["destination"]
        ensure_no_symlink_parents(destination, overlay, "mapped runtime payload")
        copy_regular(source_path, destination, "mapped runtime payload")
        metadata[payload["destination"]] = {"mode": int(payload["mode"], 8), "uid": 0, "gid": 0}

    embedded = {
        "usr/share/wucios/release.json": load_json(RELEASE_ROOT / "release.json"),
        "usr/share/wucios/package-lock.json": load_json(RELEASE_ROOT / "package-lock.json"),
        "usr/share/wucios/component-map.json": load_json(RELEASE_ROOT / "component-map.json"),
        "usr/share/wucios/source-manifest.json": source,
        "usr/share/wucios/sbom.spdx.json": sbom,
        "usr/share/wucios/input-verification.json": input_verification,
        "usr/share/wucios/runtime-package-contract.json": runtime_package_contract,
    }
    for name, value in embedded.items():
        path = overlay / name
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, canonical_json(value))

    copy_regular(
        REPO / "wucios/sets/cantor-denied-noether-packages.txt",
        overlay / "usr/share/wucios/cantor-denied-noether-packages.txt",
        "canonical Noether denied-package set",
    )

    fixture_root = overlay / "usr/share/wucios/fixtures"
    fixture_root.mkdir(parents=True, exist_ok=True)
    copy_regular(RELEASE_ROOT / "fixtures/bounded-claims.txt", fixture_root / "bounded-claims.txt", "bounded claim fixture")
    atomic_write(fixture_root / "forbidden-claims.txt", b"This artifact has production authority.\n")
    public_fixture = b"WJSEAL\x03\x01" + bytes(range(32)) + bytes(range(16)) + bytes(range(12)) + b"N" + bytes(range(16))
    atomic_write(fixture_root / "public-fixture.wj", public_fixture)
    atomic_write(fixture_root / "malformed.wj", b"not-a-wjseal-artifact\n")

    for home in ("home/wj", "home/wj_low"):
        (overlay / home).mkdir(parents=True, exist_ok=True)

    runlevels = load_json(RELEASE_ROOT / "runlevels.json")["runlevels"]
    for runlevel, services in sorted(runlevels.items()):
        directory = overlay / "etc/runlevels" / runlevel
        directory.mkdir(parents=True, exist_ok=True)
        for service in sorted(services):
            link = directory / service
            os.symlink(f"/etc/init.d/{service}", link)

    package_lines = [f"{item['filename']} {item['sha256']}" for item in load_json(RELEASE_ROOT / "package-lock.json")["packages"]]
    sha256sum_lines = [f"{item['sha256']}  {item['filename']}" for item in load_json(RELEASE_ROOT / "package-lock.json")["packages"]]
    evidence = overlay / "usr/share/wucios/evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    atomic_write(evidence / "package-manifest.txt", ("\n".join(package_lines) + "\n").encode("utf-8"))
    atomic_write(
        overlay / "usr/share/wucios/locked-apk-manifest.sha256",
        ("\n".join(sha256sum_lines) + "\n").encode("ascii"),
    )
    atomic_write(
        evidence / "godel-boundary.md",
        (
            "# Noether Forge boundary\n\n"
            "The image verifies a pinned artifact, local runtime surface, and default-drop nftables policy. "
            "It does not claim general runtime containment, production authority, external certification, or quantum safety.\n"
        ).encode("utf-8"),
    )
    overlay_manifest = {
        "schema": "wucios.noether_forge.overlay_manifest.v1",
        "release": "noether-forge-v2.4.0",
        "source_payload_sha256": source["source_payload_sha256"],
        "payload_count": len(payload_map["payloads"]),
        "runlevels": runlevels,
    }
    atomic_write(overlay / "usr/share/wucios/overlay-manifest.json", canonical_json(overlay_manifest))
    return overlay, metadata, overlay_manifest


def normalized_metadata(path: str, is_dir: bool, metadata: dict[str, dict[str, int]]) -> dict[str, int]:
    defaults = {"mode": 0o755 if is_dir else 0o644, "uid": 0, "gid": 0}
    return {**defaults, **metadata.get(path, {})}


def write_deterministic_apkovl(
    overlay: Path,
    output: Path,
    metadata: dict[str, dict[str, int]],
    source_date_epoch: int,
) -> dict[str, Any]:
    entries: set[Path] = {Path(".")}
    for path in overlay.rglob("*"):
        relative = path.relative_to(overlay)
        entries.add(relative)
        entries.update(relative.parents)
    ordered = sorted((item for item in entries if str(item) != "."), key=lambda item: (len(item.parts), item.as_posix()))
    buffer = io.BytesIO()
    records: list[dict[str, Any]] = []
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for relative in ordered:
            path = overlay / relative
            info = path.lstat()
            name = relative.as_posix()
            if name.startswith("/") or ".." in relative.parts:
                raise NoetherForgeError(f"unsafe overlay path: {name}")
            tar_info = tarfile.TarInfo(name + ("/" if stat.S_ISDIR(info.st_mode) else ""))
            tar_info.mtime = source_date_epoch
            # Numeric ownership is authoritative.  A hard-coded textual
            # "root" owner causes BusyBox tar to resolve uid/gid 1000/1001
            # back to root while applying the diskless overlay.
            tar_info.uname = ""
            tar_info.gname = ""
            values = normalized_metadata(name, stat.S_ISDIR(info.st_mode), metadata)
            tar_info.mode = values["mode"]
            tar_info.uid = values["uid"]
            tar_info.gid = values["gid"]
            if stat.S_ISDIR(info.st_mode):
                tar_info.type = tarfile.DIRTYPE
                archive.addfile(tar_info)
                records.append({"path": name + "/", "type": "directory", **values})
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise NoetherForgeError(f"overlay hardlink rejected: {name}")
                data = path.read_bytes()
                tar_info.size = len(data)
                archive.addfile(tar_info, io.BytesIO(data))
                records.append({"path": name, "type": "file", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), **values})
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                tar_info.type = tarfile.SYMTYPE
                tar_info.linkname = target
                archive.addfile(tar_info)
                records.append({"path": name, "type": "symlink", "target": target, **values})
            else:
                raise NoetherForgeError(f"unsupported overlay entry: {name}")
    output.parent.mkdir(parents=True, exist_ok=True)
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=source_date_epoch, compresslevel=9) as stream:
        stream.write(buffer.getvalue())
    atomic_write(output, compressed.getvalue())
    return {
        "schema": "wucios.noether_forge.apkovl_build.v1",
        "filename": output.name,
        "size": output.stat().st_size,
        "sha256": digest_file(output),
        "entry_count": len(records),
        "entries": records,
    }


def patch_volume_label(source: Path, destination: Path, old: str, new: str) -> None:
    old_bytes = old.encode("ascii")
    new_bytes = new.encode("ascii")
    if len(old_bytes) != len(new_bytes):
        raise NoetherForgeError("EFI label replacement must preserve byte length")
    data = source.read_bytes()
    if data.count(old_bytes) != 1:
        raise NoetherForgeError(f"EFI label occurrence drift in {source.name}")
    atomic_write(destination, data.replace(old_bytes, new_bytes), mode=0o644)


def prepare_iso_metadata(
    work: Path,
    source: dict[str, Any],
    sbom: dict[str, Any],
    input_verification: dict[str, Any],
    runtime_package_contract: dict[str, Any],
) -> Path:
    metadata = work / "iso-metadata"
    metadata.mkdir()
    files = {
        "release.json": load_json(RELEASE_ROOT / "release.json"),
        "package-lock.json": load_json(RELEASE_ROOT / "package-lock.json"),
        "component-map.json": load_json(RELEASE_ROOT / "component-map.json"),
        "source-manifest.json": source,
        "sbom.spdx.json": sbom,
        "input-verification.json": input_verification,
        "runtime-package-contract.json": runtime_package_contract,
    }
    for name, value in files.items():
        atomic_write(metadata / name, canonical_json(value))
    atomic_write(
        metadata / "BOUNDARY.txt",
        (
            "WuciOS 2.4.0 Noether Forge is an internal Alpine-based live ISO.\n"
            "Its nftables policy is tested default-drop configuration, not a general runtime sandbox claim.\n"
            "The artifact has no production signature, hardware trace, operated witness, tag, or publication authority.\n"
        ).encode("utf-8"),
    )
    return metadata


def build_iso_once(
    cache: Path,
    package_source: Path,
    work: Path,
    output: Path,
    source: dict[str, Any],
    sbom: dict[str, Any],
    input_verification: dict[str, Any],
    runtime_package_contract: dict[str, Any],
) -> dict[str, Any]:
    release, input_lock, package_lock = validate_configuration()
    patch_spec = load_initramfs_patch_spec(input_lock)
    overlay, metadata, overlay_manifest = prepare_overlay(work, source, sbom, input_verification, runtime_package_contract)
    apkovl = work / OVERLAY_FILENAME
    apkovl_result = write_deterministic_apkovl(overlay, apkovl, metadata, release["source_date_epoch"])

    repository = work / "repository/x86_64"
    repository.mkdir(parents=True)
    for package in package_lock["packages"]:
        shutil.copyfile(package_source / package["filename"], repository / package["filename"])

    boot = work / "boot"
    boot.mkdir()
    upstream_bootx64 = boot / "upstream-bootx64.efi"
    upstream_efi_image = boot / "upstream-efi.img"
    upstream_initramfs = boot / "upstream-initramfs-lts"
    iso = cache / input_lock["boot_media"]["iso"]["filename"]
    xorriso_extract(iso, "/efi/boot/bootx64.efi", upstream_bootx64)
    xorriso_extract(iso, "/boot/grub/efi.img", upstream_efi_image)
    xorriso_extract(iso, input_lock["bootstrap"]["initramfs"]["iso_path"], upstream_initramfs)
    patched_bootx64 = boot / "bootx64.efi"
    patched_efi_image = boot / "efi.img"
    patched_initramfs = boot / "initramfs-lts"
    patch_volume_label(upstream_bootx64, patched_bootx64, input_lock["upstream_layout"]["volume_id"], release["volume_id"])
    patch_volume_label(upstream_efi_image, patched_efi_image, input_lock["upstream_layout"]["volume_id"], release["volume_id"])
    initramfs_result = write_patched_initramfs(
        upstream_initramfs,
        patched_initramfs,
        input_lock["bootstrap"]["initramfs"],
        input_lock["bootstrap"]["patch"],
        patch_spec,
    )
    iso_metadata = prepare_iso_metadata(work, source, sbom, input_verification, runtime_package_contract)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = work / "candidate.iso"
    date_text = datetime.fromtimestamp(release["source_date_epoch"], timezone.utc).strftime("%Y%m%d%H%M%S00")
    command: list[str | os.PathLike[str]] = [
        "xorriso",
        "-indev", iso,
        "-outdev", temporary,
        "-boot_image", "any", "replay",
        "-compliance", "iso_9660_level=2",
        "-rockridge", "on",
        "-joliet", "on",
        "-compliance", "full_ascii",
        "-compliance", "relaxed_pvd_atts=vol",
        "-compliance", "joliet_long_names",
        "-compliance", "old_rr",
        "-volid", release["volume_id"],
        "-preparer_id", BUILDER_VERSION,
        "-volume_date", "uuid", date_text,
        "-volume_date", "c", date_text,
        "-volume_date", "m", date_text,
        "-volume_date", "all_file_dates", date_text,
        "-boot_image", "any", "gpt_disk_guid=volume_date_uuid",
        "-rm_r", "/apks/x86_64", "--",
        "-rm", "/apks/.boot_repository", "--",
        "-map", repository, "/apks/x86_64",
        "-map", RELEASE_ROOT / "boot/grub.cfg", "/boot/grub/grub.cfg",
        "-map", RELEASE_ROOT / "boot/syslinux.cfg", "/boot/syslinux/syslinux.cfg",
        "-map", patched_efi_image, "/boot/grub/efi.img",
        "-map", patched_bootx64, "/efi/boot/bootx64.efi",
        "-map", patched_initramfs, "/boot/initramfs-lts",
        "-map", iso_metadata, "/wucios",
        "-map", apkovl, f"/{OVERLAY_FILENAME}",
        "-commit",
        "-end",
    ]
    environment = {**os.environ, "SOURCE_DATE_EPOCH": str(release["source_date_epoch"])}
    result = run(command, cwd=work, env=environment, timeout=600)
    ensure_regular(temporary, "generated ISO")
    os.replace(temporary, output)
    return {
        "schema": "wucios.noether_forge.build_once.v1",
        "status": "pass",
        "artifact": {"filename": output.name, "size": output.stat().st_size, **digest_vector(output)},
        "apkovl": apkovl_result,
        "overlay_manifest": overlay_manifest,
        "runtime_package_contract_sha256": hashlib.sha256(canonical_json(runtime_package_contract)).hexdigest(),
        "initramfs": initramfs_result,
        "xorriso_stdout_tail": result.stdout[-3000:],
        "xorriso_stderr_tail": result.stderr[-3000:],
    }


def safe_tar_audit(apkovl: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    patterns = privacy_patterns()
    seen: set[str] = set()
    symlinks: list[dict[str, str]] = []
    scanned_files = 0
    scanned_bytes = 0
    findings: list[dict[str, str]] = []
    passwd_text = ""
    os_release_text = ""
    with tarfile.open(apkovl, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if not name or name in seen or path.is_absolute() or ".." in path.parts:
                raise NoetherForgeError(f"unsafe or duplicate apkovl member: {member.name}")
            seen.add(name)
            if member.islnk() or member.isdev() or member.isfifo():
                raise NoetherForgeError(f"forbidden apkovl member type: {member.name}")
            if member.issym():
                resolved = posixpath.normpath(posixpath.join("/", posixpath.dirname(name), member.linkname))
                if not resolved.startswith("/etc/init.d/"):
                    raise NoetherForgeError(f"apkovl symlink escapes approved init targets: {member.name} -> {member.linkname}")
                symlinks.append({"path": name, "target": member.linkname, "resolved": resolved})
                continue
            if not member.isfile():
                continue
            stream = archive.extractfile(member)
            if stream is None:
                raise NoetherForgeError(f"cannot read apkovl member: {member.name}")
            data = stream.read()
            scanned_files += 1
            scanned_bytes += len(data)
            if name == "etc/passwd":
                passwd_text = data.decode("utf-8")
            elif name == "etc/os-release":
                os_release_text = data.decode("utf-8")
            lower_name = name.lower()
            if "/.ssh/" in f"/{lower_name}/" or lower_name.endswith((".key", ".pem", ".history")):
                findings.append({"path": name, "pattern": "private-path-shape"})
            for pattern, pattern_name in patterns:
                if pattern.lower() in data.lower():
                    findings.append({"path": name, "pattern": pattern_name})
    if any(line.startswith("anon:") for line in passwd_text.splitlines()):
        findings.append({"path": "etc/passwd", "pattern": "legacy-anon-account"})
    if "wj:x:1000:1000:" not in passwd_text or "wj_low:x:1001:1001:" not in passwd_text:
        findings.append({"path": "etc/passwd", "pattern": "account-contract-missing"})
    if "ID=wucios" not in os_release_text or "ID_LIKE=alpine" not in os_release_text:
        findings.append({"path": "etc/os-release", "pattern": "release-identity-missing"})
    privacy = {
        "schema": "wucios.noether_forge.privacy_audit.v1",
        "status": "pass" if not findings else "fail",
        "files_scanned": scanned_files,
        "bytes_scanned": scanned_bytes,
        "findings": findings,
        "raw_iso_pattern_ids": [pattern_name for _, pattern_name in patterns],
    }
    links = {
        "schema": "wucios.noether_forge.link_audit.v1",
        "status": "pass",
        "hardlinks": 0,
        "symlink_count": len(symlinks),
        "symlinks": sorted(symlinks, key=lambda item: item["path"]),
        "policy": "Only release-generated /etc/runlevels links to /etc/init.d are permitted.",
    }
    return privacy, links


def inspect_iso(iso: Path, work: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    release, input_lock, package_lock = validate_configuration()
    patch_spec = load_initramfs_patch_spec(input_lock)
    ensure_regular(iso, "Noether Forge ISO")
    pvd_result = run(["xorriso", "-indev", iso, "-pvd_info"])
    boot_result = run(["xorriso", "-indev", iso, "-report_el_torito", "plain"])
    pvd = pvd_result.stdout + pvd_result.stderr
    boot = boot_result.stdout + boot_result.stderr
    if f"Volume id    : '{release['volume_id']}'" not in pvd:
        raise NoetherForgeError("ISO volume identity mismatch")
    boot_entry_count = sum(1 for line in boot.splitlines() if line.startswith("El Torito boot img :"))
    if boot_entry_count != 2 or "/boot/syslinux/isolinux.bin" not in boot or "/boot/grub/efi.img" not in boot:
        raise NoetherForgeError("ISO does not preserve both BIOS and UEFI boot entries")
    extracted = work / "inspect"
    extracted.mkdir()
    apks_root = extracted / "apks"
    run(["xorriso", "-osirrox", "on", "-indev", iso, "-extract", "/apks", apks_root])
    if sorted(path.name for path in apks_root.iterdir()) != ["x86_64"] or not (apks_root / "x86_64").is_dir():
        raise NoetherForgeError("ISO /apks must contain only the x86_64 direct-file package directory")
    packages = apks_root / "x86_64"
    package_files = sorted(path.name for path in packages.iterdir() if path.is_file() and path.name.endswith(".apk"))
    expected_packages = [item["filename"] for item in package_lock["packages"]]
    if package_files != expected_packages:
        raise NoetherForgeError("ISO APK payload set differs from the exact package lock")
    expected_repository_files = sorted(expected_packages)
    observed_repository_files = sorted(path.name for path in packages.iterdir())
    if observed_repository_files != expected_repository_files or any(not path.is_file() for path in packages.iterdir()):
        raise NoetherForgeError("ISO package directory must contain exactly 52 locked APKs and no repository index")
    for locked in package_lock["packages"]:
        verify_locked_file(packages / locked["filename"], locked, "ISO APK payload")

    patched_initramfs = extracted / "initramfs-lts"
    xorriso_extract(iso, "/boot/initramfs-lts", patched_initramfs)
    _, initramfs_evidence = read_patched_initramfs(
        patched_initramfs,
        input_lock["bootstrap"]["patch"],
        patch_spec,
        expected_entry_count=input_lock["bootstrap"]["initramfs"]["entry_count"],
    )

    apkovl = extracted / OVERLAY_FILENAME
    xorriso_extract(iso, f"/{OVERLAY_FILENAME}", apkovl)
    privacy, links = safe_tar_audit(apkovl)
    expected_runtime_package_contract = generate_runtime_package_contract(packages, package_lock)
    with tarfile.open(apkovl, "r:gz") as archive:
        try:
            member = archive.getmember("usr/share/wucios/runtime-package-contract.json")
        except KeyError as exc:
            raise NoetherForgeError("apkovl runtime package contract is missing") from exc
        if not member.isfile():
            raise NoetherForgeError("apkovl runtime package contract is not a regular file")
        stream = archive.extractfile(member)
        if stream is None:
            raise NoetherForgeError("apkovl runtime package contract is unreadable")
        try:
            apkovl_runtime_package_contract = json.loads(stream.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise NoetherForgeError(f"apkovl runtime package contract is invalid JSON: {exc}") from exc
    outer_contract_path = extracted / "runtime-package-contract.json"
    xorriso_extract(iso, "/wucios/runtime-package-contract.json", outer_contract_path)
    outer_runtime_package_contract = load_json(outer_contract_path)
    if (
        canonical_json(apkovl_runtime_package_contract) != canonical_json(expected_runtime_package_contract)
        or canonical_json(outer_runtime_package_contract) != canonical_json(expected_runtime_package_contract)
    ):
        raise NoetherForgeError("embedded runtime package contract differs from the authenticated APK closure")
    runtime_package_contract_sha256 = hashlib.sha256(canonical_json(expected_runtime_package_contract)).hexdigest()
    raw = iso.read_bytes()
    raw_findings = [pattern_name for pattern, pattern_name in privacy_patterns() if pattern.lower() in raw.lower()]
    privacy["raw_iso_findings"] = raw_findings
    if raw_findings:
        privacy["status"] = "fail"
    if privacy["status"] != "pass":
        raise NoetherForgeError(f"ISO privacy audit failed: {privacy['findings']} {raw_findings}")

    pvd = normalize_xorriso_report(pvd, iso)
    boot = normalize_xorriso_report(boot, iso)
    layout = {
        "schema": "wucios.noether_forge.iso_layout.v1",
        "status": "pass",
        "artifact": {"filename": iso.name, "size": iso.stat().st_size, **digest_vector(iso)},
        "volume_id": release["volume_id"],
        "bios_boot_image": "/boot/syslinux/isolinux.bin",
        "uefi_boot_image": "/boot/grub/efi.img",
        "boot_entry_count": boot_entry_count,
        "package_payload_count": len(package_files),
        "package_source_media": input_lock["package_source_media"]["iso"]["filename"],
        "signed_apk_index_embedded": False,
        "apkindex_files_present": False,
        "boot_repository_marker_present": False,
        "patched_initramfs": {
            **initramfs_evidence,
            "size": patched_initramfs.stat().st_size,
            "sha256": digest_file(patched_initramfs),
        },
        "apkovl_sha256": digest_file(apkovl),
        "runtime_package_contract_sha256": runtime_package_contract_sha256,
        "pvd_report": pvd,
        "el_torito_report": boot,
    }
    return layout, privacy, links


def release_paths(output: Path, release: dict[str, Any]) -> tuple[Path, Path, Path]:
    release_dir = output / "release"
    evidence_dir = release_dir / "evidence"
    iso = release_dir / release["artifact_filename"]
    return release_dir, evidence_dir, iso


def write_artifact_sidecars(iso: Path) -> dict[str, str]:
    digests = digest_vector(iso)
    for algorithm, value in digests.items():
        atomic_write(iso.with_name(iso.name + f".{algorithm}"), f"{value}  {iso.name}\n".encode("ascii"))
    return digests


def host_tool_identity(name: str) -> tuple[Path, dict[str, str]]:
    executable = shutil.which(name)
    if executable is None:
        raise NoetherForgeError(f"required Wuci-Ji build tool is unavailable: {name}")
    resolved = Path(executable).resolve(strict=True)
    ensure_regular(resolved, f"{name} executable")
    result = run([resolved, "--version"])
    version_output = (result.stdout or result.stderr).strip()
    if not version_output:
        raise NoetherForgeError(f"{name} did not report a version")
    try:
        display_path = "${HOME}/" + resolved.relative_to(Path.home().resolve()).as_posix()
    except ValueError:
        display_path = str(resolved)
    return resolved, {
        "path": display_path,
        "sha256": digest_file(resolved),
        "version": version_output.splitlines()[0],
    }


def build_wuci_runtime() -> dict[str, Any]:
    identities = {name: host_tool_identity(name) for name in ("as", "ld", "make", "file")}
    executables = {name: value[0] for name, value in identities.items()}
    toolchain = {name: value[1] for name, value in identities.items()}
    build_result = run([
        executables["make"],
        "-B",
        f"AS={executables['as']}",
        f"LD={executables['ld']}",
        "build/wuci-ji",
    ], cwd=REPO, timeout=300)
    binary = REPO / "build/wuci-ji"
    ensure_regular(binary, "fresh Wuci-Ji runtime binary")
    file_result = run([executables["file"], binary])
    if "ELF 64-bit LSB executable" not in file_result.stdout or "statically linked" not in file_result.stdout:
        raise NoetherForgeError(f"Wuci-Ji runtime is not the expected static x86_64 ELF: {file_result.stdout.strip()}")
    selftest = run([binary, "selftest"])
    regression = run([binary, "asm-regression"])
    if "wuci-ji selftest: PASS" not in selftest.stdout or "wuci-ji asm-regression: PASS" not in regression.stdout:
        raise NoetherForgeError("fresh Wuci-Ji runtime did not pass host selftest and assembly regression")
    return {
        "path": "build/wuci-ji",
        "size": binary.stat().st_size,
        "sha256": digest_file(binary),
        "file": file_result.stdout.strip().replace(str(REPO) + "/", ""),
        "selftest": "pass",
        "asm_regression": "pass",
        "toolchain": toolchain,
        "build_stdout_tail": build_result.stdout[-2000:].replace(str(REPO), "${REPO}"),
    }


def command_fetch(args: argparse.Namespace) -> int:
    _, input_lock, package_lock = validate_configuration()
    cache = Path(args.cache)
    for record in cache_records(input_lock):
        print(f"fetch {record['kind']}: {record['filename']}", flush=True)
        download_locked(record, cache)
    with tempfile.TemporaryDirectory(prefix="noether-input-verify-", dir=args.temp_dir) as temporary:
        evidence = verify_inputs(cache, Path(temporary))
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


def command_verify_inputs(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="noether-input-verify-", dir=args.temp_dir) as temporary:
        evidence = verify_inputs(Path(args.cache), Path(temporary))
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


def command_build(args: argparse.Namespace) -> int:
    release, _, package_lock = validate_configuration()
    cache = Path(args.cache)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    release_dir, evidence_dir, final_iso = release_paths(output, release)
    safe_reset_directory(release_dir, output)
    evidence_dir.mkdir(parents=True, exist_ok=False)

    verification_work = output / "verify-inputs"
    safe_reset_directory(verification_work, output)
    input_verification = verify_inputs(cache, verification_work)
    package_source = verification_work / "package-source/x86_64"
    runtime_package_contract = generate_runtime_package_contract(package_source, package_lock)

    work_a = output / "work-a"
    work_b = output / "work-b"
    safe_reset_directory(work_a, output)
    safe_reset_directory(work_b, output)
    iso_a = work_a / "noether-a.iso"
    iso_b = work_b / "noether-b.iso"

    runtime_a = build_wuci_runtime()
    source_a = source_manifest()
    sbom_a = generate_sbom(package_source, package_lock, source_a)
    build_a = build_iso_once(cache, package_source, work_a, iso_a, source_a, sbom_a, input_verification, runtime_package_contract)

    runtime_b = build_wuci_runtime()
    source_b = source_manifest()
    sbom_b = generate_sbom(package_source, package_lock, source_b)
    if canonical_json(source_a) != canonical_json(source_b):
        raise NoetherForgeError("tracked source changed between independent ISO builds")
    if canonical_json(runtime_a) != canonical_json(runtime_b):
        raise NoetherForgeError("independent Wuci-Ji native builds did not produce identical evidence")
    if canonical_json(sbom_a) != canonical_json(sbom_b):
        raise NoetherForgeError("SBOM changed between independent ISO builds")
    build_b = build_iso_once(cache, package_source, work_b, iso_b, source_b, sbom_b, input_verification, runtime_package_contract)
    digest_a = digest_file(iso_a)
    digest_b = digest_file(iso_b)
    if iso_a.stat().st_size != iso_b.stat().st_size or digest_a != digest_b:
        raise NoetherForgeError(f"repeat build mismatch: {digest_a} != {digest_b}")
    shutil.copyfile(iso_a, final_iso)
    digests = write_artifact_sidecars(final_iso)

    inspect_work = output / "inspect-build"
    safe_reset_directory(inspect_work, output)
    layout, privacy, links = inspect_iso(final_iso, inspect_work)
    reproducibility = {
        "schema": "wucios.noether_forge.reproducibility.v1",
        "status": "pass",
        "source_date_epoch": release["source_date_epoch"],
        "build_a": build_a["artifact"],
        "build_b": build_b["artifact"],
        "byte_identical": True,
        "independent_wuci_ji_rebuilds": True,
        "wuci_ji_sha256": runtime_a["sha256"],
        "source_manifests_identical": True,
        "runtime_package_contract_sha256": hashlib.sha256(canonical_json(runtime_package_contract)).hexdigest(),
        "sha256": digest_a,
    }

    provenance = {
        "schema": "wucios.noether_forge.provenance.v1",
        "builder": BUILDER_VERSION,
        "artifact": {"filename": final_iso.name, "size": final_iso.stat().st_size, **digests},
        "source": {
            "payload_sha256": source_a["source_payload_sha256"],
            "git": source_a["git"],
        },
        "inputs": input_verification,
        "build": {
            "source_date_epoch": release["source_date_epoch"],
            "network_used": False,
            "shell_used": True,
            "shell_boundary": "The Python builder uses shell=False; GNU Make executes the tracked native assembly/link recipes.",
            "xorriso_mode": "native replay of authenticated BIOS/UEFI equipment",
            "repeat_build_byte_identical": True,
            "runtime_package_contract_sha256": hashlib.sha256(canonical_json(runtime_package_contract)).hexdigest(),
            "wuci_ji_runtime": {
                "independent_rebuilds": 2,
                "byte_identical": True,
                "build_a": runtime_a,
                "build_b": runtime_b,
            },
        },
        "publication": {"authorized": False, "holds": release["publication_holds"]},
        "non_claims": release["non_claims"],
    }
    external_sbom = release_dir / "sbom.spdx.json"
    external_provenance = release_dir / "provenance.json"
    write_json(external_sbom, sbom_a)
    write_json(external_provenance, provenance)
    write_json(evidence_dir / "input-verification.json", input_verification)
    write_json(evidence_dir / "source-manifest.json", source_a)
    write_json(evidence_dir / "reproducibility.json", reproducibility)
    write_json(evidence_dir / "iso-layout.json", layout)
    write_json(evidence_dir / "privacy-audit.json", privacy)
    write_json(evidence_dir / "link-audit.json", links)
    atomic_write(evidence_dir / "locked-apk-manifest.txt", ("\n".join(item["filename"] for item in package_lock["packages"]) + "\n").encode("utf-8"))
    build_evidence: dict[str, dict[str, Any]] = {}
    for name in (
        "input-verification.json",
        "source-manifest.json",
        "reproducibility.json",
        "iso-layout.json",
        "privacy-audit.json",
        "link-audit.json",
        "locked-apk-manifest.txt",
    ):
        path = evidence_dir / name
        ensure_regular(path, "build evidence")
        build_evidence[name] = {"path": f"evidence/{name}", "size": path.stat().st_size, "sha256": digest_file(path)}
    manifest = {
        "schema": "wucios.noether_forge.artifact_manifest.v1",
        "release_id": release["release_id"],
        "artifact": {"filename": final_iso.name, "size": final_iso.stat().st_size, **digests},
        "source_manifest_sha256": hashlib.sha256(canonical_json(source_a)).hexdigest(),
        "package_lock_sha256": digest_file(RELEASE_ROOT / "package-lock.json"),
        "sbom": {"filename": external_sbom.name, "size": external_sbom.stat().st_size, "sha256": digest_file(external_sbom), "validation": "spdx-2.3-closed-structural-profile-pass"},
        "provenance": {"filename": external_provenance.name, "size": external_provenance.stat().st_size, "sha256": digest_file(external_provenance)},
        "build_evidence": build_evidence,
        "internal_candidate": True,
        "public_release_authorized": False,
        "publication_holds": release["publication_holds"],
    }
    write_json(release_dir / "manifest.json", manifest)
    print(json.dumps({"status": "pass", "artifact": manifest["artifact"], "reproducibility": reproducibility}, indent=2, sort_keys=True))
    return 0


def sanitize_qemu_argv(argv: Sequence[str], iso: Path, firmware: Path | None) -> list[str]:
    values: list[str] = []
    for item in argv:
        value = item.replace(str(iso), iso.name)
        if firmware is not None:
            value = value.replace(str(firmware), firmware.name)
        values.append(value)
    return values


def qemu_argv(iso: Path, firmware_mode: str, firmware: Path | None) -> list[str]:
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        raise NoetherForgeError("qemu-system-x86_64 is required for exact-image boot verification")
    machine = "pc,accel=tcg" if firmware_mode == "bios" else "q35,accel=tcg"
    argv = [
        qemu,
        "-machine", machine,
        "-cpu", "max",
        "-m", "1024",
        "-smp", "2",
    ]
    if firmware_mode == "uefi":
        if firmware is None:
            raise NoetherForgeError("UEFI firmware path is required")
        ensure_regular(firmware, "OVMF stateless firmware")
        argv.extend(["-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}"])
    argv.extend([
        "-drive", f"file={iso},format=raw,media=cdrom,readonly=on",
        "-boot", "once=d,menu=off",
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-no-reboot",
        "-nic", "none",
        "-rtc", "base=utc",
    ])
    return argv


def interactive_guest_commands() -> bytes:
    commands = [
        "set -e",
        f"printf '\\n{RUNTIME_JSON_BEGIN}\\n'",
        "cat /run/wucios/runtime-contract.json",
        f"printf '\\n{RUNTIME_JSON_END}\\n'",
        "printf 'NOETHER_FORGE_HOST_UID=%s\\n' \"$(id -u)\"",
        "printf 'NOETHER_FORGE_HOST_USER=%s\\n' \"$(id -un)\"",
        "printf 'NOETHER_FORGE_HOST_GROUPS=%s\\n' \"$(id -Gn)\"",
        "cd \"$HOME\"",
        "printf 'home-write-proof\\n' > .noether-home-write-test",
        "rm .noether-home-write-test",
        f"printf '{HOME_PASS_MARKER}\\n'",
        "wuci-ji selftest",
        "wuci-ji asm-regression",
        "doas /usr/sbin/nft list ruleset",
        "printf 'printf \"NOETHER_FORGE_LOW_UID=%%s\\\\n\" \"$(id -u)\"\\nexit\\n' | wuci-low",
        (
            "if doas -n /bin/sh -c true >/dev/null 2>&1; "
            "then printf 'NOETHER_FORGE_DOAS_ARBITRARY_ROOT_ALLOWED\\n'; exit 91; "
            f"else printf '{DOAS_DENY_PASS_MARKER}\\n'; fi"
        ),
        "rc-status -a",
        f"printf '{HOST_PASS_MARKER}\\n'",
        "wuci-poweroff",
    ]
    return (" && ".join(commands) + "\n").encode("utf-8")


def extract_runtime_json(log_text: str) -> dict[str, Any]:
    end = log_text.rfind(RUNTIME_JSON_END)
    if end < 0:
        raise NoetherForgeError("runtime JSON end marker missing from QEMU trace")
    start = log_text.rfind(RUNTIME_JSON_BEGIN, 0, end)
    if start < 0:
        raise NoetherForgeError("runtime JSON begin marker missing from QEMU trace")
    start += len(RUNTIME_JSON_BEGIN)
    payload = log_text[start:end].strip()
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise NoetherForgeError(f"runtime JSON in QEMU trace is invalid: {exc}; prefix={payload[:160]!r}") from exc
    if not isinstance(value, dict):
        raise NoetherForgeError("runtime JSON report is not an object")
    return value


def run_qemu_boot(
    iso: Path,
    firmware_mode: str,
    firmware: Path | None,
    *,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    if firmware_mode not in {"bios", "uefi"}:
        raise NoetherForgeError(f"unsupported firmware mode: {firmware_mode}")
    host_sha256 = digest_file(iso)
    argv = qemu_argv(iso, firmware_mode, firmware)
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    if process.stdout is None or process.stdin is None:
        raise NoetherForgeError("QEMU stdio pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    stty_sent = False
    stty_output_start = 0
    commands_sent = False
    timed_out = False
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                process.terminate()
                break
            events = selector.select(timeout=1.0)
            for key, _ in events:
                block = os.read(key.fileobj.fileno(), 65536)
                if block:
                    output.extend(block)
            if not stty_sent and PASS_MARKER.encode("utf-8") in output and b"WJ>_ " in output:
                process.stdin.write(b"stty -echo\n")
                process.stdin.flush()
                stty_sent = True
                stty_output_start = len(output)
            elif stty_sent and not commands_sent and output.find(b"WJ>_ ", stty_output_start) >= 0:
                process.stdin.write(interactive_guest_commands())
                process.stdin.flush()
                commands_sent = True
            if process.poll() is not None:
                while True:
                    block = os.read(process.stdout.fileno(), 65536)
                    if not block:
                        break
                    output.extend(block)
                break
        if timed_out:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        return_code = process.wait(timeout=30)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    log_text = output.decode("utf-8", errors="replace").replace("\r", "")
    failures: list[str] = []
    if timed_out:
        failures.append("timeout")
    if return_code != 0:
        failures.append(f"qemu-exit-{return_code}")
    if not commands_sent:
        failures.append("console-prompt-not-reached")
    for required in (
        PASS_MARKER,
        APK_SHA256_PASS_MARKER,
        BOOT_MEDIA_MARKER + host_sha256,
        RUNTIME_JSON_BEGIN,
        RUNTIME_JSON_END,
        "NOETHER_FORGE_HOST_UID=1000",
        "NOETHER_FORGE_HOST_USER=wj",
        HOME_PASS_MARKER,
        "wuci-ji selftest: PASS",
        "wuci-ji asm-regression: PASS",
        "table inet wuci_noether",
        LOW_UID_MARKER,
        DOAS_DENY_PASS_MARKER,
        HOST_PASS_MARKER,
        SHUTDOWN_MARKER,
    ):
        if required not in log_text:
            failures.append(f"missing-marker:{required}")
    if "NOETHER_FORGE_RUNTIME_FAIL" in log_text:
        failures.append("guest-runtime-contract-failed")
    for denied in DENIED_BOOT_LOG_FRAGMENTS:
        if denied in log_text:
            failures.append(f"denied-boot-log-fragment:{denied}")
    runtime_report: dict[str, Any] = {}
    if RUNTIME_JSON_BEGIN in log_text and RUNTIME_JSON_END in log_text:
        runtime_report = extract_runtime_json(log_text)
        if runtime_report.get("schema") != RUNTIME_SCHEMA or runtime_report.get("status") != "pass":
            failures.append("runtime-json-not-pass")
        runtime_media = runtime_report.get("inventory", {}).get("boot_media", {}).get("sha256")
        if runtime_media != host_sha256:
            failures.append("runtime-boot-media-digest-mismatch")
        failed_checks = [item.get("id") for item in runtime_report.get("checks", []) if item.get("status") != "pass"]
        if failed_checks:
            failures.append(f"runtime-failed-checks:{','.join(str(item) for item in failed_checks)}")

    firmware_record: dict[str, Any] | None = None
    if firmware is not None:
        firmware_record = {"filename": firmware.name, "size": firmware.stat().st_size, "sha256": digest_file(firmware)}
    evidence = {
        "schema": "wucios.noether_forge.boot_trace.v1",
        "status": "pass" if not failures else "fail",
        "firmware_mode": firmware_mode,
        "artifact": {"filename": iso.name, "size": iso.stat().st_size, "sha256": host_sha256},
        "firmware": firmware_record,
        "qemu": {
            "version": tool_version("qemu-system-x86_64", "--version"),
            "argv": sanitize_qemu_argv(argv, iso, firmware),
            "acceleration": "tcg",
            "network_device": "none",
            "exit_code": return_code,
        },
        "markers": {
            "runtime_pass": PASS_MARKER in log_text,
            "apk_sha256_pass": APK_SHA256_PASS_MARKER in log_text,
            "boot_media_sha256": host_sha256 if BOOT_MEDIA_MARKER + host_sha256 in log_text else None,
            "interactive_pass": HOST_PASS_MARKER in log_text,
            "home_writable": HOME_PASS_MARKER in log_text,
            "low_privilege_uid": LOW_UID_MARKER in log_text,
            "arbitrary_root_denied": DOAS_DENY_PASS_MARKER in log_text,
            "shutdown_requested": SHUTDOWN_MARKER in log_text,
        },
        "runtime_report_sha256": hashlib.sha256(canonical_json(runtime_report)).hexdigest() if runtime_report else None,
        "serial_log_sha256": hashlib.sha256(output).hexdigest(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "failures": failures,
    }
    if failures:
        tail = log_text[-12000:]
        raise NoetherForgeError(f"{firmware_mode} QEMU boot failed: {failures}\n--- serial tail ---\n{tail}")
    return evidence, runtime_report, bytes(output)


def verify_file_binding(path: Path, binding: dict[str, Any], label: str) -> None:
    info = ensure_regular(path, label)
    if binding.get("size") != info.st_size or binding.get("sha256") != digest_file(path):
        raise NoetherForgeError(f"{label} size or SHA-256 binding mismatch")


def verify_evidence_index(release_dir: Path, evidence_dir: Path, artifact_sha256: str) -> str | None:
    index_path = evidence_dir / "evidence-index.json"
    hash_manifest = release_dir / "hash-manifest.sha256"
    final_claims = (
        release_dir / "INTERNAL-READINESS.md",
        evidence_dir / "internal-readiness.json",
        evidence_dir / "review.json",
    )
    if not (index_path.exists() or index_path.is_symlink()) and not (hash_manifest.exists() or hash_manifest.is_symlink()):
        if any(path.exists() or path.is_symlink() for path in final_claims):
            raise NoetherForgeError("readiness claims exist without a finalized evidence index and hash manifest")
        return None
    if not (index_path.exists() or index_path.is_symlink()) or not (hash_manifest.exists() or hash_manifest.is_symlink()):
        raise NoetherForgeError("final evidence index and hash manifest must exist together")
    ensure_regular(index_path, "final evidence index")
    index = load_json(index_path)
    if index.get("schema") != "wucios.noether_forge.evidence_index.v1" or index.get("status") != "pass" or index.get("artifact_sha256") != artifact_sha256:
        raise NoetherForgeError("final evidence index identity or artifact binding mismatch")
    listed: set[str] = set()
    for record in index.get("files", []):
        if not isinstance(record, dict):
            raise NoetherForgeError("evidence index entry must be an object")
        relative = validated_relative_posix(record.get("path"), "evidence index path")
        if len(relative.parts) != 2 or relative.parts[0] != "evidence" or relative.name == "evidence-index.json":
            raise NoetherForgeError(f"evidence index path is out of scope: {relative}")
        name = relative.name
        if name in listed:
            raise NoetherForgeError(f"duplicate evidence index path: {name}")
        listed.add(name)
        verify_file_binding(evidence_dir / name, record, f"indexed evidence {name}")
    entries = list(evidence_dir.iterdir())
    unexpected = [path.name for path in entries if path.name != "evidence-index.json" and not path.is_file()]
    if unexpected:
        raise NoetherForgeError(f"non-file entries in evidence directory: {sorted(unexpected)}")
    actual = {path.name for path in entries if path.is_file() and path.name != "evidence-index.json"}
    if listed != actual:
        raise NoetherForgeError(f"evidence index coverage mismatch: listed={sorted(listed)} actual={sorted(actual)}")
    return digest_file(index_path)


def verify_release_hash_manifest(release_dir: Path, evidence_index_sha256: str | None) -> None:
    path = release_dir / "hash-manifest.sha256"
    if evidence_index_sha256 is None:
        if path.exists():
            raise NoetherForgeError("hash manifest exists without a bound evidence index")
        return
    ensure_regular(path, "release hash manifest")
    records: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if "  " not in line:
            raise NoetherForgeError("malformed release hash-manifest line")
        digest, name = line.split("  ", 1)
        relative = validated_relative_posix(name, "release hash-manifest path")
        if name in records or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise NoetherForgeError("duplicate path or malformed digest in release hash manifest")
        records[name] = digest
        candidate = release_dir / Path(*relative.parts)
        ensure_no_symlink_parents(candidate, release_dir, "release hash-manifest target")
        ensure_regular(candidate, "release hash-manifest target")
        if digest_file(candidate) != digest:
            raise NoetherForgeError(f"release hash-manifest mismatch: {name}")
    expected = {
        path.name for path in release_dir.iterdir()
        if path.is_file() and path.name != "hash-manifest.sha256"
    }
    expected.add("evidence/evidence-index.json")
    if set(records) != expected:
        raise NoetherForgeError(f"release hash-manifest coverage mismatch: listed={sorted(records)} expected={sorted(expected)}")
    if records["evidence/evidence-index.json"] != evidence_index_sha256:
        raise NoetherForgeError("release hash manifest does not bind the evidence index")


def verify_existing_artifact(output: Path) -> tuple[dict[str, Any], Path, Path]:
    release, _, _ = validate_configuration()
    release_dir, evidence_dir, iso = release_paths(output, release)
    ensure_regular(iso, "Noether Forge release ISO")
    manifest = load_json(release_dir / "manifest.json")
    if manifest.get("schema") != "wucios.noether_forge.artifact_manifest.v1":
        raise NoetherForgeError("artifact manifest schema mismatch")
    artifact = manifest.get("artifact", {})
    observed = digest_vector(iso)
    if artifact.get("size") != iso.stat().st_size or any(artifact.get(name) != value for name, value in observed.items()):
        raise NoetherForgeError("artifact manifest is stale or does not bind the ISO")
    for algorithm, value in observed.items():
        sidecar = iso.with_name(iso.name + f".{algorithm}")
        ensure_regular(sidecar, f"ISO {algorithm} sidecar")
        if sidecar.read_text(encoding="ascii").strip() != f"{value}  {iso.name}":
            raise NoetherForgeError(f"ISO {algorithm} sidecar mismatch")
    for key in ("sbom", "provenance"):
        binding = manifest.get(key, {})
        filename = validated_basename(binding.get("filename"), f"manifest {key} filename")
        verify_file_binding(release_dir / filename, binding, f"manifest-bound {key}")
    build_evidence = manifest.get("build_evidence")
    if not isinstance(build_evidence, dict) or not build_evidence:
        raise NoetherForgeError("artifact manifest does not bind core build evidence")
    for name, binding in build_evidence.items():
        validated_basename(name, "build evidence key")
        if not isinstance(binding, dict) or binding.get("path") != f"evidence/{name}":
            raise NoetherForgeError(f"invalid build evidence binding: {name}")
        verify_file_binding(evidence_dir / name, binding, f"manifest-bound build evidence {name}")
    source_evidence = load_json(evidence_dir / "source-manifest.json")
    if manifest.get("source_manifest_sha256") != hashlib.sha256(canonical_json(source_evidence)).hexdigest():
        raise NoetherForgeError("source manifest digest does not match the artifact manifest")
    if manifest.get("package_lock_sha256") != digest_file(RELEASE_ROOT / "package-lock.json"):
        raise NoetherForgeError("tracked package lock drifted from the built artifact")
    if canonical_json(source_evidence) != canonical_json(source_manifest()):
        raise NoetherForgeError("current ISO source closure drifted from the built artifact")
    sbom = load_json(release_dir / manifest["sbom"]["filename"])
    validate_spdx_sbom(sbom, load_json(RELEASE_ROOT / "package-lock.json"), source_evidence)
    provenance = load_json(release_dir / manifest["provenance"]["filename"])
    if provenance.get("artifact") != artifact or provenance.get("source", {}).get("payload_sha256") != source_evidence.get("source_payload_sha256"):
        raise NoetherForgeError("provenance does not bind the artifact and source closure")
    reproducibility = load_json(evidence_dir / "reproducibility.json")
    if (
        reproducibility.get("status") != "pass"
        or reproducibility.get("byte_identical") is not True
        or reproducibility.get("independent_wuci_ji_rebuilds") is not True
        or reproducibility.get("source_manifests_identical") is not True
        or reproducibility.get("sha256") != observed["sha256"]
        or reproducibility.get("build_a", {}).get("sha256") != observed["sha256"]
        or reproducibility.get("build_b", {}).get("sha256") != observed["sha256"]
    ):
        raise NoetherForgeError("repeat-build evidence does not bind the ISO")
    index_sha256 = verify_evidence_index(release_dir, evidence_dir, observed["sha256"])
    verify_release_hash_manifest(release_dir, index_sha256)
    inspect_work = output / "inspect-existing"
    safe_reset_directory(inspect_work, output)
    layout, privacy, links = inspect_iso(iso, inspect_work)
    for name, value in (
        ("iso-layout.json", layout),
        ("privacy-audit.json", privacy),
        ("link-audit.json", links),
    ):
        path = evidence_dir / name
        ensure_regular(path, f"fresh {name}")
        if path.read_bytes() != canonical_json(value):
            raise NoetherForgeError(f"fresh ISO inspection disagrees with manifest-bound evidence: {name}")
    return manifest, evidence_dir, iso


def command_inspect(args: argparse.Namespace) -> int:
    manifest, evidence_dir, iso = verify_existing_artifact(Path(args.output))
    print(json.dumps({
        "status": "pass",
        "artifact": manifest["artifact"],
        "iso_layout": load_json(evidence_dir / "iso-layout.json"),
        "privacy": load_json(evidence_dir / "privacy-audit.json")["status"],
        "links": load_json(evidence_dir / "link-audit.json")["status"],
    }, indent=2, sort_keys=True))
    return 0


def invalidate_final_evidence(release_dir: Path, evidence_dir: Path) -> None:
    top_level = ("hash-manifest.sha256", "INTERNAL-READINESS.md")
    derived_evidence = (
        "evidence-index.json",
        "boot-bios.log", "boot-bios.json", "boot-bios-runtime.json",
        "boot-uefi.log", "boot-uefi.json", "boot-uefi-runtime.json",
        "runtime-contract.json", "package-manifest.txt", "enabled-services.txt",
        "listening-ports.txt", "suid-sgid.txt", "kernel-modules.txt",
        "daylight-wucios-score.json", "surface-report.json", "surface-report.md",
        "godel-boundary.md", "internal-readiness.json", "review.json", "review.md",
    )
    for path in [*(release_dir / name for name in top_level), *(evidence_dir / name for name in derived_evidence)]:
        if path.exists() or path.is_symlink():
            ensure_regular(path, "stale derived release evidence")
            path.unlink()


def run_boot_modes(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], Path, Path]:
    output = Path(args.output)
    _, evidence_dir, iso = verify_existing_artifact(output)
    invalidate_final_evidence(iso.parent, evidence_dir)
    modes = [args.firmware] if args.firmware != "all" else ["bios", "uefi"]
    firmware = Path(args.ovmf) if "uefi" in modes else None
    reports: dict[str, dict[str, Any]] = {}
    runtimes: dict[str, dict[str, Any]] = {}
    for mode in modes:
        print(f"boot {mode}: {iso.name}", flush=True)
        boot_evidence, runtime_report, log = run_qemu_boot(
            iso,
            mode,
            firmware if mode == "uefi" else None,
            timeout_seconds=args.boot_timeout,
        )
        reports[mode] = boot_evidence
        runtimes[mode] = runtime_report
        atomic_write(evidence_dir / f"boot-{mode}.log", log)
        write_json(evidence_dir / f"boot-{mode}.json", boot_evidence)
        write_json(evidence_dir / f"boot-{mode}-runtime.json", runtime_report)
    if set(modes) == {"bios", "uefi"}:
        bios_packages = [(item["name"], item["version"]) for item in runtimes["bios"]["inventory"]["packages"]]
        uefi_packages = [(item["name"], item["version"]) for item in runtimes["uefi"]["inventory"]["packages"]]
        if bios_packages != uefi_packages:
            raise NoetherForgeError("BIOS and UEFI runtime package inventories differ")
        if reports["bios"]["artifact"] != reports["uefi"]["artifact"]:
            raise NoetherForgeError("BIOS and UEFI boot evidence does not bind the same ISO")
    return reports, runtimes, evidence_dir, iso


def command_boot(args: argparse.Namespace) -> int:
    reports, _, _, _ = run_boot_modes(args)
    print(json.dumps({"status": "pass", "boot": reports}, indent=2, sort_keys=True))
    return 0


def command_launch(args: argparse.Namespace) -> int:
    _, _, iso = verify_existing_artifact(Path(args.output))
    firmware = Path(args.ovmf) if args.firmware == "uefi" else None
    argv = qemu_argv(iso, args.firmware, firmware)
    print(
        f"Launching {iso.name} in {args.firmware.upper()} mode with no virtual network device. "
        "Run wuci-poweroff inside the guest for a clean exit.",
        flush=True,
    )
    os.execv(argv[0], argv)
    raise AssertionError("os.execv returned")


def write_required_runtime_evidence(evidence_dir: Path, runtime: dict[str, Any]) -> None:
    inventory = runtime["inventory"]
    packages = inventory["packages"]
    atomic_write(
        evidence_dir / "package-manifest.txt",
        ("\n".join(f"{item['name']}={item['version']}" for item in packages) + "\n").encode("utf-8"),
    )
    service_lines = [f"{runlevel}: {service}" for runlevel, services in sorted(inventory["runlevels"].items()) for service in services]
    atomic_write(evidence_dir / "enabled-services.txt", ("\n".join(service_lines) + "\n").encode("utf-8"))
    listener_lines = [f"{item['protocol']} {item['address_hex']}:{item['port']} state={item['state']}" for item in inventory["listeners"]]
    atomic_write(evidence_dir / "listening-ports.txt", (("\n".join(listener_lines) if listener_lines else "NONE") + "\n").encode("utf-8"))
    privilege_lines = [f"{item['path']} mode={item['mode']} uid={item['uid']} gid={item['gid']}" for item in inventory["privileged_files"]]
    atomic_write(evidence_dir / "suid-sgid.txt", ("\n".join(privilege_lines) + "\n").encode("utf-8"))
    atomic_write(evidence_dir / "kernel-modules.txt", ("\n".join(inventory["kernel_modules"]) + "\n").encode("utf-8"))


def readiness_outputs(
    output: Path,
    boot_reports: dict[str, dict[str, Any]],
    runtimes: dict[str, dict[str, Any]],
    evidence_dir: Path,
    iso: Path,
) -> dict[str, Any]:
    release = load_json(RELEASE_ROOT / "release.json")
    manifest, verified_evidence_dir, verified_iso = verify_existing_artifact(output)
    if verified_evidence_dir != evidence_dir or verified_iso != iso:
        raise NoetherForgeError("post-boot artifact verification resolved a different release packet")
    verified_sha256 = digest_file(verified_iso)
    if any(report.get("artifact", {}).get("sha256") != verified_sha256 for report in boot_reports.values()):
        raise NoetherForgeError("post-boot source/artifact verification disagrees with boot evidence")
    input_verification = load_json(evidence_dir / "input-verification.json")
    reproducibility = load_json(evidence_dir / "reproducibility.json")
    privacy = load_json(evidence_dir / "privacy-audit.json")
    links = load_json(evidence_dir / "link-audit.json")
    required_modes = {"bios", "uefi"}
    if set(boot_reports) != required_modes:
        raise NoetherForgeError("internal readiness requires fresh BIOS and UEFI boot evidence")
    canonical_runtime = runtimes["bios"]
    write_json(evidence_dir / "runtime-contract.json", canonical_runtime)
    write_required_runtime_evidence(evidence_dir, canonical_runtime)

    local_gates = {
        "authenticated_alpine_input": input_verification.get("status") == "pass",
        "signed_offline_apk_closure": input_verification.get("apk", {}).get("rootless_offline_closure_install") == "pass",
        "repeat_build_byte_identical": reproducibility.get("status") == "pass" and reproducibility.get("byte_identical") is True,
        "iso_layout_bios_uefi": load_json(evidence_dir / "iso-layout.json").get("status") == "pass",
        "privacy_audit": privacy.get("status") == "pass",
        "link_audit": links.get("status") == "pass",
        "bios_exact_iso_boot": boot_reports["bios"].get("status") == "pass",
        "uefi_exact_iso_boot": boot_reports["uefi"].get("status") == "pass",
        "runtime_contract": canonical_runtime.get("status") == "pass",
        "exact_runtime_package_closure": any(
            item.get("id") == "exact-installed-package-closure" and item.get("status") == "pass"
            for item in canonical_runtime.get("checks", [])
        ),
        "openrc_service_health": any(
            item.get("id") == "openrc-failed-services" and item.get("status") == "pass"
            for item in canonical_runtime.get("checks", [])
        ),
        "zero_listening_ports": canonical_runtime.get("inventory", {}).get("listeners") == [],
        "default_drop_firewall": any(item.get("id") == "nftables-default-drop" and item.get("status") == "pass" for item in canonical_runtime.get("checks", [])),
    }
    local_blockers = sorted(name for name, passed in local_gates.items() if not passed)
    passed_count = sum(1 for passed in local_gates.values() if passed)
    score_value = round(100.0 * passed_count / len(local_gates), 1)
    score = {
        "schema": "wucios.noether_forge.daylight_score.v1",
        "status": "INTERNAL_DIAGNOSTIC_ONLY",
        "artifact_sha256": digest_file(iso),
        "score_value": score_value,
        "calculation": f"{passed_count} passing local gates / {len(local_gates)} measured local gates * 100",
        "gates": local_gates,
        "external_validation": False,
        "production_authority": False,
    }
    write_json(evidence_dir / "daylight-wucios-score.json", score)

    surface = {
        "schema": "wucios.noether_forge.surface_report.v1",
        "status": "pass" if not local_blockers else "fail",
        "artifact_sha256": digest_file(iso),
        "kernel": canonical_runtime["inventory"]["kernel"],
        "package_count": canonical_runtime["inventory"]["package_count"],
        "enabled_services": canonical_runtime["inventory"]["runlevels"],
        "listening_ports": canonical_runtime["inventory"]["listeners"],
        "interfaces": canonical_runtime["inventory"]["interfaces"],
        "default_routes": canonical_runtime["inventory"]["default_routes"],
        "privileged_files": canonical_runtime["inventory"]["privileged_files"],
        "denied_commands_present": canonical_runtime["inventory"]["denied_commands_present"],
        "runtime_checks": canonical_runtime["checks"],
        "non_claims": release["non_claims"],
    }
    write_json(evidence_dir / "surface-report.json", surface)
    surface_md = (
        "# Noether Forge surface report\n\n"
        f"- Status: `{surface['status']}`\n"
        f"- Artifact SHA-256: `{surface['artifact_sha256']}`\n"
        f"- Kernel: `{surface['kernel']}`\n"
        f"- Installed packages: `{surface['package_count']}`\n"
        f"- Listening ports: `{len(surface['listening_ports'])}`\n"
        f"- Default routes: `{len(surface['default_routes'])}`\n"
        f"- Privileged files: `{len(surface['privileged_files'])}` (allowlisted doas only)\n\n"
        "The measured nftables policy is not a general runtime sandbox claim.\n"
    )
    atomic_write(evidence_dir / "surface-report.md", surface_md.encode("utf-8"))
    atomic_write(
        evidence_dir / "godel-boundary.md",
        (
            "# Noether Forge non-claim boundary\n\n"
            + "\n".join(f"- {item}" for item in release["non_claims"])
            + "\n"
        ).encode("utf-8"),
    )

    readiness = {
        "schema": "wucios.noether_forge.internal_readiness.v1",
        "status": "ready" if not local_blockers else "blocked",
        "release": {"product": release["product"], "version": release["version"], "codename": release["codename"]},
        "artifact": manifest["artifact"],
        "profile": release["profile"],
        "substrate": release["substrate"],
        "local_gates": local_gates,
        "local_blockers": local_blockers,
        "internal_release_candidate_ready": not local_blockers,
        "public_release_authorized": False,
        "publication_holds": release["publication_holds"],
        "tag_created": False,
        "published": False,
        "non_claims": release["non_claims"],
    }
    write_json(evidence_dir / "internal-readiness.json", readiness)
    readiness_md = (
        "# WuciOS 2.4.0 - Noether Forge internal readiness\n\n"
        f"Internal candidate status: **{readiness['status'].upper()}**\n\n"
        f"Artifact: `{manifest['artifact']['filename']}`  \n"
        f"SHA-256: `{manifest['artifact']['sha256']}`  \n"
        f"Size: `{manifest['artifact']['size']}` bytes\n\n"
        "## Local gates\n\n"
        + "\n".join(f"- {'PASS' if passed else 'FAIL'}: `{name}`" for name, passed in local_gates.items())
        + "\n\n## Publication holds\n\n"
        + "\n".join(f"- {item}" for item in release["publication_holds"])
        + "\n\nNo tag, production signature, witness append, or publication was performed.\n"
    )
    atomic_write(output / "release/INTERNAL-READINESS.md", readiness_md.encode("utf-8"))

    review = {
        "schema": "wucios.noether_forge.review.v1",
        "status": "pass" if not local_blockers else "fail",
        "artifact": manifest["artifact"],
        "local_gates": local_gates,
        "local_blockers": local_blockers,
        "score": score,
        "bios": boot_reports["bios"],
        "uefi": boot_reports["uefi"],
        "publication_holds": release["publication_holds"],
        "non_claims": release["non_claims"],
    }
    write_json(evidence_dir / "review.json", review)
    atomic_write(
        evidence_dir / "review.md",
        (
            "# Noether Forge review\n\n"
            f"Local review: **{'PASS' if not local_blockers else 'FAIL'}**  \n"
            f"Diagnostic local-gate score: `{score_value}` bound to `{digest_file(iso)}`.\n\n"
            "The score covers the listed local gates only and is not external validation or production authority.\n"
        ).encode("utf-8"),
    )

    raw_release_bytes = b"".join(
        path.read_bytes()
        for path in sorted((output / "release").rglob("*"))
        if path.is_file() and path.stat().st_size < 8 * 1024 * 1024
    )
    leaked = [
        pattern_name
        for pattern, pattern_name in privacy_patterns()
        if pattern_name.startswith("workstation-") and pattern.lower() in raw_release_bytes.lower()
    ]
    if leaked:
        invalidate_final_evidence(output / "release", evidence_dir)
        raise NoetherForgeError(f"generated release evidence leaked workstation identity: {leaked}")
    if local_blockers:
        raise NoetherForgeError(f"internal readiness has local blockers: {local_blockers}")

    evidence_files: list[dict[str, Any]] = []
    for path in sorted(evidence_dir.iterdir(), key=lambda item: item.name):
        if path.name == "evidence-index.json":
            continue
        ensure_regular(path, "release evidence")
        evidence_files.append({"path": f"evidence/{path.name}", "size": path.stat().st_size, "sha256": digest_file(path)})
    evidence_index = {
        "schema": "wucios.noether_forge.evidence_index.v1",
        "artifact_sha256": digest_file(iso),
        "status": "pass" if not local_blockers else "fail",
        "files": evidence_files,
    }
    write_json(evidence_dir / "evidence-index.json", evidence_index)

    hash_lines: list[str] = []
    for path in sorted((output / "release").iterdir(), key=lambda item: item.name):
        if path.is_file() and path.name != "hash-manifest.sha256":
            ensure_regular(path, "top-level release file")
            hash_lines.append(f"{digest_file(path)}  {path.name}")
    hash_lines.append(f"{digest_file(evidence_dir / 'evidence-index.json')}  evidence/evidence-index.json")
    hash_lines.sort(key=lambda line: line.split("  ", 1)[1])
    atomic_write(output / "release/hash-manifest.sha256", ("\n".join(hash_lines) + "\n").encode("ascii"))
    index_sha256 = verify_evidence_index(output / "release", evidence_dir, digest_file(iso))
    verify_release_hash_manifest(output / "release", index_sha256)

    return readiness


def command_internal(args: argparse.Namespace) -> int:
    if args.firmware != "all":
        raise NoetherForgeError("internal readiness requires --firmware all")
    reports, runtimes, evidence_dir, iso = run_boot_modes(args)
    readiness = readiness_outputs(Path(args.output), reports, runtimes, evidence_dir, iso)
    print(json.dumps(readiness, indent=2, sort_keys=True))
    return 0


def add_common_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--cache", default=str(DEFAULT_CACHE), help="verified Alpine input cache")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="generated release root")
    parser.add_argument("--temp-dir", default="/tmp", help="temporary directory parent")


def add_boot_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--firmware", choices=("bios", "uefi", "all"), default="all")
    parser.add_argument("--ovmf", default="/usr/share/edk2/ovmf/OVMF.stateless.fd")
    parser.add_argument("--boot-timeout", type=int, default=480)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch = subparsers.add_parser("fetch", help="download only the exact locked Alpine inputs")
    add_common_paths(fetch)
    fetch.set_defaults(func=command_fetch)

    verify_inputs_parser = subparsers.add_parser("verify-inputs", help="authenticate the cached ISO and signed APK closure")
    add_common_paths(verify_inputs_parser)
    verify_inputs_parser.set_defaults(func=command_verify_inputs)

    build = subparsers.add_parser("build", help="perform two offline builds and promote only byte-identical ISO bytes")
    add_common_paths(build)
    build.set_defaults(func=command_build)

    inspect = subparsers.add_parser("inspect", help="reinspect the exact release ISO, privacy, links, and boot layout")
    add_common_paths(inspect)
    inspect.set_defaults(func=command_inspect)

    boot = subparsers.add_parser("boot", help="boot the exact release ISO in BIOS and/or UEFI QEMU")
    add_common_paths(boot)
    add_boot_options(boot)
    boot.set_defaults(func=command_boot)

    launch = subparsers.add_parser("launch", help="open an interactive terminal session on the built live ISO")
    add_common_paths(launch)
    launch.add_argument("--firmware", choices=("bios", "uefi"), default="bios")
    launch.add_argument("--ovmf", default="/usr/share/edk2/ovmf/OVMF.stateless.fd")
    launch.set_defaults(func=command_launch)

    internal = subparsers.add_parser("internal", help="run all boot gates and emit the internal readiness packet")
    add_common_paths(internal)
    add_boot_options(internal)
    internal.set_defaults(func=command_internal)
    return parser


def resolve_cli_paths(args: argparse.Namespace) -> argparse.Namespace:
    for name in ("cache", "output", "temp_dir", "ovmf"):
        if hasattr(args, name):
            setattr(args, name, str(Path(getattr(args, name)).expanduser().resolve()))
    return args


def run_with_release_lock(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    lock_path = output / ".noether-forge.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise NoetherForgeError("release pipeline lock must be a single-link regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NoetherForgeError(f"another Noether Forge pipeline command holds {lock_path}") from exc
        return args.func(args)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def main(argv: Sequence[str] | None = None) -> int:
    args = resolve_cli_paths(build_parser().parse_args(argv))
    try:
        return run_with_release_lock(args)
    except (NoetherForgeError, OSError, subprocess.SubprocessError, urllib.error.URLError) as exc:
        print(f"noether-forge: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
