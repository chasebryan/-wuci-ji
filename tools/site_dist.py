#!/usr/bin/env python3
"""Build the exact bounded Cloudflare Pages upload tree for No Such Machine."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "site"
OUTPUT_ROOT = REPOSITORY_ROOT / "build" / "site-dist"
INVENTORY_NAME = "site-inventory.json"
INVENTORY_SCHEMA = "wuci-site-dist-inventory-v1"
CONFIG_FILES = ("_headers", "_redirects")
EXCLUDED_SOURCE_FILES = (
    "daylight-grok-audit.html",
    "security.txt",
    "validate.mjs",
)
NOT_FOUND_PROBE_PATH = "/.well-known/wuci-site-integrity-not-found-7f36c09e"

MAX_SITE_FILES = 96
MAX_SITE_FILE_BYTES = 4 * 1024 * 1024
MAX_SITE_TOTAL_BYTES = 40 * 1024 * 1024
MAX_SITE_REDIRECTS = 32

CANONICAL_ABSOLUTE_REDIRECT_SOURCES = {
    "http://nosuchmachine.net/*",
    "http://www.nosuchmachine.net/*",
    "https://www.nosuchmachine.net/*",
}
CANONICAL_ABSOLUTE_REDIRECT_TARGET = "https://nosuchmachine.net/:splat"

SAFE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
MEDIA_TYPES = {
    ".cff": "text/plain",
    ".css": "text/css",
    ".html": "text/html",
    ".jpeg": "image/jpeg",
    ".jpg": "image/jpeg",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain",
    ".webmanifest": "application/manifest+json",
    ".webp": "image/webp",
    ".xml": "application/xml",
}
PATH_MEDIA_TYPES = {"codemeta.json": "application/ld+json"}


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def valid_relative_path(path: str) -> bool:
    return (
        bool(path)
        and bool(SAFE_PATH_PATTERN.fullmatch(path))
        and not path.startswith("/")
        and not path.endswith("/")
        and ".." not in path
        and "//" not in path
        and "\\" not in path
    )


STABLE_METADATA_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(metadata, field) for field in STABLE_METADATA_FIELDS)


def ensure_no_symlink_ancestors(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"path ancestor must not be a symlink: {current}")


def stable_read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    if max_bytes < 0:
        raise ValueError("regular-file read budget must be nonnegative")
    try:
        ensure_no_symlink_ancestors(path.parent)
        before_path = path.lstat()
        if (
            stat.S_ISLNK(before_path.st_mode)
            or not stat.S_ISREG(before_path.st_mode)
            or before_path.st_nlink != 1
        ):
            raise ValueError(f"entry must be a single-link regular file: {path}")
        if before_path.st_size > max_bytes:
            raise ValueError(f"entry exceeds {max_bytes} bytes: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"entry could not be opened safely: {path}") from error
    try:
        before_fd = os.fstat(descriptor)
        if metadata_signature(before_path) != metadata_signature(before_fd):
            raise ValueError(f"entry changed before the bounded read: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(max_bytes + 1)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        ensure_no_symlink_ancestors(path.parent)
        signatures = {
            metadata_signature(before_path),
            metadata_signature(before_fd),
            metadata_signature(after_fd),
            metadata_signature(after_path),
        }
        if len(signatures) != 1 or len(content) != after_fd.st_size:
            raise ValueError(f"entry changed during the bounded read: {path}")
        if len(content) > max_bytes:
            raise ValueError(f"entry exceeds {max_bytes} bytes: {path}")
        return content
    except OSError as error:
        raise ValueError(f"entry changed during the bounded read: {path}") from error
    finally:
        os.close(descriptor)


def collect_regular_tree(
    root: Path,
    *,
    max_files: int = MAX_SITE_FILES,
    max_file_bytes: int = MAX_SITE_FILE_BYTES,
    max_total_bytes: int = MAX_SITE_TOTAL_BYTES,
) -> dict[str, bytes]:
    ensure_no_symlink_ancestors(root.parent)
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ValueError(f"site tree root must be a real directory: {root}") from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError(f"site tree root must be a real directory: {root}")

    files: dict[str, bytes] = {}
    total_bytes = 0

    def visit(directory: Path) -> None:
        nonlocal total_bytes
        before_directory = directory.lstat()
        if stat.S_ISLNK(before_directory.st_mode) or not stat.S_ISDIR(before_directory.st_mode):
            raise ValueError(f"site tree directory changed: {directory}")
        try:
            entries = sorted(directory.iterdir(), key=lambda candidate: candidate.name)
        except OSError as error:
            raise ValueError(f"site tree directory could not be read: {directory}") from error
        for path in entries:
            try:
                metadata = path.lstat()
            except OSError as error:
                raise ValueError(f"site tree entry changed: {path}") from error
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"site tree entry must not be a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                visit(path)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError(
                    f"site tree entry must be a single-link regular file: {relative}"
                )
            if not valid_relative_path(relative):
                raise ValueError(f"site tree entry has an unsafe path: {relative}")
            if len(files) >= max_files:
                raise ValueError(f"site tree exceeds the {max_files}-file budget")
            content = stable_read_regular_file(path, max_bytes=max_file_bytes)
            total_bytes += len(content)
            if total_bytes > max_total_bytes:
                raise ValueError(
                    f"site tree exceeds the {max_total_bytes}-byte aggregate budget"
                )
            files[relative] = content
        after_directory = directory.lstat()
        if metadata_signature(before_directory) != metadata_signature(after_directory):
            raise ValueError(f"site tree directory changed during traversal: {directory}")

    visit(root)
    after_root = root.lstat()
    if metadata_signature(root_metadata) != metadata_signature(after_root):
        raise ValueError(f"site tree root changed during traversal: {root}")
    ensure_no_symlink_ancestors(root.parent)
    return files


def media_type_for_path(path: str) -> str:
    media_type = PATH_MEDIA_TYPES.get(path, MEDIA_TYPES.get(Path(path).suffix.lower()))
    if media_type is None:
        raise ValueError(f"site public file has no explicit safe MIME contract: {path}")
    return media_type


def public_url_and_status(path: str) -> tuple[str, int]:
    if path == "404.html":
        return NOT_FOUND_PROBE_PATH, 404
    if path == "index.html":
        return "/", 200
    if path.endswith("/index.html"):
        return f"/{path.removesuffix('index.html')}", 200
    if path.endswith(".html"):
        return f"/{path.removesuffix('.html')}", 200
    return f"/{path}", 200


def redirect_shadowed_files(
    redirects: bytes,
    source_paths: set[str],
) -> set[str]:
    try:
        text = redirects.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("site/_redirects must be UTF-8") from error
    shadowed: set[str] = set()
    absolute_sources: set[str] = set()
    rule_count = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or parts[2] not in {"301", "302", "307", "308"}:
            raise ValueError(f"invalid site/_redirects line {line_number}")
        rule_count += 1
        if rule_count > MAX_SITE_REDIRECTS:
            raise ValueError("site/_redirects exceeds the fixed redirect-count budget")
        source, target, raw_status = parts
        if not source.startswith("/"):
            if (
                source not in CANONICAL_ABSOLUTE_REDIRECT_SOURCES
                or target != CANONICAL_ABSOLUTE_REDIRECT_TARGET
                or raw_status != "301"
            ):
                raise ValueError(
                    f"site/_redirects absolute wildcard line {line_number} is invalid"
                )
            absolute_sources.add(source)
            continue
        wildcard = "*" in source or ":" in source
        pattern = re.sub(r":[A-Za-z][A-Za-z0-9_]*", "*", source)
        for path in source_paths:
            if path in CONFIG_FILES or path == "validate.mjs":
                continue
            aliases = public_route_aliases(path)
            if (
                wildcard
                and any(fnmatch.fnmatchcase(alias, pattern) for alias in aliases)
            ) or (not wildcard and source in aliases):
                shadowed.add(path)
    if absolute_sources != CANONICAL_ABSOLUTE_REDIRECT_SOURCES:
        missing = sorted(CANONICAL_ABSOLUTE_REDIRECT_SOURCES - absolute_sources)
        raise ValueError(
            f"site/_redirects canonical wildcard set is not exact: missing={missing}"
        )
    return shadowed


def validate_relative_redirect_sources(redirects: bytes) -> None:
    text = redirects.decode("utf-8")
    safe = re.compile(r"^/[A-Za-z0-9._/-]+$")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        source = line.split()[0]
        if source.startswith(("http://", "https://")):
            continue
        if (
            not safe.fullmatch(source)
            or source.startswith("//")
            or source.endswith("/")
            or ".." in source
            or "*" in source
            or ":" in source
        ):
            raise ValueError(
                f"site/_redirects relative source line {line_number} is invalid"
            )


def public_route_aliases(path: str) -> set[str]:
    """Return clean and raw Pages routes that can be shadowed by _redirects."""
    raw = f"/{path}"
    aliases = {raw}
    if path.endswith(".html"):
        clean, _status = public_url_and_status(path)
        aliases.add(clean)
        if path.endswith("/index.html") and clean != "/":
            aliases.add(clean.rstrip("/"))
    return aliases


def file_record(path: str, content: bytes) -> dict[str, Any]:
    return {"path": path, "bytes": len(content), "sha256": sha256(content)}


def public_file_record(path: str, content: bytes) -> dict[str, Any]:
    url_path, status = public_url_and_status(path)
    return {
        **file_record(path, content),
        "urlPath": url_path,
        "status": status,
        "mediaType": media_type_for_path(path),
    }


def build_inventory(source_files: Mapping[str, bytes]) -> dict[str, Any]:
    source_paths = set(source_files)
    required = set(CONFIG_FILES) | set(EXCLUDED_SOURCE_FILES)
    missing = sorted(required - source_paths)
    if missing:
        raise ValueError(f"site source is missing required staged-tree inputs: {missing}")
    if INVENTORY_NAME in source_paths:
        raise ValueError(f"site/{INVENTORY_NAME} is reserved for generated output")

    shadowed = redirect_shadowed_files(source_files["_redirects"], source_paths)
    expected_shadowed = set(EXCLUDED_SOURCE_FILES) - {"validate.mjs"}
    if shadowed != expected_shadowed:
        raise ValueError(
            "redirect-shadowed site sources do not match the explicit exclusion set: "
            f"observed={sorted(shadowed)} expected={sorted(expected_shadowed)}"
        )
    validate_relative_redirect_sources(source_files["_redirects"])

    public_paths = sorted(source_paths - set(CONFIG_FILES) - set(EXCLUDED_SOURCE_FILES))
    public_files = [public_file_record(path, source_files[path]) for path in public_paths]
    config_files = [file_record(path, source_files[path]) for path in CONFIG_FILES]
    total_bytes = sum(record["bytes"] for record in public_files)
    return {
        "schema": INVENTORY_SCHEMA,
        "sourceRoot": "site",
        "excludedSourceFiles": list(EXCLUDED_SOURCE_FILES),
        "configFiles": config_files,
        "publicFiles": public_files,
        "publicFileCount": len(public_files),
        "publicBytes": total_bytes,
        "limits": {
            "maxFiles": MAX_SITE_FILES,
            "maxFileBytes": MAX_SITE_FILE_BYTES,
            "maxTotalBytes": MAX_SITE_TOTAL_BYTES,
        },
    }


def inventory_bytes(inventory: Mapping[str, Any]) -> bytes:
    return (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_inventory(
    inventory: Any,
    staged_files: Mapping[str, bytes],
) -> None:
    fields = {
        "schema",
        "sourceRoot",
        "excludedSourceFiles",
        "configFiles",
        "publicFiles",
        "publicFileCount",
        "publicBytes",
        "limits",
    }
    if not isinstance(inventory, dict) or set(inventory) != fields:
        raise ValueError("site inventory fields are not exact")
    if inventory.get("schema") != INVENTORY_SCHEMA or inventory.get("sourceRoot") != "site":
        raise ValueError("site inventory identity is invalid")
    if inventory.get("excludedSourceFiles") != list(EXCLUDED_SOURCE_FILES):
        raise ValueError("site inventory exclusion list is invalid")
    if inventory.get("limits") != {
        "maxFiles": MAX_SITE_FILES,
        "maxFileBytes": MAX_SITE_FILE_BYTES,
        "maxTotalBytes": MAX_SITE_TOTAL_BYTES,
    }:
        raise ValueError("site inventory limits are invalid")

    configs = inventory.get("configFiles")
    public = inventory.get("publicFiles")
    if not isinstance(configs, list) or not isinstance(public, list):
        raise ValueError("site inventory file lists are invalid")
    expected_paths = {INVENTORY_NAME}
    observed_records: list[dict[str, Any]] = []
    for record in configs:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise ValueError("site inventory config record is invalid")
        path = record.get("path")
        if path not in CONFIG_FILES or path in expected_paths:
            raise ValueError("site inventory config path is invalid or duplicated")
        content = staged_files.get(path)
        if content is None or record != file_record(path, content):
            raise ValueError(f"site inventory config bytes do not match: {path}")
        expected_paths.add(path)

    for record in public:
        expected_fields = {"path", "urlPath", "status", "mediaType", "bytes", "sha256"}
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise ValueError("site inventory public record is invalid")
        path = record.get("path")
        if not isinstance(path, str) or path in expected_paths or not valid_relative_path(path):
            raise ValueError("site inventory public path is invalid or duplicated")
        content = staged_files.get(path)
        if content is None or record != public_file_record(path, content):
            raise ValueError(f"site inventory public bytes or route do not match: {path}")
        expected_paths.add(path)
        observed_records.append(record)

    if set(staged_files) != expected_paths:
        missing = sorted(expected_paths - set(staged_files))
        extra = sorted(set(staged_files) - expected_paths)
        raise ValueError(f"site inventory tree mismatch: missing={missing} extra={extra}")
    if [record["path"] for record in public] != sorted(record["path"] for record in public):
        raise ValueError("site inventory public records are not sorted")
    if [record["path"] for record in configs] != list(CONFIG_FILES):
        raise ValueError("site inventory config records are not canonical")
    if inventory.get("publicFileCount") != len(observed_records):
        raise ValueError("site inventory public file count is invalid")
    if inventory.get("publicBytes") != sum(record["bytes"] for record in observed_records):
        raise ValueError("site inventory public byte total is invalid")
    if len(staged_files) > MAX_SITE_FILES:
        raise ValueError("staged site tree exceeds the file-count budget")
    if any(len(content) > MAX_SITE_FILE_BYTES for content in staged_files.values()):
        raise ValueError("staged site tree exceeds the per-file byte budget")
    if sum(len(content) for content in staged_files.values()) > MAX_SITE_TOTAL_BYTES:
        raise ValueError("staged site tree exceeds the aggregate byte budget")
    manifest = staged_files.get(INVENTORY_NAME)
    if manifest != inventory_bytes(inventory):
        raise ValueError("staged site inventory bytes are not canonical")


def build_site_dist(source: Path = SOURCE_ROOT, output: Path = OUTPUT_ROOT) -> dict[str, Any]:
    source_absolute = source.absolute()
    output_absolute = output.absolute()
    if (
        source_absolute == output_absolute
        or source_absolute in output_absolute.parents
        or output_absolute in source_absolute.parents
    ):
        raise ValueError("site source and output trees must not overlap")
    ensure_no_symlink_ancestors(source_absolute)
    ensure_no_symlink_ancestors(output_absolute.parent)
    source_files = collect_regular_tree(source)
    inventory = build_inventory(source_files)
    inventory_content = inventory_bytes(inventory)

    output_parent = output.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    ensure_no_symlink_ancestors(output_parent)
    output_parent_metadata = output_parent.lstat()
    if not stat.S_ISDIR(output_parent_metadata.st_mode):
        raise ValueError(f"site output parent must be a real directory: {output_parent}")
    temporary = Path(tempfile.mkdtemp(prefix=".site-dist-", dir=output_parent))
    output_parent_before = output_parent.lstat()
    try:
        staged_paths = (
            set(source_files) - set(EXCLUDED_SOURCE_FILES)
        ) | {INVENTORY_NAME}
        for relative in sorted(staged_paths):
            content = (
                inventory_content if relative == INVENTORY_NAME else source_files[relative]
            )
            destination = temporary / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)

        staged_files = collect_regular_tree(temporary)
        validate_inventory(inventory, staged_files)
        ensure_no_symlink_ancestors(output_parent)
        output_parent_after = output_parent.lstat()
        if metadata_signature(output_parent_before) != metadata_signature(output_parent_after):
            raise ValueError("site output parent changed during staging")
        if output.exists() or output.is_symlink():
            output_metadata = output.lstat()
            if stat.S_ISLNK(output_metadata.st_mode) or not stat.S_ISDIR(output_metadata.st_mode):
                raise ValueError(f"site output must be a real directory: {output}")
            shutil.rmtree(output)
        temporary.replace(output)
        ensure_no_symlink_ancestors(output)
        if not stat.S_ISDIR(output.lstat().st_mode):
            raise ValueError(f"site output must be a real directory: {output}")
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_ROOT)
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args(argv)
    try:
        inventory = build_site_dist(args.source, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"site-dist: {error}")
        return 1
    print(
        "site-dist: OK "
        f"({inventory['publicFileCount']} public files, "
        f"{inventory['publicBytes']} public bytes, output={args.output})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
