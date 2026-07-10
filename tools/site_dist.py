#!/usr/bin/env python3
"""Build the exact bounded Cloudflare Pages upload tree for No Such Machine."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
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


def collect_regular_tree(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"site tree root must be a real directory: {root}")

    files: dict[str, bytes] = {}

    def visit(directory: Path) -> None:
        for path in sorted(directory.iterdir(), key=lambda candidate: candidate.name):
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ValueError(f"site tree entry must not be a symlink: {relative}")
            if path.is_dir():
                visit(path)
                continue
            if not path.is_file() or metadata.st_nlink != 1:
                raise ValueError(
                    f"site tree entry must be a single-link regular file: {relative}"
                )
            if not valid_relative_path(relative):
                raise ValueError(f"site tree entry has an unsafe path: {relative}")
            if metadata.st_size > MAX_SITE_FILE_BYTES:
                raise ValueError(
                    f"site tree entry exceeds {MAX_SITE_FILE_BYTES} bytes: {relative}"
                )
            files[relative] = path.read_bytes()

    visit(root)
    if len(files) > MAX_SITE_FILES:
        raise ValueError(f"site tree exceeds the {MAX_SITE_FILES}-file budget")
    if sum(len(content) for content in files.values()) > MAX_SITE_TOTAL_BYTES:
        raise ValueError(
            f"site tree exceeds the {MAX_SITE_TOTAL_BYTES}-byte aggregate budget"
        )
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
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3 or not parts[2].isdigit():
            raise ValueError(f"invalid site/_redirects line {line_number}")
        source = parts[0]
        if not source.startswith("/"):
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
    return shadowed


def public_route_aliases(path: str) -> set[str]:
    """Return clean and raw Pages routes that can be shadowed by _redirects."""
    raw = f"/{path}"
    aliases = {raw}
    if path.endswith(".html"):
        clean, _status = public_url_and_status(path)
        aliases.add(clean)
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
    source_files = collect_regular_tree(source)
    inventory = build_inventory(source_files)
    inventory_content = inventory_bytes(inventory)

    output_parent = output.parent
    output_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".site-dist-", dir=output_parent))
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
        if output.exists() or output.is_symlink():
            if output.is_symlink() or not output.is_dir():
                raise ValueError(f"site output must be a real directory: {output}")
            shutil.rmtree(output)
        temporary.replace(output)
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
