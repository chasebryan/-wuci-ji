#!/usr/bin/env python3
"""Generate the Noether Forge third-party review inventory.

The inventory is derived only from the committed Alpine input and package
locks.  Missing source, license, notice, firmware, and export-review facts stay
``NOASSERTION`` or explicitly unreviewed; this tool never infers legal
clearance from an artifact digest or package name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RELEASE_ROOT = ROOT / "wucios/releases/noether-forge-v2.4.0"
INPUT_LOCK = RELEASE_ROOT / "alpine-input-lock.json"
PACKAGE_LOCK = RELEASE_ROOT / "package-lock.json"
DEFAULT_INVENTORY = RELEASE_ROOT / "third-party-obligations.json"
SCHEMA = "wucios.noether_forge.third_party_obligations.v1"
NOASSERTION = "NOASSERTION"
PACKAGE_PATTERN = re.compile(r"^(?P<package>.+)-(?P<version>[0-9][A-Za-z0-9._+~-]*-r[0-9]+)\.apk$")


class ObligationsError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def regular_bytes(path: Path, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObligationsError(f"{label} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ObligationsError(f"{label} must be a regular file: {path}")
    if info.st_nlink != 1:
        raise ObligationsError(f"{label} hardlink rejected: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise ObligationsError(f"cannot read {label}: {path}") from exc


def load_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = regular_bytes(path, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ObligationsError(f"{label} must be valid UTF-8 JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ObligationsError(f"{label} must be a JSON object: {path}")
    return value, raw


def require_hex(value: Any, length: int, label: str) -> str:
    if not isinstance(value, str) or len(value) != length or re.fullmatch(r"[0-9a-f]+", value) is None:
        raise ObligationsError(f"{label} must be {length} lowercase hexadecimal characters")
    return value


def parse_package_filename(filename: Any) -> tuple[str, str]:
    if not isinstance(filename, str):
        raise ObligationsError("locked APK filename must be a string")
    match = PACKAGE_PATTERN.fullmatch(filename)
    if match is None:
        raise ObligationsError(f"cannot derive package and version from locked APK filename: {filename!r}")
    return match.group("package"), match.group("version")


def review_fields() -> dict[str, Any]:
    return {
        "export_review": {
            "classification": NOASSERTION,
            "review_state": "not-determined",
        },
        "firmware": {
            "content_state": "not-determined",
            "redistribution_review": "not-reviewed",
        },
        "license_metadata": {
            "declared_expression": NOASSERTION,
            "evidence": NOASSERTION,
            "review_state": "not-reviewed",
        },
        "notices": {
            "provided": NOASSERTION,
            "required": NOASSERTION,
            "review_state": "not-reviewed",
        },
        "redistribution_review": "not-cleared",
        "source_metadata": {
            "origin_package": NOASSERTION,
            "source_archive_digest": NOASSERTION,
            "upstream_source_url": NOASSERTION,
            "review_state": "not-reviewed",
        },
    }


def inventory_item(
    *,
    kind: str,
    filename: str,
    url: str,
    sha256: str,
    size: int | None,
    package: str = NOASSERTION,
    version: str = NOASSERTION,
    sha512: str = NOASSERTION,
) -> dict[str, Any]:
    if not filename or "/" in filename or "\\" in filename:
        raise ObligationsError(f"locked artifact filename must be a basename: {filename!r}")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ObligationsError(f"locked artifact origin must be an HTTPS URL: {filename}")
    require_hex(sha256, 64, f"{filename} SHA-256")
    if sha512 != NOASSERTION:
        require_hex(sha512, 128, f"{filename} SHA-512")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 1):
        raise ObligationsError(f"{filename} size must be a positive integer when recorded")
    return {
        "artifact_filename": filename,
        "digests": {"sha256": sha256, "sha512": sha512},
        "item_id": f"{kind}:{filename}",
        "kind": kind,
        "origin": {
            "artifact_url": url,
            "record_state": "locked",
            "repository_url": url.rsplit("/", 1)[0],
        },
        "package": package,
        "size_bytes": size if size is not None else NOASSERTION,
        "version": version,
        **review_fields(),
    }


def input_items(input_lock: dict[str, Any]) -> list[dict[str, Any]]:
    signer = input_lock.get("release_signer")
    iso = input_lock.get("iso")
    sidecars = input_lock.get("sidecars")
    apk_index = input_lock.get("apk_index")
    apk_static = input_lock.get("apk_static")
    if not all(isinstance(item, dict) for item in (signer, iso, apk_index, apk_static)):
        raise ObligationsError("Alpine input lock is missing a required object")
    if not isinstance(sidecars, list) or not all(isinstance(item, dict) for item in sidecars):
        raise ObligationsError("Alpine input lock sidecars must be an array of objects")

    records: list[dict[str, Any]] = [
        inventory_item(
            kind="release-signing-key",
            filename=signer["key_filename"],
            url=signer["key_url"],
            sha256=signer["key_sha256"],
            size=None,
        ),
        inventory_item(
            kind="alpine-iso",
            filename=iso["filename"],
            url=iso["url"],
            sha256=iso["sha256"],
            sha512=iso.get("sha512", NOASSERTION),
            size=iso.get("size"),
        ),
    ]
    records.extend(
        inventory_item(
            kind="alpine-sidecar",
            filename=item["filename"],
            url=item["url"],
            sha256=item["sha256"],
            size=item.get("size"),
        )
        for item in sidecars
    )
    records.extend([
        inventory_item(
            kind="alpine-apk-index",
            filename=apk_index["filename"],
            url=apk_index["url"],
            sha256=apk_index["sha256"],
            size=apk_index.get("size"),
        ),
        inventory_item(
            kind="alpine-bootstrap-apk",
            filename=apk_static["filename"],
            url=apk_static["url"],
            sha256=apk_static["sha256"],
            size=apk_static.get("size"),
            package="apk-tools-static",
            version=parse_package_filename(apk_static["filename"])[1],
        ),
    ])
    return sorted(records, key=lambda item: item["item_id"])


def package_items(package_lock: dict[str, Any]) -> list[dict[str, Any]]:
    repository = package_lock.get("repository_url")
    packages = package_lock.get("packages")
    if not isinstance(repository, str) or not repository.startswith("https://"):
        raise ObligationsError("package lock repository_url must be HTTPS")
    if not isinstance(packages, list) or not packages or not all(isinstance(item, dict) for item in packages):
        raise ObligationsError("package lock packages must be a non-empty array of objects")
    records: list[dict[str, Any]] = []
    for item in packages:
        package, version = parse_package_filename(item.get("filename"))
        records.append(inventory_item(
            kind="alpine-apk-package",
            filename=item["filename"],
            url=f"{repository.rstrip('/')}/{item['filename']}",
            sha256=item["sha256"],
            size=item.get("size"),
            package=package,
            version=version,
        ))
    item_ids = [item["item_id"] for item in records]
    if len(item_ids) != len(set(item_ids)):
        raise ObligationsError("package lock contains duplicate artifact filenames")
    return sorted(records, key=lambda item: item["item_id"])


def build_inventory(
    input_lock_path: Path = INPUT_LOCK,
    package_lock_path: Path = PACKAGE_LOCK,
) -> dict[str, Any]:
    input_lock, input_raw = load_object(input_lock_path, "Alpine input lock")
    package_lock, package_raw = load_object(package_lock_path, "Alpine package lock")
    packages = package_items(package_lock)
    inputs = input_items(input_lock)
    if input_lock.get("architecture") != package_lock.get("architecture"):
        raise ObligationsError("input and package lock architectures differ")
    if str(input_lock.get("alpine_release", "")).split(".")[:2] != str(package_lock.get("alpine_release", "")).split(".")[:2]:
        raise ObligationsError("input and package locks identify different Alpine release series")
    return {
        "schema": SCHEMA,
        "release_id": "noether-forge-v2.4.0",
        "inventory_status": "review-input-only",
        "generated_from": [
            {
                "path": input_lock_path.relative_to(ROOT).as_posix(),
                "schema": input_lock.get("schema", NOASSERTION),
                "sha256": hashlib.sha256(input_raw).hexdigest(),
            },
            {
                "path": package_lock_path.relative_to(ROOT).as_posix(),
                "schema": package_lock.get("schema", NOASSERTION),
                "sha256": hashlib.sha256(package_raw).hexdigest(),
            },
        ],
        "summary": {
            "input_records": len(inputs),
            "package_records": len(packages),
            "total_records": len(inputs) + len(packages),
            "records_with_license_conclusions": 0,
            "records_with_redistribution_clearance": 0,
            "records_with_export_classification": 0,
        },
        "policy": {
            "binary_distribution_authorized": False,
            "legal_clearance": "not-provided-by-this-inventory",
            "network_performed": False,
            "official_release_authority": False,
        },
        "items": sorted(inputs + packages, key=lambda item: item["item_id"]),
        "non_claims": [
            "This deterministic inventory is a review aid, not legal advice or legal clearance.",
            "NOASSERTION means the locked records do not establish the field and a reviewer must investigate it.",
            "Artifact origins and digests do not establish source availability, license terms, required notices, firmware treatment, redistribution permission, or export classification.",
            "This inventory does not authorize an ISO, APK cache, firmware, bootloader, or other binary publication.",
        ],
    }


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise ObligationsError(f"refusing symlink output: {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def check_inventory(path: Path = DEFAULT_INVENTORY) -> None:
    expected = canonical_json(build_inventory())
    observed = regular_bytes(path, "third-party obligations inventory")
    if observed != expected:
        raise ObligationsError(
            f"third-party obligations inventory is stale or non-canonical: {path}; "
            "run tools/wucios/noether_obligations.py write"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check", help="verify the committed deterministic inventory")
    check.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    write = subparsers.add_parser("write", help="regenerate the deterministic inventory")
    write.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "write":
            atomic_write(args.inventory, canonical_json(build_inventory()))
            print(f"Noether third-party obligations inventory: WROTE {args.inventory}")
        else:
            check_inventory(args.inventory)
            print("Noether third-party obligations inventory: PASS (review aid only; no legal clearance)")
    except ObligationsError as exc:
        print(f"Noether third-party obligations inventory: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
