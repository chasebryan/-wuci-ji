#!/usr/bin/env python3
"""Generate the Noether Forge third-party review inventory.

The inventory is derived only from the committed Alpine input/package locks
and the release-scoped initramfs patch specification. Missing source, license,
notice, firmware, and export-review facts stay ``NOASSERTION`` or explicitly
unreviewed; recorded declared-license metadata never becomes legal clearance.
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
PATCH_SPEC = RELEASE_ROOT / "initramfs-patch-spec.json"
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
    url: str | None,
    sha256: str,
    size: int | None,
    package: str = NOASSERTION,
    version: str = NOASSERTION,
    sha512: str = NOASSERTION,
    container_filename: str = NOASSERTION,
    container_url: str = NOASSERTION,
    member_path: str = NOASSERTION,
) -> dict[str, Any]:
    if not filename or "/" in filename or "\\" in filename:
        raise ObligationsError(f"locked artifact filename must be a basename: {filename!r}")
    if url is not None and (not isinstance(url, str) or not url.startswith("https://")):
        raise ObligationsError(f"locked artifact origin must be an HTTPS URL: {filename}")
    if url is None:
        if (
            container_filename == NOASSERTION
            or not isinstance(container_url, str)
            or not container_url.startswith("https://")
            or not isinstance(member_path, str)
            or not member_path.startswith("/")
        ):
            raise ObligationsError(f"container-member origin is incomplete: {filename}")
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
            "acquisition": "network" if url is not None else "container-member",
            "artifact_url": url if url is not None else NOASSERTION,
            "container_filename": container_filename,
            "container_url": container_url,
            "member_path": member_path,
            "record_state": "locked",
            "repository_url": url.rsplit("/", 1)[0] if url is not None else NOASSERTION,
        },
        "package": package,
        "size_bytes": size if size is not None else NOASSERTION,
        "version": version,
        **review_fields(),
    }


def input_items(input_lock: dict[str, Any]) -> list[dict[str, Any]]:
    signer = input_lock.get("release_signer")
    boot_media = input_lock.get("boot_media")
    package_media = input_lock.get("package_source_media")
    if not all(isinstance(item, dict) for item in (signer, boot_media, package_media)):
        raise ObligationsError("Alpine input lock is missing a required object")

    records: list[dict[str, Any]] = [
        inventory_item(
            kind="release-signing-key",
            filename=signer["key_filename"],
            url=signer["key_url"],
            sha256=signer["key_sha256"],
            size=None,
        ),
    ]
    for media in (boot_media, package_media):
        iso = media["iso"]
        records.append(inventory_item(
            kind=f"alpine-{media['role']}-iso",
            filename=iso["filename"],
            url=iso["url"],
            sha256=iso["sha256"],
            sha512=iso["sha512"],
            size=iso["size"],
        ))
        records.extend(
            inventory_item(
                kind=f"alpine-{media['role']}-sidecar",
                filename=item["filename"],
                url=item["url"],
                sha256=item["sha256"],
                size=item["size"],
            )
            for item in media["sidecars"]
        )
    repository = package_media["repository"]
    records.append(inventory_item(
        kind="alpine-apk-index-container-member",
        filename=repository["index_filename"],
        url=None,
        sha256=repository["index_sha256"],
        size=repository["index_size"],
        container_filename=package_media["iso"]["filename"],
        container_url=package_media["iso"]["url"],
        member_path=f"{repository['path']}/{repository['index_filename']}",
    ))
    return sorted(records, key=lambda item: item["item_id"])


def package_items(package_lock: dict[str, Any], input_lock: dict[str, Any]) -> list[dict[str, Any]]:
    packages = package_lock.get("packages")
    if not isinstance(packages, list) or not packages or not all(isinstance(item, dict) for item in packages):
        raise ObligationsError("package lock packages must be a non-empty array of objects")
    package_media = input_lock["package_source_media"]
    overlay = {item["filename"]: item for item in input_lock["post_release_overlay"]}
    records: list[dict[str, Any]] = []
    for item in packages:
        package, version = parse_package_filename(item.get("filename"))
        overlay_record = overlay.get(item["filename"])
        records.append(inventory_item(
            kind="alpine-apk-post-release-overlay" if overlay_record else "alpine-apk-container-member",
            filename=item["filename"],
            url=overlay_record["url"] if overlay_record else None,
            sha256=item["sha256"],
            sha512=overlay_record["sha512"] if overlay_record else NOASSERTION,
            size=item.get("size"),
            package=package,
            version=version,
            container_filename=NOASSERTION if overlay_record else package_media["iso"]["filename"],
            container_url=NOASSERTION if overlay_record else package_media["iso"]["url"],
            member_path=NOASSERTION if overlay_record else f"{package_lock['repository_path']}/{item['filename']}",
        ))
    item_ids = [item["item_id"] for item in records]
    if len(item_ids) != len(set(item_ids)):
        raise ObligationsError("package lock contains duplicate artifact filenames")
    return sorted(records, key=lambda item: item["item_id"])


def patch_provenance_item(patch_spec: dict[str, Any]) -> dict[str, Any]:
    upstream = patch_spec.get("upstream")
    if patch_spec.get("license") != "GPL-2.0-only" or not isinstance(upstream, dict):
        raise ObligationsError("initramfs patch specification licensing or provenance is invalid")
    archive = upstream.get("source_archive")
    if not isinstance(archive, dict) or not isinstance(archive.get("instantiation"), dict):
        raise ObligationsError("initramfs patch source archive provenance is missing")
    record = inventory_item(
        kind="alpine-mkinitfs-source-provenance",
        filename="mkinitfs-3.14.0.tar.gz",
        url=archive.get("url"),
        sha256=archive.get("sha256"),
        sha512=archive.get("sha512"),
        size=archive.get("size"),
        package="mkinitfs",
        version=upstream.get("version", NOASSERTION),
    )
    record["license_metadata"] = {
        "declared_expression": "GPL-2.0-only",
        "evidence": "initramfs-patch-spec.json and authenticated Alpine package-index metadata",
        "review_state": "declared-metadata-recorded",
    }
    record["notices"] = {
        "provided": "PATCH-NOTICE.md and LICENSES/GPL-2.0-only.txt",
        "required": NOASSERTION,
        "review_state": "provided-files-recorded",
    }
    record["source_metadata"] = {
        "origin_package": "mkinitfs",
        "source_archive_digest": f"sha256:{archive['sha256']};sha512:{archive['sha512']}",
        "upstream_source_url": archive["url"],
        "review_state": "exact-source-provenance-recorded",
    }
    return record


def build_inventory(
    input_lock_path: Path = INPUT_LOCK,
    package_lock_path: Path = PACKAGE_LOCK,
    patch_spec_path: Path = PATCH_SPEC,
) -> dict[str, Any]:
    input_lock, input_raw = load_object(input_lock_path, "Alpine input lock")
    package_lock, package_raw = load_object(package_lock_path, "Alpine package lock")
    patch_spec, patch_spec_raw = load_object(patch_spec_path, "initramfs patch specification")
    packages = package_items(package_lock, input_lock)
    inputs = input_items(input_lock)
    provenance = [patch_provenance_item(patch_spec)]
    records = inputs + packages + provenance
    if input_lock.get("architecture") != package_lock.get("architecture"):
        raise ObligationsError("input and package lock architectures differ")
    if input_lock.get("alpine_release") != package_lock.get("alpine_release"):
        raise ObligationsError("input and package locks identify different Alpine releases")
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
            {
                "path": patch_spec_path.relative_to(ROOT).as_posix(),
                "schema": patch_spec.get("schema", NOASSERTION),
                "sha256": hashlib.sha256(patch_spec_raw).hexdigest(),
            },
        ],
        "summary": {
            "input_records": len(inputs),
            "package_records": len(packages),
            "provenance_records": len(provenance),
            "total_records": len(records),
            "network_records": sum(1 for item in records if item["origin"]["acquisition"] == "network"),
            "container_member_records": sum(1 for item in records if item["origin"]["acquisition"] == "container-member"),
            "records_with_declared_license_metadata": 1,
            "records_with_source_provenance": 1,
            "records_with_notice_files": 1,
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
        "items": sorted(records, key=lambda item: item["item_id"]),
        "non_claims": [
            "This deterministic inventory is a review aid, not legal advice or legal clearance.",
            "NOASSERTION means the locked records do not establish the field and a reviewer must investigate it.",
            "Artifact origins and digests do not establish source availability, license terms, required notices, firmware treatment, redistribution permission, or export classification.",
            "The three post-release overlay URLs are authenticity-checked versioned locators, but the mutable Alpine repository does not guarantee their future availability.",
            "This inventory does not authorize an ISO, APK cache, firmware, bootloader, or other binary publication.",
            "The mkinitfs row records declared license metadata, exact source provenance, and provided files; it is not a license conclusion or redistribution clearance.",
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
