#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


FIELDS = (
    "schema",
    "suite",
    "production",
    "authority-id",
    "group-public-key",
    "allow-open",
    "allow-release",
    "allow-trust",
    "allow-publish",
)
HEX_RE = re.compile(r"^[0-9a-f]+$")


class ProductionAuthorityError(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_hex(value: str, chars: int, context: str) -> None:
    if len(value) != chars or HEX_RE.fullmatch(value) is None:
        raise ProductionAuthorityError(f"{context} must be {chars} lowercase hex characters")


def parse_authority(text: str) -> dict[str, str]:
    if "\r" in text or not text.endswith("\n") or text.endswith("\n\n"):
        raise ProductionAuthorityError("authority root must be LF text with one trailing newline")
    lines = text[:-1].split("\n")
    if len(lines) != len(FIELDS):
        raise ProductionAuthorityError("authority root has unexpected field count")
    fields: dict[str, str] = {}
    for line, expected in zip(lines, FIELDS):
        if ": " not in line:
            raise ProductionAuthorityError("authority root line is not label: value")
        label, value = line.split(": ", 1)
        if label != expected:
            raise ProductionAuthorityError(f"authority root expected label {expected}")
        fields[label] = value
    require_hex(fields["authority-id"], 64, "authority-id")
    require_hex(fields["group-public-key"], 66, "group-public-key")
    if fields["group-public-key"][:2] not in {"02", "03"}:
        raise ProductionAuthorityError("group-public-key must be compressed SEC1")
    expected_id = sha256_bytes(bytes.fromhex(fields["group-public-key"]))
    if fields["authority-id"] != expected_id:
        raise ProductionAuthorityError("authority-id does not match group-public-key")
    for label in ("allow-open", "allow-release", "allow-trust", "allow-publish"):
        if fields[label] not in {"true", "false"}:
            raise ProductionAuthorityError(f"{label} must be true or false")
    return fields


def load_json(path: Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProductionAuthorityError(f"could not read {context}: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProductionAuthorityError(f"{context} is not valid JSON: {exc.msg}") from exc


def reject_fixture_path(path: Path) -> None:
    lowered = path.as_posix().lower()
    if "fixture" in lowered or lowered.startswith("authority/"):
        raise ProductionAuthorityError("fixture or repo-local authority path is not production authority")


def validate_ceremony(path: Path, authority_sha256: str) -> None:
    value = load_json(path, "production authority ceremony")
    if not isinstance(value, dict):
        raise ProductionAuthorityError("ceremony evidence must be a JSON object")
    if value.get("schema") != "wuci-production-authority-ceremony-v1":
        raise ProductionAuthorityError("unsupported ceremony schema")
    if value.get("authority_sha256") != authority_sha256:
        raise ProductionAuthorityError("ceremony authority digest mismatch")
    if not isinstance(value.get("operator"), str) or not value["operator"]:
        raise ProductionAuthorityError("ceremony operator is required")
    if value.get("fixture_material_used") is not False:
        raise ProductionAuthorityError("production ceremony must reject fixture material")


def run_verify(args: argparse.Namespace) -> int:
    authority_path = Path(args.authority)
    reject_fixture_path(authority_path)
    fields = parse_authority(authority_path.read_text(encoding="ascii"))
    if fields["production"] != "true":
        raise ProductionAuthorityError("production authority must set production: true")
    if args.ceremony is None:
        raise ProductionAuthorityError("production authority requires key ceremony evidence")
    validate_ceremony(Path(args.ceremony), sha256_file(authority_path))
    if not args.quiet:
        print("wuci production authority: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify non-fixture WUCI production authority evidence.")
    parser.add_argument("verify", choices=("verify",))
    parser.add_argument("--authority", required=True)
    parser.add_argument("--ceremony")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    try:
        return run_verify(args)
    except (OSError, UnicodeDecodeError, ProductionAuthorityError) as exc:
        print(f"wuci production authority: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
