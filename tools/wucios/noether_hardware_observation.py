#!/usr/bin/env python3
"""Verify a digest-bound Noether Forge physical-hardware observation record.

The verifier checks record shape, claim boundaries, commit identity, and the
optional local ISO digest vector.  A passing record means only that the record
is internally consistent; it does not turn an operator observation into
independent validation, release authority, certification, or OS containment.
Mutable values are closed enums or bounded metadata tokens; the verifier does
not attempt to infer meaning from arbitrary prose.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import wuci_safeio  # noqa: E402


DEFAULT_FIXTURE = ROOT / "wucios/releases/noether-forge-v2.4.0/fixtures/physical-hardware-observation.json"
SCHEMA = "wucios.noether_forge.physical_hardware_observation.v1"
BOUNDARY_STATEMENT = (
    "This record is a digest-bound operator observation only; it is not independent hardware "
    "validation, certification, official release authority, or proof of OS containment."
)
MAX_RECORD_BYTES = 128 * 1024
MAX_ISO_BYTES = 4 * 1024 * 1024 * 1024
FIXTURE_SUBJECT_DESCRIPTION = "synthetic-fixture-marker-only"
OPERATOR_SUBJECT_DESCRIPTION = "private-reviewer-built-iso"
FIXTURE_ISO_FILENAME = "NOT-A-RELEASE-noether-hardware-observation-fixture.iso"
OPERATOR_ISO_FILENAME = "WuciOS-v2.4.0-Noether-Forge-x86_64.iso"
OPERATOR_ID_PATTERN = re.compile(r"reviewer-[1-9][0-9]{0,5}")
VERSION_TOKEN_PATTERN = re.compile(r"version:[0-9]+(?:[._+-][0-9]+)*")
DIGEST_TOKEN_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REDACTED_TOKENS = {"redacted", "not-observed", "fixture-not-observed"}
CAPTURE_OPERATING_SYSTEMS = {
    "linux", "windows", "macos", "freebsd", "openbsd", "netbsd",
    "redacted", "not-observed", "fixture-not-observed",
}
TOOL_NAMES = {
    "noether-hardware-observation",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "serial-capture",
    "console-capture",
    "camera-capture",
    "firmware-setup",
    "boot-media-writer",
}
TOOL_PURPOSES = {
    "record-shape-check",
    "iso-digest-comparison",
    "boot-observation-capture",
    "firmware-state-observation",
    "local-runtime-status-observation",
    "private-media-hash-recording",
}
OBSERVATION_NAMES = {
    "fixture-record-shape",
    "boot-menu-visible",
    "kernel-start-visible",
    "local-tty-login-prompt-visible",
    "release-notes-visible",
    "local-runtime-status-visible",
    "shutdown-completed",
}
BOOT_CHAIN_OBSERVATIONS = {
    "boot-menu-visible",
    "kernel-start-visible",
    "local-tty-login-prompt-visible",
    "local-runtime-status-visible",
}
NOTES_BY_RESULT = {
    "observed": {
        "observed-on-attached-display",
        "observed-on-local-console",
        "observed-in-private-capture",
        "observed-without-retained-capture",
    },
    "not-observed": {"not-observed-during-session"},
    "not-tested": {"not-tested", "fixture-shape-only"},
}


class HardwareObservationError(RuntimeError):
    pass


def require_exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HardwareObservationError(f"{label} must be an object")
    observed = set(value)
    if observed != keys:
        missing = sorted(keys - observed)
        extra = sorted(observed - keys)
        raise HardwareObservationError(f"{label} keys differ; missing={missing}, extra={extra}")
    return value


def require_string(
    value: Any,
    label: str,
    *,
    choices: set[str] | None = None,
    max_length: int,
) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HardwareObservationError(f"{label} must be a non-empty, trimmed string")
    if len(value) > max_length:
        raise HardwareObservationError(f"{label} exceeds {max_length} characters")
    if any(ord(character) < 0x20 for character in value):
        raise HardwareObservationError(f"{label} contains a control character")
    if choices is not None and value not in choices:
        raise HardwareObservationError(f"{label} must be one of {sorted(choices)}")
    return value


def require_operator_id(value: Any, label: str) -> str:
    text = require_string(value, label, max_length=71)
    if OPERATOR_ID_PATTERN.fullmatch(text) is None and DIGEST_TOKEN_PATTERN.fullmatch(text) is None:
        raise HardwareObservationError(f"{label} must be reviewer-N or a SHA-256 token")
    return text


def require_metadata_token(value: Any, label: str, *, allow_version: bool = False) -> str:
    text = require_string(value, label, max_length=71)
    if text in REDACTED_TOKENS or DIGEST_TOKEN_PATTERN.fullmatch(text) is not None:
        return text
    if allow_version and VERSION_TOKEN_PATTERN.fullmatch(text) is not None:
        return text
    raise HardwareObservationError(f"{label} must be a structured redaction, digest, or version token")


def require_closed_map(value: Any, choices: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise HardwareObservationError(f"{label} must be a non-empty object")
    unexpected = sorted(set(value) - choices)
    if unexpected:
        raise HardwareObservationError(f"{label} contains unsupported keys: {unexpected}")
    return value


def require_integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise HardwareObservationError(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def require_runtime_size(value: Any) -> None:
    """Bound already-parsed records as well as the file-reading entry point."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise HardwareObservationError("record must be a finite JSON value") from exc
    if len(encoded) > MAX_RECORD_BYTES:
        raise HardwareObservationError(f"record exceeds {MAX_RECORD_BYTES} bytes")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HardwareObservationError(f"duplicate JSON key rejected: {key}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    raise HardwareObservationError(f"non-finite JSON constant rejected: {value}")


def require_false(value: Any, label: str) -> None:
    if value is not False:
        raise HardwareObservationError(f"{label} must be false")


def require_hex(value: Any, length: int, label: str) -> str:
    text = require_string(value, label, max_length=length)
    if len(text) != length or re.fullmatch(r"[0-9a-f]+", text) is None:
        raise HardwareObservationError(f"{label} must be {length} lowercase hexadecimal characters")
    return text


def verify_timestamp(value: Any) -> None:
    text = require_string(value, "observation.observed_at_utc", max_length=20)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text) is None:
        raise HardwareObservationError(
            "observation.observed_at_utc must be UTC with whole-second precision"
        )
    try:
        observed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise HardwareObservationError("observation.observed_at_utc must be valid RFC 3339") from exc
    if observed.tzinfo != timezone.utc:
        raise HardwareObservationError("observation.observed_at_utc must use UTC")


def verify_record(value: Any) -> dict[str, Any]:
    require_runtime_size(value)
    record = require_exact_keys(value, {
        "schema", "release_id", "record_status", "subject", "observation", "claim_boundary"
    }, "record")
    if record["schema"] != SCHEMA:
        raise HardwareObservationError(f"record.schema must be {SCHEMA}")
    if record["release_id"] != "noether-forge-v2.4.0":
        raise HardwareObservationError("record.release_id must be noether-forge-v2.4.0")
    status = require_string(
        record["record_status"],
        "record.record_status",
        choices={"fixture-only", "operator-observation"},
        max_length=20,
    )

    subject = require_exact_keys(record["subject"], {
        "subject_kind", "subject_description", "commit", "iso_filename", "iso_size_bytes",
        "iso_digests"
    }, "subject")
    subject_kind = require_string(
        subject["subject_kind"], "subject.subject_kind",
        choices={"synthetic-fixture", "private-reviewer-built-iso"},
        max_length=26,
    )
    subject_description = require_string(
        subject["subject_description"],
        "subject.subject_description",
        choices={FIXTURE_SUBJECT_DESCRIPTION, OPERATOR_SUBJECT_DESCRIPTION},
        max_length=29,
    )
    require_hex(subject["commit"], 40, "subject.commit")
    filename = require_string(
        subject["iso_filename"],
        "subject.iso_filename",
        choices={FIXTURE_ISO_FILENAME, OPERATOR_ISO_FILENAME},
        max_length=54,
    )
    iso_size_bytes = require_integer(
        subject["iso_size_bytes"], "subject.iso_size_bytes", minimum=1, maximum=MAX_ISO_BYTES
    )
    digests = require_exact_keys(subject["iso_digests"], {"sha256", "sha384", "sha512"}, "subject.iso_digests")
    require_hex(digests["sha256"], 64, "subject.iso_digests.sha256")
    require_hex(digests["sha384"], 96, "subject.iso_digests.sha384")
    require_hex(digests["sha512"], 128, "subject.iso_digests.sha512")
    if status == "fixture-only" and subject_kind != "synthetic-fixture":
        raise HardwareObservationError("fixture-only records must bind a synthetic-fixture subject")
    if status == "operator-observation" and subject_kind != "private-reviewer-built-iso":
        raise HardwareObservationError("operator-observation records must bind a private-reviewer-built-iso subject")
    expected_description = (
        FIXTURE_SUBJECT_DESCRIPTION if status == "fixture-only" else OPERATOR_SUBJECT_DESCRIPTION
    )
    if subject_description != expected_description:
        raise HardwareObservationError("subject.subject_description does not match record_status")
    expected_filename = FIXTURE_ISO_FILENAME if status == "fixture-only" else OPERATOR_ISO_FILENAME
    if filename != expected_filename:
        raise HardwareObservationError("subject.iso_filename does not match record_status")
    if status == "operator-observation" and subject["commit"] == "0" * 40:
        raise HardwareObservationError("operator-observation records must bind a non-placeholder Git commit")
    if status == "fixture-only" and iso_size_bytes != 43:
        raise HardwareObservationError("fixture-only subject.iso_size_bytes must be 43")

    observation = require_exact_keys(record["observation"], {
        "observed_at_utc", "operator_id", "hardware", "firmware", "capture_host", "tools", "observations"
    }, "observation")
    verify_timestamp(observation["observed_at_utc"])
    if status == "fixture-only":
        operator_id = require_string(
            observation["operator_id"],
            "observation.operator_id",
            choices={"fixture-only"},
            max_length=12,
        )
    else:
        operator_id = require_operator_id(observation["operator_id"], "observation.operator_id")

    hardware = require_exact_keys(
        observation["hardware"], {"manufacturer", "model", "architecture", "identifiers_redacted"},
        "observation.hardware",
    )
    for key in ("manufacturer", "model"):
        require_metadata_token(hardware[key], f"observation.hardware.{key}")
    hardware_architecture = require_string(
        hardware["architecture"],
        "observation.hardware.architecture",
        choices={"x86_64", "fixture-not-observed"},
        max_length=20,
    )
    if hardware["identifiers_redacted"] is not True:
        raise HardwareObservationError("observation.hardware.identifiers_redacted must be true")

    firmware = require_exact_keys(
        observation["firmware"], {"boot_mode", "vendor", "version", "secure_boot"},
        "observation.firmware",
    )
    boot_mode = require_string(
        firmware["boot_mode"],
        "observation.firmware.boot_mode",
        choices={"bios", "uefi", "not-observed", "fixture-not-observed"},
        max_length=20,
    )
    require_metadata_token(firmware["vendor"], "observation.firmware.vendor")
    require_metadata_token(firmware["version"], "observation.firmware.version", allow_version=True)
    secure_boot = require_string(
        firmware["secure_boot"], "observation.firmware.secure_boot",
        choices={"enabled", "disabled", "not-observed", "not-applicable", "fixture-not-observed"},
        max_length=20,
    )

    capture_host = require_exact_keys(
        observation["capture_host"], {"operating_system", "kernel", "architecture"},
        "observation.capture_host",
    )
    require_string(
        capture_host["operating_system"],
        "observation.capture_host.operating_system",
        choices=CAPTURE_OPERATING_SYSTEMS,
        max_length=20,
    )
    require_metadata_token(
        capture_host["kernel"], "observation.capture_host.kernel", allow_version=True
    )
    capture_architecture = require_string(
        capture_host["architecture"],
        "observation.capture_host.architecture",
        choices={"x86_64", "fixture-not-observed"},
        max_length=20,
    )

    tools = require_closed_map(observation["tools"], TOOL_NAMES, "observation.tools")
    for name, item in tools.items():
        tool = require_exact_keys(item, {"version", "purpose"}, f"observation.tools.{name}")
        tool_version = require_metadata_token(
            tool["version"], f"observation.tools.{name}.version", allow_version=True
        )
        if tool_version == "fixture-not-observed":
            raise HardwareObservationError(
                f"observation.tools.{name}.version cannot use a fixture token"
            )
        require_string(
            tool["purpose"],
            f"observation.tools.{name}.purpose",
            choices=TOOL_PURPOSES,
            max_length=40,
        )

    observations = require_closed_map(
        observation["observations"], OBSERVATION_NAMES, "observation.observations"
    )
    for name, item in observations.items():
        entry = require_exact_keys(item, {"result", "notes"}, f"observation.observations.{name}")
        result = require_string(
            entry["result"], f"observation.observations.{name}.result",
            choices={"observed", "not-observed", "not-tested"},
            max_length=12,
        )
        notes = require_string(
            entry["notes"],
            f"observation.observations.{name}.notes",
            choices=set().union(*NOTES_BY_RESULT.values()),
            max_length=36,
        )
        if notes not in NOTES_BY_RESULT[result]:
            raise HardwareObservationError(
                f"observation.observations.{name}.notes does not match result"
            )

    fixture_tokens = {
        hardware["manufacturer"],
        hardware["model"],
        firmware["boot_mode"],
        firmware["vendor"],
        firmware["version"],
        firmware["secure_boot"],
        capture_host["operating_system"],
        capture_host["kernel"],
    }
    if status == "fixture-only":
        if (
            operator_id != "fixture-only"
            or fixture_tokens != {"fixture-not-observed"}
            or hardware_architecture != "fixture-not-observed"
            or capture_architecture != "fixture-not-observed"
        ):
            raise HardwareObservationError("fixture-only observation metadata must use fixture tokens")
        if tools != {"noether-hardware-observation": {
            "version": "version:1", "purpose": "record-shape-check"
        }}:
            raise HardwareObservationError("fixture-only record must use the fixed verifier tool entry")
        if observations != {"fixture-record-shape": {
            "result": "not-tested", "notes": "fixture-shape-only"
        }}:
            raise HardwareObservationError("fixture-only record must use the fixed shape observation")
    else:
        if "fixture-not-observed" in fixture_tokens:
            raise HardwareObservationError("operator-observation records cannot use fixture tokens")
        if hardware_architecture != "x86_64" or capture_architecture != "x86_64":
            raise HardwareObservationError("operator-observation architectures must be x86_64")
        if boot_mode == "bios" and secure_boot != "not-applicable":
            raise HardwareObservationError("BIOS observations require secure_boot=not-applicable")
        if boot_mode == "uefi" and secure_boot not in {"enabled", "disabled", "not-observed"}:
            raise HardwareObservationError("UEFI observations require a UEFI secure-boot state")
        if boot_mode == "not-observed" and secure_boot != "not-observed":
            raise HardwareObservationError("unobserved firmware mode requires secure_boot=not-observed")
        if "fixture-record-shape" in observations or any(
            entry["notes"] == "fixture-shape-only" for entry in observations.values()
        ):
            raise HardwareObservationError("operator-observation records cannot use fixture observations")
        if not any(
            name in BOOT_CHAIN_OBSERVATIONS and entry["result"] == "observed"
            for name, entry in observations.items()
        ):
            raise HardwareObservationError(
                "operator-observation records require an observed boot-chain result"
            )

    boundary = require_exact_keys(record["claim_boundary"], {
        "hardware_validation_claimed", "external_validation_claimed", "official_release_claimed",
        "production_authority_claimed", "statement"
    }, "claim_boundary")
    for key in (
        "hardware_validation_claimed", "external_validation_claimed", "official_release_claimed",
        "production_authority_claimed",
    ):
        require_false(boundary[key], f"claim_boundary.{key}")
    if boundary["statement"] != BOUNDARY_STATEMENT:
        raise HardwareObservationError("claim_boundary.statement must preserve the bounded observation statement")
    return record


def read_record(path: Path) -> dict[str, Any]:
    try:
        raw = wuci_safeio.read_regular_bytes(
            path,
            "Noether physical-hardware observation record",
            reject_symlink=True,
            reject_hardlink=True,
            max_bytes=MAX_RECORD_BYTES,
        )
    except wuci_safeio.SafeIOError as exc:
        raise HardwareObservationError(str(exc)) from exc
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_json_constant,
        )
    except HardwareObservationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HardwareObservationError(f"cannot read observation JSON: {path}") from exc
    return verify_record(value)


def stable_stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def iso_binding(path: Path) -> dict[str, Any]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha384", "sha512")}
    try:
        expected = path.lstat()
    except OSError as exc:
        raise HardwareObservationError(f"subject artifact is missing: {path}") from exc
    if not stat.S_ISREG(expected.st_mode):
        raise HardwareObservationError(f"subject artifact must be a regular file: {path}")
    if expected.st_nlink != 1:
        raise HardwareObservationError(f"subject artifact hardlink rejected: {path}")
    if not 1 <= expected.st_size <= MAX_ISO_BYTES:
        raise HardwareObservationError(f"subject artifact size must be from 1 through {MAX_ISO_BYTES}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HardwareObservationError(f"cannot open subject artifact safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise HardwareObservationError(f"subject artifact must remain a single-link regular file: {path}")
        if (expected.st_dev, expected.st_ino) != (before.st_dev, before.st_ino):
            raise HardwareObservationError(f"subject artifact changed while opening: {path}")
        if not 1 <= before.st_size <= MAX_ISO_BYTES:
            raise HardwareObservationError(f"subject artifact size must be from 1 through {MAX_ISO_BYTES}")
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, before.st_size + 1 - total))
            if not block:
                break
            total += len(block)
            if total > before.st_size:
                raise HardwareObservationError(f"subject artifact grew while hashing: {path}")
            for digest in digests.values():
                digest.update(block)
        after = os.fstat(descriptor)
        if total != before.st_size or stable_stat_identity(before) != stable_stat_identity(after):
            raise HardwareObservationError(f"subject artifact changed while hashing: {path}")
    except OSError as exc:
        raise HardwareObservationError(f"cannot read subject artifact safely: {path}") from exc
    finally:
        os.close(descriptor)
    return {
        "iso_size_bytes": total,
        "iso_digests": {name: digest.hexdigest() for name, digest in digests.items()},
    }


def digest_vector(path: Path) -> dict[str, str]:
    return iso_binding(path)["iso_digests"]


def verify_path(path: Path, *, iso: Path | None = None, expected_commit: str | None = None) -> dict[str, Any]:
    record = read_record(path)
    if expected_commit is not None:
        require_hex(expected_commit, 40, "expected commit")
        if record["subject"]["commit"] != expected_commit:
            raise HardwareObservationError("record commit does not match --expected-commit")
    if iso is not None:
        if iso.name != record["subject"]["iso_filename"]:
            raise HardwareObservationError("subject artifact basename does not match record iso_filename")
        observed = iso_binding(iso)
        if observed["iso_size_bytes"] != record["subject"]["iso_size_bytes"]:
            raise HardwareObservationError("subject artifact size does not match record")
        if observed["iso_digests"] != record["subject"]["iso_digests"]:
            raise HardwareObservationError("subject artifact digest vector does not match record")
    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", nargs="?", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--iso", type=Path, help="optional private local ISO to digest and compare")
    parser.add_argument("--expected-commit", help="optional expected 40-character Git commit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        record = verify_path(args.record, iso=args.iso, expected_commit=args.expected_commit)
    except HardwareObservationError as exc:
        print(f"Noether physical-hardware observation: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "Noether physical-hardware observation: PASS "
        f"({record['record_status']}; structured consistency only, no authority granted)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
