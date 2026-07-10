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
import re
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
MAX_TOOLS = 16
MAX_OBSERVATIONS = 32
FIXTURE_SUBJECT_DESCRIPTION = "synthetic-fixture-marker-only"
OPERATOR_SUBJECT_DESCRIPTION = "private-reviewer-built-iso"
FIXTURE_ISO_FILENAME = "NOT-A-RELEASE-noether-hardware-observation-fixture.iso"
OPERATOR_ISO_FILENAME = "WuciOS-v2.4.0-Noether-Forge-x86_64.iso"
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?")
VERSION_TOKEN_PATTERN = re.compile(
    r"version:[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?"
)
DIGEST_TOKEN_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
REDACTED_TOKENS = {"redacted", "not-observed", "fixture-not-observed"}
ARCHITECTURES = {"x86_64", "aarch64", "riscv64", "not-observed", "fixture-not-observed"}
CAPTURE_OPERATING_SYSTEMS = {
    "linux", "windows", "macos", "freebsd", "openbsd", "netbsd",
    "redacted", "not-observed", "fixture-not-observed",
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


def require_identifier(value: Any, label: str, *, version: bool = False) -> str:
    text = require_string(value, label, max_length=64)
    pattern = VERSION_PATTERN if version else IDENTIFIER_PATTERN
    if pattern.fullmatch(text) is None:
        kind = "version identifier" if version else "lowercase identifier"
        raise HardwareObservationError(f"{label} must be a bounded {kind}")
    return text


def require_metadata_token(value: Any, label: str, *, allow_version: bool = False) -> str:
    text = require_string(value, label, max_length=72)
    if text in REDACTED_TOKENS or DIGEST_TOKEN_PATTERN.fullmatch(text) is not None:
        return text
    if allow_version and VERSION_TOKEN_PATTERN.fullmatch(text) is not None:
        return text
    raise HardwareObservationError(f"{label} must be a structured redaction, digest, or version token")


def require_array(value: Any, label: str, *, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise HardwareObservationError(f"{label} must be a non-empty array")
    if len(value) > maximum:
        raise HardwareObservationError(f"{label} exceeds {maximum} entries")
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
        "subject_kind", "subject_description", "commit", "iso_filename", "iso_digests"
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

    observation = require_exact_keys(record["observation"], {
        "observed_at_utc", "operator_id", "hardware", "firmware", "capture_host", "tools", "observations"
    }, "observation")
    verify_timestamp(observation["observed_at_utc"])
    operator_id = require_identifier(observation["operator_id"], "observation.operator_id")

    hardware = require_exact_keys(
        observation["hardware"], {"manufacturer", "model", "architecture", "identifiers_redacted"},
        "observation.hardware",
    )
    for key in ("manufacturer", "model"):
        require_metadata_token(hardware[key], f"observation.hardware.{key}")
    require_string(
        hardware["architecture"],
        "observation.hardware.architecture",
        choices=ARCHITECTURES,
        max_length=20,
    )
    if hardware["identifiers_redacted"] is not True:
        raise HardwareObservationError("observation.hardware.identifiers_redacted must be true")

    firmware = require_exact_keys(
        observation["firmware"], {"boot_mode", "vendor", "version", "secure_boot"},
        "observation.firmware",
    )
    require_string(
        firmware["boot_mode"],
        "observation.firmware.boot_mode",
        choices={"bios", "uefi", "not-observed", "fixture-not-observed"},
        max_length=20,
    )
    require_metadata_token(firmware["vendor"], "observation.firmware.vendor")
    require_metadata_token(firmware["version"], "observation.firmware.version", allow_version=True)
    require_string(
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
    require_string(
        capture_host["architecture"],
        "observation.capture_host.architecture",
        choices=ARCHITECTURES,
        max_length=20,
    )

    tools = require_array(observation["tools"], "observation.tools", maximum=MAX_TOOLS)
    tool_names: set[str] = set()
    for index, item in enumerate(tools):
        tool = require_exact_keys(item, {"name", "version", "purpose"}, f"observation.tools[{index}]")
        require_identifier(tool["name"], f"observation.tools[{index}].name")
        require_identifier(tool["version"], f"observation.tools[{index}].version", version=True)
        require_string(
            tool["purpose"],
            f"observation.tools[{index}].purpose",
            choices=TOOL_PURPOSES,
            max_length=40,
        )
        if tool["name"] in tool_names:
            raise HardwareObservationError("observation.tools contains a duplicate name")
        tool_names.add(tool["name"])

    observations = require_array(
        observation["observations"], "observation.observations", maximum=MAX_OBSERVATIONS
    )
    observation_names: set[str] = set()
    observed_count = 0
    for index, item in enumerate(observations):
        entry = require_exact_keys(item, {"name", "result", "notes"}, f"observation.observations[{index}]")
        name = require_string(
            entry["name"],
            f"observation.observations[{index}].name",
            choices=OBSERVATION_NAMES,
            max_length=36,
        )
        result = require_string(
            entry["result"], f"observation.observations[{index}].result",
            choices={"observed", "not-observed", "not-tested"},
            max_length=12,
        )
        notes = require_string(
            entry["notes"],
            f"observation.observations[{index}].notes",
            choices=set().union(*NOTES_BY_RESULT.values()),
            max_length=36,
        )
        if notes not in NOTES_BY_RESULT[result]:
            raise HardwareObservationError(
                f"observation.observations[{index}].notes does not match result"
            )
        if name in observation_names:
            raise HardwareObservationError("observation.observations contains a duplicate name")
        observation_names.add(name)
        if result == "observed":
            observed_count += 1

    fixture_tokens = {
        hardware["manufacturer"],
        hardware["model"],
        hardware["architecture"],
        firmware["boot_mode"],
        firmware["vendor"],
        firmware["version"],
        firmware["secure_boot"],
        capture_host["operating_system"],
        capture_host["kernel"],
        capture_host["architecture"],
    }
    if status == "fixture-only":
        if operator_id != "fixture-only" or fixture_tokens != {"fixture-not-observed"}:
            raise HardwareObservationError("fixture-only observation metadata must use fixture tokens")
        if tools != [{
            "name": "noether_hardware_observation.py",
            "version": "v1",
            "purpose": "record-shape-check",
        }]:
            raise HardwareObservationError("fixture-only record must use the fixed verifier tool entry")
        if observations != [{
            "name": "fixture-record-shape",
            "result": "not-tested",
            "notes": "fixture-shape-only",
        }]:
            raise HardwareObservationError("fixture-only record must use the fixed shape observation")
    else:
        if operator_id == "fixture-only":
            raise HardwareObservationError("operator-observation records cannot use fixture operator_id")
        if "fixture-not-observed" in fixture_tokens:
            raise HardwareObservationError("operator-observation records cannot use fixture tokens")
        if "fixture-record-shape" in observation_names or any(
            entry["notes"] == "fixture-shape-only" for entry in observations
        ):
            raise HardwareObservationError("operator-observation records cannot use fixture observations")
        if observed_count == 0:
            raise HardwareObservationError("operator-observation records require an observed result")

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


def digest_vector(path: Path) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in ("sha256", "sha384", "sha512")}
    try:
        for block in wuci_safeio.iter_regular_chunks(
            path,
            "Noether physical-hardware observation subject artifact",
            reject_symlink=True,
            reject_hardlink=True,
        ):
            for digest in digests.values():
                digest.update(block)
    except wuci_safeio.SafeIOError as exc:
        raise HardwareObservationError(str(exc)) from exc
    return {name: digest.hexdigest() for name, digest in digests.items()}


def verify_path(path: Path, *, iso: Path | None = None, expected_commit: str | None = None) -> dict[str, Any]:
    record = read_record(path)
    if expected_commit is not None:
        require_hex(expected_commit, 40, "expected commit")
        if record["subject"]["commit"] != expected_commit:
            raise HardwareObservationError("record commit does not match --expected-commit")
    if iso is not None:
        if iso.name != record["subject"]["iso_filename"]:
            raise HardwareObservationError("subject artifact basename does not match record iso_filename")
        observed = digest_vector(iso)
        if observed != record["subject"]["iso_digests"]:
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
