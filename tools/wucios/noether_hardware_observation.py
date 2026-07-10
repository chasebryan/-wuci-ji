#!/usr/bin/env python3
"""Verify a digest-bound Noether Forge physical-hardware observation record.

The verifier checks record shape, claim boundaries, commit identity, and the
optional local ISO digest vector.  A passing record means only that the record
is internally consistent; it does not turn an operator observation into
independent validation, release authority, certification, or OS containment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = ROOT / "wucios/releases/noether-forge-v2.4.0/fixtures/physical-hardware-observation.json"
SCHEMA = "wucios.noether_forge.physical_hardware_observation.v1"
BOUNDARY_STATEMENT = (
    "This record is a digest-bound operator observation only; it is not independent hardware "
    "validation, certification, official release authority, or proof of OS containment."
)
# Unicode's Default_Ignorable_Code_Point property includes format controls plus
# a small number of marks and reserved ranges.  Python's stdlib exposes general
# categories rather than that derived property, so keep the non-Cf ranges here.
# NFKC is applied before these characters are removed.
DEFAULT_IGNORABLE_RANGES = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2065, 0x2065),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

# Mutable observation text may record facts, but it may not grant assurance,
# release, containment, or quantum-resistance status.  These expressions run on
# normalized text and intentionally reserve the claim families rather than a
# finite list of marketing phrases.  Negated versions are also rejected: the
# exact claim_boundary.statement is the sole supported non-claim statement.
FORBIDDEN_FREE_TEXT_AUTHORITY_PATTERNS = (
    ("validation", re.compile(r"\bvalidat(?:e|ed|es|ing|ion|ions|or|ors)\b")),
    (
        "certification",
        re.compile(r"\bcertif(?:y|ies|ied|icate|icates|ication|ications|ying)\b"),
    ),
    ("accreditation", re.compile(r"\baccredit(?:ed|ing|s|ation|ations)?\b")),
    ("assurance", re.compile(r"\bassur(?:e|ed|es|ing|ance|ances)\b")),
    ("attestation", re.compile(r"\battest(?:s|ed|ing|ation|ations)?\b")),
    ("approval", re.compile(r"\bapprov(?:e|es|ed|ing|al|als)\b")),
    (
        "endorsement",
        re.compile(r"\bendors(?:e|es|ed|ing|ement|ements)\b"),
    ),
    (
        "conformance",
        re.compile(r"\bconform(?:s|ed|ing|ance|ant|ity)?\b"),
    ),
    (
        "compliance",
        re.compile(r"\bcompl(?:y|ies|ied|ying|iance|iant)\b"),
    ),
    (
        "qualification",
        re.compile(r"\bqualif(?:y|ies|ied|ying|ication|ications)\b"),
    ),
    (
        "acceptance",
        re.compile(r"\baccept(?:ed|ance|ances|able|ability)\b"),
    ),
    ("authority", re.compile(r"authorit(?:y|ies|ative|atively)\b")),
    (
        "official-release",
        re.compile(
            r"(?:official(?:ly)?\s*releas(?:e|ed|es|ing)?"
            r"|releas(?:e|ed|es|ing)?(?:\s+\w+){0,2}\s*official(?:ly)?)\b"
        ),
    ),
    (
        "independent-assurance",
        re.compile(
            r"(?:\b(?:independent(?:ly)?|external(?:ly)?|outside|third\s+party)\s*"
            r"(?:laborator(?:y|ies)|labs?|audits?|reviews?|reviewers?|"
            r"assess(?:ed|ing|ment|ments|or|ors)|tests?|verification)\b"
            r"|\b(?:laborator(?:y|ies)|labs?|audits?|reviews?|reviewers?|"
            r"assess(?:ed|ing|ment|ments|or|ors)|tests?|verification)"
            r"(?:\s+\w+){0,3}\s+(?:independent(?:ly)?|external(?:ly)?|outside|third\s+party)\b)"
        ),
    ),
    (
        "all-hardware-tests",
        re.compile(
            r"(?:\bpass(?:ed|es|ing)?\s+(?:all|every)\s+(?:the\s+)?hardware\s+tests?\b"
            r"|\b(?:all|every)\s+(?:the\s+)?hardware\s+tests?"
            r"(?:\s+\w+){0,2}\s+pass(?:ed|es|ing)?\b"
            r"|\bhardware\s+pass(?:ed|es|ing)?\s+(?:all|every)\s+tests?\b)"
        ),
    ),
    (
        "hardware-verification",
        re.compile(
            r"\bhardware\s+(?:(?:has\s+been|is|was|independently|externally|"
            r"fully|successfully)\s+){0,4}"
            r"verif(?:y|ied|ies|ying|ication|ications)\b"
        ),
    ),
    (
        "production-readiness",
        re.compile(
            r"(?:\bproduction(?:\s+(?:deployment|use|release|trust)){0,2}\s+"
            r"(?:ready|readiness|approved|authorized|trusted)\b"
            r"|\b(?:ready|readiness|approved|authorized|trusted)\s+"
            r"(?:for\s+)?production\b)"
        ),
    ),
    (
        "production-release",
        re.compile(r"\b(?:canonical\s+)?production\s+(?:grade|release)\b"),
    ),
    ("containment", re.compile(r"\bcontainment\b")),
    (
        "os-containment",
        re.compile(
            r"(?:\b(?:os|operating\s+system|kernel|runtime|workloads?)"
            r"(?:\s+\w+){0,2}\s+contain(?:ed|s|ing)\b"
            r"|\bcontain(?:ed|s|ing)(?:\s+\w+){0,2}\s+"
            r"(?:os|operating\s+system|kernel|runtime|workloads?)\b)"
        ),
    ),
    ("sandbox", re.compile(r"sandbox(?:ed|es|ing)?\b")),
    (
        "os-isolation",
        re.compile(
            r"(?:\bisolat(?:e|es|ed|ing|ion)\s*(?:(?:the|of|for)\s+){0,2}"
            r"(?:os|operating\s+system|kernel|runtime|workloads?)\b"
            r"|\b(?:os|operating\s+system|kernel|runtime|workloads?)"
            r"(?:\s+\w+){0,2}\s+isolat(?:e|es|ed|ing|ion)\b)"
        ),
    ),
    (
        "os-separation",
        re.compile(
            r"(?:\b(?:os|operating\s+system|kernel|runtime|workloads?)"
            r"(?:\s+\w+){0,4}\s+separat(?:e|es|ed|ing|ion)\b"
            r"|\bseparat(?:e|es|ed|ing|ion)(?:\s+\w+){0,4}\s+"
            r"(?:os|operating\s+system|kernel|runtime|workloads?)\b)"
        ),
    ),
    (
        "enforced-boundary",
        re.compile(
            r"(?:\benforc(?:e|es|ed|ing|ement)(?:\s+\w+){0,2}\s+boundar(?:y|ies)\b"
            r"|\bboundar(?:y|ies)(?:\s+\w+){0,2}\s+enforc(?:e|es|ed|ing|ement)\b)"
        ),
    ),
    ("quantum-resistance", re.compile(r"(?:quantum|\bpqc\b)")),
)


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


def require_string(value: Any, label: str, *, choices: set[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HardwareObservationError(f"{label} must be a non-empty, trimmed string")
    if any(ord(character) < 0x20 for character in value):
        raise HardwareObservationError(f"{label} contains a control character")
    if choices is not None and value not in choices:
        raise HardwareObservationError(f"{label} must be one of {sorted(choices)}")
    return value


def is_default_ignorable(character: str) -> bool:
    """Return whether a Unicode character is format/default-ignorable."""

    if unicodedata.category(character) == "Cf":
        return True
    codepoint = ord(character)
    return any(start <= codepoint <= end for start, end in DEFAULT_IGNORABLE_RANGES)


def normalize_free_text_for_claim_scan(value: str) -> str:
    """Canonicalize claim text without changing the evidence value itself."""

    characters: list[str] = []
    nfkc_text = unicodedata.normalize("NFKC", value).casefold()
    # Decompose after NFKC so precomposed accents and attacker-supplied
    # combining marks receive the same mark-stripping treatment.
    for character in unicodedata.normalize("NFKD", nfkc_text):
        if is_default_ignorable(character):
            continue
        category = unicodedata.category(character)
        if category[0] == "M":
            continue
        if character.isspace() or category[0] in {"P", "S", "Z"}:
            characters.append(" ")
        else:
            characters.append(character)
    return " ".join("".join(characters).split())


def require_bounded_free_text(value: Any, label: str) -> str:
    """Reject authority language from operator-controlled record strings."""

    text = require_string(value, label)
    normalized = normalize_free_text_for_claim_scan(text)
    for claim_id, pattern in FORBIDDEN_FREE_TEXT_AUTHORITY_PATTERNS:
        if pattern.search(normalized):
            raise HardwareObservationError(
                f"{label} contains reserved authority language: {claim_id}"
            )
    return text


def require_false(value: Any, label: str) -> None:
    if value is not False:
        raise HardwareObservationError(f"{label} must be false")


def require_hex(value: Any, length: int, label: str) -> str:
    text = require_string(value, label)
    if len(text) != length or re.fullmatch(r"[0-9a-f]+", text) is None:
        raise HardwareObservationError(f"{label} must be {length} lowercase hexadecimal characters")
    return text


def verify_timestamp(value: Any) -> None:
    text = require_string(value, "observation.observed_at_utc")
    if not text.endswith("Z"):
        raise HardwareObservationError("observation.observed_at_utc must be an explicit UTC timestamp ending in Z")
    try:
        observed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise HardwareObservationError("observation.observed_at_utc must be valid RFC 3339") from exc
    if observed.tzinfo != timezone.utc:
        raise HardwareObservationError("observation.observed_at_utc must use UTC")


def verify_record(value: Any) -> dict[str, Any]:
    record = require_exact_keys(value, {
        "schema", "release_id", "record_status", "subject", "observation", "claim_boundary"
    }, "record")
    if record["schema"] != SCHEMA:
        raise HardwareObservationError(f"record.schema must be {SCHEMA}")
    if record["release_id"] != "noether-forge-v2.4.0":
        raise HardwareObservationError("record.release_id must be noether-forge-v2.4.0")
    status = require_string(
        record["record_status"], "record.record_status", choices={"fixture-only", "operator-observation"}
    )

    subject = require_exact_keys(record["subject"], {
        "subject_kind", "subject_description", "commit", "iso_filename", "iso_digests"
    }, "subject")
    subject_kind = require_string(
        subject["subject_kind"], "subject.subject_kind",
        choices={"synthetic-fixture", "private-reviewer-built-iso"},
    )
    require_bounded_free_text(subject["subject_description"], "subject.subject_description")
    require_hex(subject["commit"], 40, "subject.commit")
    filename = require_bounded_free_text(subject["iso_filename"], "subject.iso_filename")
    if filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise HardwareObservationError("subject.iso_filename must be a basename")
    digests = require_exact_keys(subject["iso_digests"], {"sha256", "sha384", "sha512"}, "subject.iso_digests")
    require_hex(digests["sha256"], 64, "subject.iso_digests.sha256")
    require_hex(digests["sha384"], 96, "subject.iso_digests.sha384")
    require_hex(digests["sha512"], 128, "subject.iso_digests.sha512")
    if status == "fixture-only" and subject_kind != "synthetic-fixture":
        raise HardwareObservationError("fixture-only records must bind a synthetic-fixture subject")
    if status == "operator-observation" and subject_kind != "private-reviewer-built-iso":
        raise HardwareObservationError("operator-observation records must bind a private-reviewer-built-iso subject")
    if status == "operator-observation" and subject["commit"] == "0" * 40:
        raise HardwareObservationError("operator-observation records must bind a non-placeholder Git commit")

    observation = require_exact_keys(record["observation"], {
        "observed_at_utc", "operator_id", "hardware", "firmware", "capture_host", "tools", "observations"
    }, "observation")
    verify_timestamp(observation["observed_at_utc"])
    require_bounded_free_text(observation["operator_id"], "observation.operator_id")

    hardware = require_exact_keys(
        observation["hardware"], {"manufacturer", "model", "architecture", "identifiers_redacted"},
        "observation.hardware",
    )
    for key in ("manufacturer", "model", "architecture"):
        require_bounded_free_text(hardware[key], f"observation.hardware.{key}")
    if hardware["identifiers_redacted"] is not True:
        raise HardwareObservationError("observation.hardware.identifiers_redacted must be true")

    firmware = require_exact_keys(
        observation["firmware"], {"boot_mode", "vendor", "version", "secure_boot"},
        "observation.firmware",
    )
    require_string(firmware["boot_mode"], "observation.firmware.boot_mode", choices={"bios", "uefi", "other"})
    require_bounded_free_text(firmware["vendor"], "observation.firmware.vendor")
    require_bounded_free_text(firmware["version"], "observation.firmware.version")
    require_string(
        firmware["secure_boot"], "observation.firmware.secure_boot",
        choices={"enabled", "disabled", "not-observed", "not-applicable"},
    )

    capture_host = require_exact_keys(
        observation["capture_host"], {"operating_system", "kernel", "architecture"},
        "observation.capture_host",
    )
    for key in ("operating_system", "kernel", "architecture"):
        require_bounded_free_text(capture_host[key], f"observation.capture_host.{key}")

    tools = observation["tools"]
    if not isinstance(tools, list) or not tools:
        raise HardwareObservationError("observation.tools must be a non-empty array")
    tool_names: set[str] = set()
    for index, item in enumerate(tools):
        tool = require_exact_keys(item, {"name", "version", "purpose"}, f"observation.tools[{index}]")
        for key in ("name", "version", "purpose"):
            require_bounded_free_text(tool[key], f"observation.tools[{index}].{key}")
        if tool["name"] in tool_names:
            raise HardwareObservationError("observation.tools contains a duplicate name")
        tool_names.add(tool["name"])

    observations = observation["observations"]
    if not isinstance(observations, list) or not observations:
        raise HardwareObservationError("observation.observations must be a non-empty array")
    observation_names: set[str] = set()
    for index, item in enumerate(observations):
        entry = require_exact_keys(item, {"name", "result", "notes"}, f"observation.observations[{index}]")
        require_bounded_free_text(entry["name"], f"observation.observations[{index}].name")
        require_string(
            entry["result"], f"observation.observations[{index}].result",
            choices={"observed", "not-observed", "not-tested"},
        )
        require_bounded_free_text(entry["notes"], f"observation.observations[{index}].notes")
        if entry["name"] in observation_names:
            raise HardwareObservationError("observation.observations contains a duplicate name")
        observation_names.add(entry["name"])

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
        info = path.lstat()
    except OSError as exc:
        raise HardwareObservationError(f"observation record is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise HardwareObservationError(f"observation record must be a regular file: {path}")
    if info.st_nlink != 1:
        raise HardwareObservationError(f"observation record hardlink rejected: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HardwareObservationError(f"cannot read observation JSON: {path}") from exc
    return verify_record(value)


def digest_vector(path: Path) -> dict[str, str]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HardwareObservationError(f"subject artifact is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise HardwareObservationError(f"subject artifact must be a regular file: {path}")
    if info.st_nlink != 1:
        raise HardwareObservationError(f"subject artifact hardlink rejected: {path}")
    digests = {name: hashlib.new(name) for name in ("sha256", "sha384", "sha512")}
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            for digest in digests.values():
                digest.update(block)
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
        f"({record['record_status']}; internal consistency only, no hardware validation claim)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
