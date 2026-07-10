#!/usr/bin/env python3
"""Stdlib-only validation for the Daylight Equation Standard v1."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from daylight_claim_scan import (
        FORBIDDEN_AUTHORITY_PATTERNS,
        phrase_is_negated,
        scan_paths as scan_claim_paths,
        unsupported_claims_in_text,
    )
except ImportError:  # pragma: no cover - package import path used by tests
    from tools.daylight_claim_scan import (  # type: ignore[no-redef]
        FORBIDDEN_AUTHORITY_PATTERNS,
        phrase_is_negated,
        scan_paths as scan_claim_paths,
        unsupported_claims_in_text,
    )


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "specs" / "daylight-equation" / "v1"
EXAMPLE_DIR = ROOT / "examples" / "daylight-standard"

SCHEMA_BY_TAG = {
    "daylight-equation-standard-v1": "daylight-equation.v1.schema.json",
    "daylight-claim-v1": "daylight-claim.v1.schema.json",
    "daylight-evidence-v1": "daylight-evidence.v1.schema.json",
    "daylight-attestation-v1": "daylight-attestation.v1.schema.json",
    "daylight-scorecard-v1": "daylight-scorecard.v1.schema.json",
    "daylight-release-gate-v1": "daylight-release-gate.v1.schema.json",
    "daylight-control-map-v1": "daylight-control-map.v1.schema.json",
    "daylight-monitor-signal-v1": "daylight-monitor-signal.v1.schema.json",
    "daylight-conformance-report-v1": "daylight-conformance-report.v1.schema.json",
    "daylight-claim-scan-report-v1": "daylight-claim-scan-report.v1.schema.json",
}


class ValidationError(Exception):
    pass


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def schema_path_for_tag(tag: str) -> Path:
    try:
        return SCHEMA_DIR / SCHEMA_BY_TAG[tag]
    except KeyError as exc:
        raise ValidationError(f"unknown schema tag: {tag}") from exc


def load_schema_for_object(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise ValidationError("top-level JSON value must be an object")
    tag = obj.get("schema")
    if not isinstance(tag, str):
        raise ValidationError("object is missing string schema field")
    return load_json(schema_path_for_tag(tag))


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def _check_type(value: Any, expected: str, path: str) -> None:
    checks = {
        "object": lambda item: isinstance(item, dict),
        "array": lambda item: isinstance(item, list),
        "string": lambda item: isinstance(item, str),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "boolean": lambda item: isinstance(item, bool),
    }
    if expected not in checks:
        return
    if not checks[expected](value):
        raise ValidationError(f"{path}: expected {expected}, got {_type_name(value)}")


def validate_against_schema(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "type" in schema:
        _check_type(value, schema["type"], path)

    if "const" in schema and value != schema["const"]:
        raise ValidationError(f"{path}: expected const {schema['const']!r}")

    if "enum" in schema and value not in schema["enum"]:
        raise ValidationError(f"{path}: value {value!r} is not in enum")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValidationError(f"{path}: string shorter than minLength")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise ValidationError(f"{path}: string does not match pattern {schema['pattern']!r}")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationError(f"{path}: integer below minimum {schema['minimum']}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise ValidationError(f"{path}: array shorter than minItems")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_against_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ValidationError(f"{path}: missing required key {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            allowed = set(properties)
            for key in value:
                if key not in allowed:
                    raise ValidationError(f"{path}: unexpected key {key}")
        for key, child_schema in properties.items():
            if key in value and isinstance(child_schema, dict):
                validate_against_schema(value[key], child_schema, f"{path}.{key}")


def validate_claim_scan_report_contract(obj: dict[str, Any]) -> None:
    summary = obj["summary"]
    files = obj["files"]
    findings = obj["findings"]
    errors = obj["errors"]
    inputs = obj["inputs"]

    if inputs != sorted(set(inputs)):
        raise ValidationError("$.inputs: paths must be sorted and unique")
    file_paths = [item["path"] for item in files]
    if file_paths != sorted(set(file_paths)):
        raise ValidationError("$.files: paths must be sorted and unique")
    if findings != sorted(
        findings,
        key=lambda item: (item["path"], item["line"], item["column"], item["phrase"]),
    ):
        raise ValidationError("$.findings: entries must use deterministic source order")
    if errors != sorted(errors, key=lambda item: (item["path"], item["code"], item["message"])):
        raise ValidationError("$.errors: entries must use deterministic order")
    if summary["files_scanned"] != len(files):
        raise ValidationError("$.summary.files_scanned: must equal files length")
    if summary["bytes_scanned"] != sum(item["bytes"] for item in files):
        raise ValidationError("$.summary.bytes_scanned: must equal scanned file bytes")
    if summary["phrase_occurrences"] != (
        summary["negated_occurrences"] + summary["unsupported_occurrences"]
    ):
        raise ValidationError("$.summary.phrase_occurrences: must equal negated plus unsupported")
    if summary["unsupported_occurrences"] != len(findings):
        raise ValidationError("$.summary.unsupported_occurrences: must equal findings length")

    status = obj["status"]
    if status == "pass" and (findings or errors):
        raise ValidationError("$.status: pass report must not contain findings or errors")
    if status == "fail" and (not findings or errors):
        raise ValidationError("$.status: fail report requires findings and no input errors")
    if status == "invalid-input" and not errors:
        raise ValidationError("$.status: invalid-input report requires at least one input error")


def validate_object(obj: dict[str, Any]) -> None:
    validate_against_schema(obj, load_schema_for_object(obj))
    if obj.get("schema") == "daylight-claim-scan-report-v1":
        validate_claim_scan_report_contract(obj)


def iter_schema_files() -> list[Path]:
    return sorted(SCHEMA_DIR.glob("daylight-*.schema.json"))


def iter_example_files() -> list[Path]:
    return sorted(EXAMPLE_DIR.glob("*.json"))


def validate_schema_documents() -> list[str]:
    findings: list[str] = []
    expected = {SCHEMA_DIR / name for name in SCHEMA_BY_TAG.values()}
    actual = set(iter_schema_files())
    for missing in sorted(expected - actual):
        findings.append(f"missing schema file: {missing.relative_to(ROOT)}")
    for path in iter_schema_files():
        try:
            schema = load_json(path)
        except json.JSONDecodeError as exc:
            findings.append(f"{path.relative_to(ROOT)}: invalid JSON: {exc}")
            continue
        for key in ["$schema", "$id", "title", "type", "required", "properties"]:
            if key not in schema:
                findings.append(f"{path.relative_to(ROOT)}: missing {key}")
        if schema.get("type") != "object":
            findings.append(f"{path.relative_to(ROOT)}: top-level type must be object")
        if not isinstance(schema.get("required"), list) or not schema["required"]:
            findings.append(f"{path.relative_to(ROOT)}: required must be a non-empty list")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            findings.append(f"{path.relative_to(ROOT)}: properties must be object")
            continue
        for required_key in schema.get("required", []):
            if required_key not in properties:
                findings.append(f"{path.relative_to(ROOT)}: required key {required_key} missing property")
    return findings


def policy_findings(obj: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    schema = obj.get("schema")
    if schema == "daylight-claim-v1":
        text = str(obj.get("claim_text", ""))
        for phrase in unsupported_claims_in_text(text):
            findings.append(f"unsupported authority claim in {obj.get('claim_id')}: {phrase}")
        score_impact = obj.get("score_impact", {})
        if isinstance(score_impact, dict) and score_impact.get("manual_score_allowed") is not False:
            findings.append(f"manual score is not rejected in {obj.get('claim_id')}")
        if not obj.get("evidence_refs") and obj.get("status") not in {"forbidden", "non-claim"}:
            findings.append(f"NoEvidence({obj.get('claim_id')}) -> NoScore")
    elif schema == "daylight-scorecard-v1":
        if obj.get("manual_score_rejected") is not True:
            findings.append(f"scorecard {obj.get('scorecard_id')} does not reject manual score")
        if obj.get("unsupported_claims"):
            findings.append(f"scorecard {obj.get('scorecard_id')} carries unsupported claims")
    elif schema == "daylight-attestation-v1":
        if obj.get("claim_usable") is True and str(obj.get("signature", "")).lower() in {"fixture", "unsigned"}:
            findings.append(f"claim-usable attestation {obj.get('attestation_id')} is fixture or unsigned")
    elif schema == "daylight-release-gate-v1":
        if obj.get("decision") == "pass" and not obj.get("required_evidence"):
            findings.append(f"release {obj.get('release_id')} passes without required evidence")
    return findings


def validate_examples() -> list[str]:
    findings: list[str] = []
    for path in iter_example_files():
        try:
            obj = load_json(path)
            validate_object(obj)
        except (json.JSONDecodeError, ValidationError) as exc:
            findings.append(f"{path.relative_to(ROOT)}: {exc}")

    claim = load_json(EXAMPLE_DIR / "minimal-claim.json")
    broken = dict(claim)
    broken.pop("claim_id")
    try:
        validate_object(broken)
        findings.append("deliberately broken claim without claim_id was accepted")
    except ValidationError:
        pass

    unsupported = load_json(EXAMPLE_DIR / "unsupported-certification-claim.json")
    if not policy_findings(unsupported):
        findings.append("unsupported certification claim did not produce a policy finding")

    no_evidence_gate = load_json(EXAMPLE_DIR / "release-gate-fail-no-evidence.json")
    if no_evidence_gate.get("decision") != "fail" or "publish" not in no_evidence_gate.get("blocked_actions", []):
        findings.append("no-evidence release gate is not a failing closed example")

    claim_scan_example = load_json(EXAMPLE_DIR / "claim-scan-report-example.json")
    regenerated_claim_scan = scan_claim_paths(
        claim_scan_example["inputs"],
        root=ROOT,
        max_file_bytes=claim_scan_example["limits"]["max_file_bytes"],
        max_files=claim_scan_example["limits"]["max_files"],
        max_total_bytes=claim_scan_example["limits"]["max_total_bytes"],
    )
    if regenerated_claim_scan != claim_scan_example:
        findings.append("claim scan report example is not reproducible from its declared input")

    return findings


def command_schema_test(_args: argparse.Namespace) -> int:
    findings = validate_schema_documents()
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("daylight standard schema test: pass")
    return 0


def command_examples_test(_args: argparse.Namespace) -> int:
    findings = validate_examples()
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("daylight standard examples test: pass")
    return 0


def command_validate(args: argparse.Namespace) -> int:
    path = Path(args.input)
    obj = load_json(path)
    try:
        validate_object(obj)
    except ValidationError as exc:
        print(f"{path}: {exc}", file=sys.stderr)
        return 1
    findings = policy_findings(obj) if args.policy else []
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 2
    print(f"{path}: valid")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    schema_test = sub.add_parser("schema-test")
    schema_test.set_defaults(func=command_schema_test)

    examples_test = sub.add_parser("examples-test")
    examples_test.set_defaults(func=command_examples_test)

    validate = sub.add_parser("validate")
    validate.add_argument("--input", required=True)
    validate.add_argument("--policy", action="store_true")
    validate.set_defaults(func=command_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
