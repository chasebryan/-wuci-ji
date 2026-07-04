#!/usr/bin/env python3
"""Gate Daylight/Penumbra coupling on external gap attestations.

Angel does not create cryptographic strength, production authority, runtime
containment, or quantum-safety claims. It verifies that local external
attestation artifacts exist, are pinned by SHA-256, use an allowed issuer class
for each declared gap, and avoid reserved overclaims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import wuci_safeio


MANIFEST_SCHEMA = "wuci-angel-gap-manifest-v1"
ATTESTATION_SCHEMA = "wuci-angel-attestation-v1"
REPORT_SCHEMA = "wuci-angel-gap-report-v1"
REGISTRY_SCHEMA = "wuci-angel-gap-registry-v1"
DEFAULT_MANIFEST = Path("build/wuci-angel/angel-gap-manifest.json")
DEFAULT_REPORT = Path("build/wuci-angel/angel-gap-report.json")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

GAP_REGISTRY: dict[str, dict[str, Any]] = {
    "penumbra.crypto-integration.external-review": {
        "owner": "penumbra",
        "title": "independent review of the AEAD/HKDF/codec integration",
        "issuer_classes": ("independent-reviewer", "cryptographic-reviewer"),
        "requirement": "External review must be pinned; Penumbra cannot self-certify its implementation quality.",
    },
    "penumbra.secret-entropy.external-bound": {
        "owner": "penumbra",
        "title": "deployment-specific H-infinity bound for the secret witness component",
        "issuer_classes": ("deployment-operator", "independent-reviewer"),
        "requirement": "A deployment operator or reviewer must attest the witness entropy boundary.",
    },
    "penumbra.meridian-rederiver.external-attestation": {
        "owner": "penumbra",
        "title": "production Meridian transcript re-deriver attestation",
        "issuer_classes": ("deployment-operator", "independent-reviewer"),
        "requirement": "The production re-deriver is external to the library and must be attested separately.",
    },
    "daylight.independent-external-review": {
        "owner": "daylight",
        "title": "independent review residue for Daylight score and claim discipline",
        "issuer_classes": ("independent-reviewer",),
        "requirement": "Daylight scores local evidence; independent review lives outside that score.",
    },
    "daylight.production-authority.external-root": {
        "owner": "daylight",
        "title": "production release/trust authority root evidence",
        "issuer_classes": ("release-authority", "production-authority"),
        "requirement": "Production authority must come from an external root, not fixture material.",
    },
    "daylight.operated-witness-ledger.external-entry": {
        "owner": "daylight",
        "title": "operated witness ledger entry or inclusion evidence",
        "issuer_classes": ("operated-ledger",),
        "requirement": "An operated ledger entry is external residue; local assertions do not retire this gap.",
    },
    "host.containment-posture.external-evidence": {
        "owner": "host",
        "title": "external host containment posture evidence",
        "issuer_classes": ("containment-auditor", "deployment-operator"),
        "requirement": "Host containment claims are out of scope unless externally evidenced and bounded.",
    },
}

DEFAULT_REQUIRED_GAPS = tuple(GAP_REGISTRY)
ALLOWED_ISSUER_CLASSES = sorted({cls for gap in GAP_REGISTRY.values() for cls in gap["issuer_classes"]})
FIXTURE_ISSUER_TOKENS = {"demo", "example", "fixture", "sample", "self", "test", "testing"}
FORBIDDEN_OVERCLAIMS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bunbreakable\b", re.IGNORECASE), "unbreakable"),
    (re.compile(r"\buncrackable\b", re.IGNORECASE), "uncrackable"),
    (re.compile(r"\bperfect secrecy\b", re.IGNORECASE), "perfect secrecy"),
    (re.compile(r"\bimpossible to break\b", re.IGNORECASE), "impossible to break"),
    (re.compile(r"\bguaranteed secure\b", re.IGNORECASE), "guaranteed secure"),
    (re.compile(r"\b100%\s+secure\b", re.IGNORECASE), "100% secure"),
    (re.compile(r"\bquantum[- ]proof\b", re.IGNORECASE), "quantum-proof"),
    (re.compile(r"\bquantum[- ]safe\b", re.IGNORECASE), "quantum-safe"),
    (re.compile(r"\bpost[- ]quantum\s+immune\b", re.IGNORECASE), "post-quantum immune"),
    (re.compile(r"\bruntime\s+sandboxed\b", re.IGNORECASE), "runtime sandboxed"),
    (re.compile(r"\bno[- ]network\s+sandbox\b", re.IGNORECASE), "no-network sandbox"),
)
NON_CLAIMS = (
    "Angel records local external residue; it does not verify the real-world truth of that residue.",
    "Angel is not production authority, an operated ledger, a runtime sandbox, or a PQ verifier.",
    "Angel does not replace Daylight scoring or Penumbra proof-gated opening.",
)


class AngelError(RuntimeError):
    """Expected Angel gate error."""


def stable_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_hex64(value: Any, context: str) -> str:
    if not isinstance(value, str) or HEX64_RE.fullmatch(value) is None:
        raise AngelError(f"{context} must be a lowercase SHA-256 hex digest")
    return value


def validate_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or ID_RE.fullmatch(value) is None:
        raise AngelError(f"{context} must match {ID_RE.pattern}")
    return value


def validate_utc(value: Any, context: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise AngelError(f"{context} must use YYYY-MM-DDTHH:MM:SSZ")
    return value


def validate_relative_path(value: Any, context: str) -> Path:
    if not isinstance(value, str) or not value:
        raise AngelError(f"{context} must be a non-empty relative path")
    if "\\" in value:
        raise AngelError(f"{context} must use POSIX separators")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise AngelError(f"{context} must stay under the manifest directory: {value!r}")
    return Path(*pure.parts)


def read_bytes(path: Path, context: str, *, max_bytes: int = 1024 * 1024) -> bytes:
    try:
        return wuci_safeio.read_regular_bytes(
            path,
            context,
            reject_symlink=True,
            reject_hardlink=True,
            max_bytes=max_bytes,
        )
    except wuci_safeio.SafeIOError as exc:
        raise AngelError(str(exc)) from exc


def reject_symlink_ancestors(root: Path, rel: Path, context: str) -> None:
    current = root
    for part in rel.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise AngelError(f"{context} parent is missing: {current}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise AngelError(f"{context} parent must not be a symlink: {current}")
        if not stat.S_ISDIR(info.st_mode):
            raise AngelError(f"{context} parent must be a directory: {current}")


def read_json(path: Path, context: str) -> tuple[dict[str, Any], bytes]:
    data = read_bytes(path, context)
    try:
        value = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise AngelError(f"{context} is not UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise AngelError(f"{context} is not valid JSON: {path}: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise AngelError(f"{context} must be a JSON object: {path}")
    return value, data


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    try:
        wuci_safeio.atomic_replace_text(path, stable_json(value), "Angel JSON report", mode=0o644)
    except wuci_safeio.SafeIOError as exc:
        raise AngelError(str(exc)) from exc


def gap_registry_public() -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for gap_id, gap in GAP_REGISTRY.items():
        gaps.append(
            {
                "id": gap_id,
                "issuer_classes": list(gap["issuer_classes"]),
                "owner": gap["owner"],
                "requirement": gap["requirement"],
                "title": gap["title"],
            }
        )
    return gaps


def gap_registry_digest() -> str:
    payload = {"schema": REGISTRY_SCHEMA, "gaps": gap_registry_public()}
    return sha256_bytes(stable_json(payload).encode("ascii"))


def manifest_template() -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA,
        "subject": {
            "name": "penumbra-daylight-coupling",
            "scope": "local external gap gate",
        },
        "required_gaps": list(DEFAULT_REQUIRED_GAPS),
        "attestations": [
            {
                "path": "angel-attestations/review.json",
                "sha256": "replace-with-lowercase-sha256-of-review-json",
            }
        ],
        "non_claims": list(NON_CLAIMS),
    }


def attestation_template(attestation_id: str, issuer: str, issuer_class: str, fills: list[str]) -> dict[str, Any]:
    return {
        "schema": ATTESTATION_SCHEMA,
        "attestation_id": attestation_id,
        "issuer": issuer,
        "issuer_class": issuer_class,
        "completed_utc": "2026-07-04T00:00:00Z",
        "fills": fills,
        "subject_sha256": "replace-with-lowercase-subject-sha256",
        "statement": "Bounded external attestation for the listed Angel gaps.",
        "offensive_tooling_included": False,
        "non_claims": list(NON_CLAIMS),
    }


def validate_manifest(value: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    if value.get("schema") != MANIFEST_SCHEMA:
        raise AngelError(f"unsupported Angel manifest schema: {value.get('schema')!r}")
    subject = value.get("subject", {})
    if not isinstance(subject, dict):
        raise AngelError("Angel manifest subject must be a JSON object")
    required_raw = value.get("required_gaps", list(DEFAULT_REQUIRED_GAPS))
    if not isinstance(required_raw, list) or not required_raw:
        raise AngelError("Angel manifest required_gaps must be a non-empty list")
    required: list[str] = []
    seen: set[str] = set()
    for item in required_raw:
        if not isinstance(item, str):
            raise AngelError("Angel manifest required_gaps entries must be strings")
        if item not in GAP_REGISTRY:
            raise AngelError(f"unknown Angel gap: {item}")
        if item in seen:
            raise AngelError(f"duplicate Angel gap: {item}")
        seen.add(item)
        required.append(item)
    attestations = value.get("attestations", [])
    if not isinstance(attestations, list):
        raise AngelError("Angel manifest attestations must be a list")
    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(attestations):
        if not isinstance(entry, dict):
            raise AngelError(f"Angel manifest attestation entry {index} must be an object")
        entries.append(entry)
    return subject, required, entries


def _issuer_uses_fixture_material(issuer: str) -> bool:
    tokens = {token for token in re.split(r"[^a-z0-9]+", issuer.lower()) if token}
    return bool(tokens.intersection(FIXTURE_ISSUER_TOKENS))


def _string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise AngelError(f"{context} must be a {'possibly empty ' if allow_empty else ''}list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise AngelError(f"{context}[{index}] must be a non-empty string")
        result.append(item)
    return result


def _forbidden_overclaims(strings: list[str]) -> list[str]:
    findings: list[str] = []
    for text in strings:
        for pattern, label in FORBIDDEN_OVERCLAIMS:
            if pattern.search(text):
                findings.append(label)
    return sorted(set(findings))


def _invalid_attestation_record(entry: dict[str, Any], issues: list[str]) -> dict[str, Any]:
    return {
        "status": "invalid",
        "path": str(entry.get("path", "")),
        "sha256": str(entry.get("sha256", "")),
        "attestation_id": None,
        "issuer": None,
        "issuer_class": None,
        "fills": [],
        "credited_gaps": [],
        "issues": issues,
    }


def validate_attestation_entry(entry: dict[str, Any], manifest_dir: Path) -> dict[str, Any]:
    try:
        rel = validate_relative_path(entry.get("path"), "Angel attestation path")
        expected_sha256 = validate_hex64(entry.get("sha256"), "Angel attestation sha256")
    except AngelError as exc:
        return _invalid_attestation_record(entry, [str(exc)])

    path = manifest_dir / rel
    try:
        reject_symlink_ancestors(manifest_dir, rel, f"Angel attestation {rel.as_posix()}")
        data = read_bytes(path, f"Angel attestation {rel.as_posix()}")
    except AngelError as exc:
        return _invalid_attestation_record(entry | {"path": rel.as_posix(), "sha256": expected_sha256}, [str(exc)])

    actual_sha256 = sha256_bytes(data)
    if actual_sha256 != expected_sha256:
        return _invalid_attestation_record(
            entry | {"path": rel.as_posix(), "sha256": expected_sha256},
            [f"attestation digest mismatch: expected={expected_sha256} actual={actual_sha256}"],
        )

    try:
        value = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        return _invalid_attestation_record(entry | {"path": rel.as_posix(), "sha256": expected_sha256}, [f"attestation is not UTF-8: {exc}"])
    except json.JSONDecodeError as exc:
        return _invalid_attestation_record(entry | {"path": rel.as_posix(), "sha256": expected_sha256}, [f"attestation is not valid JSON: {exc.msg}"])
    if not isinstance(value, dict):
        return _invalid_attestation_record(entry | {"path": rel.as_posix(), "sha256": expected_sha256}, ["attestation must be a JSON object"])

    issues: list[str] = []

    def capture(fn: Any) -> Any:
        try:
            return fn()
        except AngelError as exc:
            issues.append(str(exc))
            return None

    if value.get("schema") != ATTESTATION_SCHEMA:
        issues.append(f"unsupported Angel attestation schema: {value.get('schema')!r}")
    attestation_id = capture(lambda: validate_id(value.get("attestation_id"), "Angel attestation_id"))
    issuer = value.get("issuer")
    if not isinstance(issuer, str) or not issuer.strip():
        issues.append("Angel attestation issuer must be a non-empty string")
        issuer = None
    elif _issuer_uses_fixture_material(issuer):
        issues.append("Angel attestation issuer must not be fixture, demo, sample, test, example, or self-issued")
    issuer_class = value.get("issuer_class")
    if not isinstance(issuer_class, str) or issuer_class not in ALLOWED_ISSUER_CLASSES:
        issues.append("Angel attestation issuer_class is not allowed")
        issuer_class = None
    capture(lambda: validate_utc(value.get("completed_utc"), "Angel completed_utc"))
    fills = capture(lambda: _string_list(value.get("fills"), "Angel fills")) or []
    if len(set(fills)) != len(fills):
        issues.append("Angel fills must not contain duplicates")
    for gap_id in fills:
        if gap_id not in GAP_REGISTRY:
            issues.append(f"unknown Angel filled gap: {gap_id}")
        elif issuer_class is not None and issuer_class not in GAP_REGISTRY[gap_id]["issuer_classes"]:
            issues.append(f"issuer_class {issuer_class!r} is not authorized for gap {gap_id}")
    statement = value.get("statement")
    statement_strings: list[str] = []
    if not isinstance(statement, str) or not statement.strip():
        issues.append("Angel attestation statement must be a non-empty string")
    else:
        statement_strings.append(statement)
    claims = value.get("claims", [])
    if claims != []:
        if not isinstance(claims, list):
            issues.append("Angel claims must be a list when present")
        else:
            for index, claim in enumerate(claims):
                if not isinstance(claim, str) or not claim.strip():
                    issues.append(f"Angel claims[{index}] must be a non-empty string")
                else:
                    statement_strings.append(claim)
    overclaims = _forbidden_overclaims(statement_strings)
    if overclaims:
        issues.append("Angel attestation contains reserved overclaim(s): " + ", ".join(overclaims))
    if value.get("offensive_tooling_included") is not False:
        issues.append("Angel attestation offensive_tooling_included must be false")
    non_claims = value.get("non_claims")
    if not isinstance(non_claims, list) or not non_claims:
        issues.append("Angel attestation non_claims must be a non-empty list")
    else:
        for index, item in enumerate(non_claims):
            if not isinstance(item, str) or not item.strip():
                issues.append(f"Angel non_claims[{index}] must be a non-empty string")
    if "subject_sha256" in value:
        capture(lambda: validate_hex64(value.get("subject_sha256"), "Angel subject_sha256"))

    status = "pass" if not issues else "invalid"
    return {
        "status": status,
        "path": rel.as_posix(),
        "sha256": actual_sha256,
        "attestation_id": attestation_id,
        "issuer": issuer,
        "issuer_class": issuer_class,
        "fills": fills,
        "credited_gaps": fills if status == "pass" else [],
        "issues": issues,
    }


def apply_duplicate_id_guard(records: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = {}
    for record in records:
        attestation_id = record.get("attestation_id")
        if isinstance(attestation_id, str):
            counts[attestation_id] = counts.get(attestation_id, 0) + 1
    duplicates = {attestation_id for attestation_id, count in counts.items() if count > 1}
    if not duplicates:
        return
    for record in records:
        attestation_id = record.get("attestation_id")
        if attestation_id in duplicates:
            record["status"] = "invalid"
            record["credited_gaps"] = []
            record.setdefault("issues", []).append(f"duplicate Angel attestation_id: {attestation_id}")


def evaluate_manifest(manifest_path: Path) -> dict[str, Any]:
    manifest, manifest_bytes = read_json(manifest_path, "Angel manifest")
    subject, required_gaps, attestation_entries = validate_manifest(manifest)
    manifest_sha256 = sha256_bytes(manifest_bytes)
    manifest_dir = manifest_path.parent

    records = [validate_attestation_entry(entry, manifest_dir) for entry in attestation_entries]
    apply_duplicate_id_guard(records)

    credited_by_gap: dict[str, list[str]] = {gap_id: [] for gap_id in required_gaps}
    for record in records:
        if record["status"] != "pass":
            continue
        attestation_id = record.get("attestation_id")
        for gap_id in record["credited_gaps"]:
            if gap_id in credited_by_gap and isinstance(attestation_id, str):
                credited_by_gap[gap_id].append(attestation_id)

    gap_results: list[dict[str, Any]] = []
    gap_blockers: list[str] = []
    for gap_id in required_gaps:
        gap = GAP_REGISTRY[gap_id]
        credited = sorted(set(credited_by_gap[gap_id]))
        status = "pass" if credited else "blocked"
        if not credited:
            gap_blockers.append(gap_id)
        gap_results.append(
            {
                "id": gap_id,
                "status": status,
                "owner": gap["owner"],
                "title": gap["title"],
                "required_issuer_classes": list(gap["issuer_classes"]),
                "credited_attestations": credited,
                "requirement": gap["requirement"],
            }
        )

    invalid_blockers = [
        f"attestation-invalid:{record['path'] or 'manifest-entry'}"
        for record in records
        if record["status"] != "pass"
    ]
    blockers = gap_blockers + invalid_blockers

    return {
        "schema": REPORT_SCHEMA,
        "status": "pass" if not blockers else "blocked",
        "coupling_allowed": not blockers,
        "manifest": {
            "path": str(manifest_path),
            "sha256": manifest_sha256,
            "bytes": len(manifest_bytes),
        },
        "subject": subject,
        "gap_registry": {
            "schema": REGISTRY_SCHEMA,
            "sha256": gap_registry_digest(),
            "gaps": gap_registry_public(),
        },
        "required_gaps": gap_results,
        "attestations": records,
        "blockers": blockers,
        "non_claims": list(NON_CLAIMS),
    }


def command_gaps(args: argparse.Namespace) -> int:
    registry = {
        "schema": REGISTRY_SCHEMA,
        "sha256": gap_registry_digest(),
        "allowed_issuer_classes": ALLOWED_ISSUER_CLASSES,
        "gaps": gap_registry_public(),
        "non_claims": list(NON_CLAIMS),
    }
    print(stable_json(registry), end="")
    return 0


def command_template(args: argparse.Namespace) -> int:
    fills = args.fills or ["penumbra.crypto-integration.external-review"]
    value = manifest_template() if args.kind == "manifest" else attestation_template(
        args.attestation_id,
        args.issuer,
        args.issuer_class,
        fills,
    )
    if args.out:
        write_json_atomic(Path(args.out), value)
        print(f"wuci-angel template: {args.out}")
    else:
        print(stable_json(value), end="")
    return 0


def command_gate(args: argparse.Namespace) -> int:
    report = evaluate_manifest(Path(args.manifest))
    out = Path(args.out)
    write_json_atomic(out, report)
    print(f"wuci-angel gate: {report['status']}")
    print(f"coupling_allowed: {str(report['coupling_allowed']).lower()}")
    if report["blockers"]:
        print("blockers:")
        for blocker in report["blockers"]:
            print(f"  - {blocker}")
    print(f"report: {out}")
    return 0 if report["coupling_allowed"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gate Daylight/Penumbra coupling on local external gap evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gaps", help="print the Angel gap registry").set_defaults(func=command_gaps)

    template = subparsers.add_parser("template", help="print or write an Angel manifest/attestation template")
    template.add_argument("kind", choices=("manifest", "attestation"))
    template.add_argument("--out", help="optional output path")
    template.add_argument("--attestation-id", default="external-review-001")
    template.add_argument("--issuer", default="Replace With External Issuer")
    template.add_argument("--issuer-class", default="independent-reviewer", choices=ALLOWED_ISSUER_CLASSES)
    template.add_argument(
        "--fills",
        action="append",
        default=None,
        choices=list(GAP_REGISTRY),
        help="gap filled by an attestation template; repeatable",
    )
    template.set_defaults(func=command_template)

    gate = subparsers.add_parser("gate", help="evaluate an Angel gap manifest")
    gate.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Angel gap manifest path")
    gate.add_argument("--out", default=str(DEFAULT_REPORT), help="Angel gap report output path")
    gate.set_defaults(func=command_gate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except AngelError as exc:
        print(f"wuci-angel: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
