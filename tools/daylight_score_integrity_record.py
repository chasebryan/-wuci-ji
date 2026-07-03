"""Validate tracked Daylight score-integrity audit records.

This helper intentionally performs only local file checks. It does not create a
website page, contact the network, or bless score claims beyond the generated
reports it validates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path("audits/daylight/score-integrity")
INDEX = ROOT / "index.json"
FORBIDDEN_RE = re.compile(
    r"(/home/|/Users/|/tmp/|Tailscale|tailscale|token|secret|PRIVATE KEY|BEGIN .*KEY|sk-[A-Za-z0-9]|ghp_|github_pat_|password)"
)

REQUIRED_TOP_LEVEL = [
    Path("audits/README.md"),
    Path("audits/daylight/README.md"),
    ROOT / "README.md",
    ROOT / "INDEX.md",
    ROOT / "NON_CLAIMS.md",
    ROOT / "METHODOLOGY.md",
    ROOT / "SITE_PAGE_PLAN.md",
    ROOT / "index.json",
]

REQUIRED_SCHEMAS = [
    "daylight-score-claims.schema.json",
    "ratio-percent-audit.schema.json",
    "public-surface-score-diff.schema.json",
    "daylight-score-integrity-report.schema.json",
    "run-manifest.schema.json",
]

REQUIRED_REPORTS = [
    "daylight-score-claims.json",
    "ratio-percent-audit.json",
    "public-surface-score-diff.json",
    "daylight-score-integrity.report.json",
]

REQUIRED_NOTES = [
    "original-claim-integrity.md",
    "score-family-summary.md",
    "ratio-percentage-math.md",
    "quorum-blocker-boundary.md",
    "public-surface-consistency.md",
    "residual-limitations.md",
]


def stable_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_file(path: Path, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"missing required file: {path.as_posix()}")


def check_forbidden(run_dir: Path, errors: list[str]) -> None:
    for path in sorted(p for p in run_dir.rglob("*") if p.is_file()):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-utf8 audit file: {path.as_posix()}")
            continue
        match = FORBIDDEN_RE.search(text)
        if match:
            errors.append(f"forbidden local/private pattern in {path.as_posix()}: {match.group(0)}")


def check_sha256sums(run_dir: Path, errors: list[str]) -> None:
    sums = run_dir / "SHA256SUMS.txt"
    require_file(sums, errors)
    if not sums.is_file():
        return
    for line_no, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            errors.append(f"malformed SHA256SUMS line {line_no}")
            continue
        expected, raw_path = parts
        path = Path(raw_path.strip())
        if path.name == "SHA256SUMS.txt":
            errors.append("SHA256SUMS.txt must not hash itself")
            continue
        if not path.is_file():
            errors.append(f"SHA256SUMS path missing: {path.as_posix()}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"sha256 mismatch for {path.as_posix()}: expected {expected}, got {actual}")


def check_manifest(run_dir: Path, errors: list[str]) -> dict[str, Any] | None:
    manifest_path = run_dir / "MANIFEST.json"
    require_file(manifest_path, errors)
    if not manifest_path.is_file():
        return None
    try:
        manifest = stable_json(manifest_path)
    except json.JSONDecodeError as exc:
        errors.append(f"MANIFEST.json does not parse: {exc}")
        return None
    if manifest.get("schema") != "wuci.audit.daylight.score_integrity.run_manifest.v1":
        errors.append("MANIFEST.json schema mismatch")
    boundary = manifest.get("non_claim_boundary", {})
    for key, value in boundary.items():
        if value is not False:
            errors.append(f"non-claim boundary must be false: {key}")
    report_entries = manifest.get("reports", [])
    by_path = {entry.get("path"): entry for entry in report_entries}
    for name in REQUIRED_REPORTS:
        path = f"reports/{name}"
        entry = by_path.get(path)
        if entry is None:
            errors.append(f"manifest missing report entry: {path}")
            continue
        report_path = run_dir / path
        require_file(report_path, errors)
        if report_path.is_file() and entry.get("sha256") != sha256_file(report_path):
            errors.append(f"manifest sha256 mismatch: {path}")
    return manifest


def check_index(errors: list[str]) -> tuple[str | None, dict[str, Any] | None]:
    require_file(INDEX, errors)
    if not INDEX.is_file():
        return None, None
    try:
        index = stable_json(INDEX)
    except json.JSONDecodeError as exc:
        errors.append(f"index.json does not parse: {exc}")
        return None, None
    if index.get("schema") != "wuci.audit.daylight.score_integrity.index.v1":
        errors.append("index.json schema mismatch")
    latest = index.get("latest_run")
    if not latest:
        errors.append("index.json latest_run missing")
    runs = index.get("runs", [])
    if latest and not any(run.get("id") == latest for run in runs):
        errors.append("index.json latest_run is not listed in runs")
    return latest, index


def check(args: argparse.Namespace) -> int:
    errors: list[str] = []
    for path in REQUIRED_TOP_LEVEL:
        require_file(path, errors)
    for name in REQUIRED_SCHEMAS:
        path = ROOT / "schemas" / name
        require_file(path, errors)
        if path.is_file():
            try:
                stable_json(path)
            except json.JSONDecodeError as exc:
                errors.append(f"schema does not parse: {path.as_posix()}: {exc}")

    latest, _index = check_index(errors)
    run_id = args.run_id or latest
    if not run_id:
        errors.append("no audit run id available")
    else:
        run_dir = ROOT / "runs" / run_id
        if not run_dir.is_dir():
            errors.append(f"run directory missing: {run_dir.as_posix()}")
        else:
            for name in ["README.md", "MANIFEST.json", "COMMANDS.txt", "VALIDATION.md", "SHA256SUMS.txt"]:
                require_file(run_dir / name, errors)
            for name in REQUIRED_REPORTS:
                require_file(run_dir / "reports" / name, errors)
            for name in REQUIRED_NOTES:
                require_file(run_dir / "notes" / name, errors)
            manifest = check_manifest(run_dir, errors)
            check_sha256sums(run_dir, errors)
            check_forbidden(run_dir, errors)
            if manifest:
                result = manifest.get("result")
                if result not in {"PASS_SCORE_INTEGRITY", "FAIL_SCORE_INTEGRITY", "UNRESOLVED_SCORE_INTEGRITY"}:
                    errors.append(f"unsupported manifest result: {result}")

    if errors:
        for error in errors:
            print(f"daylight-score-integrity-audit-directory-check: {error}", file=sys.stderr)
        return 1
    print(f"daylight-score-integrity-audit-directory-check: OK ({run_id})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight_score_integrity_record")
    parser.add_argument("command", choices=["check"])
    parser.add_argument("--run-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return check(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
