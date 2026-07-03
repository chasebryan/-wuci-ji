"""Deterministic DaylightNPT scan reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import TOOL, VERSION
from .classify import Finding, classify_token
from .extract import extract_tokens, is_probably_binary
from .registry import sha256_file

EXCLUDED_DIRS = {".git", "node_modules", "build", "dist", ".tools", "__pycache__", "target"}
DEFAULT_SUFFIXES = {".md", ".json"}


def dumps_stable(data: Any) -> str:
    return json.dumps(data, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"


def repo_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def iter_scan_files(inputs: list[str], root: Path) -> list[Path]:
    files: list[Path] = []
    for raw in inputs:
        path = root / raw
        if not path.exists():
            continue
        if path.is_file():
            if path.suffix.lower() in DEFAULT_SUFFIXES:
                files.append(path)
            continue
        for child in sorted(path.rglob("*")):
            rel_parts = child.relative_to(root).parts
            if any(part in EXCLUDED_DIRS for part in rel_parts):
                continue
            if child.relative_to(root).as_posix().startswith("daylight/npt/v1/examples/negative/"):
                continue
            if child.is_file() and child.suffix.lower() in DEFAULT_SUFFIXES:
                files.append(child)
    return sorted(dict.fromkeys(files), key=lambda item: repo_relative(item, root))


def scan(
    registry: dict[str, Any],
    registry_path: Path,
    inputs: list[str],
    root: Path,
) -> dict[str, Any]:
    all_findings: list[Finding] = []
    files = iter_scan_files(inputs, root)
    numbers_seen = 0
    for path in files:
        if is_probably_binary(path):
            continue
        display_path = repo_relative(path, root)
        try:
            tokens = extract_tokens(path, display_path)
        except (OSError, UnicodeDecodeError):
            continue
        numbers_seen += len(tokens)
        for token in tokens:
            all_findings.extend(classify_token(token, registry, root))

    sorted_findings = sorted(
        [finding.as_dict() for finding in all_findings],
        key=lambda item: (item["path"], item["line"], item["column"], item["code"], item["value_raw"]),
    )
    errors = sum(1 for item in sorted_findings if item["severity"] == "error")
    warnings = sum(1 for item in sorted_findings if item["severity"] == "warning")
    claims = registry.get("claims", [])
    verified = sum(1 for claim in claims if claim.get("status") == "verified")
    report = {
        "schema": "daylight.npt.v1.report",
        "tool": TOOL,
        "version": VERSION,
        "result": "fail" if errors else "pass",
        "summary": {
            "files_scanned": len(files),
            "numbers_seen": numbers_seen,
            "claims_checked": len(claims) + len(sorted_findings),
            "verified": verified,
            "exempt": sum(1 for claim in claims if claim.get("status") in {"exempt", "non_claim", "illustrative"}),
            "warnings": warnings,
            "errors": errors,
        },
        "findings": sorted_findings,
        "registry_sha256": sha256_file(registry_path),
        "inputs": sorted(inputs),
    }
    return report
