#!/usr/bin/env python3
"""Deterministic, safe-I/O phrase firewall for bounded Daylight claims.

This scanner is defensive claim-policy tooling. It does not attempt semantic
proof, vulnerability discovery, or runtime enforcement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

try:
    import wuci_safeio
    if not hasattr(wuci_safeio, "read_regular_bytes"):
        raise ImportError("wrong wuci_safeio module")
except ImportError:  # pragma: no cover - package import path used by tests
    from tools import wuci_safeio  # type: ignore[no-redef]


SCHEMA = "daylight-claim-scan-report-v1"
POLICY = "daylight-authority-phrase-firewall-v1"
BOUNDARY = (
    "This local phrase firewall detects configured authority phrases. "
    "It does not prove security, certification, production readiness, runtime "
    "containment, quantum safety, or the absence of other unsupported claims."
)

DEFAULT_MAX_FILE_BYTES = 1_048_576
DEFAULT_MAX_FILES = 256
DEFAULT_MAX_TOTAL_BYTES = 8_388_608

FORBIDDEN_AUTHORITY_PATTERNS = (
    "production cryptography",
    "general runtime sandbox",
    "runtime sandboxing",
    "runtime containment",
    "post-quantum secure",
    "quantum-safe",
    "independently audited",
    "department of war approved",
    "government endorsed",
    "government approved",
    "cato authorized",
    "rmf authorized",
    "fips validated",
    "fedramp authorized",
    "common criteria certified",
    "niap certified",
    "production authority",
    "publish authority",
    "trust authority",
    "replacement for edr",
    "replacement for siem",
    "replacement for iam",
)

_CONTRAST_RE = re.compile(r"\b(?:but|however|yet|except)\b", re.IGNORECASE)
_NEGATED_LIST_RE = re.compile(
    r"(?:"
    r"\b(?:do|does|did|must|should|shall|can|could|would)\s+not\s+"
    r"(?:claim|assert|prove|establish|confer|imply|create)\b"
    r"|\bcannot\s+(?:claim|assert|prove|establish|confer|imply|create)\b"
    r"|\bwithout\s+(?:claiming|asserting|proving|establishing|conferring|implying|creating)\b"
    r"|\b(?:forbidden|unsupported|rejected|reserved)\s*:"
    r"|\b(?:forbidden|unsupported|rejected|reserved)\s+"
    r"(?:authority\s+)?(?:claim|claims|language|phrase|phrases|expansion|expansions)\b"
    r"|\bnon[- ]claims?\b"
    r")",
    re.IGNORECASE,
)
_DIRECT_NEGATION_RE = re.compile(
    r"(?:"
    r"\bnot(?:\s+(?:a|an|the))?(?:\s+[\w-]+){0,4}"
    r"|\bno(?:\s+(?:claim|assertion|authority)\s+(?:of|that|to))?"
    r"|\b(?:is|are|was|were|be|being|been)\s+not(?:\s+(?:a|an|the))?"
    r")\s*$",
    re.IGNORECASE,
)
_FOLLOWING_NEGATION_RE = re.compile(
    r"\b(?:is|are|was|were|remain|remains)\s+not\s+"
    r"(?:allowed|authorized|available|claimed|established|implemented|proven|supported)\b",
    re.IGNORECASE,
)


class ClaimScanWriteError(RuntimeError):
    """Raised when a deterministic report cannot be written safely."""


def _phrase_regex(phrase: str) -> re.Pattern[str]:
    tokens = [re.escape(token) for token in re.split(r"[\s-]+", phrase) if token]
    body = r"(?:[\s-]+)".join(tokens)
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)


_PHRASE_REGEXES = tuple((phrase, _phrase_regex(phrase)) for phrase in FORBIDDEN_AUTHORITY_PATTERNS)


def _normalized_clause_prefix(text: str, start: int) -> str:
    prefix = text[max(0, start - 768):start]
    prefix = re.sub(r"(?m)^\s*>\s?", " ", prefix)
    sentence_parts = re.split(r"[.!?;]", prefix)
    clause = sentence_parts[-1]
    contrast_parts = _CONTRAST_RE.split(clause)
    clause = contrast_parts[-1]
    return re.sub(r"\s+", " ", clause).strip().lower()


def _markdown_table_cell_is_non_claim(text: str, start: int) -> bool:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    relative_start = start - line_start
    if "|" not in line[:relative_start]:
        return False
    column = line[:relative_start].count("|") - (1 if line.lstrip().startswith("|") else 0)
    if column < 0:
        return False

    previous_lines = text[max(0, line_start - 512):line_start].splitlines()
    for candidate in reversed(previous_lines[-4:]):
        if "|" not in candidate or re.fullmatch(r"[\s|:-]+", candidate):
            continue
        cells = [cell.strip().lower() for cell in candidate.strip().strip("|").split("|")]
        if column >= len(cells):
            continue
        if re.search(r"\b(?:refuses?|forbidden|non[- ]claim|does not claim)\b", cells[column]):
            return True
    return False


def phrase_is_negated(text: str, start: int, end: int | None = None) -> bool:
    """Return whether the occurrence at *start* is inside an explicit non-claim."""

    if _markdown_table_cell_is_non_claim(text, start):
        return True
    clause = _normalized_clause_prefix(text, start)
    if _DIRECT_NEGATION_RE.search(clause):
        return True
    if _NEGATED_LIST_RE.search(clause):
        return True
    suffix = text[end if end is not None else start:start + 160]
    return bool(_FOLLOWING_NEGATION_RE.search(suffix))


def _line_column(text: str, start: int) -> tuple[int, int]:
    line = text.count("\n", 0, start) + 1
    previous_newline = text.rfind("\n", 0, start)
    return line, start - previous_newline


def claim_phrase_occurrences(text: str) -> list[dict[str, Any]]:
    """Return every configured phrase occurrence in deterministic source order."""

    occurrences: list[dict[str, Any]] = []
    for phrase, pattern in _PHRASE_REGEXES:
        for match in pattern.finditer(text):
            line, column = _line_column(text, match.start())
            occurrences.append({
                "start": match.start(),
                "line": line,
                "column": column,
                "phrase": phrase,
                "negated": phrase_is_negated(text, match.start(), match.end()),
            })
    occurrences.sort(key=lambda item: (item["start"], item["phrase"]))
    return occurrences


def unsupported_claims_in_text(text: str) -> list[str]:
    """Compatibility view returning each unsupported canonical phrase once."""

    unsupported = {
        occurrence["phrase"]
        for occurrence in claim_phrase_occurrences(text)
        if not occurrence["negated"]
    }
    return [phrase for phrase in FORBIDDEN_AUTHORITY_PATTERNS if phrase in unsupported]


def _absolute_lexical(path: Path, root: Path) -> Path:
    candidate = path if path.is_absolute() else root / path
    return Path(os.path.abspath(os.fspath(candidate)))


def _display_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "<outside-scan-root>"
    value = relative.as_posix()
    return value or "."


def _error(path: str, code: str, message: str) -> dict[str, str]:
    return {"path": path, "code": code, "message": message}


def _validate_ancestors(path: Path, root: Path, errors: list[dict[str, str]]) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        errors.append(_error("<outside-scan-root>", "unsafe-input-path", "input must stay under the scan root"))
        return False
    current = root
    for part in relative.parts[:-1]:
        current = current / part
        display = _display_path(current, root)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            errors.append(_error(display, "input-not-found", "input ancestor does not exist"))
            return False
        except OSError:
            errors.append(_error(display, "read-failed", "input ancestor could not be inspected"))
            return False
        if stat.S_ISLNK(info.st_mode):
            errors.append(_error(display, "input-symlink", "input ancestor must not be a symlink"))
            return False
        if not stat.S_ISDIR(info.st_mode):
            errors.append(_error(display, "input-not-regular", "input ancestor must be a directory"))
            return False
    return True


def _discover_path(
    path: Path,
    root: Path,
    files: list[Path],
    seen_files: set[Path],
    seen_directories: set[Path],
    errors: list[dict[str, str]],
    max_files: int,
    limit_reached: list[bool],
) -> None:
    if limit_reached[0]:
        return
    display = _display_path(path, root)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        errors.append(_error(display, "input-not-found", "input does not exist"))
        return
    except OSError:
        errors.append(_error(display, "read-failed", "input could not be inspected"))
        return

    if stat.S_ISLNK(info.st_mode):
        errors.append(_error(display, "input-symlink", "input must not be a symlink"))
        return
    if stat.S_ISREG(info.st_mode):
        if info.st_nlink != 1:
            errors.append(_error(display, "input-hardlink", "input file must not be hardlinked"))
            return
        if path in seen_files:
            return
        if len(files) >= max_files:
            errors.append(_error(display, "max-files-exceeded", "scan exceeds the configured file-count limit"))
            limit_reached[0] = True
            return
        seen_files.add(path)
        files.append(path)
        return
    if stat.S_ISDIR(info.st_mode):
        if path in seen_directories:
            return
        seen_directories.add(path)
        try:
            children = sorted(path.iterdir(), key=lambda child: child.name)
        except OSError:
            errors.append(_error(display, "read-failed", "input directory could not be enumerated"))
            return
        for child in children:
            _discover_path(
                child,
                root,
                files,
                seen_files,
                seen_directories,
                errors,
                max_files,
                limit_reached,
            )
        return
    errors.append(_error(display, "input-not-regular", "input must be a regular file or directory"))


def _base_report(
    inputs: list[str],
    max_file_bytes: int,
    max_files: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "policy": POLICY,
        "boundary": BOUNDARY,
        "inputs": inputs,
        "limits": {
            "max_file_bytes": max_file_bytes,
            "max_files": max_files,
            "max_total_bytes": max_total_bytes,
        },
        "summary": {
            "files_scanned": 0,
            "bytes_scanned": 0,
            "phrase_occurrences": 0,
            "negated_occurrences": 0,
            "unsupported_occurrences": 0,
        },
        "files": [],
        "findings": [],
        "errors": [],
        "status": "pass",
    }


def scan_paths(
    paths: Sequence[str | os.PathLike[str]],
    *,
    root: Path | None = None,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    """Scan explicit files/directories below *root* and return a stable report."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    normalized: list[Path] = []
    initial_errors: list[dict[str, str]] = []
    for raw_path in paths:
        candidate = _absolute_lexical(Path(raw_path), scan_root)
        if candidate in normalized:
            continue
        try:
            candidate.relative_to(scan_root)
        except ValueError:
            initial_errors.append(_error("<outside-scan-root>", "unsafe-input-path", "input must stay under the scan root"))
            continue
        if not _validate_ancestors(candidate, scan_root, initial_errors):
            continue
        normalized.append(candidate)
    normalized.sort(key=lambda path: _display_path(path, scan_root))
    inputs = [_display_path(path, scan_root) for path in normalized]
    reported_limits = [
        value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 1
        for value in (max_file_bytes, max_files, max_total_bytes)
    ]
    report = _base_report(inputs, *reported_limits)
    errors = report["errors"]
    errors.extend(initial_errors)

    for name, value in [
        ("max_file_bytes", max_file_bytes),
        ("max_files", max_files),
        ("max_total_bytes", max_total_bytes),
    ]:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            errors.append(_error("<limits>", "invalid-limit", f"{name} must be a positive integer"))
    if not paths:
        errors.append(_error("<inputs>", "no-inputs", "at least one input path is required"))
    if errors:
        report["errors"] = sorted(errors, key=lambda item: (item["path"], item["code"], item["message"]))
        report["status"] = "invalid-input"
        return report

    discovered: list[Path] = []
    seen_files: set[Path] = set()
    seen_directories: set[Path] = set()
    limit_reached = [False]
    for path in normalized:
        _discover_path(
            path,
            scan_root,
            discovered,
            seen_files,
            seen_directories,
            errors,
            max_files,
            limit_reached,
        )
    discovered.sort(key=lambda path: _display_path(path, scan_root))

    total_bytes = 0
    phrase_occurrences = 0
    negated_occurrences = 0
    findings: list[dict[str, Any]] = []
    file_records: list[dict[str, Any]] = []
    for path in discovered:
        display = _display_path(path, scan_root)
        try:
            info = os.lstat(path)
        except OSError:
            errors.append(_error(display, "read-failed", "input could not be inspected before reading"))
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(_error(display, "input-symlink", "input must not be a symlink"))
            continue
        if not stat.S_ISREG(info.st_mode):
            errors.append(_error(display, "input-not-regular", "input must remain a regular file"))
            continue
        if info.st_nlink != 1:
            errors.append(_error(display, "input-hardlink", "input file must not be hardlinked"))
            continue
        if info.st_size > max_file_bytes:
            errors.append(_error(display, "file-too-large", "input exceeds the configured per-file size limit"))
            continue
        if total_bytes + info.st_size > max_total_bytes:
            errors.append(_error(display, "max-total-bytes-exceeded", "scan exceeds the configured total-byte limit"))
            break
        try:
            data = wuci_safeio.read_regular_bytes(
                path,
                f"claim scan input {display}",
                reject_symlink=True,
                reject_hardlink=True,
                max_bytes=max_file_bytes,
            )
        except wuci_safeio.SafeIOError:
            errors.append(_error(display, "read-failed", "input failed safe regular-file reading"))
            continue
        if total_bytes + len(data) > max_total_bytes:
            errors.append(_error(display, "max-total-bytes-exceeded", "scan exceeds the configured total-byte limit"))
            break
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(_error(display, "invalid-utf8", "input must be valid UTF-8 text"))
            continue

        total_bytes += len(data)
        file_records.append({
            "path": display,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
        occurrences = claim_phrase_occurrences(text)
        phrase_occurrences += len(occurrences)
        negated_occurrences += sum(1 for occurrence in occurrences if occurrence["negated"])
        for occurrence in occurrences:
            if occurrence["negated"]:
                continue
            findings.append({
                "path": display,
                "line": occurrence["line"],
                "column": occurrence["column"],
                "phrase": occurrence["phrase"],
            })

    file_records.sort(key=lambda item: item["path"])
    findings.sort(key=lambda item: (item["path"], item["line"], item["column"], item["phrase"]))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    report["files"] = file_records
    report["findings"] = findings
    report["errors"] = errors
    report["summary"] = {
        "files_scanned": len(file_records),
        "bytes_scanned": sum(item["bytes"] for item in file_records),
        "phrase_occurrences": phrase_occurrences,
        "negated_occurrences": negated_occurrences,
        "unsupported_occurrences": len(findings),
    }
    report["status"] = "invalid-input" if errors else "fail" if findings else "pass"
    return report


def dump_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=True) + "\n"


def write_report(path: Path, report: dict[str, Any]) -> None:
    try:
        wuci_safeio.atomic_replace_text(
            path,
            dump_report(report),
            "Daylight claim scan report",
            mode=0o644,
        )
    except wuci_safeio.SafeIOError as exc:
        raise ClaimScanWriteError("claim scan report could not be written safely") from exc


def report_path_overlaps_inputs(
    output: Path,
    paths: Sequence[str | os.PathLike[str]],
    *,
    root: Path | None = None,
) -> bool:
    """Return whether an output would overwrite or enter a scanned input tree."""

    scan_root = (root or Path.cwd()).resolve(strict=True)
    output_path = _absolute_lexical(output, scan_root)
    for raw_path in paths:
        input_path = _absolute_lexical(Path(raw_path), scan_root)
        try:
            info = os.lstat(input_path)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            if output_path == input_path or input_path in output_path.parents:
                return True
        elif output_path == input_path:
            return True
    return False


def report_exit_code(report: dict[str, Any]) -> int:
    if report["status"] == "invalid-input":
        return 2
    if report["status"] == "fail":
        return 1
    return 0


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", required=True, help="file or directory below the current directory")
    parser.add_argument("--out", default="-", help="report path, or - for stdout")
    parser.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-files", type=_positive_int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_MAX_TOTAL_BYTES)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = scan_paths(
        args.path,
        max_file_bytes=args.max_file_bytes,
        max_files=args.max_files,
        max_total_bytes=args.max_total_bytes,
    )
    if args.out == "-":
        print(dump_report(report), end="")
    else:
        output = _absolute_lexical(Path(args.out), Path.cwd().resolve(strict=True))
        try:
            output.relative_to(Path.cwd().resolve(strict=True))
        except ValueError:
            print("claim scan report path must stay under the current directory", file=sys.stderr)
            return 2
        if report_path_overlaps_inputs(output, args.path):
            print("claim scan report path must not overlap a scanned input", file=sys.stderr)
            return 2
        try:
            write_report(output, report)
        except ClaimScanWriteError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    return report_exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
