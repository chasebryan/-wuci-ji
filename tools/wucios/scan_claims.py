#!/usr/bin/env python3
"""Scan current WuciOS public surfaces for denied claim phrases."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DENIED_PHRASES = ROOT / "wucios/sets/cantor-denied-claim-phrases.txt"
ALLOWLIST = ROOT / "wucios/sets/cantor-claim-phrase-allowlist.json"
SCAN_EXTENSIONS = {".md", ".html", ".txt", ".cff"}
HISTORICAL_MARKER = "WuciOS-Fluff-Audit: historical-non-authoritative"
SKIP_DIRS = {
    ".git",
    "build",
    "site/assets",
    "docs/wuci-os/assets",
}


def load_phrases() -> list[str]:
    return [
        line.strip()
        for line in DENIED_PHRASES.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_allowlist() -> set[tuple[str, str]]:
    if not ALLOWLIST.is_file():
        return set()
    data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    entries = set()
    for entry in data.get("entries", []):
        path = str(entry.get("path", "")).strip()
        phrase = str(entry.get("phrase", "")).strip().lower()
        if path and phrase:
            entries.add((path, phrase))
    return entries


def should_skip(path: Path, include_archive: bool) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    if not include_archive and (rel == "docs/archive" or rel.startswith("docs/archive/")):
        return True
    for skipped in SKIP_DIRS:
        if rel == skipped or rel.startswith(skipped + "/"):
            return True
    return False


def files_to_scan(include_archive: bool) -> list[Path]:
    candidates: list[Path] = []
    readme = ROOT / "README.md"
    if readme.is_file():
        candidates.append(readme)
    for base in [ROOT / "docs", ROOT / "site"]:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or should_skip(path, include_archive):
                continue
            if path.suffix.lower() in SCAN_EXTENSIONS:
                candidates.append(path)
    return candidates


def is_historical_fixture(lines: list[str]) -> bool:
    return any(HISTORICAL_MARKER in line for line in lines[:20])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-archive", action="store_true", help="also scan docs/archive")
    parser.add_argument(
        "--include-historical",
        action="store_true",
        help="also scan files explicitly marked historical-non-authoritative",
    )
    args = parser.parse_args()

    phrases = load_phrases()
    allowlist = load_allowlist()
    violations: list[str] = []
    allowlisted: list[str] = []
    historical_skipped: list[str] = []

    for path in files_to_scan(args.include_archive):
        rel = path.relative_to(ROOT).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            violations.append(f"{rel}:0: read failed: {exc}")
            continue
        if not args.include_historical and is_historical_fixture(lines):
            historical_skipped.append(rel)
            continue
        for lineno, line in enumerate(lines, start=1):
            lowered = line.lower()
            for phrase in phrases:
                phrase_lower = phrase.lower()
                if phrase_lower not in lowered:
                    continue
                record = f"{rel}:{lineno}: {phrase}"
                if (rel, phrase_lower) in allowlist:
                    allowlisted.append(record)
                else:
                    violations.append(record)

    if allowlisted:
        print("WuciOS fluff audit allowlisted non-claim phrases:")
        for item in allowlisted:
            print(f"ALLOWLISTED {item}")
    if historical_skipped:
        print("WuciOS fluff audit skipped historical non-authoritative fixtures:")
        for item in historical_skipped:
            print(f"HISTORICAL {item}")
    if violations:
        print("WuciOS fluff audit: FAIL")
        for item in violations:
            print(item)
        return 1
    print("WuciOS fluff audit: PASS")
    print(f"- scanned files: {len(files_to_scan(args.include_archive))}")
    print(f"- denied phrase rules: {len(phrases)}")
    print(f"- allowlisted non-claim occurrences: {len(allowlisted)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
