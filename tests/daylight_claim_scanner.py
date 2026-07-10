#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools"
sys.path.insert(0, str(TOOLS))

import daylight_claim_scan as scanner  # noqa: E402
from daylight_standard_validate import ValidationError, validate_object  # noqa: E402


EXPECTED_KEYS = [
    "schema",
    "policy",
    "boundary",
    "inputs",
    "limits",
    "summary",
    "files",
    "findings",
    "errors",
    "status",
]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scan(root: Path, *paths: str, **limits: int) -> dict[str, object]:
    return scanner.scan_paths(list(paths), root=root, **limits)


def run_cli(script: Path, cwd: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_policy_matching() -> None:
    all_positive = "\n".join(phrase.upper() for phrase in scanner.FORBIDDEN_AUTHORITY_PATTERNS)
    occurrences = scanner.claim_phrase_occurrences(all_positive)
    assert len(occurrences) == len(scanner.FORBIDDEN_AUTHORITY_PATTERNS), occurrences
    assert all(not item["negated"] for item in occurrences), occurrences

    mixed = "This is not FIPS validated.\nThis is FIPS validated."
    mixed_occurrences = scanner.claim_phrase_occurrences(mixed)
    assert [(item["line"], item["column"], item["negated"]) for item in mixed_occurrences] == [
        (1, 13, True),
        (2, 9, False),
    ], mixed_occurrences
    assert scanner.unsupported_claims_in_text(mixed) == ["fips validated"]

    repeated = scanner.claim_phrase_occurrences("FIPS-VALIDATED\nfips validated")
    assert len(repeated) == 2 and all(item["phrase"] == "fips validated" for item in repeated)
    assert scanner.claim_phrase_occurrences("prefixfips validatedsuffix") == []
    assert scanner.unsupported_claims_in_text("Not a prototype but it is FIPS validated.") == ["fips validated"]
    assert scanner.unsupported_claims_in_text("Forbidden: FIPS validated.") == []
    assert scanner.unsupported_claims_in_text("Positive trust authority is not implemented.") == []
    unicode_occurrence = scanner.claim_phrase_occurrences("αβ FIPS validated")[0]
    assert (unicode_occurrence["line"], unicode_occurrence["column"]) == (1, 4)


def assert_report_contract() -> None:
    schema = json.loads(
        (REPO / "specs/daylight-equation/v1/daylight-claim-scan-report.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    schema_phrases = schema["properties"]["findings"]["items"]["properties"]["phrase"]["enum"]
    assert schema_phrases == list(scanner.FORBIDDEN_AUTHORITY_PATTERNS)

    with tempfile.TemporaryDirectory(prefix="daylight-claim-report-") as tmp_name:
        root = Path(tmp_name)
        write(root / "b.md", "This is FIPS validated.\n")
        write(root / "a.md", "This does not claim production cryptography.\n")
        first = scan(root, "b.md", ".")
        second = scan(root, ".", "b.md")
        assert scanner.dump_report(first) == scanner.dump_report(second)
        assert list(first) == EXPECTED_KEYS
        assert first["status"] == "fail"
        assert first["inputs"] == [".", "b.md"]
        assert [item["path"] for item in first["files"]] == ["a.md", "b.md"]
        assert first["summary"]["files_scanned"] == 2
        assert first["summary"]["phrase_occurrences"] == 2
        assert first["summary"]["negated_occurrences"] == 1
        assert first["summary"]["unsupported_occurrences"] == 1
        assert first["findings"] == [
            {"path": "b.md", "line": 1, "column": 9, "phrase": "fips validated"}
        ]
        assert all(not item["path"].startswith("/") for item in first["files"])
        validate_object(first)

        mutated = json.loads(scanner.dump_report(first))
        mutated["extra"] = True
        try:
            validate_object(mutated)
        except ValidationError:
            pass
        else:
            raise AssertionError("claim report schema accepted an extra field")

        mutated = json.loads(scanner.dump_report(first))
        mutated["status"] = "pass"
        try:
            validate_object(mutated)
        except ValidationError:
            pass
        else:
            raise AssertionError("claim report contract accepted pass with findings")


def assert_invalid_inputs_and_limits() -> None:
    with tempfile.TemporaryDirectory(prefix="daylight-claim-missing-") as tmp_name:
        root = Path(tmp_name)
        report = scan(root, "missing.md")
        assert report["status"] == "invalid-input"
        assert [item["code"] for item in report["errors"]] == ["input-not-found"]
        validate_object(report)

    with tempfile.TemporaryDirectory(prefix="daylight-claim-utf8-") as tmp_name:
        root = Path(tmp_name)
        (root / "invalid.md").write_bytes(b"\xff\n")
        report = scan(root, "invalid.md")
        assert [item["code"] for item in report["errors"]] == ["invalid-utf8"]
        validate_object(report)

    with tempfile.TemporaryDirectory(prefix="daylight-claim-size-") as tmp_name:
        root = Path(tmp_name)
        (root / "exact.md").write_bytes(b"12345678")
        assert scan(root, "exact.md", max_file_bytes=8)["status"] == "pass"
        (root / "over.md").write_bytes(b"123456789")
        report = scan(root, "over.md", max_file_bytes=8)
        assert [item["code"] for item in report["errors"]] == ["file-too-large"]

    with tempfile.TemporaryDirectory(prefix="daylight-claim-count-") as tmp_name:
        root = Path(tmp_name)
        for index in range(3):
            write(root / f"{index}.md", "bounded\n")
        assert scan(root, "0.md", "1.md", max_files=2)["status"] == "pass"
        report = scan(root, ".", max_files=2)
        assert [item["code"] for item in report["errors"]] == ["max-files-exceeded"]

    with tempfile.TemporaryDirectory(prefix="daylight-claim-total-") as tmp_name:
        root = Path(tmp_name)
        (root / "a.md").write_bytes(b"1234")
        (root / "b.md").write_bytes(b"5678")
        assert scan(root, ".", max_total_bytes=8)["status"] == "pass"
        (root / "c.md").write_bytes(b"9")
        report = scan(root, ".", max_total_bytes=8)
        assert [item["code"] for item in report["errors"]] == ["max-total-bytes-exceeded"]

    with tempfile.TemporaryDirectory(prefix="daylight-claim-link-") as tmp_name:
        root = Path(tmp_name)
        target = root / "target.md"
        write(target, "bounded\n")
        symlink = root / "linked.md"
        try:
            symlink.symlink_to(target)
        except (OSError, NotImplementedError):
            pass
        else:
            report = scan(root, "linked.md")
            assert [item["code"] for item in report["errors"]] == ["input-symlink"]

    with tempfile.TemporaryDirectory(prefix="daylight-claim-hardlink-") as tmp_name:
        root = Path(tmp_name)
        target = root / "target.md"
        write(target, "bounded\n")
        hardlink = root / "hardlink.md"
        try:
            os.link(target, hardlink)
        except (OSError, NotImplementedError):
            pass
        else:
            assert target.stat().st_nlink > 1
            report = scan(root, "hardlink.md")
            assert [item["code"] for item in report["errors"]] == ["input-hardlink"]

    if hasattr(os, "mkfifo"):
        with tempfile.TemporaryDirectory(prefix="daylight-claim-fifo-") as tmp_name:
            root = Path(tmp_name)
            fifo = root / "claim.pipe"
            try:
                os.mkfifo(fifo)
            except (OSError, NotImplementedError):
                pass
            else:
                report = scan(root, "claim.pipe")
                assert [item["code"] for item in report["errors"]] == ["input-not-regular"]


def assert_cli_contract() -> None:
    conformance = TOOLS / "daylight_conformance.py"
    standalone = TOOLS / "daylight_claim_scan.py"
    with tempfile.TemporaryDirectory(prefix="daylight-claim-cli-") as tmp_name:
        root = Path(tmp_name)
        write(root / "clean.md", "This does not claim production cryptography.\n")
        write(root / "bad.md", "This is FIPS validated.\n")

        clean = run_cli(conformance, root, "reject-overclaims", "--path", "clean.md")
        assert clean.returncode == 0, clean.stderr
        assert clean.stdout == b"clean.md: no unsupported authority claims\n"

        bad = run_cli(conformance, root, "reject-overclaims", "--path", "bad.md")
        assert bad.returncode == 1
        assert b"bad.md: unsupported authority phrase: fips validated (line 1, column 9)" in bad.stderr

        missing = run_cli(conformance, root, "reject-overclaims", "--path", "missing.md")
        assert missing.returncode == 2
        assert b"input-not-found" in missing.stderr and b"Traceback" not in missing.stderr

        standalone_json = run_cli(standalone, root, "--path", "bad.md")
        wrapper_json = run_cli(
            conformance,
            root,
            "reject-overclaims",
            "--path",
            "bad.md",
            "--report",
            "-",
        )
        assert standalone_json.returncode == wrapper_json.returncode == 1
        assert standalone_json.stdout == wrapper_json.stdout
        validate_object(json.loads(standalone_json.stdout.decode("utf-8")))

        report_path = root / "build" / "claim-report.json"
        file_report = run_cli(
            conformance,
            root,
            "reject-overclaims",
            "--path",
            "clean.md",
            "--report",
            str(report_path.relative_to(root)),
        )
        assert file_report.returncode == 0 and file_report.stdout == b""
        validate_object(json.loads(report_path.read_text(encoding="utf-8")))

        overlap = run_cli(
            standalone,
            root,
            "--path",
            ".",
            "--out",
            "nested/report.json",
        )
        assert overlap.returncode == 2
        assert b"must not overlap" in overlap.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description="Test the Daylight Claim Firewall MVP.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    assert_policy_matching()
    assert_report_contract()
    assert_invalid_inputs_and_limits()
    assert_cli_contract()
    if not args.quiet:
        print("daylight claim scanner: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
