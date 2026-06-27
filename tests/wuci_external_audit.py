#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL = REPO_ROOT / "tools" / "wuci_external_audit.py"


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def run_tool(*args: str) -> subprocess.CompletedProcess[bytes]:
    return run_cmd([sys.executable, str(TOOL), *args])


def assert_ok(proc: subprocess.CompletedProcess[bytes], context: str) -> None:
    assert proc.returncode == 0, (
        context,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def current_commit() -> str:
    proc = run_cmd(["git", "rev-parse", "HEAD"])
    assert_ok(proc, "read current git commit")
    return proc.stdout.decode("ascii").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI external audit evidence tooling.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="wuci-external-audit-") as tmp_name:
        tmp = Path(tmp_name)
        report = tmp / "external-audit-report.txt"
        evidence = tmp / "external-audit.json"
        report.write_text(
            "WUCI external audit fixture report\n"
            "scope: crypto, pq-verifier, production-authority, release-bundle, runtime-sandbox\n",
            encoding="ascii",
        )
        assert_ok(
            run_tool(
                "emit",
                "--repo",
                str(REPO_ROOT),
                "--report",
                str(report),
                "--auditor",
                "Example Security Lab",
                "--audit-id",
                "external-audit-test-v1",
                "--reviewed-commit",
                current_commit(),
                "--completed-utc",
                "2026-06-27T00:00:00Z",
                "--production-sufficient",
                "--out",
                str(evidence),
                "--quiet",
            ),
            "emit external audit evidence",
        )

        unsigned = run_tool(
            "verify",
            "--repo",
            str(REPO_ROOT),
            "--evidence",
            str(evidence),
            "--report",
            str(report),
            "--quiet",
        )
        assert unsigned.returncode != 0
        assert b"signed external audit evidence" in unsigned.stderr

        allowed = run_tool(
            "verify",
            "--repo",
            str(REPO_ROOT),
            "--evidence",
            str(evidence),
            "--report",
            str(report),
            "--allow-unsigned-audit",
            "--json",
        )
        assert_ok(allowed, "verify unsigned external audit in explicit test mode")
        summary = json.loads(allowed.stdout.decode("utf-8"))
        assert summary["schema"] == "wuci-external-audit-verification-v1"
        assert summary["external_audit_verified"] is True
        assert summary["production_sufficient"] is True
        assert summary["signature_verified"] is False

        tampered_report = tmp / "tampered-report.txt"
        tampered_report.write_text(report.read_text(encoding="ascii") + "tampered\n", encoding="ascii")
        bad_report = run_tool(
            "verify",
            "--repo",
            str(REPO_ROOT),
            "--evidence",
            str(evidence),
            "--report",
            str(tampered_report),
            "--allow-unsigned-audit",
            "--quiet",
        )
        assert bad_report.returncode != 0
        assert b"report SHA-256 mismatch" in bad_report.stderr

        bad_evidence = tmp / "bad-external-audit.json"
        value = json.loads(evidence.read_text(encoding="utf-8"))
        value["scope"] = ["crypto"]
        bad_evidence.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        bad_scope = run_tool(
            "verify",
            "--repo",
            str(REPO_ROOT),
            "--evidence",
            str(bad_evidence),
            "--report",
            str(report),
            "--allow-unsigned-audit",
            "--quiet",
        )
        assert bad_scope.returncode != 0
        assert b"scope missing required entries" in bad_scope.stderr

        ssh_keygen = shutil.which("ssh-keygen")
        if ssh_keygen:
            signing_key = tmp / "audit_signing_key"
            signature = tmp / "external-audit.json.sig"
            keygen = run_cmd(
                [
                    ssh_keygen,
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(signing_key),
                ]
            )
            assert_ok(keygen, "generate external audit signing key")
            root_key = signing_key.with_suffix(".pub")
            assert_ok(
                run_tool(
                    "sign-evidence",
                    "--evidence",
                    str(evidence),
                    "--signing-key",
                    str(signing_key),
                    "--audit-root-key",
                    str(root_key),
                    "--signature",
                    str(signature),
                    "--quiet",
                ),
                "sign external audit evidence",
            )
            signed = run_tool(
                "verify",
                "--repo",
                str(REPO_ROOT),
                "--evidence",
                str(evidence),
                "--report",
                str(report),
                "--audit-root-key",
                str(root_key),
                "--signature",
                str(signature),
                "--json",
            )
            assert_ok(signed, "verify signed external audit evidence")
            signed_summary = json.loads(signed.stdout.decode("utf-8"))
            assert signed_summary["signature_verified"] is True

    if not args.quiet:
        print("wuci external audit: PASS")


if __name__ == "__main__":
    main()
