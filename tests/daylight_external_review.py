#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
TOOL = REPO / "tools" / "daylight_external_review.py"


def run_cmd(argv: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        argv,
        cwd=REPO,
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
    assert_ok(proc, "read current commit")
    return proc.stdout.decode("ascii").strip()


def keygen(path: Path) -> None:
    ssh_keygen = shutil.which("ssh-keygen")
    assert ssh_keygen is not None, "ssh-keygen is required for signed review tests"
    assert_ok(
        run_cmd([ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(path)]),
        "generate review signing key",
    )


def emit_review(tmp: Path, name: str, reviewer: str, completed: str) -> dict[str, Path]:
    report = tmp / f"{name}-report.txt"
    evidence = tmp / f"{name}.json"
    key = tmp / f"{name}-signing-key"
    signature = tmp / f"{name}.json.sig"
    report.write_text(
        f"Daylight v0.6 external review fixture report: {reviewer}\n"
        "scope: formal model, provider-backed vectors, cryptographic boundary, "
        "production-authority blockers, claim discipline\n",
        encoding="ascii",
    )
    assert_ok(
        run_tool(
            "emit",
            "--repo",
            str(REPO),
            "--report",
            str(report),
            "--reviewer",
            reviewer,
            "--review-id",
            name,
            "--reviewed-commit",
            current_commit(),
            "--completed-utc",
            completed,
            "--production-blocking-findings-closed",
            "--out",
            str(evidence),
            "--quiet",
        ),
        f"emit review {name}",
    )
    keygen(key)
    root_key = key.with_suffix(".pub")
    assert_ok(
        run_tool(
            "sign-evidence",
            "--evidence",
            str(evidence),
            "--signing-key",
            str(key),
            "--review-root-key",
            str(root_key),
            "--signature",
            str(signature),
            "--quiet",
        ),
        f"sign review {name}",
    )
    return {
        "evidence": evidence,
        "report": report,
        "key": key,
        "root_key": root_key,
        "signature": signature,
    }


def write_manifest(path: Path, reviews: list[dict[str, Path]]) -> None:
    value = {
        "schema": "daylight-v06-external-review-set-v1",
        "subject": "Daylight_v0.6",
        "reviews": [
            {
                "evidence": item["evidence"].name,
                "report": item["report"].name,
                "review_root_key": item["root_key"].name,
                "signature": item["signature"].name,
            }
            for item in reviews
        ],
    }
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Daylight external review verifier.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="daylight-external-review-") as tmp_name:
        tmp = Path(tmp_name)
        review_a = emit_review(tmp, "daylight-review-a", "Example Review Lab A", "2026-06-27T00:00:00Z")
        review_b = emit_review(tmp, "daylight-review-b", "Example Review Lab B", "2026-06-27T01:00:00Z")

        unsigned = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(review_a["evidence"]),
            "--report",
            str(review_a["report"]),
            "--quiet",
        )
        assert unsigned.returncode != 0
        assert b"signed Daylight external review evidence" in unsigned.stderr

        single = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(review_a["evidence"]),
            "--report",
            str(review_a["report"]),
            "--review-root-key",
            str(review_a["root_key"]),
            "--signature",
            str(review_a["signature"]),
            "--json",
        )
        assert_ok(single, "verify signed single review")
        single_summary = json.loads(single.stdout.decode("utf-8"))
        assert single_summary["external_review_verified"] is True
        assert single_summary["signature_verified"] is True

        manifest = tmp / "reviews.json"
        write_manifest(manifest, [review_a, review_b])
        review_set = run_tool("verify-set", "--repo", str(REPO), "--manifest", str(manifest), "--json")
        assert_ok(review_set, "verify signed review set")
        summary = json.loads(review_set.stdout.decode("utf-8"))
        assert summary["external_review_set_verified"] is True
        assert summary["review_count"] == 2
        assert len({item["reviewer_identity"] for item in summary["reviews"]}) == 2
        assert len({item["root_key_sha256"] for item in summary["reviews"]}) == 2

        duplicate_manifest = tmp / "duplicate-reviews.json"
        write_manifest(duplicate_manifest, [review_a, review_a])
        duplicate = run_tool("verify-set", "--repo", str(REPO), "--manifest", str(duplicate_manifest), "--quiet")
        assert duplicate.returncode != 0
        assert b"two distinct review ids" in duplicate.stderr

        tampered_report = tmp / "tampered-report.txt"
        tampered_report.write_text(review_a["report"].read_text(encoding="ascii") + "tampered\n", encoding="ascii")
        tampered = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(review_a["evidence"]),
            "--report",
            str(tampered_report),
            "--review-root-key",
            str(review_a["root_key"]),
            "--signature",
            str(review_a["signature"]),
            "--quiet",
        )
        assert tampered.returncode != 0
        assert b"review report SHA-256 mismatch" in tampered.stderr

        bad_scope = tmp / "bad-scope.json"
        value = json.loads(review_a["evidence"].read_text(encoding="utf-8"))
        value["scope"] = ["formal-model"]
        bad_scope.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        bad = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(bad_scope),
            "--report",
            str(review_a["report"]),
            "--allow-unsigned-review",
            "--quiet",
        )
        assert bad.returncode != 0
        assert b"review scope missing required entries" in bad.stderr

    if not args.quiet:
        print("Daylight external review verifier: PASS")


if __name__ == "__main__":
    main()
