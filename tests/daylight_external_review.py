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
    keygen(key)
    root_key = key.with_suffix(".pub")
    assert_ok(
        run_tool(
            "emit",
            "--repo",
            str(REPO),
            "--report",
            str(report),
            "--review-root-key",
            str(root_key),
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


def emit_set_manifest(
    path: Path,
    reviews: list[dict[str, Path]],
) -> subprocess.CompletedProcess[bytes]:
    assert len(reviews) == 2
    return run_tool(
        "emit-set",
        "--review-a-evidence",
        reviews[0]["evidence"].name,
        "--review-a-report",
        reviews[0]["report"].name,
        "--review-a-root-key",
        reviews[0]["root_key"].name,
        "--review-a-signature",
        reviews[0]["signature"].name,
        "--review-b-evidence",
        reviews[1]["evidence"].name,
        "--review-b-report",
        reviews[1]["report"].name,
        "--review-b-root-key",
        reviews[1]["root_key"].name,
        "--review-b-signature",
        reviews[1]["signature"].name,
        "--out",
        str(path),
        "--quiet",
    )


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
        assert single_summary["root_key_sha256"] == json.loads(
            review_a["evidence"].read_text(encoding="utf-8")
        )["review_root_key_sha256"]

        mismatch_key = tmp / "mismatch-review-key"
        keygen(mismatch_key)
        mismatch = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(review_a["evidence"]),
            "--report",
            str(review_a["report"]),
            "--review-root-key",
            str(mismatch_key.with_suffix(".pub")),
            "--signature",
            str(review_a["signature"]),
            "--quiet",
        )
        assert mismatch.returncode != 0
        assert b"Daylight external review signature verification failed" in mismatch.stderr

        digest_mismatch_evidence = tmp / "digest-mismatch-review.json"
        digest_mismatch_signature = tmp / "digest-mismatch-review.json.sig"
        digest_mismatch_value = json.loads(review_a["evidence"].read_text(encoding="utf-8"))
        digest_mismatch_value["review_root_key_sha256"] = json.loads(
            review_b["evidence"].read_text(encoding="utf-8")
        )["review_root_key_sha256"]
        digest_mismatch_evidence.write_text(
            json.dumps(digest_mismatch_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        assert_ok(
            run_tool(
                "sign-evidence",
                "--evidence",
                str(digest_mismatch_evidence),
                "--signing-key",
                str(review_a["key"]),
                "--review-root-key",
                str(review_a["root_key"]),
                "--signature",
                str(digest_mismatch_signature),
                "--quiet",
            ),
            "sign root-key digest mismatch review",
        )
        digest_mismatch = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(digest_mismatch_evidence),
            "--report",
            str(review_a["report"]),
            "--review-root-key",
            str(review_a["root_key"]),
            "--signature",
            str(digest_mismatch_signature),
            "--quiet",
        )
        assert digest_mismatch.returncode != 0
        assert b"review root key SHA-256 mismatch" in digest_mismatch.stderr

        self_claiming_review = tmp / "self-claiming-review.json"
        self_claiming_value = json.loads(review_a["evidence"].read_text(encoding="utf-8"))
        self_claiming_value["external_review_verified"] = True
        self_claiming_review.write_text(
            json.dumps(self_claiming_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self_claiming = run_tool(
            "verify",
            "--repo",
            str(REPO),
            "--evidence",
            str(self_claiming_review),
            "--report",
            str(review_a["report"]),
            "--allow-unsigned-review",
            "--quiet",
        )
        assert self_claiming.returncode != 0
        assert b"unexpected Daylight external review evidence fields" in self_claiming.stderr

        manifest = tmp / "reviews.json"
        assert_ok(
            emit_set_manifest(manifest, [review_a, review_b]),
            "emit signed review set manifest",
        )
        manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
        assert manifest_value["schema"] == "daylight-v06-external-review-set-v1"
        assert manifest_value["reviews"][0]["evidence"] == review_a["evidence"].name
        assert "external review set manifests do not create production authority" in manifest_value["non_claims"]
        overwrite = emit_set_manifest(manifest, [review_a, review_b])
        assert overwrite.returncode != 0
        assert b"could not create new Daylight external review set" in overwrite.stderr
        absolute_manifest = tmp / "absolute-reviews.json"
        absolute_emit = run_tool(
            "emit-set",
            "--review-a-evidence",
            str(review_a["evidence"]),
            "--review-a-report",
            review_a["report"].name,
            "--review-a-root-key",
            review_a["root_key"].name,
            "--review-a-signature",
            review_a["signature"].name,
            "--review-b-evidence",
            review_b["evidence"].name,
            "--review-b-report",
            review_b["report"].name,
            "--review-b-root-key",
            review_b["root_key"].name,
            "--review-b-signature",
            review_b["signature"].name,
            "--out",
            str(absolute_manifest),
            "--quiet",
        )
        assert absolute_emit.returncode != 0
        assert b"portable relative path" in absolute_emit.stderr
        assert not absolute_manifest.exists()
        review_set = run_tool("verify-set", "--repo", str(REPO), "--manifest", str(manifest), "--json")
        assert_ok(review_set, "verify signed review set")
        summary = json.loads(review_set.stdout.decode("utf-8"))
        assert summary["external_review_set_verified"] is True
        assert summary["review_count"] == 2
        assert len({item["reviewer_identity"] for item in summary["reviews"]}) == 2
        assert len({item["root_key_sha256"] for item in summary["reviews"]}) == 2

        duplicate_manifest = tmp / "duplicate-reviews.json"
        assert_ok(
            emit_set_manifest(duplicate_manifest, [review_a, review_a]),
            "emit duplicate review set manifest",
        )
        duplicate = run_tool("verify-set", "--repo", str(REPO), "--manifest", str(duplicate_manifest), "--quiet")
        assert duplicate.returncode != 0
        assert b"two distinct review ids" in duplicate.stderr

        escaping_manifest = tmp / "escaping-reviews.json"
        escaping_value = json.loads(manifest.read_text(encoding="utf-8"))
        escaping_value["reviews"][0]["evidence"] = "../escape.json"
        escaping_manifest.write_text(
            json.dumps(escaping_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        escaping = run_tool("verify-set", "--repo", str(REPO), "--manifest", str(escaping_manifest), "--quiet")
        assert escaping.returncode != 0
        assert b"portable relative path" in escaping.stderr

        self_claiming_manifest = tmp / "self-claiming-reviews.json"
        self_claiming_value = json.loads(manifest.read_text(encoding="utf-8"))
        self_claiming_value["external_review_set_verified"] = True
        self_claiming_manifest.write_text(
            json.dumps(self_claiming_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self_claiming = run_tool(
            "verify-set",
            "--repo",
            str(REPO),
            "--manifest",
            str(self_claiming_manifest),
            "--quiet",
        )
        assert self_claiming.returncode != 0
        assert b"unexpected Daylight external review set fields" in self_claiming.stderr

        self_claiming_entry_manifest = tmp / "self-claiming-entry-reviews.json"
        self_claiming_entry_value = json.loads(manifest.read_text(encoding="utf-8"))
        self_claiming_entry_value["reviews"][0]["signature_verified"] = True
        self_claiming_entry_manifest.write_text(
            json.dumps(self_claiming_entry_value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self_claiming_entry = run_tool(
            "verify-set",
            "--repo",
            str(REPO),
            "--manifest",
            str(self_claiming_entry_manifest),
            "--quiet",
        )
        assert self_claiming_entry.returncode != 0
        assert b"unexpected review set entry fields" in self_claiming_entry.stderr

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
