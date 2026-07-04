#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_release_privacy_audit as audit  # noqa: E402


def assert_clean_release_tree_passes(tmp: Path) -> None:
    root = tmp / "release"
    root.mkdir()
    (root / "manifest.json").write_text('{"name":"Wuci-Ji v2.2"}\n', encoding="utf-8")
    report = audit.audit_paths([root])
    assert report["status"] == "pass", report
    assert report["summary"]["findings"] == 0


def assert_secret_values_are_redacted(tmp: Path) -> None:
    root = tmp / "secret-release"
    root.mkdir()
    secret = "sk-proj-" + ("A" * 48)
    (root / "bad.txt").write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
    report = audit.audit_paths([root])
    assert report["status"] == "fail"
    assert any(item["kind"] == "openai_api_key" for item in report["findings"])
    encoded = json.dumps(report, sort_keys=True)
    assert secret not in encoded
    assert "match_sha256_16" in encoded


def assert_sensitive_paths_fail(tmp: Path) -> None:
    root = tmp / "path-release"
    ssh = root / ".ssh"
    ssh.mkdir(parents=True)
    (ssh / "id_ed25519").write_text("not a real key\n", encoding="utf-8")
    report = audit.audit_paths([root])
    assert report["status"] == "fail"
    assert any(item["kind"] == "sensitive_path" and item["indicator"] == ".ssh" for item in report["findings"])


def assert_archive_members_are_scanned(tmp: Path) -> None:
    root = tmp / "archives"
    root.mkdir()
    zip_path = root / "candidate.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(".config/gh/hosts.yml", "token: github_pat_" + ("B" * 40))
    report = audit.audit_paths([root])
    assert report["status"] == "fail"
    assert any(".config/gh/hosts.yml" in item["path"] for item in report["findings"])
    assert "github_pat_" not in json.dumps(report, sort_keys=True)

    tar_path = root / "candidate.ova"
    with tarfile.open(tar_path, "w") as archive:
        payload = (
            b"-----BEGIN "
            + b"PRIVATE KEY-----\n"
            + b"ZmFrZS1idXQtc2hhcGVkLWxpa2UtYS1wZW0tYmxvY2s=\n"
            + b"-----END "
            + b"PRIVATE KEY-----\n"
        )
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        archive.addfile(info, fileobj=__import__("io").BytesIO(payload))
    report = audit.audit_paths([tar_path])
    assert report["status"] == "fail"
    assert any(item["kind"] == "private_key_block" for item in report["findings"])


def assert_marker_only_and_raw_iso_do_not_fail(tmp: Path) -> None:
    root = tmp / "marker-release"
    root.mkdir()
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    (root / "scanner.py").write_text(f'PATTERN = "{marker}"\n', encoding="utf-8")
    (root / "artifact.iso").write_bytes(b"random iso bytes sk-ssh-ed25519@openssh.com " + marker.encode("ascii") + b"\n")
    report = audit.audit_paths([root])
    assert report["status"] == "pass", report
    iso_records = [item for item in report["scanned_files"] if item["path"].endswith("artifact.iso")]
    assert iso_records and iso_records[0]["content_scan"] == "skipped-raw-iso-container"


def assert_symlinks_are_rejected(tmp: Path) -> None:
    if not hasattr(os, "symlink"):
        return
    root = tmp / "symlink-release"
    root.mkdir()
    target = tmp / "target.txt"
    target.write_text("private\n", encoding="utf-8")
    (root / "link.txt").symlink_to(target)
    report = audit.audit_paths([root])
    assert report["status"] == "fail"
    assert any(item["kind"] == "unsafe_file" for item in report["findings"])


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-privacy-audit-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_clean_release_tree_passes(tmp)
        assert_secret_values_are_redacted(tmp)
        assert_sensitive_paths_fail(tmp)
        assert_archive_members_are_scanned(tmp)
        assert_marker_only_and_raw_iso_do_not_fail(tmp)
        assert_symlinks_are_rejected(tmp)
    print("wuci-release-privacy-audit tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
