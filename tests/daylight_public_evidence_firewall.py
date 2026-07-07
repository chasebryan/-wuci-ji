#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools import daylight_public_evidence_firewall as firewall


SAFE_FILES = {
    "scorecard.v15-meridian.json": b"{}\n",
    "reproducibility-receipt.v15-meridian.json": b"{}\n",
    "frontier-report.v15-meridian.json": b"{}\n",
    "frontier-report.v15-meridian.md": b"frontier\n",
    "ledger.with-scorecard.jsonl": b"{}\n",
}


def write_clean_public(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    outputs = {}
    for name, data in SAFE_FILES.items():
        (root / name).write_bytes(data)
        outputs[name] = {"sha256": firewall.sha256_file(root / name)}
    manifest = {"manifest_version": "test", "outputs": outputs}
    (root / "artifact-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    sums = "".join(
        f"{firewall.sha256_file(root / name)}  {name}\n"
        for name in sorted(set(SAFE_FILES) | {"artifact-manifest.json"})
    )
    (root / "SHA256SUMS").write_text(sums, encoding="utf-8")


def assert_rejects(root: Path, reason: str) -> None:
    result = firewall.scan_root(root, profile="daylight-v15-meridian-public", max_file_bytes=5_000_000)
    assert not result["ok"], result
    assert any(reason in item["reason"] for item in result["violations"]), result


def assert_workflow_rejects(text: str, reason: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "workflow.yml"
        path.write_text(text, encoding="utf-8")
        result = firewall.check_workflow(path)
    assert not result["ok"], result
    assert any(reason in item["reason"] for item in result["violations"]), result


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "public"
        write_clean_public(root)
        result = firewall.scan_root(root, profile="daylight-v15-meridian-public", max_file_bytes=5_000_000)
        assert result["ok"], result
        manifest = firewall.verify_manifest(root / "artifact-manifest.json", root)
        assert manifest["ok"], manifest

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "manifest-traversal"
        write_clean_public(root)
        manifest_path = root / "artifact-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["outputs"]["../outside.txt"] = {"sha256": "0" * 64}
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
        result = firewall.verify_manifest(manifest_path, root)
        assert not result["ok"], result
        assert any("unsafe_manifest_output" in item["reason"] for item in result["violations"]), result

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "vault-key"
        write_clean_public(root)
        (root / "vault.key").write_text("1" * 64 + "\n", encoding="ascii")
        assert_rejects(root, "forbidden_private_material_suffix")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "smoke-secret"
        write_clean_public(root)
        (root / "smoke-secret.txt").write_text("smoke\n", encoding="utf-8")
        assert_rejects(root, "forbidden_secret_path")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "vault-work"
        write_clean_public(root)
        (root / "vault-work").mkdir()
        (root / "vault-work" / "secret.txt").write_text("plaintext\n", encoding="utf-8")
        assert_rejects(root, "public_artifact_contains_private_directory")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "codex-auth"
        write_clean_public(root)
        (root / ".codex").mkdir()
        (root / ".codex" / "auth.json").write_text('{"refresh_token":"' + "A" * 32 + '"}\n', encoding="utf-8")
        assert_rejects(root, "public_artifact_contains_private_directory")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "oversize"
        write_clean_public(root)
        (root / "large.txt").write_bytes(b"A" * 32)
        result = firewall.scan_root(root, profile=None, max_file_bytes=8)
        assert not result["ok"], result
        assert any("file_exceeds_public_artifact_size_limit" in item["reason"] for item in result["violations"]), result

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "oracle"
        write_clean_public(root)
        (root / "index.json").write_text('{"plaintext_bytes": 5, "sha256": "' + "a" * 64 + '"}\n', encoding="utf-8")
        assert_rejects(root, "plaintext_sha256_oracle")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "symlink"
        write_clean_public(root)
        private = Path(tmp) / "private.key"
        private.write_text("1" * 64 + "\n", encoding="ascii")
        try:
            (root / "linked-key").symlink_to(private)
        except (OSError, NotImplementedError):
            pass
        else:
            assert_rejects(root, "symlink_inside_public_artifact")

    assert_workflow_rejects(
        """
name: bad
on: [push]
jobs:
  x:
    steps:
      - name: Upload
        uses: actions/upload-artifact@abc
        with:
          path: build/daylight/v15-meridian/
          if-no-files-found: error
""",
        "broad_upload_root",
    )

    assert_workflow_rejects(
        """
name: bad
on: [push]
permissions:
  contents: read
jobs:
  x:
    steps:
      - name: Upload
        uses: actions/upload-artifact@abc
        with:
          path: build/daylight/v15-meridian-public/
          if-no-files-found: error
""",
        "workflow_upload_without_firewall",
    )

    assert_workflow_rejects(
        """
name: bad
on: [push]
permissions:
  contents: read
jobs:
  x:
    steps:
      - name: Public evidence firewall
        run: make daylight-public-artifact-firewall
      - name: Upload
        uses: actions/upload-artifact@abc
        with:
          path: build/daylight/v15-meridian-public/
          if-no-files-found: warn
""",
        "artifact_upload_warns_on_missing_files",
    )

    print("daylight public evidence firewall: PASS")


if __name__ == "__main__":
    main()
