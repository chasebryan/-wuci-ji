#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_release_contingencies as contingencies  # noqa: E402
import wuci_release_gate as gate  # noqa: E402


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def write_fixture_manifest(tmp: Path) -> tuple[Path, Path]:
    tmp.mkdir(parents=True, exist_ok=True)
    iso = tmp / "Wuci-OS-x86_64-musl.iso"
    iso.write_bytes(b"fixture final iso\n")
    iso_sha, iso_bytes = gate.file_digest(iso, "fixture iso")
    manifest = {
        "schema": "wuci-os-final-iso-manifest-v1",
        "status": "built",
        "iso": {
            "path": str(iso),
            "bytes": iso_bytes,
            "digest_vector": {"sha256": iso_sha},
        },
        "validation": {"rootfs_remastered": True},
        "rootfs_remaster": {
            "secure_default_package_closure": {
                "status": "pass",
                "policy": "secure-default-firstboot-v1",
            }
        },
    }
    manifest_path = tmp / "manifest.json"
    manifest_path.write_text(gate.stable_json(manifest), encoding="utf-8")
    return manifest_path, iso


def assert_packet_is_digest_bound_and_pending(tmp: Path) -> None:
    manifest, iso = write_fixture_manifest(tmp / "inputs")
    context = gate.manifest_context(manifest, iso)
    release_gate = tmp / "release-evidence" / "release-gate.json"
    write_json(
        release_gate,
        {
            "schema": "wuci-os-release-gate-v1",
            "status": "blocked",
            "release_allowed": False,
            "blockers": [
                "hardware-boot-trace-missing",
                "final-iso-manifest-signature-missing",
                "witness-ledger-entry-missing",
            ],
        },
    )
    out = tmp / "contingencies"
    packet = contingencies.build_packet(
        manifest=manifest,
        iso=iso,
        release_gate=release_gate,
        out=out,
        force=True,
    )
    assert packet["schema"] == contingencies.SCHEMA
    assert packet["status"] == "pending"
    assert packet["final_iso"]["sha256"] == context["iso_sha256"]
    assert packet["final_manifest"]["sha256"] == context["manifest_sha256"]
    assert "hardware-boot-trace-missing" in packet["release_gate"]["blockers"]

    expected = {
        "contingency-packet.json",
        "FINALIZE-COMMANDS.txt",
        "HARDWARE-TRACE.txt",
        "SIGNING-REQUEST.txt",
        "WITNESS-REQUEST.txt",
    }
    actual = {path.name for path in out.iterdir() if path.is_file()}
    assert expected == actual

    joined = "\n".join(path.read_text(encoding="utf-8") for path in out.iterdir() if path.is_file())
    assert context["iso_sha256"] in joined
    assert context["manifest_sha256"] in joined
    assert "wuci-release-hardware-trace /tmp/wuci-hardware-boot.log" in joined
    assert "minisign -S" in joined
    assert "tools/wuci_release_gate.py witness" in joined
    assert "make wuci-os-release-gate" in joined
    assert '"release_allowed": true' in joined
    assert "Fixture/demo keys or local-only ledgers must not be used" in joined
    assert ".ssh" not in joined
    assert "OPENAI_API_KEY" not in joined
    assert "id_ed25519" not in joined


def assert_missing_release_gate_is_pending(tmp: Path) -> None:
    manifest, iso = write_fixture_manifest(tmp / "inputs")
    packet = contingencies.build_packet(
        manifest=manifest,
        iso=iso,
        release_gate=tmp / "release-evidence" / "release-gate.json",
        out=tmp / "contingencies",
        force=True,
    )
    assert packet["status"] == "pending"
    assert packet["release_gate"]["status"] == "missing"
    assert packet["release_gate"]["release_allowed"] is False


def assert_passed_release_gate_is_ready(tmp: Path) -> None:
    manifest, iso = write_fixture_manifest(tmp / "inputs")
    release_gate = tmp / "release-evidence" / "release-gate.json"
    write_json(
        release_gate,
        {
            "schema": "wuci-os-release-gate-v1",
            "status": "pass",
            "release_allowed": True,
            "blockers": [],
        },
    )
    packet = contingencies.build_packet(
        manifest=manifest,
        iso=iso,
        release_gate=release_gate,
        out=tmp / "contingencies",
        force=True,
    )
    assert packet["status"] == "ready"


def assert_symlink_output_is_rejected(tmp: Path) -> None:
    if not hasattr(os, "symlink"):
        return
    manifest, iso = write_fixture_manifest(tmp / "inputs")
    target = tmp / "real-output"
    target.mkdir()
    out = tmp / "contingencies"
    out.symlink_to(target, target_is_directory=True)
    try:
        contingencies.build_packet(
            manifest=manifest,
            iso=iso,
            release_gate=tmp / "release-evidence" / "release-gate.json",
            out=out,
            force=True,
        )
    except contingencies.ContingencyError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlink output directory was accepted")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-release-contingencies-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_packet_is_digest_bound_and_pending(tmp / "pending")
        assert_missing_release_gate_is_pending(tmp / "missing-gate")
        assert_passed_release_gate_is_ready(tmp / "ready")
        assert_symlink_output_is_rejected(tmp / "symlink")
    print("wuci-release-contingencies tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
