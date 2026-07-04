#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_release_bundle as bundle  # noqa: E402


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def write_file(path: Path, data: bytes = b"fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fixture_tree(tmp: Path, *, privacy_status: str = "pass") -> dict[str, Path]:
    root = tmp / "inputs"
    final = root / "final"
    vbox = root / "virtualbox"
    evidence = root / "release-evidence"
    privacy = root / "privacy-audit.json"
    rootfs_privacy = root / "privacy-audit-final-rootfs.json"
    daylight = root / "daylight-ssv.report.json"

    write_file(final / "Wuci-OS-x86_64-musl.iso", b"iso fixture\n")
    write_file(final / "Wuci-OS-x86_64-musl.iso.sha256", b"abc  Wuci-OS-x86_64-musl.iso\n")
    write_json(final / "manifest.json", {"iso": {"digest_vector": {"sha256": "abc"}}})
    write_json(final / "rootfs-manifest.json", {"rootfs": True})
    write_json(final / "daylight-manifest.json", {"daylight": True})

    stem = "Wuci-Ji-v2.2-Aperture-Bastion"
    write_file(vbox / f"{stem}.ova", b"ova fixture\n")
    write_file(vbox / f"{stem}.ovf", b"ovf fixture\n")
    write_file(vbox / f"{stem}.mf", b"mf fixture\n")
    write_json(vbox / "virtualbox-manifest.json", {"virtualbox": True})

    write_json(
        evidence / "release-gate.json",
        {
            "schema": "wuci-os-release-gate-v1",
            "release_allowed": False,
            "blockers": ["hardware-boot-trace-missing"],
        },
    )
    write_json(evidence / "qemu-boot-trace.json", {"status": "pass"})
    write_json(
        privacy,
        {
            "schema": "wuci-release-privacy-audit-v1",
            "status": privacy_status,
            "summary": {"findings": 0 if privacy_status == "pass" else 1},
            "findings": [] if privacy_status == "pass" else [{"kind": "openai_api_key"}],
        },
    )
    write_json(rootfs_privacy, {"status": "pass", "summary": {"findings": 0}, "findings": []})
    write_json(daylight, {"score": 100.0})
    return {
        "final": final,
        "vbox": vbox,
        "evidence": evidence,
        "privacy": privacy,
        "rootfs_privacy": rootfs_privacy,
        "daylight": daylight,
    }


def build_from_fixture(tmp: Path, *, privacy_status: str = "pass") -> tuple[Path, dict[str, object]]:
    paths = fixture_tree(tmp, privacy_status=privacy_status)
    out = tmp / "bundle"
    result = bundle.build_bundle(
        out=out,
        final_dir=paths["final"],
        evidence_dir=paths["evidence"],
        privacy_audit=paths["privacy"],
        rootfs_privacy_audit=paths["rootfs_privacy"],
        daylight_ssv=paths["daylight"],
        force=True,
    )
    return out, result


def assert_bundle_allowlist_and_checksums(tmp: Path) -> None:
    out, result = build_from_fixture(tmp)
    assert result["status"] == "candidate-blocked"
    assert result["release_allowed"] is False
    assert "hardware-boot-trace-missing" in result["release_gate_blockers"]
    expected = {
        "CHECKSUMS.sha256",
        "RELEASE-NOTES.txt",
        "public-release-bundle-manifest.json",
        "iso/Wuci-OS-x86_64-musl.iso",
        "iso/Wuci-OS-x86_64-musl.iso.sha256",
        "evidence/final-manifest.json",
        "evidence/rootfs-manifest.json",
        "evidence/daylight-manifest.json",
        "evidence/release-gate.json",
        "evidence/qemu-boot-trace.json",
        "evidence/privacy-audit.json",
        "evidence/privacy-audit-final-rootfs.json",
        "evidence/daylight-ssv.report.json",
    }
    actual = {path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()}
    assert expected == actual
    assert not any(".ssh" in item or item.endswith(".key") for item in actual)
    checksums = (out / "CHECKSUMS.sha256").read_text(encoding="utf-8").splitlines()
    checksum_paths = {line.split("  ", 1)[1] for line in checksums}
    assert "public-release-bundle-manifest.json" in checksum_paths
    assert "CHECKSUMS.sha256" not in checksum_paths


def assert_privacy_failure_blocks_bundle(tmp: Path) -> None:
    try:
        build_from_fixture(tmp, privacy_status="fail")
    except bundle.ReleaseBundleError as exc:
        assert "privacy audit" in str(exc)
    else:
        raise AssertionError("privacy failure did not block bundle")


def assert_symlink_input_is_rejected(tmp: Path) -> None:
    if not hasattr(os, "symlink"):
        return
    paths = fixture_tree(tmp)
    target = paths["final"] / "manifest-real.json"
    target.write_text("{}\n", encoding="utf-8")
    (paths["final"] / "manifest.json").unlink()
    (paths["final"] / "manifest.json").symlink_to(target)
    try:
        bundle.build_bundle(
            out=tmp / "bundle",
            final_dir=paths["final"],
            evidence_dir=paths["evidence"],
            privacy_audit=paths["privacy"],
            rootfs_privacy_audit=paths["rootfs_privacy"],
            daylight_ssv=paths["daylight"],
            force=True,
        )
    except bundle.ReleaseBundleError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("symlink input was accepted")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-release-bundle-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_bundle_allowlist_and_checksums(tmp / "allowlist")
        assert_privacy_failure_blocks_bundle(tmp / "privacy")
        assert_symlink_input_is_rejected(tmp / "symlink")
    print("wuci-release-bundle tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
