#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import hashlib
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


def scanned_file(path: Path, *, content_scan: str | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        "path": str(path),
        "type": "file",
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }
    if content_scan is not None:
        record["content_scan"] = content_scan
    return record


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
    write_json(rootfs_privacy, {"status": "pass", "summary": {"findings": 0}, "findings": []})
    write_json(daylight, {"score": 100.0})
    scanned = [
        scanned_file(final / "Wuci-OS-x86_64-musl.iso", content_scan="inspected-fixture-container"),
        scanned_file(final / "Wuci-OS-x86_64-musl.iso.sha256"),
        scanned_file(final / "manifest.json"),
        scanned_file(final / "rootfs-manifest.json"),
        scanned_file(final / "daylight-manifest.json"),
        scanned_file(evidence / "release-gate.json"),
        scanned_file(evidence / "qemu-boot-trace.json"),
        scanned_file(daylight),
    ]
    write_json(
        privacy,
        {
            "schema": "wuci-release-privacy-audit-v1",
            "status": privacy_status,
            "summary": {"findings": 0 if privacy_status == "pass" else 1},
            "findings": [] if privacy_status == "pass" else [{"kind": "openai_api_key"}],
            "scanned_files": scanned,
        },
    )
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


def assert_missing_rootfs_privacy_blocks_bundle(tmp: Path) -> None:
    paths = fixture_tree(tmp)
    paths["rootfs_privacy"].unlink()
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
        assert "privacy audit" in str(exc) or "required public artifact is missing" in str(exc)
    else:
        raise AssertionError("missing final-rootfs privacy audit did not block bundle")


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


def assert_stale_privacy_report_blocks_bundle(tmp: Path) -> None:
    paths = fixture_tree(tmp)
    (paths["final"] / "manifest.json").write_text('{"tampered":true}\n', encoding="utf-8")
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
        assert "privacy audit digest is stale" in str(exc)
    else:
        raise AssertionError("stale privacy report was accepted")


def assert_uninspected_container_privacy_blocks_bundle(tmp: Path) -> None:
    paths = fixture_tree(tmp)
    report = json.loads(paths["privacy"].read_text(encoding="utf-8"))
    for item in report["scanned_files"]:
        if str(item.get("path", "")).endswith("Wuci-OS-x86_64-musl.iso"):
            item["content_scan"] = "skipped-raw-iso-container"
    write_json(paths["privacy"], report)
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
        assert "did not inspect copied container payload" in str(exc)
    else:
        raise AssertionError("uninspected raw container privacy evidence was accepted")


def assert_duplicate_json_privacy_report_is_rejected(tmp: Path) -> None:
    report = tmp / "privacy.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text('{"status":"pass","status":"fail","summary":{"findings":0},"findings":[]}\n', encoding="utf-8")
    try:
        bundle.require_privacy_pass(report)
    except bundle.ReleaseBundleError as exc:
        assert "duplicate JSON key" in str(exc)
    else:
        raise AssertionError("duplicate-key privacy report was accepted")


def assert_symlink_output_parent_is_rejected(tmp: Path) -> None:
    if not hasattr(os, "symlink"):
        return
    paths = fixture_tree(tmp)
    real_parent = tmp / "real-out"
    real_parent.mkdir()
    linked_parent = tmp / "linked-out"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    try:
        bundle.build_bundle(
            out=linked_parent / "bundle",
            final_dir=paths["final"],
            evidence_dir=paths["evidence"],
            privacy_audit=paths["privacy"],
            rootfs_privacy_audit=paths["rootfs_privacy"],
            daylight_ssv=paths["daylight"],
            force=True,
        )
    except bundle.ReleaseBundleError as exc:
        assert "parent must not be a symlink" in str(exc)
    else:
        raise AssertionError("symlinked output parent was accepted")


def assert_verify_parser_accepts_makefile_shape() -> None:
    args = bundle.build_parser().parse_args(
        [
            "verify",
            "--repo",
            ".",
            "--bin",
            "build/wuci-ji",
            "--sbom",
            "build/wuci-sbom.json",
            "--provenance",
            "build/wuci-provenance.json",
            "--carrot",
            "build/wuci-carrot-attestation.json",
            "--pq",
            "build/wuci-pq-verifier.json",
            "--pq-pins",
            "docs/wuci_pq_verifier_pins.json",
            "--crypto-audit",
            "build/wuci-crypto-self-audit.json",
            "--parser-replay",
            "build/wuci-parser-corpus-replay.json",
            "--production-authority-policy",
            "docs/wuci_production_authority_policy.json",
            "--witness-bundle",
            "build/wuci-witness-bundle",
            "--ledger",
            "build/wuci-ledger",
            "--install-manifest",
            "install/wuci-install-manifest.v1",
            "--install-signature",
            "install/wuci-install-manifest.v1.sig",
            "--install-root-key",
            "install/wuci-install-root.v1.pub",
            "--rust-sandbox",
            "build/wuci-sandbox",
            "--zig-witness",
            "build/wuci-witness",
            "--zig-ledger",
            "build/wuci-ledger-tool",
            "--out",
            "build/wuci-release-bundle-verification.json",
            "--quiet",
        ]
    )
    assert args.command == "verify"
    assert args.real_pq_evidence is None
    assert args.external_audit_evidence is None


def assert_optional_evidence_groups_are_fail_closed() -> None:
    supplied, blockers = bundle.verify_optional_group(
        paths=[None, None],
        names=["one", "two"],
        blocker="missing-both",
    )
    assert supplied is False
    assert blockers == ["missing-both"]

    try:
        bundle.verify_optional_group(
            paths=[Path("one"), None],
            names=["one", "two"],
            blocker="missing-both",
        )
    except bundle.ReleaseBundleError as exc:
        assert "partial optional evidence" in str(exc)
    else:
        raise AssertionError("partial optional evidence was accepted")


def assert_repo_build_tool_identity_is_restricted(tmp: Path) -> None:
    repo = tmp / "repo"
    build = repo / "build"
    build.mkdir(parents=True)
    expected = build / "wuci-witness"
    expected.write_bytes(b"expected verifier\n")
    observed = bundle.require_repo_build_tool(expected, repo, "wuci-witness", "witness verifier")
    assert observed["path"] == str(expected)

    other = build / "other-witness"
    other.write_bytes(b"other verifier\n")
    try:
        bundle.require_repo_build_tool(other, repo, "wuci-witness", "witness verifier")
    except bundle.ReleaseBundleError as exc:
        assert "repository build output" in str(exc)
    else:
        raise AssertionError("arbitrary verifier binary path was accepted")


def assert_parser_replay_requires_non_offensive_fail_closed_evidence(tmp: Path) -> None:
    good = tmp / "parser-replay.json"
    write_json(
        good,
        {
            "fail_closed": True,
            "network_required": False,
            "offensive_fuzzing": False,
            "cases": 1,
            "accepted_cases": 1,
            "rejected_cases": 0,
            "required_surfaces": ["fixture"],
            "results": [{"timeout": False, "signal": None}],
        },
    )
    assert bundle.verify_parser_replay(good)["cases"] == 1

    bad = tmp / "bad-parser-replay.json"
    write_json(
        bad,
        {
            "fail_closed": True,
            "network_required": False,
            "offensive_fuzzing": True,
            "results": [{"timeout": False, "signal": None}],
        },
    )
    try:
        bundle.verify_parser_replay(bad)
    except bundle.ReleaseBundleError as exc:
        assert "offensive" in str(exc)
    else:
        raise AssertionError("offensive parser replay evidence was accepted")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-release-bundle-test-") as tmp_name:
        tmp = Path(tmp_name)
        assert_bundle_allowlist_and_checksums(tmp / "allowlist")
        assert_privacy_failure_blocks_bundle(tmp / "privacy")
        assert_missing_rootfs_privacy_blocks_bundle(tmp / "rootfs-privacy")
        assert_symlink_input_is_rejected(tmp / "symlink")
        assert_stale_privacy_report_blocks_bundle(tmp / "stale-privacy")
        assert_uninspected_container_privacy_blocks_bundle(tmp / "uninspected-container")
        assert_duplicate_json_privacy_report_is_rejected(tmp / "duplicate-json")
        assert_symlink_output_parent_is_rejected(tmp / "symlink-out")
        assert_parser_replay_requires_non_offensive_fail_closed_evidence(tmp / "parser")
        assert_verify_parser_accepts_makefile_shape()
        assert_optional_evidence_groups_are_fail_closed()
        assert_repo_build_tool_identity_is_restricted(tmp / "verifier-tool")
    print("wuci-release-bundle tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
