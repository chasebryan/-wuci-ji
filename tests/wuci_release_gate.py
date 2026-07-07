#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_release_gate as gate  # noqa: E402
import wuci_ledger  # noqa: E402


BUILD_BIN = REPO / "build" / "wuci-ji"
FIXTURE_GROUP_PUBLIC_KEY = "02" + ("11" * 32)
ZERO64 = "0" * 64


def write_manifest(
    tmp: Path,
    *,
    remastered: bool = True,
    package_pass: bool = False,
    secure_default_pass: bool = False,
) -> tuple[Path, Path]:
    tmp.mkdir(parents=True, exist_ok=True)
    iso = tmp / "Wuci-OS-x86_64-musl.iso"
    iso.write_bytes(b"fixture final iso\n")
    iso_sha, iso_size = gate.file_digest(iso, "fixture iso")
    suite = {"status": "pass", "package_count": 3} if package_pass else {"status": "not-requested"}
    rootfs_remaster = {"suite_package_install": suite}
    if secure_default_pass:
        rootfs_remaster["secure_default_package_closure"] = {
            "schema": "wuci-os-secure-default-package-closure-v1",
            "status": "pass",
            "policy": "secure-default-firstboot-v1",
            "required_command_count": 18,
            "required_firstboot_executable_count": 5,
            "required_firstboot_file_count": 15,
            "optional_suite_status": "partial",
            "optional_suite_failed_count": 197,
            "non_claims": [
                "secure-default closure proves first-boot/network/install readiness, not the optional workstation suite"
            ],
        }
    manifest = {
        "schema": "wuci-os-final-iso-manifest-v1",
        "status": "built",
        "iso": {
            "path": str(iso),
            "bytes": iso_size,
            "digest_vector": {"sha256": iso_sha},
        },
        "validation": {"rootfs_remastered": remastered},
        "rootfs_remaster": rootfs_remaster,
    }
    manifest_path = tmp / "manifest.json"
    manifest_path.write_text(gate.stable_json(manifest), encoding="utf-8")
    return manifest_path, iso


def assert_qemu_trace_binds_to_manifest(tmp: Path) -> None:
    manifest, iso = write_manifest(tmp)
    boot_log = tmp / "qemu.log"
    boot_log.write_text(
        "=> Loading sysctl(8) settings...\n"
        "Wuci-OS live profile\n"
        "\x1b[?2004hWJ>_ \n",
        encoding="utf-8",
    )
    evidence_root = tmp / "evidence"
    trace = gate.bind_boot_trace(
        manifest_path=manifest,
        iso_path=iso,
        boot_log=boot_log,
        out=evidence_root / gate.QEMU_TRACE_NAME,
        kind="qemu",
        required_markers=gate.QEMU_REQUIRED_MARKERS,
    )
    assert trace["status"] == "pass"
    assert (evidence_root / gate.QEMU_TRACE_NAME).stat().st_mode & 0o777 == 0o644
    status = gate.release_status(
        manifest_path=manifest,
        iso_path=iso,
        evidence_root=evidence_root,
    )
    assert "qemu-boot-trace-not-bound-to-final-manifest" not in status["blockers"]
    assert "package-closure-fixed-point-missing" in status["blockers"]
    assert "hardware-boot-trace-missing" in status["blockers"]


def assert_stale_trace_does_not_clear_blocker(tmp: Path) -> None:
    manifest, iso = write_manifest(tmp)
    boot_log = tmp / "qemu.log"
    boot_log.write_text("=> Loading sysctl(8) settings...\nWuci-OS live profile\nWJ>_ \n", encoding="utf-8")
    evidence_root = tmp / "evidence"
    gate.bind_boot_trace(
        manifest_path=manifest,
        iso_path=iso,
        boot_log=boot_log,
        out=evidence_root / gate.QEMU_TRACE_NAME,
        kind="qemu",
        required_markers=gate.QEMU_REQUIRED_MARKERS,
    )
    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_data["status"] = "rebuilt"
    manifest.write_text(gate.stable_json(manifest_data), encoding="utf-8")
    status = gate.release_status(
        manifest_path=manifest,
        iso_path=iso,
        evidence_root=evidence_root,
    )
    assert "qemu-boot-trace-not-bound-to-final-manifest" in status["blockers"]
    check = status["evidence"]["qemu-boot-trace-not-bound-to-final-manifest"]
    assert check["checks"]["manifest_sha256"] is False


def assert_signature_and_witness_evidence_clear_when_bound(tmp: Path) -> None:
    assert BUILD_BIN.exists(), "build/wuci-ji is required for ledger proof verification"
    manifest, iso = write_manifest(tmp, package_pass=True)
    context = gate.manifest_context(manifest, iso)
    evidence_root = tmp / "evidence"
    signature_file = tmp / "manifest.json.minisig"
    signature_file.write_text("fixture public detached signature\n", encoding="utf-8")
    sig_sha, sig_bytes = gate.file_digest(signature_file, "fixture signature")
    signature_evidence = {
        "schema": f"{gate.SCHEMA_PREFIX}-manifest-signature-v1",
        "status": "pass",
        "final_manifest": {
            "path": str(manifest),
            "sha256": context["manifest_sha256"],
            "bytes": context["manifest_bytes"],
        },
        "final_iso": {
            "path": str(iso),
            "sha256": context["iso_sha256"],
            "bytes": context["iso_bytes"],
        },
        "signature": {"path": str(signature_file), "sha256": sig_sha, "bytes": sig_bytes},
    }
    gate.write_json_atomic(evidence_root / gate.SIGNATURE_NAME, signature_evidence)
    entry = tmp / "ledger-entry.txt"
    head = tmp / "ledger-head.txt"
    proof = tmp / "inclusion-proof.txt"
    entry_text = wuci_ledger.format_entry(
        {
            "schema": wuci_ledger.ENTRY_SCHEMA,
            "sequence": "0",
            "artifact-sha256": ZERO64,
            "manifest-sha256": context["manifest_sha256"],
            "warrant-message-sha256": ZERO64,
            "release-receipt-sha256": ZERO64,
            "receipt-contract-sha256": ZERO64,
            "authority-root-sha256": ZERO64,
            "release-decision-sha256": ZERO64,
            "attestation-sha256": ZERO64,
            "release-authority-group-public-key": FIXTURE_GROUP_PUBLIC_KEY,
        }
    )
    entry.write_text(entry_text, encoding="ascii")
    leaf = wuci_ledger.leaf_file(BUILD_BIN, entry)
    head_text = wuci_ledger.format_head(
        {
            "schema": wuci_ledger.HEAD_SCHEMA,
            "tree-size": "1",
            "root-hash": leaf,
            "previous-tree-size": "0",
            "previous-root-hash": wuci_ledger.empty_root(BUILD_BIN),
            "entry-hash": gate.sha256_bytes(entry_text.encode("ascii")),
        }
    )
    head.write_text(head_text, encoding="ascii")
    proof.write_text(
        wuci_ledger.format_proof(
            {
                "schema": wuci_ledger.INCLUSION_SCHEMA,
                "tree-size": "1",
                "leaf-index": "0",
                "leaf-hash": leaf,
                "root-hash": leaf,
            },
            wuci_ledger.INCLUSION_FIELDS,
            [],
        ),
        encoding="ascii",
    )
    witness = gate.bind_witness_entry(
        manifest_path=manifest,
        iso_path=iso,
        signature_evidence=evidence_root / gate.SIGNATURE_NAME,
        ledger_entry=entry,
        ledger_head=head,
        inclusion_proof=proof,
        out=evidence_root / gate.WITNESS_NAME,
        operated_ledger_id="fixture-ledger",
        operator="fixture-operator",
        ledger_url="https://example.invalid/wuci-witness/ledger-head.txt",
        ledger_bin=BUILD_BIN,
    )
    assert witness["status"] == "pass"
    status = gate.release_status(manifest_path=manifest, iso_path=iso, evidence_root=evidence_root)
    assert "final-iso-manifest-signature-missing" not in status["blockers"]
    assert "witness-ledger-entry-missing" not in status["blockers"]
    assert "package-closure-fixed-point-missing" not in status["blockers"]

    stale_signature = dict(signature_evidence)
    stale_signature["status"] = "blocked"
    gate.write_json_atomic(evidence_root / gate.SIGNATURE_NAME, stale_signature)
    try:
        gate.bind_witness_entry(
            manifest_path=manifest,
            iso_path=iso,
            signature_evidence=evidence_root / gate.SIGNATURE_NAME,
            ledger_entry=entry,
            ledger_head=head,
            inclusion_proof=proof,
            out=evidence_root / "stale-witness.json",
            operated_ledger_id="fixture-ledger",
            operator="fixture-operator",
            ledger_url="https://example.invalid/wuci-witness/ledger-head.txt",
            ledger_bin=BUILD_BIN,
        )
    except gate.ReleaseGateError as exc:
        assert "verified manifest signature evidence" in str(exc)
    else:
        raise AssertionError("blocked signature evidence was accepted for witness binding")


def assert_witness_rejects_substring_only_ledger_text(tmp: Path) -> None:
    manifest, iso = write_manifest(tmp, package_pass=True)
    context = gate.manifest_context(manifest, iso)
    evidence_root = tmp / "evidence"
    signature_file = tmp / "manifest.json.minisig"
    signature_file.write_text("fixture public detached signature\n", encoding="utf-8")
    sig_sha, sig_bytes = gate.file_digest(signature_file, "fixture signature")
    gate.write_json_atomic(
        evidence_root / gate.SIGNATURE_NAME,
        {
            "schema": f"{gate.SCHEMA_PREFIX}-manifest-signature-v1",
            "status": "pass",
            "final_manifest": {
                "path": str(manifest),
                "sha256": context["manifest_sha256"],
                "bytes": context["manifest_bytes"],
            },
            "final_iso": {
                "path": str(iso),
                "sha256": context["iso_sha256"],
                "bytes": context["iso_bytes"],
            },
            "signature": {"path": str(signature_file), "sha256": sig_sha, "bytes": sig_bytes},
        },
    )
    entry = tmp / "ledger-entry.txt"
    head = tmp / "ledger-head.txt"
    proof = tmp / "inclusion-proof.txt"
    entry.write_text(f"manifest={context['manifest_sha256']}\nsignature={sig_sha}\n", encoding="utf-8")
    head.write_text("ledger-head\n", encoding="utf-8")
    proof.write_text("inclusion-proof\n", encoding="utf-8")
    try:
        gate.bind_witness_entry(
            manifest_path=manifest,
            iso_path=iso,
            signature_evidence=evidence_root / gate.SIGNATURE_NAME,
            ledger_entry=entry,
            ledger_head=head,
            inclusion_proof=proof,
            out=evidence_root / gate.WITNESS_NAME,
            operated_ledger_id="fixture-ledger",
            operator="fixture-operator",
            ledger_url="https://example.invalid/wuci-witness/ledger-head.txt",
            ledger_bin=BUILD_BIN,
        )
    except gate.ReleaseGateError as exc:
        assert "inclusion verification failed" in str(exc)
    else:
        raise AssertionError("substring-only witness ledger evidence was accepted")


def assert_secure_default_package_closure_retires_blocker(tmp: Path) -> None:
    manifest, iso = write_manifest(tmp, secure_default_pass=True)
    status = gate.release_status(
        manifest_path=manifest,
        iso_path=iso,
        evidence_root=tmp / "evidence",
    )
    package_status = status["evidence"]["package_closure"]
    assert package_status["status"] == "pass"
    assert package_status["source"] == "rootfs_remaster.secure_default_package_closure"
    assert package_status["policy"] == "secure-default-firstboot-v1"
    assert package_status["optional_suite_status"] == "partial"
    assert "package-closure-fixed-point-missing" not in status["blockers"]


def assert_release_gate_rejects_symlink_output(tmp: Path) -> None:
    manifest, iso = write_manifest(tmp)
    boot_log = tmp / "qemu.log"
    boot_log.write_text("=> Loading sysctl(8) settings...\nWuci-OS live profile\nWJ>_ \n", encoding="utf-8")
    target = tmp / "target.json"
    target.write_text("existing\n", encoding="utf-8")
    link = tmp / "evidence" / gate.QEMU_TRACE_NAME
    link.parent.mkdir(parents=True)
    link.symlink_to(target)
    try:
        gate.bind_boot_trace(
            manifest_path=manifest,
            iso_path=iso,
            boot_log=boot_log,
            out=link,
            kind="qemu",
            required_markers=gate.QEMU_REQUIRED_MARKERS,
        )
    except gate.ReleaseGateError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("release gate wrote through a symlink output")
    assert target.read_text(encoding="utf-8") == "existing\n"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-release-gate-test-") as raw:
        tmp = Path(raw)
        assert_qemu_trace_binds_to_manifest(tmp / "qemu")
        assert_stale_trace_does_not_clear_blocker(tmp / "stale")
        assert_signature_and_witness_evidence_clear_when_bound(tmp / "sig")
        assert_witness_rejects_substring_only_ledger_text(tmp / "substring")
        assert_secure_default_package_closure_retires_blocker(tmp / "secure-default")
        assert_release_gate_rejects_symlink_output(tmp / "symlink-output")
    print("wuci-release-gate tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
