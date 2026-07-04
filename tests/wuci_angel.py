#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
import wuci_angel as angel  # noqa: E402


SUBJECT_SHA256 = hashlib.sha256(b"penumbra daylight subject\n").hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(angel.stable_json(value), encoding="ascii")


def write_attestation(
    manifest_dir: Path,
    rel: str,
    *,
    attestation_id: str,
    issuer: str,
    issuer_class: str,
    fills: list[str],
    statement: str = "Bounded external residue attestation for the listed Angel gaps.",
) -> dict[str, str]:
    value = {
        "schema": angel.ATTESTATION_SCHEMA,
        "attestation_id": attestation_id,
        "issuer": issuer,
        "issuer_class": issuer_class,
        "completed_utc": "2026-07-04T00:00:00Z",
        "fills": fills,
        "subject_sha256": SUBJECT_SHA256,
        "statement": statement,
        "offensive_tooling_included": False,
        "non_claims": list(angel.NON_CLAIMS),
    }
    path = manifest_dir / rel
    write_json(path, value)
    return {"path": rel, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def write_manifest(manifest_dir: Path, required_gaps: list[str], attestations: list[dict[str, str]]) -> Path:
    path = manifest_dir / "angel-manifest.json"
    write_json(
        path,
        {
            "schema": angel.MANIFEST_SCHEMA,
            "subject": {"name": "penumbra-daylight-coupling"},
            "required_gaps": required_gaps,
            "attestations": attestations,
            "non_claims": list(angel.NON_CLAIMS),
        },
    )
    return path


def valid_full_manifest(tmp: Path) -> Path:
    entries = [
        write_attestation(
            tmp,
            "attestations/review.json",
            attestation_id="northstar-review-001",
            issuer="Northstar Audit Lab",
            issuer_class="independent-reviewer",
            fills=[
                "penumbra.crypto-integration.external-review",
                "daylight.independent-external-review",
            ],
        ),
        write_attestation(
            tmp,
            "attestations/meridian.json",
            attestation_id="meridian-ops-001",
            issuer="Meridian Ops Council",
            issuer_class="deployment-operator",
            fills=[
                "penumbra.secret-entropy.external-bound",
                "penumbra.meridian-rederiver.external-attestation",
            ],
        ),
        write_attestation(
            tmp,
            "attestations/release-root.json",
            attestation_id="release-root-001",
            issuer="Release Root Board",
            issuer_class="release-authority",
            fills=["daylight.production-authority.external-root"],
        ),
        write_attestation(
            tmp,
            "attestations/ledger.json",
            attestation_id="ledger-entry-001",
            issuer="Ledger Operator One",
            issuer_class="operated-ledger",
            fills=["daylight.operated-witness-ledger.external-entry"],
        ),
        write_attestation(
            tmp,
            "attestations/containment.json",
            attestation_id="containment-posture-001",
            issuer="Kernel Boundary Lab",
            issuer_class="containment-auditor",
            fills=["host.containment-posture.external-evidence"],
            statement="Bounded external host containment posture evidence is attached.",
        ),
    ]
    return write_manifest(tmp, list(angel.DEFAULT_REQUIRED_GAPS), entries)


def assert_valid_manifest_passes_and_is_deterministic(tmp: Path) -> None:
    manifest = valid_full_manifest(tmp)
    first = angel.evaluate_manifest(manifest)
    second = angel.evaluate_manifest(manifest)
    assert first["status"] == "pass"
    assert first["coupling_allowed"] is True
    assert first["blockers"] == []
    assert angel.stable_json(first) == angel.stable_json(second)
    assert {gap["status"] for gap in first["required_gaps"]} == {"pass"}


def assert_missing_gap_blocks(tmp: Path) -> None:
    manifest = write_manifest(tmp, ["penumbra.crypto-integration.external-review"], [])
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    assert report["coupling_allowed"] is False
    assert "penumbra.crypto-integration.external-review" in report["blockers"]


def assert_digest_mismatch_blocks(tmp: Path) -> None:
    entry = write_attestation(
        tmp,
        "attestations/review.json",
        attestation_id="northstar-review-001",
        issuer="Northstar Audit Lab",
        issuer_class="independent-reviewer",
        fills=["penumbra.crypto-integration.external-review"],
    )
    entry["sha256"] = "0" * 64
    manifest = write_manifest(tmp, ["penumbra.crypto-integration.external-review"], [entry])
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    assert "penumbra.crypto-integration.external-review" in report["blockers"]
    assert any(blocker.startswith("attestation-invalid:") for blocker in report["blockers"])
    assert "digest mismatch" in " ".join(report["attestations"][0]["issues"])


def assert_symlink_and_hardlink_attestations_block(tmp: Path) -> None:
    source_entry = write_attestation(
        tmp,
        "attestations/source.json",
        attestation_id="northstar-review-001",
        issuer="Northstar Audit Lab",
        issuer_class="independent-reviewer",
        fills=["penumbra.crypto-integration.external-review"],
    )
    if hasattr(os, "symlink"):
        link = tmp / "attestations/link.json"
        link.symlink_to("source.json")
        manifest = write_manifest(
            tmp / "symlink",
            ["penumbra.crypto-integration.external-review"],
            [{"path": "../attestations/link.json", "sha256": source_entry["sha256"]}],
        )
        report = angel.evaluate_manifest(manifest)
        assert report["status"] == "blocked"
        assert "must stay under" in " ".join(report["attestations"][0]["issues"])

        manifest = write_manifest(
            tmp,
            ["penumbra.crypto-integration.external-review"],
            [{"path": "attestations/link.json", "sha256": source_entry["sha256"]}],
        )
        report = angel.evaluate_manifest(manifest)
        assert report["status"] == "blocked"
        assert "symlink" in " ".join(report["attestations"][0]["issues"])

        parent_link = tmp / "linked-attestations"
        parent_link.symlink_to("attestations", target_is_directory=True)
        manifest = write_manifest(
            tmp,
            ["penumbra.crypto-integration.external-review"],
            [{"path": "linked-attestations/source.json", "sha256": source_entry["sha256"]}],
        )
        report = angel.evaluate_manifest(manifest)
        assert report["status"] == "blocked"
        assert "parent must not be a symlink" in " ".join(report["attestations"][0]["issues"])

    hardlink = tmp / "attestations/hardlink.json"
    try:
        os.link(tmp / source_entry["path"], hardlink)
    except OSError:
        return
    manifest = write_manifest(
        tmp,
        ["penumbra.crypto-integration.external-review"],
        [{"path": "attestations/hardlink.json", "sha256": source_entry["sha256"]}],
    )
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    assert "hardlinked" in " ".join(report["attestations"][0]["issues"])


def assert_fixture_issuer_blocks(tmp: Path) -> None:
    entry = write_attestation(
        tmp,
        "attestations/fixture.json",
        attestation_id="fixture-review-001",
        issuer="Fixture Lab",
        issuer_class="independent-reviewer",
        fills=["penumbra.crypto-integration.external-review"],
    )
    manifest = write_manifest(tmp, ["penumbra.crypto-integration.external-review"], [entry])
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    assert "fixture" in " ".join(report["attestations"][0]["issues"]).lower()


def assert_reserved_overclaim_blocks(tmp: Path) -> None:
    entry = write_attestation(
        tmp,
        "attestations/overclaim.json",
        attestation_id="northstar-review-001",
        issuer="Northstar Audit Lab",
        issuer_class="independent-reviewer",
        fills=["penumbra.crypto-integration.external-review"],
        statement="This coupling is unbreakable, quantum-proof, and runtime sandboxed.",
    )
    manifest = write_manifest(tmp, ["penumbra.crypto-integration.external-review"], [entry])
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    issues = " ".join(report["attestations"][0]["issues"])
    assert "reserved overclaim" in issues
    assert "quantum-proof" in issues
    assert "runtime sandboxed" in issues


def assert_unauthorized_issuer_class_blocks(tmp: Path) -> None:
    entry = write_attestation(
        tmp,
        "attestations/wrong-class.json",
        attestation_id="ledger-entry-001",
        issuer="Ledger Operator One",
        issuer_class="operated-ledger",
        fills=["penumbra.crypto-integration.external-review"],
    )
    manifest = write_manifest(tmp, ["penumbra.crypto-integration.external-review"], [entry])
    report = angel.evaluate_manifest(manifest)
    assert report["status"] == "blocked"
    assert "not authorized" in " ".join(report["attestations"][0]["issues"])


def assert_cli_gate_writes_report(tmp: Path) -> None:
    manifest = valid_full_manifest(tmp)
    out = tmp / "report.json"
    rc = angel.main(["gate", "--manifest", str(manifest), "--out", str(out)])
    assert rc == 0
    report, _ = angel.read_json(out, "Angel test report")
    assert report["status"] == "pass"
    assert out.stat().st_mode & 0o777 == 0o644


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="wuci-angel-test-") as raw:
        root = Path(raw)
        assert_valid_manifest_passes_and_is_deterministic(root / "valid")
        assert_missing_gap_blocks(root / "missing")
        assert_digest_mismatch_blocks(root / "digest")
        assert_symlink_and_hardlink_attestations_block(root / "links")
        assert_fixture_issuer_blocks(root / "fixture")
        assert_reserved_overclaim_blocks(root / "overclaim")
        assert_unauthorized_issuer_class_blocks(root / "issuer-class")
        assert_cli_gate_writes_report(root / "cli")
    print("wuci-angel tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
