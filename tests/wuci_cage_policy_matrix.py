#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = REPO_ROOT / "docs" / "wuci_cage_policy.json"
GATE_BOUNDARY_PATH = REPO_ROOT / "docs" / "wuci_gate_boundary.json"
LEDGER_BOUNDARY_PATH = REPO_ROOT / "docs" / "wuci_ledger_format.json"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Check WUCI-CAGE policy matrix.")
    parser.add_argument("--quiet", action="store_true", help="suppress summary")
    args = parser.parse_args()

    policy = load_json(POLICY_PATH)
    gate = load_json(GATE_BOUNDARY_PATH)
    ledger = load_json(LEDGER_BOUNDARY_PATH)

    assert policy["schema"] == "wuci-cage-policy-v1"
    assert policy["status"] == "defensive-artifact-airlock-v1"
    assert policy["purpose"] == (
        "Bind AI-era artifacts to WUCI seal, warrant, gate, witness, and "
        "ledger evidence before trust."
    )

    actions = policy["canonical_actions"]
    assert actions["stage"]["wuci_action"] == "open"
    assert actions["publish"]["wuci_action"] == "release"
    assert actions["run"]["status"] == "unsupported-in-v1"
    assert actions["run"]["wuci_action"] is None
    assert actions["trust"]["status"] == "reserved"

    runtime = policy["runtime_claims"]
    assert runtime["no_network_enforced_v1"] is False
    assert runtime["public_witness_secret_free_v1"] is True
    assert runtime["ledger_hash_only_v1"] is True

    current_surfaces = set(gate["assembly_owned_surfaces"])
    current_surfaces.update(command["name"] for command in ledger["assembly_commands"])
    for surface in policy["required_existing_surfaces"]:
        assert surface in current_surfaces, surface

    required_files = policy["required_public_witness_files"]
    assert required_files == [
        "wuci-ji.self.wj",
        "manifest.txt",
        "warrant-message.txt",
        "release-receipt.json",
        "receipt-contract.txt",
        "authority-root.txt",
        "release-decision.txt",
        "publish-index.txt",
        "attestation.json",
    ]

    forbidden = set(policy["forbidden_public_witness_files"])
    for name in (
        "artifact.key",
        "opened-wuci-ji",
        "auth-transcript.json",
        "release-transcript.json",
    ):
        assert name in forbidden
    assert "any file containing private material markers" in forbidden

    rejections = set(policy["rejection_classes"])
    for name in (
        "private_material_in_public_bundle",
        "opened_binary_in_public_bundle",
        "transcript_in_public_bundle",
        "ledger_proof_mismatch",
        "runtime_sandbox_claim_without_enforcement",
        "symlink_public_witness_file",
        "hardlink_public_witness_file",
    ):
        assert name in rejections

    if not args.quiet:
        print("wuci cage policy matrix: PASS")


if __name__ == "__main__":
    main()
