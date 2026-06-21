#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BOUNDARY = REPO_ROOT / "docs" / "wuci_gate_boundary.json"
BIN = Path(os.environ.get("WUCI_JI_BIN", REPO_ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))


def run_wuci(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_list(value: dict[str, Any], key: str) -> list[Any]:
    item = value[key]
    assert isinstance(item, list), key
    return item


def main() -> None:
    boundary = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    expected_keys = {
        "schema",
        "status",
        "enforcement_implemented",
        "assembly_command_enforcement_implemented",
        "assembly_owned_surfaces",
        "authority_root",
        "authority_anchor",
        "assembly_contract_commands",
        "python_workflow_surfaces",
        "future_commands",
        "receipt_policy_inputs",
        "receipt_display_only_fields",
        "receipt_private_material_forbidden",
        "expected_rejection_classes",
        "non_goals",
    }
    assert set(boundary) == expected_keys
    assert boundary["schema"] == "wuci-gate-boundary-v1"
    assert boundary["status"] == "python-preview-plus-assembly-anchored-rooted-contracts"
    assert boundary["enforcement_implemented"] is True
    assert boundary["assembly_command_enforcement_implemented"] is True

    assembly_surfaces = set(require_list(boundary, "assembly_owned_surfaces"))
    assert "manifest-file" in assembly_surfaces
    assert "warrant-message-file" in assembly_surfaces
    assert "frost-secp256k1-verify" in assembly_surfaces
    assert "authority-root-verify" in assembly_surfaces
    assert "gate-contract-verify" in assembly_surfaces
    assert "gate-contract-verify-rooted" in assembly_surfaces
    assert "open-authorized-contract" in assembly_surfaces
    assert "open-authorized-rooted" in assembly_surfaces
    assert "release-authorized-contract" in assembly_surfaces
    assert "release-authorized-rooted" in assembly_surfaces

    python_surfaces = set(require_list(boundary, "python_workflow_surfaces"))
    assert "tools/wuci_frost_authorize.py" in python_surfaces
    assert "tools/wuci_gate.py" in python_surfaces
    assert "tools/wuci_authority_root.py" in python_surfaces
    assert "tools/wuci_authority_anchor.py" in python_surfaces
    assert "tests/wuci_authority_anchor.py" in python_surfaces
    assert "tests/wuci_gate_contract_asm.py" in python_surfaces
    assert "tests/wuci_gate_rooted_contract_asm.py" in python_surfaces
    assert "tests/wuci_gate_policy_matrix.py" in python_surfaces
    assert "tests/wuci_gate_workflow.py" in python_surfaces

    authority_root = boundary["authority_root"]
    assert isinstance(authority_root, dict)
    assert authority_root["schema"] == "wuci-authority-root-v1"
    assert authority_root["authority_id"] == "sha256(decoded group-public-key)"
    required_policy = authority_root["required_policy"]
    assert required_policy["allow-open"].startswith("required true for rooted open")
    assert required_policy["allow-release"].startswith(
        "required true for release-authorized-rooted"
    )
    assert required_policy["allow-trust"] is False
    assert required_policy["allow-publish"] is False

    authority_anchor = boundary["authority_anchor"]
    assert isinstance(authority_anchor, dict)
    assert set(authority_anchor) == {"open", "release"}
    open_anchor = authority_anchor["open"]
    assert open_anchor["path"] == "authority/wuci-root.fixture.txt"
    assert open_anchor["sha256_path"] == "authority/wuci-root.fixture.sha256"
    assert open_anchor["group_public_key"].startswith("022f8bde4d1a0720")
    assert open_anchor["allow_open"] is True
    assert open_anchor["allow_release"] is False
    assert open_anchor["allow_trust"] is False
    assert open_anchor["allow_publish"] is False
    release_anchor = authority_anchor["release"]
    assert release_anchor["path"] == "authority/wuci-release-root.fixture.txt"
    assert release_anchor["sha256_path"] == "authority/wuci-release-root.fixture.sha256"
    assert release_anchor["group_public_key"] == open_anchor["group_public_key"]
    assert release_anchor["allow_open"] is False
    assert release_anchor["allow_release"] is True
    assert release_anchor["allow_trust"] is False
    assert release_anchor["allow_publish"] is False

    policy_inputs = set(require_list(boundary, "receipt_policy_inputs"))
    for field in (
        "action",
        "authorization_message_sha256",
        "artifact_manifest_sha256",
        "artifact_manifest",
        "challenge",
        "signature_scalar",
    ):
        assert field in policy_inputs

    display_only = set(require_list(boundary, "receipt_display_only_fields"))
    assert display_only == {"mode", "warning"}
    assert not (policy_inputs & display_only)

    forbidden_private = set(require_list(boundary, "receipt_private_material_forbidden"))
    assert {"group_secret", "hiding_nonce", "binding_nonce", "signature_share"} <= forbidden_private

    rejection_classes = set(require_list(boundary, "expected_rejection_classes"))
    assert "malformed_receipt" in rejection_classes
    assert "private_material" in rejection_classes
    assert "malformed_authority_root" in rejection_classes
    assert "authority_group_key_mismatch" in rejection_classes
    assert "authority_open_disallowed" in rejection_classes
    assert "authority_release_disallowed" in rejection_classes
    assert "authority_anchor_path_mismatch" in rejection_classes
    assert "authority_anchor_digest_mismatch" in rejection_classes
    assert "self_derived_authority_rejected" in rejection_classes
    assert "anchored_authority_policy_mismatch" in rejection_classes
    assert "wrong_release_action" in rejection_classes
    assert "wrong_rooted_release_action" in rejection_classes
    assert "publish_bundle_tamper" in rejection_classes
    assert "output_exists" in rejection_classes

    assembly_commands = require_list(boundary, "assembly_contract_commands")
    assembly_names = {command["name"] for command in assembly_commands}
    assert assembly_names == {
        "gate-contract-verify",
        "gate-contract-verify-rooted",
        "open-authorized-contract",
        "open-authorized-rooted",
        "release-authorized-contract",
        "release-authorized-rooted",
    }
    expected_actions = {
        "gate-contract-verify": "open",
        "gate-contract-verify-rooted": "open",
        "open-authorized-contract": "open",
        "open-authorized-rooted": "open",
        "release-authorized-contract": "release",
        "release-authorized-rooted": "release",
    }
    for command in assembly_commands:
        assert command["implemented"] is True
        assert command["required_action"] == expected_actions[command["name"]]
        assert command["contract_schema"] == "wuci-gate-receipt-contract-v1"
        if command["name"].endswith("-rooted"):
            assert command["authority_schema"] == "wuci-authority-root-v1"

    future_commands = require_list(boundary, "future_commands")
    future_names = {command["name"] for command in future_commands}
    assert future_names == {"release-authorized"}
    for command in future_commands:
        assert command["implemented"] is False
        assert command["required_action"] == "release"

    help_proc = run_wuci(["--help"])
    assert help_proc.returncode == 0, help_proc.stderr.decode("utf-8", "replace")
    help_text = help_proc.stdout.decode("ascii")
    assert "warrant-message-file <action> <path>" in help_text
    assert "authority-root-verify <authority>" in help_text
    assert "gate-contract-verify <artifact> <contract>" in help_text
    assert "gate-contract-verify-rooted <authority> <artifact> <contract>" in help_text
    assert "open-authorized-contract <keyfile> <artifact> <contract> <out>" in help_text
    assert "open-authorized-rooted <authority> <keyfile> <artifact> <contract> <out>" in help_text
    assert "release-authorized-contract <artifact> <contract>" in help_text
    assert "release-authorized-rooted <authority> <artifact> <contract>" in help_text
    for command in assembly_names:
        rejected = run_wuci([command])
        assert rejected.returncode != 0
        assert rejected.stdout == b""
    for command in future_names:
        assert not any(line.startswith(f"  {command} ") for line in help_text.splitlines())
        rejected = run_wuci([command])
        assert rejected.returncode != 0
        assert rejected.stdout == b""


if __name__ == "__main__":
    main()
