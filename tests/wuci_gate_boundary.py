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
        "assembly_owned_surfaces",
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
    assert boundary["status"] == "design-only"
    assert boundary["enforcement_implemented"] is False

    assembly_surfaces = set(require_list(boundary, "assembly_owned_surfaces"))
    assert "manifest-file" in assembly_surfaces
    assert "warrant-message-file" in assembly_surfaces
    assert "frost-secp256k1-verify" in assembly_surfaces

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

    future_commands = require_list(boundary, "future_commands")
    future_names = {command["name"] for command in future_commands}
    assert future_names == {"open-authorized", "release-authorized"}
    for command in future_commands:
        assert command["implemented"] is False
        assert command["required_action"] in {"open", "release"}

    help_proc = run_wuci(["--help"])
    assert help_proc.returncode == 0, help_proc.stderr.decode("utf-8", "replace")
    help_text = help_proc.stdout.decode("ascii")
    assert "warrant-message-file <action> <path>" in help_text
    for command in future_names:
        assert command not in help_text
        rejected = run_wuci([command])
        assert rejected.returncode != 0
        assert rejected.stdout == b""


if __name__ == "__main__":
    main()
