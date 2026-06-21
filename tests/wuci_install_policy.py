#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
POLICY = REPO / "install" / "wuci-install-policy.json"


def main() -> None:
    argparse.ArgumentParser().add_argument("--quiet", action="store_true")
    data = json.loads(POLICY.read_text(encoding="utf-8"))
    assert data["schema"] == "wuci-install-policy-v1"
    assert data["version"] == "0.1"
    assert data["install_root_key_required"] is True
    assert data["signature_required"] is True
    assert data["runtime_sandbox_claimed"] is False
    assert data["quantum_safe_claimed"] is False
    assert data["default_prefix"] == "~/.local"
    assert data["installed_binary"] == "bin/wuci-ji"
    assert data["installed_audit_command"] == "bin/wuci-ji-audit"
    assert "Do not use shell evaluation." in data["non_goals"]


if __name__ == "__main__":
    main()
