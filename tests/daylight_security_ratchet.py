#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
RATCHET = REPO_ROOT / "security" / "security-ratchet.v1.json"
REQUIRED = {
    "no_private_material_in_public_artifacts",
    "no_broad_build_root_uploads",
    "artifact_upload_requires_firewall",
    "vault_index_must_not_store_plaintext_sha256",
    "passphrases_must_not_appear_on_argv",
    "workflow_permissions_minimal",
    "security_headers_must_exist_in_headers_and_meta",
    "private_keyfiles_must_reject_symlinks",
}


def main() -> None:
    payload = json.loads(RATCHET.read_text(encoding="utf-8"))
    assert payload["schema"] == "daylight-security-ratchet-v1", payload
    invariants = set(payload["invariants"])
    missing = sorted(REQUIRED - invariants)
    assert not missing, f"security ratchet lost invariants: {missing}"
    assert len(payload["invariants"]) == len(invariants), "duplicate ratchet invariant"
    print("daylight security ratchet: PASS")


if __name__ == "__main__":
    main()
