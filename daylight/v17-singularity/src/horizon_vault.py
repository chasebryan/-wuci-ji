"""Daylight Horizon Vault Alpha.

The vault turns Event Horizon scorecards into enforced access control: a sealed
object opens only when the local proof state still satisfies the sealed policy
and reproduces the original authorization tag.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

from .canonical_json import json_bytes, load_json_no_floats
from . import horizon_crypto
from . import horizon_policy
from . import proof_atoms
from . import registry
from . import scorecard


MAGIC = b"DLTHV1A"
VAULT_OBJECT_VERSION = "daylight-horizon-vault-object-v0.1"
VAULT_CONFIG_VERSION = "daylight-horizon-vault-config-v0.1"
DEFAULT_ROOT = Path(os.environ.get("DAYLIGHT_HORIZON_HOME", ".daylight-horizon"))
DEFAULT_STATE = Path(__file__).resolve().parents[1] / "examples" / "state.current.json"
BOUNDARY = {
    "research_alpha": True,
    "production_cryptography": False,
    "production_allowed": False,
    "external_certification_claim": False,
    "runtime_containment_claim": False,
    "whole_system_post_quantum_safety_claim": False,
}


class HorizonVaultError(ValueError):
    pass


class HorizonVaultRefused(Exception):
    pass


def _safe_regular_file(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.exists():
        raise HorizonVaultError(f"input file does not exist: {path}")
    if resolved.is_symlink():
        raise HorizonVaultError(f"refusing symlink: {path}")
    if not resolved.is_file():
        raise HorizonVaultError(f"input is not a regular file: {path}")
    return resolved


def _load_policy(path: Path | str | None, *, mode: str = "research") -> dict[str, Any]:
    if path is None:
        return horizon_policy.policy_for_mode(mode)
    policy = load_json_no_floats(path)
    horizon_policy.validate_policy(policy)
    return horizon_policy.canonical_policy(policy)


def _scorecard_for_state(state_path: Path | str) -> dict[str, Any]:
    return scorecard.build_scorecard_from_paths(
        state_path=state_path,
        fields_path=registry.DEFAULT_FIELDS_PATH,
        proof_atoms_path=proof_atoms.DEFAULT_PROOF_ATOMS_PATH,
    )


def init_vault(root: Path | str = DEFAULT_ROOT, *, force: bool = False) -> dict[str, Any]:
    root = Path(root)
    if root.exists() and any(root.iterdir()) and not force:
        raise HorizonVaultError(f"Horizon vault root is not empty: {root}")
    root.mkdir(parents=True, exist_ok=True)
    key = horizon_crypto.random_key()
    horizon_crypto.write_private_key(root / "horizon.key", key)
    config = {
        "config_version": VAULT_CONFIG_VERSION,
        "suite": horizon_crypto.SUITE,
        "boundary": BOUNDARY,
    }
    (root / "horizon.json").write_bytes(json_bytes(config))
    return {"root": str(root), **config}


def inspect_bytes(sealed: bytes) -> dict[str, Any]:
    parsed = horizon_crypto.parse_framed(sealed, magic=MAGIC)
    header = parsed["header"]
    return {
        "magic": header.get("magic"),
        "version": header.get("version"),
        "object_type": header.get("object_type"),
        "suite": header.get("suite"),
        "name": header.get("name"),
        "plaintext_len": header.get("plaintext_len"),
        "policy": header.get("policy"),
        "policy_digest": header.get("policy_digest"),
        "authorization": header.get("authorization"),
        "ciphertext_len": len(parsed["ciphertext"]),
        "tag": parsed["tag"].hex(),
        "header_sha256": horizon_crypto.sha256_hex(parsed["header_bytes"]),
        "boundary": header.get("boundary"),
    }


def inspect_file(input_path: Path | str) -> dict[str, Any]:
    sealed_path = _safe_regular_file(Path(input_path))
    return inspect_bytes(sealed_path.read_bytes())


class HorizonVault:
    def __init__(self, root: Path | str = DEFAULT_ROOT):
        self.root = Path(root)
        self.config_path = self.root / "horizon.json"
        self.key_path = self.root / "horizon.key"
        if not self.config_path.is_file() or not self.key_path.is_file():
            raise HorizonVaultError(f"no Horizon vault at {self.root} (run horizon-vault init)")
        self.config = load_json_no_floats(self.config_path)
        if self.config.get("config_version") != VAULT_CONFIG_VERSION:
            raise HorizonVaultError("unsupported Horizon vault config version")

    def _key(self) -> bytes:
        return horizon_crypto.read_private_key(self.key_path)

    def status(self, *, state_path: Path | str = DEFAULT_STATE) -> dict[str, Any]:
        card = _scorecard_for_state(state_path)
        return {
            "name": "Daylight Horizon Alpha",
            "vault_root": str(self.root),
            "vault_mode": "enabled",
            "claim_score_M": horizon_policy.daylight_claim_score_m(card),
            "event_horizon_score_AM_plus": card["score_AM_plus"],
            "declared": card["declared"],
            "release_mode": "research-only",
            "production_allowed": False,
            "blockers": scorecard.declaration_blockers(card),
        }

    def seal_bytes(
        self,
        *,
        name: str,
        plaintext: bytes,
        state_path: Path | str = DEFAULT_STATE,
        policy: dict[str, Any] | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        policy = horizon_policy.canonical_policy(policy or horizon_policy.policy_for_mode("research"))
        card = _scorecard_for_state(state_path)
        blockers = horizon_policy.policy_blockers(card, policy)
        if blockers:
            raise HorizonVaultRefused("seal refused: " + "; ".join(blockers))
        auth_tag = horizon_policy.authorization_tag(scorecard=card, policy=policy, object_type="vault")
        nonce = nonce if nonce is not None else secrets.token_bytes(horizon_crypto.NONCE_LEN)
        if len(nonce) != horizon_crypto.NONCE_LEN:
            raise HorizonVaultError("nonce must be 12 bytes")
        header = {
            "magic": MAGIC.decode("ascii"),
            "version": VAULT_OBJECT_VERSION,
            "object_type": "vault",
            "suite": horizon_crypto.SUITE,
            "nonce": nonce.hex(),
            "name": name,
            "plaintext_len": len(plaintext),
            "policy": policy,
            "policy_digest": horizon_policy.policy_digest(policy),
            "authorization": {
                "authorization_tag": auth_tag,
                "scorecard_digest": card["scorecard_digest"],
                "event_horizon_score_AM_plus": card["score_AM_plus"],
                "daylight_claim_score_M": horizon_policy.daylight_claim_score_m(card),
                "declared": card["declared"],
                "status": card["status"],
                "fields_digest": card["fields_digest"],
                "proof_atoms_digest": card["proof_atoms_digest"],
                "state_digest": card["state_digest"],
                "fracture_digest": card["fracture_digest"],
            },
            "boundary": BOUNDARY,
        }
        return horizon_crypto.seal_framed(magic=MAGIC, header=header, plaintext=plaintext, root_key=self._key())

    def open_bytes(self, *, sealed: bytes, state_path: Path | str = DEFAULT_STATE) -> bytes:
        parsed = horizon_crypto.parse_framed(sealed, magic=MAGIC)
        header = parsed["header"]
        if header.get("version") != VAULT_OBJECT_VERSION or header.get("object_type") != "vault":
            raise HorizonVaultError("unsupported Horizon vault object")
        policy = header.get("policy")
        if not isinstance(policy, dict):
            raise HorizonVaultError("vault object missing policy")
        policy = horizon_policy.canonical_policy(policy)
        if header.get("policy_digest") != horizon_policy.policy_digest(policy):
            raise HorizonVaultRefused("open refused: policy digest mismatch")
        card = _scorecard_for_state(state_path)
        blockers = horizon_policy.policy_blockers(card, policy)
        if blockers:
            raise HorizonVaultRefused("open refused: " + "; ".join(blockers))
        expected_auth = horizon_policy.authorization_tag(scorecard=card, policy=policy, object_type="vault")
        sealed_auth = header.get("authorization", {}).get("authorization_tag")
        if sealed_auth != expected_auth:
            raise HorizonVaultRefused("open refused: evidence does not reproduce the sealed authorization")
        try:
            return horizon_crypto.open_framed(magic=MAGIC, framed=sealed, root_key=self._key())
        except horizon_crypto.HorizonCryptoError as exc:
            raise HorizonVaultRefused(f"open refused: {exc}") from exc

    def inspect_bytes(self, sealed: bytes) -> dict[str, Any]:
        return inspect_bytes(sealed)

    def seal_file(
        self,
        *,
        input_path: Path | str,
        output_path: Path | str | None = None,
        state_path: Path | str = DEFAULT_STATE,
        policy_path: Path | str | None = None,
        mode: str = "research",
        nonce_hex: str | None = None,
    ) -> dict[str, Any]:
        src = _safe_regular_file(Path(input_path))
        out = Path(output_path) if output_path is not None else src.with_suffix(src.suffix + ".dhv")
        policy = _load_policy(policy_path, mode=mode)
        nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
        sealed = self.seal_bytes(name=src.name, plaintext=src.read_bytes(), state_path=state_path, policy=policy, nonce=nonce)
        out.write_bytes(sealed)
        inspected = self.inspect_bytes(sealed)
        return {"sealed_path": str(out), **inspected}

    def open_file(
        self,
        *,
        input_path: Path | str,
        output_path: Path | str,
        state_path: Path | str = DEFAULT_STATE,
    ) -> dict[str, Any]:
        sealed_path = _safe_regular_file(Path(input_path))
        plaintext = self.open_bytes(sealed=sealed_path.read_bytes(), state_path=state_path)
        out = Path(output_path)
        out.write_bytes(plaintext)
        return {
            "opened_path": str(out),
            "plaintext_len": len(plaintext),
            "plaintext_sha256": horizon_crypto.sha256_hex(plaintext),
        }

    def inspect_file(self, input_path: Path | str) -> dict[str, Any]:
        return inspect_file(input_path)
