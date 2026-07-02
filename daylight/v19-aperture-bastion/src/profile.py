"""Forbidden private-material profile for the Aperture public artifact firewall.

The profile is pinned into every capsule by id and digest. Rule text lives
here in code, never inside capsules or public artifacts, so the public
artifact cannot trip its own marker scan.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from .canonical_json import canonical_sha256

PROFILE_ID = "aperture-bastion-public-v1"
D_PROFILE = "DAYLIGHT-v19-APERTURE-FIREWALL-PROFILE:"

FORBIDDEN_EXACT_NAMES = (
    ".dev.vars",
    ".env",
    ".env.local",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secret.txt",
    "vault.key",
)

FORBIDDEN_SUFFIXES = (
    ".dhv",
    ".key",
    ".keystore",
    ".mae",
    ".opened",
    ".p12",
    ".pem",
    ".pfx",
    ".priv",
    ".secret",
)

FORBIDDEN_NAME_RE = re.compile(
    r"(^|[._-])(secret|secrets|smoke-secret|plaintext|plain|opened|keyfile|vault-key|"
    r"passphrase|private|luks|private-transcript|transcript-private)([._-]|$)",
    re.IGNORECASE,
)

FORBIDDEN_PATH_PARTS = (
    ".gnupg",
    ".meridian-vault",
    ".ssh",
    "private",
    "private-transcripts",
    "secrets",
    "smoke-vault",
    "vault",
    "vault-work",
)

FORBIDDEN_CONTENT_MARKERS = (
    b"PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"DAYLIGHT-VAULT-KEY",
    b"meridian vault demo: sealed by evidence, opened by proof",
    b"DAYLIGHT_BASTION_PASSPHRASE",
    b"daylight-v18-fixture-passphrase",
    b"smoke-secret",
    b"PLAINTEXT-ORACLE",
    b"WUCI_PRIVATE",
    b"DAYLIGHT_PRIVATE",
)

HEX_KEY_RE = re.compile(rb"^[0-9a-fA-F]{64}\s*$")
DEFAULT_MAX_FILE_BYTES = 5_000_000


def profile_rules() -> dict:
    return {
        "profile_id": PROFILE_ID,
        "forbidden_exact_names": list(FORBIDDEN_EXACT_NAMES),
        "forbidden_suffixes": list(FORBIDDEN_SUFFIXES),
        "forbidden_name_pattern": FORBIDDEN_NAME_RE.pattern,
        "forbidden_path_parts": list(FORBIDDEN_PATH_PARTS),
        "forbidden_content_markers": [marker.decode("ascii") for marker in FORBIDDEN_CONTENT_MARKERS],
        "hex_key_pattern": HEX_KEY_RE.pattern.decode("ascii"),
        "reject_hidden_components": True,
        "reject_symlinks": True,
        "reject_hardlinks": True,
        "default_max_file_bytes": DEFAULT_MAX_FILE_BYTES,
    }


PROFILE_DIGEST = canonical_sha256(profile_rules(), D_PROFILE)


def check_path_name(rel_path: str) -> list[str]:
    """Return violation reasons for a normalized relative path, name rules only."""
    reasons: list[str] = []
    parts = PurePosixPath(rel_path).parts
    name = parts[-1] if parts else ""
    lower = name.lower()
    for part in parts:
        if part.startswith("."):
            reasons.append("hidden_path_component")
            break
    for part in parts:
        if part.lower() in FORBIDDEN_PATH_PARTS:
            reasons.append("forbidden_private_directory")
            break
    if lower in FORBIDDEN_EXACT_NAMES:
        reasons.append("forbidden_private_filename")
    for suffix in FORBIDDEN_SUFFIXES:
        if lower.endswith(suffix):
            reasons.append("forbidden_private_material_suffix")
            break
    if FORBIDDEN_NAME_RE.search(name):
        reasons.append("forbidden_secret_name_pattern")
    return reasons


def check_content(data: bytes, *, rel_path: str = "") -> list[str]:
    """Return violation reasons for file content."""
    reasons: list[str] = []
    for marker in FORBIDDEN_CONTENT_MARKERS:
        if marker in data:
            reasons.append("known_private_material_marker")
            break
    if HEX_KEY_RE.match(data):
        reasons.append("raw_key_shaped_material")
    if rel_path.lower().endswith((".json", ".jsonl")):
        text = data.decode("utf-8", "ignore")
        if '"plaintext_bytes"' in text and re.search(r'"sha256"\s*:', text) and '"envelope_sha256"' not in text:
            reasons.append("plaintext_sha256_oracle")
    return reasons
