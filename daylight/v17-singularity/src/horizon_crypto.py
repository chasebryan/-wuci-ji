"""Daylight Horizon Alpha framing and AEAD helpers.

Boundary: this reuses the repository's pure-stdlib RFC 8439 reference AEAD from
Daylight v15 Meridian. It is for deterministic research/product-alpha proof of
evidence-gated usefulness, not production cryptography and not side-channel
hardened.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
import struct
from pathlib import Path
from types import ModuleType
from typing import Any

from .canonical_json import dumps_canonical, loads_json_no_floats


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
V15_AEAD_PATH = REPO_ROOT / "daylight" / "v15-meridian" / "src" / "aead.py"
SUITE = "ChaCha20-Poly1305-RFC8439-research-reference"
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
KDF_INFO = b"DAYLIGHT-HORIZON-ALPHA-AEAD-KEY:"


class HorizonCryptoError(ValueError):
    pass


def _load_v15_aead() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_daylight_v15_aead_for_horizon", V15_AEAD_PATH)
    if spec is None or spec.loader is None:
        raise HorizonCryptoError("Daylight v15 AEAD reference is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_AEAD = _load_v15_aead()


def random_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def write_private_key(path: Path, key: bytes) -> None:
    if len(key) != KEY_LEN:
        raise HorizonCryptoError("Horizon root key must be 32 bytes")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, key.hex().encode("ascii") + b"\n")
    finally:
        os.close(fd)


def read_private_key(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="ascii").strip()
        key = bytes.fromhex(text)
    except (OSError, ValueError) as exc:
        raise HorizonCryptoError(f"Horizon root key is unreadable: {exc}") from exc
    if len(key) != KEY_LEN:
        raise HorizonCryptoError("Horizon root key must be 32 bytes")
    return key


def sha256_hex(data: bytes) -> str:
    return _AEAD.sha256(data).hex()


def frame_header(header: dict[str, Any]) -> bytes:
    return dumps_canonical(header)


def aad(magic: bytes, header_bytes: bytes) -> bytes:
    return magic + struct.pack("<I", len(header_bytes)) + header_bytes


def derive_key(root_key: bytes, *, magic: bytes, header_bytes: bytes, auth_tag: str) -> bytes:
    if len(root_key) != KEY_LEN:
        raise HorizonCryptoError("Horizon root key must be 32 bytes")
    salt = _AEAD.sha256(magic + header_bytes)
    info = KDF_INFO + magic + b":" + auth_tag.encode("ascii")
    return _AEAD.hkdf_sha256(root_key, salt=salt, info=info, length=KEY_LEN)


def seal_framed(*, magic: bytes, header: dict[str, Any], plaintext: bytes, root_key: bytes) -> bytes:
    nonce_hex = header.get("nonce")
    if not isinstance(nonce_hex, str):
        raise HorizonCryptoError("header nonce must be hex")
    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) != NONCE_LEN:
        raise HorizonCryptoError("nonce must be 12 bytes")
    auth_tag = header.get("authorization", {}).get("authorization_tag")
    if not isinstance(auth_tag, str) or not auth_tag:
        raise HorizonCryptoError("header authorization tag missing")
    header_bytes = frame_header(header)
    key = derive_key(root_key, magic=magic, header_bytes=header_bytes, auth_tag=auth_tag)
    ciphertext, tag = _AEAD.chacha20_poly1305_encrypt(key, nonce, aad(magic, header_bytes), plaintext)
    return aad(magic, header_bytes) + ciphertext + tag


def parse_framed(data: bytes, *, magic: bytes) -> dict[str, Any]:
    if len(data) < len(magic) + 4 + TAG_LEN:
        raise HorizonCryptoError("sealed object too short")
    if data[: len(magic)] != magic:
        raise HorizonCryptoError("bad sealed object magic")
    header_len = struct.unpack("<I", data[len(magic):len(magic) + 4])[0]
    header_start = len(magic) + 4
    header_end = header_start + header_len
    if len(data) < header_end + TAG_LEN:
        raise HorizonCryptoError("sealed object truncated")
    header_bytes = data[header_start:header_end]
    try:
        header = loads_json_no_floats(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HorizonCryptoError(f"sealed object header malformed: {exc}") from exc
    if not isinstance(header, dict):
        raise HorizonCryptoError("sealed object header must be an object")
    return {
        "header": header,
        "header_bytes": header_bytes,
        "ciphertext": data[header_end:-TAG_LEN],
        "tag": data[-TAG_LEN:],
    }


def open_framed(*, magic: bytes, framed: bytes, root_key: bytes) -> bytes:
    parsed = parse_framed(framed, magic=magic)
    header = parsed["header"]
    nonce_hex = header.get("nonce")
    if not isinstance(nonce_hex, str):
        raise HorizonCryptoError("header nonce missing")
    nonce = bytes.fromhex(nonce_hex)
    auth_tag = header.get("authorization", {}).get("authorization_tag")
    if not isinstance(auth_tag, str) or not auth_tag:
        raise HorizonCryptoError("authorization tag missing")
    key = derive_key(root_key, magic=magic, header_bytes=parsed["header_bytes"], auth_tag=auth_tag)
    plaintext = _AEAD.chacha20_poly1305_decrypt(
        key,
        nonce,
        aad(magic, parsed["header_bytes"]),
        parsed["ciphertext"],
        parsed["tag"],
    )
    if plaintext is None:
        raise HorizonCryptoError("AEAD tag verification failed")
    return plaintext
