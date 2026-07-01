"""Research AEAD adapter for D16-AWE vectors.

This reuses the existing v15 Meridian pure-Python RFC 8439 reference. It is not
constant-time and is not a production cryptographic backend.
"""

from __future__ import annotations

import importlib.util
from functools import lru_cache
from pathlib import Path
from typing import Any

from .errors import UnsupportedCryptoBackend


@lru_cache(maxsize=1)
def _v15_aead() -> Any:
    path = Path(__file__).resolve().parents[2] / "v15-meridian" / "src" / "aead.py"
    if not path.is_file():
        raise UnsupportedCryptoBackend("v15 Meridian AEAD reference is unavailable")
    spec = importlib.util.spec_from_file_location("_d16_v15_aead_ref", path)
    if spec is None or spec.loader is None:
        raise UnsupportedCryptoBackend("could not load v15 Meridian AEAD reference")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    return _v15_aead().chacha20_poly1305_encrypt(key, nonce, aad, plaintext)


def open_aead(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
    return _v15_aead().chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag)
