"""Executable D16-AWE mechanics.

This package intentionally implements only the repo-safe construction slice:
canonical encoding, evidence/policy verification, domain-separated tags,
HKDF-SHA384 key schedule, hidden commitments, and a vector lane that consumes
externally supplied KEM material. It does not implement ML-KEM, DHKEM, ML-DSA,
or SLH-DSA key operations.
"""

from .errors import D16AWEError, UnsupportedCryptoBackend

__all__ = ["D16AWEError", "UnsupportedCryptoBackend"]
