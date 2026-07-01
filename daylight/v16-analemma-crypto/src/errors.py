"""D16-AWE error types."""

from __future__ import annotations


class D16AWEError(ValueError):
    """Input is malformed or a fail-closed D16-AWE predicate did not hold."""


class UnsupportedCryptoBackend(RuntimeError):
    """A real pinned crypto backend is required for this operation."""
