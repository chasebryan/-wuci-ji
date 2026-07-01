"""D16-AWE constants and suite description."""

from __future__ import annotations

VERSION = "daylight-v16-analemma-witnessed-envelope-v0.1"
MAGIC = "D16AWE1"

D_SUITE = "DAYLIGHT-v16-AWE-SUITE:"
D_RECIPIENT = "DAYLIGHT-v16-AWE-RECIPIENT:"
D_EVIDENCE = "DAYLIGHT-v16-AWE-EVIDENCE:"
D_POLICY = "DAYLIGHT-v16-AWE-POLICY:"
D_AUTHZ = "DAYLIGHT-v16-AWE-AUTHORIZATION:"
D_HEADER = "DAYLIGHT-v16-AWE-HEADER:"
D_KEM = "DAYLIGHT-v16-AWE-HYBRID-KEM:"
D_EXTRACT = "DAYLIGHT-v16-AWE-HKDF-EXTRACT:"
D_EXPAND = "DAYLIGHT-v16-AWE-HKDF-EXPAND:"
D_COMMIT = "DAYLIGHT-v16-AWE-COMMIT:"
D_SIG = "DAYLIGHT-v16-AWE-SIGNATURE:"
D_EXPORT = "DAYLIGHT-v16-AWE-EXPORT:"

SUITE = {
    "version": VERSION,
    "kem_pq": "ML-KEM-1024",
    "kem_classical": "DHKEM-P384-HKDF-SHA384",
    "kdf": "HKDF-SHA384",
    "hash": "SHA3-512",
    "aead": "CHACHA20-POLY1305-RFC8439",
    "signature_main": "ML-DSA-87",
    "signature_backup": "SLH-DSA-SHAKE-256s",
    "canonical_encoding": "deterministic-canonical-daylight-v2",
}
