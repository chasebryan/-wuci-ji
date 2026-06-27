#!/usr/bin/env python3
"""
Daylight Envelope v0.6 M1 fixture implementation.

This module is intentionally NOT a production cryptographic implementation.
It implements the v0.6 byte-level envelope, deterministic-CBOR parser,
ordered PublicPreOK procedure, transcript/KDF/AEAD wiring, and vector runner.

Real ML-KEM, ML-DSA, SLH-DSA, certificates, revocation, transparency logs,
and reviewer signatures are represented by deterministic fixture providers so
that the byte structure and fail-closed ordering can be tested today.
"""
from __future__ import annotations

import binascii
import copy
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

VERSION = 6
MAGIC = "DAYLIGHT-ENVELOPE-v6"
CTX_AUTH = "WUCI-DAYLIGHT:AUTH:v6"
CTX_REVIEW = "WUCI-DAYLIGHT:REVIEW:v6"

PROFILE_D2_HYBRID = 1
PROFILE_D3_ROOT = 2
PROFILE_D2_HYBRID_FROST = 3

MU_HYBRID = 1
MU_PQ_STRICT = 2

AEAD_AES_256_GCM = 1
AEAD_CHACHA20_POLY1305 = 2

ACTION_RESEARCH = 0
ACTION_PROOF = 1
ACTION_OPEN = 2
ACTION_RELEASE = 3
ACTION_INSTALL = 4
ACTION_ROOT_ROTATE = 5
ACTION_AUDIT_ACCEPT = 6

CONTENT_METADATA_ONLY = 0
CONTENT_PUBLIC_COMMITMENT = 1
CONTENT_REVIEWED_CONTENT = 2

ALG_MLKEM = "ML-KEM-1024.encap"
ALG_DHKEM_P384 = "DHKEM-P384-HKDF-SHA384"
ALG_MLDSA87 = "ML-DSA-87"
ALG_SLHDSA = "SLH-DSA-SHAKE-256s"

# Claim classes
CLAIM_RESEARCH = 0
CLAIM_PROOF = 1
CLAIM_OPEN_EVIDENCE = 2
CLAIM_RELEASE_CANDIDATE = 3
CLAIM_INSTALL_EVIDENCE = 4
CLAIM_HYBRID_EVIDENCE = 5
CLAIM_ROOT_CEREMONY = 6
CLAIM_AUDIT_EVIDENCE = 7

# Auth block fields
AUTH_Q_SIGS = 0
AUTH_H_SIG = 1
AUTH_FROST = 2

# Envelope fields
ENV_MAGIC = 0
ENV_HEADER = 1
ENV_KEM_BLOCK = 2
ENV_CIPHERTEXT = 3
ENV_COM_A = 4
ENV_AUTH_BLOCK = 5
ENV_AUX_BLOCK = 6

NULL_HASH: bytes  # assigned after CBOR helpers are available
SUITE_ID: bytes   # assigned after hash helpers are available


class RejectStage(str, Enum):
    REJECT_PARSE = "REJECT_PARSE"
    REJECT_SCHEMA = "REJECT_SCHEMA"
    REJECT_SUITE = "REJECT_SUITE"
    REJECT_AUX_HASH = "REJECT_AUX_HASH"
    REJECT_POLICY = "REJECT_POLICY"
    REJECT_CLAIMS = "REJECT_CLAIMS"
    REJECT_KEM_BLOCK = "REJECT_KEM_BLOCK"
    REJECT_AUTH_BLOCK = "REJECT_AUTH_BLOCK"
    REJECT_AUTH_SIGNATURE = "REJECT_AUTH_SIGNATURE"
    REJECT_REVIEW = "REJECT_REVIEW"
    REJECT_DOWNGRADE = "REJECT_DOWNGRADE"
    REJECT_LOG = "REJECT_LOG"
    REJECT_INSTALL = "REJECT_INSTALL"
    REJECT_WITNESS = "REJECT_WITNESS"
    REJECT_DECAP = "REJECT_DECAP"
    REJECT_AEAD = "REJECT_AEAD"
    REJECT_PAYLOAD = "REJECT_PAYLOAD"
    REJECT_COMMIT = "REJECT_COMMIT"
    REJECT_LEAK = "REJECT_LEAK"


class DaylightError(Exception):
    def __init__(self, stage: RejectStage, message: str):
        super().__init__(f"{stage.value}: {message}")
        self.stage = stage
        self.message = message


@dataclass
class OpenResult:
    ok: bool
    artifact: Optional[bytes] = None
    rejection_stage: Optional[RejectStage] = None
    private_kem_called: bool = False
    aead_dec_called: bool = False
    diagnostics: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "artifact_hex": self.artifact.hex() if self.artifact is not None else None,
            "rejection_stage": None if self.rejection_stage is None else self.rejection_stage.value,
            "private_kem_called": self.private_kem_called,
            "aead_dec_called": self.aead_dec_called,
            "diagnostics": self.diagnostics,
        }


# ---------------------------------------------------------------------------
# Deterministic CBOR subset
# ---------------------------------------------------------------------------

class CBORError(ValueError):
    pass


def _enc_type_len(major: int, n: int) -> bytes:
    if not isinstance(n, int) or n < 0:
        raise CBORError("CBOR length/int must be non-negative integer")
    ib = major << 5
    if n < 24:
        return bytes([ib | n])
    if n <= 0xFF:
        return bytes([ib | 24, n])
    if n <= 0xFFFF:
        return bytes([ib | 25]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([ib | 26]) + n.to_bytes(4, "big")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return bytes([ib | 27]) + n.to_bytes(8, "big")
    raise CBORError("integer too large for this CBOR subset")


def dumps(obj: Any) -> bytes:
    """Encode deterministic CBOR for the limited Daylight v0.6 domain."""
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj < 0:
            raise CBORError("negative integers forbidden")
        return _enc_type_len(0, obj)
    if isinstance(obj, bytes):
        return _enc_type_len(2, len(obj)) + obj
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _enc_type_len(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        out = _enc_type_len(4, len(obj))
        for item in obj:
            out += dumps(item)
        return out
    if isinstance(obj, dict):
        # Schema maps use unsigned-int keys. For generic maps, sort by encoded key.
        items = list(obj.items())
        if all(isinstance(k, int) and not isinstance(k, bool) and k >= 0 for k, _ in items):
            items.sort(key=lambda kv: kv[0])
        else:
            items.sort(key=lambda kv: dumps(kv[0]))
        out = _enc_type_len(5, len(items))
        prev_key = object()
        first = True
        for k, v in items:
            if not first and k == prev_key:
                raise CBORError("duplicate map key")
            first = False
            prev_key = k
            out += dumps(k) + dumps(v)
        return out
    raise CBORError(f"unsupported CBOR type: {type(obj)!r}")


def _read_len(data: bytes, pos: int, addl: int) -> Tuple[int, int]:
    if addl < 24:
        return addl, pos
    if addl == 24:
        if pos >= len(data):
            raise CBORError("truncated uint8")
        n = data[pos]
        if n < 24:
            raise CBORError("non-minimal integer/length")
        return n, pos + 1
    if addl == 25:
        if pos + 2 > len(data):
            raise CBORError("truncated uint16")
        n = int.from_bytes(data[pos:pos+2], "big")
        if n <= 0xFF:
            raise CBORError("non-minimal integer/length")
        return n, pos + 2
    if addl == 26:
        if pos + 4 > len(data):
            raise CBORError("truncated uint32")
        n = int.from_bytes(data[pos:pos+4], "big")
        if n <= 0xFFFF:
            raise CBORError("non-minimal integer/length")
        return n, pos + 4
    if addl == 27:
        if pos + 8 > len(data):
            raise CBORError("truncated uint64")
        n = int.from_bytes(data[pos:pos+8], "big")
        if n <= 0xFFFFFFFF:
            raise CBORError("non-minimal integer/length")
        return n, pos + 8
    raise CBORError("indefinite/reserved additional information forbidden")


def _loads_item(data: bytes, pos: int = 0) -> Tuple[Any, int]:
    if pos >= len(data):
        raise CBORError("unexpected end")
    b = data[pos]
    pos += 1
    major = b >> 5
    addl = b & 0x1f

    if major == 0:
        return _read_len(data, pos, addl)
    if major == 1:
        raise CBORError("negative integers forbidden")
    if major == 2:
        n, pos = _read_len(data, pos, addl)
        if pos + n > len(data):
            raise CBORError("truncated byte string")
        return data[pos:pos+n], pos + n
    if major == 3:
        n, pos = _read_len(data, pos, addl)
        if pos + n > len(data):
            raise CBORError("truncated text string")
        raw = data[pos:pos+n]
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CBORError("invalid utf-8 text string") from e
        return s, pos + n
    if major == 4:
        n, pos = _read_len(data, pos, addl)
        arr = []
        for _ in range(n):
            item, pos = _loads_item(data, pos)
            arr.append(item)
        return arr, pos
    if major == 5:
        n, pos = _read_len(data, pos, addl)
        m: Dict[Any, Any] = {}
        prev_key = None
        prev_key_bytes = None
        int_key_mode: Optional[bool] = None
        for i in range(n):
            key_start = pos
            k, pos = _loads_item(data, pos)
            key_bytes = data[key_start:pos]
            if k in m:
                raise CBORError("duplicate map key")
            this_int = isinstance(k, int) and not isinstance(k, bool)
            if int_key_mode is None:
                int_key_mode = this_int
            elif int_key_mode != this_int:
                raise CBORError("mixed integer and non-integer map keys forbidden")
            if i > 0:
                if int_key_mode:
                    if not (isinstance(prev_key, int) and k > prev_key):
                        raise CBORError("integer map keys not strictly increasing")
                else:
                    if not (key_bytes > prev_key_bytes):
                        raise CBORError("map keys not strictly increasing")
            v, pos = _loads_item(data, pos)
            m[k] = v
            prev_key = k
            prev_key_bytes = key_bytes
        return m, pos
    if major == 6:
        raise CBORError("CBOR tags forbidden")
    if major == 7:
        if addl == 20:
            return False, pos
        if addl == 21:
            return True, pos
        if addl == 22:
            return None, pos
        raise CBORError("simple values/floats forbidden")
    raise CBORError("unknown CBOR major type")


def loads(data: bytes) -> Any:
    obj, pos = _loads_item(data, 0)
    if pos != len(data):
        raise CBORError("trailing bytes")
    # Re-encode check catches non-canonical lengths/order beyond parser checks.
    if dumps(obj) != data:
        raise CBORError("non-canonical encoding")
    return obj


# ---------------------------------------------------------------------------
# Hash/KDF/AEAD
# ---------------------------------------------------------------------------

def hc(obj: Any) -> bytes:
    return hashlib.sha3_512(dumps(obj)).digest()


def hb(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def hc32(obj: Any) -> bytes:
    return hashlib.shake_256(dumps(obj)).digest(32)


def artifact_hash(a: bytes) -> bytes:
    return hb(a)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        return b""
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha512).digest()
        out += t
        counter += 1
        if counter > 255:
            raise ValueError("HKDF expand length too large")
    return out[:length]


def kdf2(secret: bytes, label: str, input_obj: Any, length: int) -> bytes:
    prk = hkdf_extract(hc(["daylight-kdf2-salt.v6", label]), secret)
    info = dumps(["daylight-kdf2-info.v6", label, input_obj])
    return hkdf_expand(prk, info, length)


def e(label: str, *xs: Any) -> bytes:
    return dumps([label, *xs])


NULL_HASH = hc(None)
SUITE_ID = hc([
    "Suite_D6-fixture-m1",
    "Deterministic-CBOR-Daylight-v6",
    "SHA3-512",
    "SHAKE256",
    "HKDF-SHA512",
    "ML-KEM-1024 fixture provider",
    "DHKEM-P384-HKDF-SHA384 fixture provider",
    "AES-256-GCM",
    "ChaCha20-Poly1305-IETF",
    "ML-DSA-87 fixture provider",
    "SLH-DSA-SHAKE-256s fixture provider",
])


# ---------------------------------------------------------------------------
# Utility validators
# ---------------------------------------------------------------------------

def is_hash64(x: Any) -> bool:
    return isinstance(x, bytes) and len(x) == 64


def is_key32(x: Any) -> bool:
    return isinstance(x, bytes) and len(x) == 32


def is_u64(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x < 2**64


def ascii_ok(s: Any, min_len: int = 0, max_len: int = 2**20) -> bool:
    if not isinstance(s, str):
        return False
    if not (min_len <= len(s) <= max_len):
        return False
    try:
        s.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def require(cond: bool, stage: RejectStage, message: str) -> None:
    if not cond:
        raise DaylightError(stage, message)


def require_keys(m: Any, keys: Iterable[int], stage: RejectStage, name: str) -> None:
    expected = set(keys)
    require(isinstance(m, dict), stage, f"{name} must be map")
    require(set(m.keys()) == expected, stage, f"{name} keys must be exactly {sorted(expected)}")


def sorted_unique(xs: List[Any]) -> bool:
    return all(xs[i] < xs[i + 1] for i in range(len(xs) - 1))


def i2osp96(j: int) -> bytes:
    if not (0 <= j < 2**96):
        raise ValueError("j out of u96 range")
    return j.to_bytes(12, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_okm(okm: bytes) -> Tuple[bytes, bytes, bytes]:
    if len(okm) != 76:
        raise ValueError("bad OKM length")
    return okm[:32], okm[32:64], okm[64:76]


def aead_encrypt(aead_id: int, key: bytes, nonce: bytes, plaintext: bytes, ad: bytes) -> bytes:
    if aead_id == AEAD_AES_256_GCM:
        return AESGCM(key).encrypt(nonce, plaintext, ad)
    if aead_id == AEAD_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)
    raise ValueError("unsupported AEAD id")


def aead_decrypt(aead_id: int, key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    if aead_id == AEAD_AES_256_GCM:
        return AESGCM(key).decrypt(nonce, ciphertext, ad)
    if aead_id == AEAD_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)
    raise ValueError("unsupported AEAD id")


# ---------------------------------------------------------------------------
# Fixture crypto provider
# ---------------------------------------------------------------------------

def fixture_bytes(label: str, n: int) -> bytes:
    return hashlib.shake_256(dumps(["daylight.fixture.v6", label])).digest(n)


def key_id(alg_id: str, public_key_bytes: bytes, domain_id: Any) -> bytes:
    return hc(["daylight.key-id.v6", alg_id, public_key_bytes, domain_id])


def fixture_encaps(seed: str, public_key: bytes, secret_key: bytes, label: str, out_len: int = 64) -> Tuple[bytes, bytes]:
    enc = hashlib.shake_256(dumps(["fixture.encaps.v6", seed, label, public_key])).digest(out_len)
    ss = fixture_decaps(secret_key, public_key, enc, label)
    return ss, enc


def fixture_decaps(secret_key: bytes, public_key: bytes, enc: bytes, label: str) -> bytes:
    return hb(dumps(["fixture.decaps.v6", label, secret_key, public_key, enc]))


def fixture_q_sig(pk_q: bytes, auth_msg: bytes) -> bytes:
    return hb(dumps(["fixture.ml-dsa-87.sig.v6", pk_q, auth_msg, CTX_AUTH]))


def fixture_h_sig(pk_h: bytes, auth_msg: bytes) -> bytes:
    return hb(dumps(["fixture.slh-dsa.sig.v6", pk_h, auth_msg, CTX_AUTH]))


def fixture_review_receipt(header: Dict[int, Any], reviewer_pk: bytes) -> Dict[int, Any]:
    review_subject = e("daylight.review.subject.v6", header)
    subject_hash = hb(review_subject)
    sig = hb(dumps(["fixture.review.sig.v6", reviewer_pk, subject_hash, CTX_REVIEW]))
    return {0: b"fixture-reviewer-1", 1: subject_hash, 2: sig}


def fixture_review_receipt_ok(receipt: Any, header: Dict[int, Any], keyset_obj: Dict[int, Any]) -> bool:
    if not isinstance(receipt, dict) or set(receipt.keys()) != {0, 1, 2}:
        return False
    reviewer_pk = keyset_obj.get(7, {}).get(0, None) if isinstance(keyset_obj.get(7), dict) else None
    if not isinstance(reviewer_pk, bytes):
        return False
    review_subject = e("daylight.review.subject.v6", header)
    subject_hash = hb(review_subject)
    if receipt[1] != subject_hash:
        return False
    expected = hb(dumps(["fixture.review.sig.v6", reviewer_pk, subject_hash, CTX_REVIEW]))
    return receipt[2] == expected


def default_fixture_material() -> Dict[str, Any]:
    """Small fixture key set. Values are deterministic and test-only."""
    ek_q = fixture_bytes("ek_Q.fixture-public", 64)
    dk_q = fixture_bytes("dk_Q.fixture-secret", 64)
    pk_c = fixture_bytes("pk_C.fixture-public", 64)
    sk_c = fixture_bytes("sk_C.fixture-secret", 64)
    pk_q = fixture_bytes("pk_Q.fixture-auth", 64)
    pk_h = fixture_bytes("pk_H.fixture-root", 64)
    reviewer_pk = fixture_bytes("reviewer.fixture", 64)

    q_sig_key_id = key_id(ALG_MLDSA87, pk_q, "domain-A")
    q_kem_key_id = key_id(ALG_MLKEM, ek_q, "kem-Q")
    c_kem_key_id = key_id(ALG_DHKEM_P384, pk_c, "kem-C")

    q_roster = [
        {0: q_sig_key_id, 1: pk_q, 2: "domain-A", 3: None},
    ]
    thresholds = {0: 1, 1: 1, 2: 0, 3: 0}
    keyset = {
        0: ek_q,
        1: pk_c,
        2: q_roster,
        3: pk_h,
        4: None,
        5: {},
        6: {},
        7: {0: reviewer_pk},
        8: thresholds,
    }
    keyset_hash = hc(keyset)
    policy = {
        0: "daylight-v6-fixture-policy",
        1: [PROFILE_D2_HYBRID, PROFILE_D3_ROOT, PROFILE_D2_HYBRID_FROST],
        2: [AEAD_AES_256_GCM, AEAD_CHACHA20_POLY1305],
        3: [ACTION_RESEARCH, ACTION_PROOF, ACTION_OPEN, ACTION_RELEASE, ACTION_INSTALL, ACTION_ROOT_ROTATE, ACTION_AUDIT_ACCEPT],
        4: {
            ACTION_RESEARCH: [0, MU_HYBRID],
            ACTION_PROOF: [0, MU_HYBRID],
            ACTION_OPEN: [1, MU_HYBRID],
            ACTION_RELEASE: [2, MU_HYBRID],
            ACTION_INSTALL: [2, MU_HYBRID],
            ACTION_ROOT_ROTATE: [3, MU_HYBRID],
            ACTION_AUDIT_ACCEPT: [3, MU_HYBRID],
        },
        5: [keyset_hash],
        6: False,
        7: False,
        8: False,
        9: [],
        10: [CLAIM_RESEARCH, CLAIM_PROOF, CLAIM_OPEN_EVIDENCE, CLAIM_RELEASE_CANDIDATE, CLAIM_INSTALL_EVIDENCE, CLAIM_HYBRID_EVIDENCE, CLAIM_ROOT_CEREMONY, CLAIM_AUDIT_EVIDENCE],
        11: None,
        12: 6,
    }
    claims = [
        {0: CLAIM_RESEARCH, 1: "vector-purpose", 2: "M1 fixture vector"},
        {0: CLAIM_OPEN_EVIDENCE, 1: "open-intent", 2: "test open path"},
    ]
    return {
        "ek_q": ek_q,
        "dk_q": dk_q,
        "pk_c": pk_c,
        "sk_c": sk_c,
        "pk_q": pk_q,
        "pk_h": pk_h,
        "reviewer_pk": reviewer_pk,
        "q_sig_key_id": q_sig_key_id,
        "q_kem_key_id": q_kem_key_id,
        "c_kem_key_id": c_kem_key_id,
        "keyset": keyset,
        "policy": policy,
        "claims": claims,
    }


# ---------------------------------------------------------------------------
# Schema validation and transcript construction
# ---------------------------------------------------------------------------

def validate_header(header: Any, stage: RejectStage = RejectStage.REJECT_SCHEMA) -> None:
    require_keys(header, range(18), stage, "Header_v6")
    require(header[0] == VERSION, RejectStage.REJECT_SUITE, "version must be 6")
    require(is_hash64(header[1]), RejectStage.REJECT_SUITE, "suite_id must be Hash64")
    require(header[1] == SUITE_ID, RejectStage.REJECT_SUITE, "suite_id mismatch")
    require(header[2] in {1, 2, 3}, RejectStage.REJECT_SUITE, "bad profile")
    require(header[3] in {0, 1, 2, 3}, RejectStage.REJECT_SUITE, "bad r")
    require(header[4] in {1, 2}, RejectStage.REJECT_SUITE, "bad mu")
    require(header[5] in {0, 1, 2, 3, 4, 5, 6}, RejectStage.REJECT_SUITE, "bad action")
    require(header[6] in {0, 1, 2}, RejectStage.REJECT_SUITE, "bad content_scope")
    validate_leak_value(header[6], header[7])
    require(header[8] in {1, 2}, RejectStage.REJECT_SUITE, "bad aead_id")
    require(ascii_ok(header[9], 1, 128), stage, "policy_id must be ASCII 1..128")
    for idx in [10, 11, 13, 14, 15]:
        require(is_hash64(header[idx]), stage, f"header[{idx}] must be Hash64")
    require(header[12] is None or is_hash64(header[12]), stage, "prev_log_head must be null or Hash64")
    require(is_u64(header[16]), stage, "key_epoch must be u64")
    require(header[17] in {1, 2, 3, 4, 5}, stage, "bad conformance_min")


def validate_leak_value(scope: int, leak_value: Any) -> None:
    if scope == CONTENT_METADATA_ONLY:
        require(is_u64(leak_value), RejectStage.REJECT_SCHEMA, "metadata_only leak_value must be u64")
    elif scope == CONTENT_PUBLIC_COMMITMENT:
        require(isinstance(leak_value, list) and len(leak_value) == 2, RejectStage.REJECT_SCHEMA, "public_commitment leak_value shape")
        require(is_u64(leak_value[0]) and is_hash64(leak_value[1]), RejectStage.REJECT_SCHEMA, "public_commitment leak types")
    elif scope == CONTENT_REVIEWED_CONTENT:
        require(isinstance(leak_value, list) and len(leak_value) == 2, RejectStage.REJECT_SCHEMA, "reviewed_content leak_value shape")
        require(is_u64(leak_value[0]) and is_hash64(leak_value[1]), RejectStage.REJECT_SCHEMA, "reviewed_content leak types")
    else:
        raise DaylightError(RejectStage.REJECT_SUITE, "unknown content scope")


def validate_envelope_shape(env: Any) -> None:
    require_keys(env, range(7), RejectStage.REJECT_SCHEMA, "Envelope_v6")
    require(env[ENV_MAGIC] == MAGIC, RejectStage.REJECT_SCHEMA, "bad magic")
    validate_header(env[ENV_HEADER], RejectStage.REJECT_SCHEMA)
    require(isinstance(env[ENV_CIPHERTEXT], bytes), RejectStage.REJECT_SCHEMA, "ciphertext must be bytes")
    require(isinstance(env[ENV_COM_A], bytes) and len(env[ENV_COM_A]) == 32, RejectStage.REJECT_SCHEMA, "com_A must be Bytes[32]")


def validate_aux_block(aux: Any) -> None:
    require_keys(aux, range(8), RejectStage.REJECT_SCHEMA, "AuxBlock_v6")
    require(aux[0] is not None, RejectStage.REJECT_SCHEMA, "policy_obj is mandatory")
    require(aux[1] is not None, RejectStage.REJECT_SCHEMA, "keyset_obj is mandatory")
    require(aux[2] is not None, RejectStage.REJECT_SCHEMA, "claims_obj is mandatory")


def object_hash_ok(obj: Any, h: bytes) -> bool:
    if obj is None:
        return h == NULL_HASH
    return hc(obj) == h


def validate_policy_schema(policy: Any) -> None:
    require_keys(policy, range(13), RejectStage.REJECT_POLICY, "Policy_v6")
    require(ascii_ok(policy[0], 1, 128), RejectStage.REJECT_POLICY, "bad policy_id")
    for idx, name in [(1, "allowed_profiles"), (2, "allowed_aeads"), (3, "allowed_actions"), (5, "allowed_keyset_hashes"), (9, "log_required_actions"), (10, "allowed_claim_classes")]:
        require(isinstance(policy[idx], list), RejectStage.REJECT_POLICY, f"{name} must be array")
        require(len(policy[idx]) == len(set(policy[idx])) if idx != 5 else True, RejectStage.REJECT_POLICY, f"{name} duplicate entries")
        require(policy[idx] == sorted(policy[idx]), RejectStage.REJECT_POLICY, f"{name} must be sorted")
    require(all(p in {1,2,3} for p in policy[1]), RejectStage.REJECT_POLICY, "bad allowed profile")
    require(all(a in {1,2} for a in policy[2]), RejectStage.REJECT_POLICY, "bad allowed aead")
    require(all(a in {0,1,2,3,4,5,6} for a in policy[3]), RejectStage.REJECT_POLICY, "bad allowed action")
    require(isinstance(policy[4], dict), RejectStage.REJECT_POLICY, "min_mode_by_action must be map")
    for act, mode in policy[4].items():
        require(act in {0,1,2,3,4,5,6}, RejectStage.REJECT_POLICY, "bad min-mode action")
        require(isinstance(mode, list) and len(mode) == 2 and mode[0] in {0,1,2,3} and mode[1] in {1,2}, RejectStage.REJECT_POLICY, "bad min-mode value")
    require(all(is_hash64(h) for h in policy[5]), RejectStage.REJECT_POLICY, "allowed_keyset_hashes must be Hash64 array")
    require(isinstance(policy[6], bool), RejectStage.REJECT_POLICY, "require_exact_content_approval must be bool")
    require(isinstance(policy[7], bool), RejectStage.REJECT_POLICY, "require_provenance must be bool")
    require(isinstance(policy[8], bool), RejectStage.REJECT_POLICY, "require_witness must be bool")
    require(all(a in {0,1,2,3,4,5,6} for a in policy[9]), RejectStage.REJECT_POLICY, "bad log_required action")
    require(all(c in {0,1,2,3,4,5,6,7} for c in policy[10]), RejectStage.REJECT_POLICY, "bad allowed claim class")
    require(policy[11] is None or is_u64(policy[11]), RejectStage.REJECT_POLICY, "expiry_epoch must be null or u64")
    require(policy[12] == 6, RejectStage.REJECT_POLICY, "policy_version must be 6")


def validate_claims_schema(claims: Any) -> None:
    require(isinstance(claims, list), RejectStage.REJECT_CLAIMS, "Claims_v6 must be array")
    for c in claims:
        require_keys(c, [0,1,2], RejectStage.REJECT_CLAIMS, "Claim_v6")
        require(c[0] in {0,1,2,3,4,5,6,7}, RejectStage.REJECT_CLAIMS, "bad claim class")
        require(ascii_ok(c[1], 1, 128), RejectStage.REJECT_CLAIMS, "claim_name must be ASCII")


def allowed_claim_classes_for_r(r: int) -> set[int]:
    s = {CLAIM_RESEARCH, CLAIM_PROOF}
    if r >= 1:
        s.add(CLAIM_OPEN_EVIDENCE)
    if r >= 2:
        s.update({CLAIM_RELEASE_CANDIDATE, CLAIM_INSTALL_EVIDENCE, CLAIM_HYBRID_EVIDENCE})
    if r >= 3:
        s.update({CLAIM_ROOT_CEREMONY, CLAIM_AUDIT_EVIDENCE})
    return s


def validate_keyset_schema(keyset: Any) -> None:
    require_keys(keyset, range(9), RejectStage.REJECT_POLICY, "KeySetPub_v6")
    require(isinstance(keyset[0], bytes) and len(keyset[0]) > 0, RejectStage.REJECT_POLICY, "ek_Q must be bytes")
    require(isinstance(keyset[1], bytes) and len(keyset[1]) > 0, RejectStage.REJECT_POLICY, "pk_C must be bytes")
    require(isinstance(keyset[2], list) and len(keyset[2]) > 0, RejectStage.REJECT_POLICY, "Q_roster must be non-empty array")
    prev = None
    seen = set()
    for q in keyset[2]:
        require_keys(q, [0,1,2,3], RejectStage.REJECT_POLICY, "QRosterEntry_v6")
        require(is_hash64(q[0]), RejectStage.REJECT_POLICY, "Q key_id must be Hash64")
        require(isinstance(q[1], bytes) and len(q[1]) > 0, RejectStage.REJECT_POLICY, "pk_Q must be bytes")
        require(ascii_ok(q[2], 1, 128), RejectStage.REJECT_POLICY, "domain_id must be ASCII")
        require(prev is None or q[0] > prev, RejectStage.REJECT_POLICY, "Q_roster must be sorted by key_id")
        require(q[0] not in seen, RejectStage.REJECT_POLICY, "duplicate Q key_id")
        expected = key_id(ALG_MLDSA87, q[1], q[2])
        require(q[0] == expected, RejectStage.REJECT_POLICY, "Q key_id mismatch")
        seen.add(q[0])
        prev = q[0]
    require(keyset[3] is None or isinstance(keyset[3], bytes), RejectStage.REJECT_POLICY, "pk_H must be null or bytes")
    require(keyset[4] is None or isinstance(keyset[4], dict), RejectStage.REJECT_POLICY, "frost_pub must be null or map")
    require(isinstance(keyset[5], dict), RejectStage.REJECT_POLICY, "certificates must be map")
    require(isinstance(keyset[6], dict), RejectStage.REJECT_POLICY, "revocation_state must be map")
    require(isinstance(keyset[7], dict), RejectStage.REJECT_POLICY, "policy_keys must be map")
    require_keys(keyset[8], [0,1,2,3], RejectStage.REJECT_POLICY, "Thresholds_v6")
    require(isinstance(keyset[8][0], int) and keyset[8][0] >= 1, RejectStage.REJECT_POLICY, "t_Q must be >=1")
    require(isinstance(keyset[8][1], int) and keyset[8][1] >= 1, RejectStage.REJECT_POLICY, "u_Q must be >=1")


def validate_kem_block_schema(kem: Any, keyset: Dict[int, Any]) -> None:
    require_keys(kem, range(4), RejectStage.REJECT_KEM_BLOCK, "KEMBlock_v6")
    require(is_hash64(kem[0]) and is_hash64(kem[1]), RejectStage.REJECT_KEM_BLOCK, "KEM key ids must be Hash64")
    require(isinstance(kem[2], bytes) and len(kem[2]) > 0, RejectStage.REJECT_KEM_BLOCK, "enc_Q must be bytes")
    require(isinstance(kem[3], bytes) and len(kem[3]) > 0, RejectStage.REJECT_KEM_BLOCK, "enc_C must be bytes")
    require(kem[0] == key_id(ALG_MLKEM, keyset[0], "kem-Q"), RejectStage.REJECT_KEM_BLOCK, "q_kem_key_id mismatch")
    require(kem[1] == key_id(ALG_DHKEM_P384, keyset[1], "kem-C"), RejectStage.REJECT_KEM_BLOCK, "c_kem_key_id mismatch")


def validate_auth_block_schema(auth: Any, profile: int) -> None:
    require_keys(auth, [0,1,2], RejectStage.REJECT_AUTH_BLOCK, "AuthBlock_v6")
    require(isinstance(auth[0], list), RejectStage.REJECT_AUTH_BLOCK, "q_sigs must be array")
    prev = None
    seen = set()
    for qsig in auth[0]:
        require_keys(qsig, [0,1], RejectStage.REJECT_AUTH_BLOCK, "QSig_v6")
        require(is_hash64(qsig[0]), RejectStage.REJECT_AUTH_BLOCK, "QSig key_id must be Hash64")
        require(isinstance(qsig[1], bytes), RejectStage.REJECT_AUTH_BLOCK, "QSig sig must be bytes")
        require(prev is None or qsig[0] > prev, RejectStage.REJECT_AUTH_BLOCK, "q_sigs not sorted")
        require(qsig[0] not in seen, RejectStage.REJECT_AUTH_BLOCK, "duplicate q_sig key_id")
        seen.add(qsig[0])
        prev = qsig[0]
    require(auth[1] is None or isinstance(auth[1], bytes), RejectStage.REJECT_AUTH_BLOCK, "h_sig must be null or bytes")
    require(auth[2] is None or isinstance(auth[2], dict), RejectStage.REJECT_AUTH_BLOCK, "frost_auth must be null or map")
    if profile != PROFILE_D2_HYBRID_FROST:
        require(auth[2] is None, RejectStage.REJECT_AUTH_BLOCK, "frost_auth forbidden for non-FROST profile")


def build_t0(header: Dict[int, Any]) -> Tuple[bytes, bytes]:
    t0 = e("daylight.pre.v6", header)
    return t0, hb(t0)


def review_receipt_hash(aux: Dict[int, Any]) -> bytes:
    return hc(aux[4]) if aux[4] is not None else NULL_HASH


def build_t1(header: Dict[int, Any], kem_block: Dict[int, Any], ciphertext: bytes, com_a: bytes, aux: Dict[int, Any]) -> Tuple[bytes, bytes, bytes]:
    t0, h0 = build_t0(header)
    kem_hash = hc(kem_block)
    cipher_hash = hb(ciphertext)
    rrh = review_receipt_hash(aux)
    t1 = e("daylight.auth.transcript.v6", h0, kem_hash, cipher_hash, com_a, rrh)
    h1 = hb(t1)
    auth_msg = e("daylight.authorization.message.v6", CTX_AUTH, h1)
    return t1, h1, auth_msg


def allowed_actions(r: int) -> set[int]:
    s = {ACTION_RESEARCH, ACTION_PROOF}
    if r >= 1:
        s.add(ACTION_OPEN)
    if r >= 2:
        s.update({ACTION_RELEASE, ACTION_INSTALL})
    if r >= 3:
        s.update({ACTION_ROOT_ROTATE, ACTION_AUDIT_ACCEPT})
    return s


def req(profile: int, r: int, mu: int) -> Optional[set[str]]:
    if profile == PROFILE_D2_HYBRID:
        if mu == MU_HYBRID:
            return {"Q"} if r < 3 else {"Q", "H"}
        if mu == MU_PQ_STRICT:
            return {"Q", "H"}
    if profile == PROFILE_D3_ROOT:
        if mu in {MU_HYBRID, MU_PQ_STRICT}:
            return {"Q", "H"}
    if profile == PROFILE_D2_HYBRID_FROST:
        if mu == MU_HYBRID:
            return {"Q", "F"} if r < 3 else {"Q", "H", "F"}
        if mu == MU_PQ_STRICT:
            return {"Q", "H", "F"}
    return None


def mode_ok(header: Dict[int, Any]) -> bool:
    requirements = req(header[2], header[3], header[4])
    return requirements is not None and header[5] in allowed_actions(header[3])


def static_policy_gate(header: Dict[int, Any], policy: Dict[int, Any], keyset_hash: bytes) -> None:
    require(policy[0] == header[9], RejectStage.REJECT_POLICY, "policy_id mismatch")
    require(header[2] in policy[1], RejectStage.REJECT_POLICY, "profile not allowed")
    require(header[8] in policy[2], RejectStage.REJECT_POLICY, "AEAD not allowed")
    require(header[5] in policy[3], RejectStage.REJECT_POLICY, "action not allowed")
    require(keyset_hash in policy[5], RejectStage.REJECT_POLICY, "keyset not allowed by policy")
    require(mode_ok(header), RejectStage.REJECT_POLICY, "mode/action invalid")


def claim_ok(header: Dict[int, Any], claims: List[Any], policy: Dict[int, Any]) -> None:
    validate_claims_schema(claims)
    allowed_for_r = allowed_claim_classes_for_r(header[3])
    policy_allowed = set(policy[10])
    for c in claims:
        require(c[0] in allowed_for_r, RejectStage.REJECT_CLAIMS, "claim not allowed at r")
        require(c[0] in policy_allowed, RejectStage.REJECT_CLAIMS, "claim not allowed by policy")


def no_downgrade(header: Dict[int, Any], policy: Dict[int, Any]) -> None:
    action = header[5]
    require(action in policy[4], RejectStage.REJECT_DOWNGRADE, "missing min mode for action")
    r_min, mu_min = policy[4][action]
    require(header[3] >= r_min, RejectStage.REJECT_DOWNGRADE, "r below policy minimum")
    require(header[4] >= mu_min, RejectStage.REJECT_DOWNGRADE, "mu below policy minimum")
    require(header[8] in policy[2], RejectStage.REJECT_DOWNGRADE, "AEAD not allowed")


def verify_authorization(header: Dict[int, Any], keyset: Dict[int, Any], auth: Dict[int, Any], auth_msg: bytes) -> None:
    requirements = req(header[2], header[3], header[4])
    require(requirements is not None, RejectStage.REJECT_AUTH_SIGNATURE, "undefined profile requirements")

    q_by_id = {entry[0]: entry for entry in keyset[2]}
    good_q = []
    for qsig in auth[0]:
        entry = q_by_id.get(qsig[0])
        if entry is None:
            continue
        pk_q = entry[1]
        if qsig[1] == fixture_q_sig(pk_q, auth_msg):
            good_q.append(entry)
    t_q = keyset[8][0]
    u_q = keyset[8][1]
    domains = {entry[2] for entry in good_q}
    if "Q" in requirements:
        require(len(good_q) >= t_q, RejectStage.REJECT_AUTH_SIGNATURE, "insufficient Q threshold")
        require(len(domains) >= u_q, RejectStage.REJECT_AUTH_SIGNATURE, "insufficient Q domain count")
    else:
        require(len(auth[0]) == 0, RejectStage.REJECT_AUTH_SIGNATURE, "unexpected Q signatures")

    if "H" in requirements:
        require(keyset[3] is not None, RejectStage.REJECT_AUTH_SIGNATURE, "pk_H absent")
        require(auth[1] is not None, RejectStage.REJECT_AUTH_SIGNATURE, "h_sig absent")
        require(auth[1] == fixture_h_sig(keyset[3], auth_msg), RejectStage.REJECT_AUTH_SIGNATURE, "bad H signature")
    else:
        require(auth[1] is None, RejectStage.REJECT_AUTH_SIGNATURE, "unexpected H signature")

    if "F" in requirements:
        raise DaylightError(RejectStage.REJECT_AUTH_SIGNATURE, "FROST fixture not implemented for C1")
    else:
        require(auth[2] is None, RejectStage.REJECT_AUTH_SIGNATURE, "unexpected FROST auth")


def content_review_pre_ok(header: Dict[int, Any], aux: Dict[int, Any], keyset: Dict[int, Any], policy: Dict[int, Any]) -> None:
    scope = header[6]
    if scope == CONTENT_METADATA_ONLY:
        require(policy[6] is False, RejectStage.REJECT_REVIEW, "metadata_only forbidden when exact approval required")
        return
    require(aux[4] is not None, RejectStage.REJECT_REVIEW, "review receipt required")
    require(fixture_review_receipt_ok(aux[4], header, keyset), RejectStage.REJECT_REVIEW, "bad review receipt")


def log_ok(header: Dict[int, Any], aux: Dict[int, Any], policy: Dict[int, Any]) -> None:
    required_actions = set(policy[9])
    if header[5] not in required_actions:
        return
    proof = aux[5]
    require(isinstance(proof, dict) and proof.get(0) == b"fixture-log-ok", RejectStage.REJECT_LOG, "missing or bad log proof")


def provenance_ok(header: Dict[int, Any], aux: Dict[int, Any], policy: Dict[int, Any]) -> None:
    if policy[7] is False:
        require(header[13] == NULL_HASH and aux[3] is None, RejectStage.REJECT_POLICY, "unexpected provenance under no-provenance policy")
    else:
        require(aux[3] is not None, RejectStage.REJECT_POLICY, "provenance required")


def witness_ok(header: Dict[int, Any], aux: Dict[int, Any], policy: Dict[int, Any]) -> None:
    if policy[8] is False:
        return
    require(aux[7] is not None, RejectStage.REJECT_WITNESS, "witness required")


def install_ok(header: Dict[int, Any], aux: Dict[int, Any]) -> None:
    if header[5] != ACTION_INSTALL:
        return
    require(aux[6] is not None, RejectStage.REJECT_INSTALL, "install manifest required")


@dataclass
class PrecheckContext:
    env: Dict[int, Any]
    header: Dict[int, Any]
    kem_block: Dict[int, Any]
    ciphertext: bytes
    com_a: bytes
    auth_block: Dict[int, Any]
    aux: Dict[int, Any]
    policy: Dict[int, Any]
    keyset: Dict[int, Any]
    claims: List[Any]
    t0: bytes
    h0: bytes
    t1: bytes
    h1: bytes
    auth_msg: bytes


def public_precheck(omega_bytes: bytes) -> PrecheckContext:
    # P0: Decode deterministic CBOR.
    try:
        env = loads(omega_bytes)
    except CBORError as ex:
        raise DaylightError(RejectStage.REJECT_PARSE, str(ex)) from ex

    # P1-P3: Envelope/header schema and suite checks.
    validate_envelope_shape(env)
    header = env[ENV_HEADER]
    kem_block = env[ENV_KEM_BLOCK]
    ciphertext = env[ENV_CIPHERTEXT]
    com_a = env[ENV_COM_A]
    auth_block = env[ENV_AUTH_BLOCK]
    aux = env[ENV_AUX_BLOCK]

    # P4: AuxBlock schema and object hashes.
    validate_aux_block(aux)
    policy = aux[0]
    keyset = aux[1]
    claims = aux[2]
    require(object_hash_ok(policy, header[10]), RejectStage.REJECT_AUX_HASH, "policy_hash mismatch")
    require(object_hash_ok(keyset, header[11]), RejectStage.REJECT_AUX_HASH, "keyset_hash mismatch")
    require(object_hash_ok(claims, header[15]), RejectStage.REJECT_AUX_HASH, "claims_hash mismatch")
    require(object_hash_ok(aux[3], header[13]), RejectStage.REJECT_AUX_HASH, "provenance_hash mismatch")
    require(object_hash_ok(aux[6], header[14]), RejectStage.REJECT_AUX_HASH, "install_manifest_hash mismatch")

    # P5: Parse policy_obj, keyset_obj, claims_obj.
    validate_policy_schema(policy)
    validate_keyset_schema(keyset)
    validate_claims_schema(claims)

    # P6: Static policy gate and claims.
    static_policy_gate(header, policy, header[11])
    claim_ok(header, claims, policy)
    provenance_ok(header, aux, policy)
    witness_ok(header, aux, policy)

    # P7: KEMBlock public shape and key references.
    validate_kem_block_schema(kem_block, keyset)

    # P8: Build transcripts.
    t0, h0 = build_t0(header)
    t1, h1, auth_msg = build_t1(header, kem_block, ciphertext, com_a, aux)

    # P9: AuthBlock schema.
    validate_auth_block_schema(auth_block, header[2])

    # P10: Authorization signatures and quorums.
    verify_authorization(header, keyset, auth_block, auth_msg)

    # P11: Content review preconditions.
    content_review_pre_ok(header, aux, keyset, policy)

    # P12: No downgrade.
    no_downgrade(header, policy)

    # P13-P14: Log/install/witness predicates.
    log_ok(header, aux, policy)
    install_ok(header, aux)

    return PrecheckContext(env, header, kem_block, ciphertext, com_a, auth_block, aux, policy, keyset, claims, t0, h0, t1, h1, auth_msg)


# ---------------------------------------------------------------------------
# Key schedule, Seal, Open
# ---------------------------------------------------------------------------

def derive_keys(header: Dict[int, Any], kem_block: Dict[int, Any], keyset: Dict[int, Any], dk_q: bytes, sk_c: bytes) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    t0, h0 = build_t0(header)
    kem_hash = hc(kem_block)
    ss_q = fixture_decaps(dk_q, keyset[0], kem_block[2], "ML-KEM-1024")
    ss_c = fixture_decaps(sk_c, keyset[1], kem_block[3], "DHKEM-P384")
    kem_context = e(
        "daylight.kem.context.v6",
        header[1], header[2], h0, header[11], kem_block[0], kem_block[1], kem_block[2], kem_block[3]
    )
    salt_kem = hc32(["daylight.kem.salt.v6", header[1], h0, header[11], kem_block[0], kem_block[1]])
    prk_d = hkdf_extract(salt_kem, dumps(["daylight.hybrid.ikm.v6", ss_q, ss_c, kem_context]))
    okm = hkdf_expand(
        prk_d,
        dumps(["daylight.key.schedule.v6", h0, kem_hash, header[1], header[2], header[4], header[8]]),
        76,
    )
    k_e, k_com, n_base = split_okm(okm)
    n0 = xor_bytes(n_base, i2osp96(0))
    return k_e, k_com, n_base, n0, ss_q + ss_c


def artifact_commitment(k_com: bytes, header: Dict[int, Any], ciphertext: bytes, artifact: bytes) -> bytes:
    t0, h0 = build_t0(header)
    return kdf2(
        k_com,
        "daylight.artifact.commit.v6",
        (h0, hb(ciphertext), len(artifact), artifact_hash(artifact), header[7]),
        32,
    )


def seal_fixture(
    vector_id: str,
    artifact: bytes,
    *,
    content_scope: int = CONTENT_METADATA_ONLY,
    aead_id: int = AEAD_AES_256_GCM,
    profile: int = PROFILE_D2_HYBRID,
    r: int = 1,
    mu: int = MU_HYBRID,
    action: int = ACTION_OPEN,
    policy_override: Optional[Dict[int, Any]] = None,
    claims_override: Optional[List[Any]] = None,
    keyset_override: Optional[Dict[int, Any]] = None,
    leak_value_override: Any = None,
    private_payload_override: Optional[bytes] = None,
    review_blind_override: Optional[bytes] = None,
    review_receipt_override: Any = "AUTO",
    log_proof: Any = None,
) -> Tuple[Dict[int, Any], Dict[str, bytes], Dict[str, bytes]]:
    mat = default_fixture_material()
    keyset = copy.deepcopy(keyset_override if keyset_override is not None else mat["keyset"])
    keyset_hash = hc(keyset)
    claims = copy.deepcopy(claims_override if claims_override is not None else mat["claims"])
    claims_hash = hc(claims)
    policy = copy.deepcopy(policy_override if policy_override is not None else mat["policy"])
    # If keyset changed, patch default policy unless caller intentionally overrides allowed hash.
    if policy_override is None:
        policy[5] = [keyset_hash]
    policy_hash = hc(policy)

    rho_r = None
    if content_scope == CONTENT_METADATA_ONLY:
        leak_value = len(artifact)
        review_blind = None
    elif content_scope == CONTENT_PUBLIC_COMMITMENT:
        leak_value = [len(artifact), artifact_hash(artifact)]
        review_blind = None
    elif content_scope == CONTENT_REVIEWED_CONTENT:
        rho_r = fixture_bytes(f"{vector_id}.review_blind", 32)
        review_blind = rho_r
        review_commit = hb(dumps(["daylight.review.hidden.v6", rho_r, len(artifact), artifact_hash(artifact), policy_hash, claims_hash]))
        leak_value = [len(artifact), review_commit]
    else:
        raise ValueError("bad content_scope")

    if leak_value_override is not None:
        leak_value = leak_value_override
    if review_blind_override is not None or review_blind_override is None:
        # Explicit override only when not sentinel? This preserves default for None naturally.
        if review_blind_override is not None:
            review_blind = review_blind_override

    header = {
        0: VERSION,
        1: SUITE_ID,
        2: profile,
        3: r,
        4: mu,
        5: action,
        6: content_scope,
        7: leak_value,
        8: aead_id,
        9: policy[0],
        10: policy_hash,
        11: keyset_hash,
        12: None,
        13: NULL_HASH,
        14: NULL_HASH,
        15: claims_hash,
        16: 0,
        17: 1,
    }

    aux = {0: policy, 1: keyset, 2: claims, 3: None, 4: None, 5: log_proof, 6: None, 7: None}
    if review_receipt_override == "AUTO":
        if content_scope in {CONTENT_PUBLIC_COMMITMENT, CONTENT_REVIEWED_CONTENT}:
            aux[4] = fixture_review_receipt(header, keyset[7][0])
    else:
        aux[4] = review_receipt_override

    t0, h0 = build_t0(header)
    ss_q, enc_q = fixture_encaps(vector_id, keyset[0], mat["dk_q"], "ML-KEM-1024")
    ss_c, enc_c = fixture_encaps(vector_id, keyset[1], mat["sk_c"], "DHKEM-P384")
    kem_block = {0: key_id(ALG_MLKEM, keyset[0], "kem-Q"), 1: key_id(ALG_DHKEM_P384, keyset[1], "kem-C"), 2: enc_q, 3: enc_c}

    k_e, k_com, n_base, n0, _ss = derive_keys(header, kem_block, keyset, mat["dk_q"], mat["sk_c"])
    if private_payload_override is not None:
        plaintext = private_payload_override
    else:
        plaintext = dumps({0: artifact, 1: review_blind})
    ciphertext = aead_encrypt(aead_id, k_e, n0, plaintext, t0)
    com_a = artifact_commitment(k_com, header, ciphertext, artifact)

    auth_placeholder = {0: [], 1: None, 2: None}
    env = {0: MAGIC, 1: header, 2: kem_block, 3: ciphertext, 4: com_a, 5: auth_placeholder, 6: aux}
    rebuild_auth_block(env)

    secrets = {
        "dk_Q": mat["dk_q"],
        "sk_C": mat["sk_c"],
    }
    secret_trace = {
        "artifact": artifact,
        "private_payload": plaintext,
        "ss_Q": fixture_decaps(mat["dk_q"], keyset[0], enc_q, "ML-KEM-1024"),
        "ss_C": fixture_decaps(mat["sk_c"], keyset[1], enc_c, "DHKEM-P384"),
        "K_E": k_e,
        "K_COM": k_com,
        "N_base": n_base,
        "N0": n0,
        "T0": t0,
        "h0": h0,
    }
    t1, h1, auth_msg = build_t1(header, kem_block, ciphertext, env[4], aux)
    secret_trace.update({"T1": t1, "h1": h1, "AuthMsg": auth_msg})
    return env, secrets, secret_trace


def rebuild_auth_block(env: Dict[int, Any]) -> None:
    header = env[ENV_HEADER]
    keyset = env[ENV_AUX_BLOCK][1]
    _t1, _h1, auth_msg = build_t1(header, env[ENV_KEM_BLOCK], env[ENV_CIPHERTEXT], env[ENV_COM_A], env[ENV_AUX_BLOCK])
    requirements = req(header[2], header[3], header[4]) or set()
    q_sigs = []
    if "Q" in requirements:
        for entry in keyset[2]:
            q_sigs.append({0: entry[0], 1: fixture_q_sig(entry[1], auth_msg)})
    q_sigs.sort(key=lambda q: q[0])
    h_sig = fixture_h_sig(keyset[3], auth_msg) if "H" in requirements and keyset[3] is not None else None
    env[ENV_AUTH_BLOCK] = {0: q_sigs, 1: h_sig, 2: None}


def open_fixture(omega_bytes: bytes, secrets: Dict[str, bytes]) -> OpenResult:
    private_kem_called = False
    aead_dec_called = False
    diagnostics: List[str] = []
    try:
        ctx = public_precheck(omega_bytes)
        diagnostics.append("PublicPreOK=1")

        private_kem_called = True
        dk_q = secrets.get("dk_Q") or secrets.get("dk_q")
        sk_c = secrets.get("sk_C") or secrets.get("sk_c")
        require(isinstance(dk_q, bytes) and isinstance(sk_c, bytes), RejectStage.REJECT_DECAP, "missing fixture decapsulation secrets")
        try:
            k_e, k_com, n_base, n0, ss = derive_keys(ctx.header, ctx.kem_block, ctx.keyset, dk_q, sk_c)
        except Exception as ex:
            raise DaylightError(RejectStage.REJECT_DECAP, str(ex)) from ex

        aead_dec_called = True
        try:
            p_prime = aead_decrypt(ctx.header[8], k_e, n0, ctx.ciphertext, ctx.t0)
        except (InvalidTag, ValueError) as ex:
            raise DaylightError(RejectStage.REJECT_AEAD, "AEAD decrypt failed") from ex

        try:
            payload = loads(p_prime)
        except CBORError as ex:
            raise DaylightError(RejectStage.REJECT_PAYLOAD, str(ex)) from ex
        try:
            require_keys(payload, [0,1], RejectStage.REJECT_PAYLOAD, "PrivatePayload_v6")
            artifact = payload[0]
            review_blind = payload[1]
            require(isinstance(artifact, bytes), RejectStage.REJECT_PAYLOAD, "artifact must be bytes")
            require(review_blind is None or (isinstance(review_blind, bytes) and len(review_blind) == 32), RejectStage.REJECT_PAYLOAD, "bad review_blind")
        except DaylightError:
            raise

        expected_com = artifact_commitment(k_com, ctx.header, ctx.ciphertext, artifact)
        require(ctx.com_a == expected_com, RejectStage.REJECT_COMMIT, "artifact commitment mismatch")

        scope = ctx.header[6]
        leak_value = ctx.header[7]
        if scope == CONTENT_METADATA_ONLY:
            require(leak_value == len(artifact), RejectStage.REJECT_LEAK, "metadata_only leak mismatch")
            require(review_blind is None, RejectStage.REJECT_LEAK, "metadata_only review_blind must be null")
        elif scope == CONTENT_PUBLIC_COMMITMENT:
            require(leak_value == [len(artifact), artifact_hash(artifact)], RejectStage.REJECT_LEAK, "public_commitment leak mismatch")
            require(review_blind is None, RejectStage.REJECT_LEAK, "public_commitment review_blind must be null")
        elif scope == CONTENT_REVIEWED_CONTENT:
            require(isinstance(review_blind, bytes) and len(review_blind) == 32, RejectStage.REJECT_LEAK, "reviewed_content review_blind required")
            expected_commit = hb(dumps(["daylight.review.hidden.v6", review_blind, len(artifact), artifact_hash(artifact), ctx.header[10], ctx.header[15]]))
            require(leak_value == [len(artifact), expected_commit], RejectStage.REJECT_LEAK, "reviewed_content hidden commitment mismatch")

        # best-effort zeroization markers are in docs; Python cannot guarantee memory zeroization.
        return OpenResult(True, artifact=artifact, private_kem_called=private_kem_called, aead_dec_called=aead_dec_called, diagnostics=diagnostics)
    except DaylightError as ex:
        diagnostics.append(ex.message)
        return OpenResult(False, rejection_stage=ex.stage, private_kem_called=private_kem_called, aead_dec_called=aead_dec_called, diagnostics=diagnostics)


# ---------------------------------------------------------------------------
# Vector serialization helpers
# ---------------------------------------------------------------------------

def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip())


def encode_json_value(x: Any) -> Any:
    if isinstance(x, bytes):
        return {"hex": x.hex()}
    if isinstance(x, dict):
        return {str(k): encode_json_value(v) for k, v in x.items()}
    if isinstance(x, list):
        return [encode_json_value(v) for v in x]
    return x


def decode_json_value(x: Any) -> Any:
    if isinstance(x, dict):
        if set(x.keys()) == {"hex"}:
            return bytes.fromhex(x["hex"])
        out = {}
        for k, v in x.items():
            try:
                kk = int(k)
            except ValueError:
                kk = k
            out[kk] = decode_json_value(v)
        return out
    if isinstance(x, list):
        return [decode_json_value(v) for v in x]
    return x


def write_vector_dir(
    root: Path,
    vector_id: str,
    env: Dict[int, Any],
    secrets: Dict[str, bytes],
    trace: Dict[str, bytes],
    expected_result: str,
    expected_rejection_stage: Optional[str],
    private_kem_allowed: bool,
    aead_dec_allowed: bool,
    mutation: Optional[Dict[str, Any]] = None,
) -> None:
    d = root / vector_id
    d.mkdir(parents=True, exist_ok=True)
    omega = dumps(env)
    (d / "omega.cbor.hex").write_text(omega.hex() + "\n")
    (d / "header.cbor.hex").write_text(dumps(env[ENV_HEADER]).hex() + "\n")
    (d / "kem_block.cbor.hex").write_text(dumps(env[ENV_KEM_BLOCK]).hex() + "\n")
    (d / "auth_block.cbor.hex").write_text(dumps(env[ENV_AUTH_BLOCK]).hex() + "\n")
    (d / "aux_block.cbor.hex").write_text(dumps(env[ENV_AUX_BLOCK]).hex() + "\n")
    t0, h0 = build_t0(env[ENV_HEADER])
    t1, h1, auth_msg = build_t1(env[ENV_HEADER], env[ENV_KEM_BLOCK], env[ENV_CIPHERTEXT], env[ENV_COM_A], env[ENV_AUX_BLOCK])
    (d / "T0.hex").write_text(t0.hex() + "\n")
    (d / "h0.hex").write_text(h0.hex() + "\n")
    (d / "T1.hex").write_text(t1.hex() + "\n")
    (d / "h1.hex").write_text(h1.hex() + "\n")
    (d / "AuthMsg.hex").write_text(auth_msg.hex() + "\n")
    if "artifact" in trace:
        (d / "expected_artifact.hex").write_text(trace["artifact"].hex() + "\n")
    secret_files = None
    if secrets:
        secret_files = {k: v.hex() for k, v in secrets.items()}
        (d / "secrets.json").write_text(json.dumps(secret_files, indent=2, sort_keys=True) + "\n")
    secret_trace = {k: v.hex() for k, v in trace.items() if isinstance(v, bytes)}
    if secret_trace:
        (d / "secret_trace.json").write_text(json.dumps(secret_trace, indent=2, sort_keys=True) + "\n")
    manifest = {
        "vector_id": vector_id,
        "conformance_level": "C1-OPEN-fixture",
        "expected_result": expected_result,
        "expected_rejection_stage": expected_rejection_stage,
        "private_kem_allowed": private_kem_allowed,
        "aead_dec_allowed": aead_dec_allowed,
        "public_files": [
            "omega.cbor.hex", "header.cbor.hex", "kem_block.cbor.hex", "auth_block.cbor.hex",
            "aux_block.cbor.hex", "T0.hex", "h0.hex", "T1.hex", "h1.hex", "AuthMsg.hex",
        ],
        "secret_files": [] if not secret_files else ["secrets.json", "secret_trace.json", "expected_artifact.hex"],
        "mutation": mutation,
        "warning": "Fixture crypto only. Not ML-KEM/ML-DSA/SLH-DSA production cryptography.",
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def load_secrets(vector_dir: Path) -> Dict[str, bytes]:
    path = vector_dir / "secrets.json"
    if not path.exists():
        return {}
    obj = json.loads(path.read_text())
    return {k: bytes.fromhex(v) for k, v in obj.items()}


# ---------------------------------------------------------------------------
# Negative vector mutations
# ---------------------------------------------------------------------------

def mutate_resign(env: Dict[int, Any]) -> Dict[int, Any]:
    out = copy.deepcopy(env)
    rebuild_auth_block(out)
    return out


def make_noncanonical_omega() -> bytes:
    # Non-minimal encoding of unsigned integer 0: 0x18 0x00.
    return b"\x18\x00"


def make_duplicate_map_key_omega(valid_env: Dict[int, Any]) -> bytes:
    # Envelope map with duplicate key 0. We prepend a duplicate magic pair manually.
    # A canonical map with 8 pairs is invalid for Envelope_v6 and also duplicate key.
    base_pairs = []
    for k in range(7):
        base_pairs.append(dumps(k) + dumps(valid_env[k]))
    return bytes([0xA8]) + dumps(0) + dumps(MAGIC) + b"".join(base_pairs)


def apply_mutation(base_env: Dict[int, Any], name: str) -> Tuple[bytes, Dict[int, Any], bool]:
    """Return (omega_bytes, env_obj_for_trace, has_cbor_obj)."""
    env = copy.deepcopy(base_env)
    if name == "noncanonical_cbor":
        return make_noncanonical_omega(), env, False
    if name == "duplicate_map_key":
        return make_duplicate_map_key_omega(env), env, False
    if name == "unknown_envelope_key":
        env[99] = b"unknown"
        return dumps(env), env, True
    if name == "unknown_header_key":
        env[ENV_HEADER][99] = 1
        return dumps(env), env, True
    if name == "wrong_field_type":
        env[ENV_HEADER][16] = b"not-u64"
        return dumps(env), env, True
    if name == "wrong_enum_value":
        env[ENV_HEADER][8] = 99
        return dumps(env), env, True
    if name == "unsorted_roster":
        # Add an entry that sorts before existing key but place it after.
        bad_pk = fixture_bytes("bad.unsorted.pk", 64)
        bad_id = b"\x00" * 64
        env[ENV_AUX_BLOCK][1][2].append({0: bad_id, 1: bad_pk, 2: "domain-B", 3: None})
        env[ENV_HEADER][11] = hc(env[ENV_AUX_BLOCK][1])
        # Patch policy allowed keyset and policy hash to get to keyset schema.
        env[ENV_AUX_BLOCK][0][5] = [env[ENV_HEADER][11]]
        env[ENV_HEADER][10] = hc(env[ENV_AUX_BLOCK][0])
        rebuild_auth_block(env)
        return dumps(env), env, True
    if name == "unsorted_policy_array":
        env[ENV_AUX_BLOCK][0][1] = [PROFILE_D3_ROOT, PROFILE_D2_HYBRID]
        env[ENV_HEADER][10] = hc(env[ENV_AUX_BLOCK][0])
        rebuild_auth_block(env)
        return dumps(env), env, True
    raise KeyError(name)


# ---------------------------------------------------------------------------
# Command-line helpers
# ---------------------------------------------------------------------------

def run_vector_dir(vector_dir: Path) -> Dict[str, Any]:
    manifest = json.loads((vector_dir / "manifest.json").read_text())
    omega = bytes.fromhex((vector_dir / "omega.cbor.hex").read_text().strip())
    secrets = load_secrets(vector_dir)
    result = open_fixture(omega, secrets)
    expected_result = manifest["expected_result"]
    expected_stage = manifest["expected_rejection_stage"]
    ok = True
    notes = []
    if expected_result == "artifact":
        if not result.ok:
            ok = False
            notes.append(f"expected artifact but got {result.rejection_stage}")
        else:
            art_hex_path = vector_dir / "expected_artifact.hex"
            if art_hex_path.exists():
                expected_artifact = bytes.fromhex(art_hex_path.read_text().strip())
                if result.artifact != expected_artifact:
                    ok = False
                    notes.append("artifact mismatch")
    elif expected_result == "bottom":
        if result.ok:
            ok = False
            notes.append("expected bottom but got artifact")
        elif expected_stage is not None and (result.rejection_stage is None or result.rejection_stage.value != expected_stage):
            ok = False
            notes.append(f"expected {expected_stage} but got {result.rejection_stage}")
    else:
        ok = False
        notes.append("bad manifest expected_result")
    if result.private_kem_called != bool(manifest["private_kem_allowed"]):
        ok = False
        notes.append(f"private_kem_called {result.private_kem_called} != expected {manifest['private_kem_allowed']}")
    if result.aead_dec_called != bool(manifest["aead_dec_allowed"]):
        ok = False
        notes.append(f"aead_dec_called {result.aead_dec_called} != expected {manifest['aead_dec_allowed']}")
    return {
        "vector_id": manifest["vector_id"],
        "ok": ok,
        "expected_result": expected_result,
        "expected_rejection_stage": expected_stage,
        "actual": result.to_dict(),
        "notes": notes,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Daylight v0.6 M1 fixture open/vector runner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_open = sub.add_parser("open", help="open one omega.cbor.hex with secrets.json")
    p_open.add_argument("vector_dir")
    p_run = sub.add_parser("run", help="run vectors under root")
    p_run.add_argument("vectors_root")
    args = ap.parse_args()
    if args.cmd == "open":
        vd = Path(args.vector_dir)
        omega = bytes.fromhex((vd / "omega.cbor.hex").read_text().strip())
        secrets = load_secrets(vd)
        print(json.dumps(open_fixture(omega, secrets).to_dict(), indent=2, sort_keys=True))
    elif args.cmd == "run":
        root = Path(args.vectors_root)
        results = []
        for manifest in sorted(root.rglob("manifest.json")):
            results.append(run_vector_dir(manifest.parent))
        print(json.dumps(results, indent=2, sort_keys=True))
        failures = [r for r in results if not r["ok"]]
        raise SystemExit(1 if failures else 0)
