#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = REPO / "daylight-equation" / "fixtures" / "daylight-v06-m1"

WARNING = "Fixture crypto only. Not ML-KEM/ML-DSA/SLH-DSA production cryptography."
HEX_RE = re.compile(r"^[0-9a-f]*$")

MAGIC = "DAYLIGHT-ENVELOPE-v6"
CTX_AUTH = "WUCI-DAYLIGHT:AUTH:v6"
CTX_REVIEW = "WUCI-DAYLIGHT:REVIEW:v6"

PROFILE_D2_HYBRID = 1
PROFILE_D3_ROOT = 2
PROFILE_D2_HYBRID_FROST = 3
MU_HYBRID = 1
MU_PQ_STRICT = 2

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

CLAIM_RESEARCH = 0
CLAIM_PROOF = 1
CLAIM_OPEN_EVIDENCE = 2
CLAIM_RELEASE_CANDIDATE = 3
CLAIM_INSTALL_EVIDENCE = 4
CLAIM_HYBRID_EVIDENCE = 5
CLAIM_ROOT_CEREMONY = 6
CLAIM_AUDIT_EVIDENCE = 7

ALG_MLKEM = "ML-KEM-1024.encap"
ALG_DHKEM_P384 = "DHKEM-P384-HKDF-SHA384"
ALG_MLDSA87 = "ML-DSA-87"

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
PUBLIC_REJECTION_STAGES = {
    REJECT_PARSE,
    REJECT_SCHEMA,
    REJECT_SUITE,
    REJECT_AUX_HASH,
    REJECT_POLICY,
    REJECT_CLAIMS,
    REJECT_KEM_BLOCK,
    REJECT_AUTH_BLOCK,
    REJECT_AUTH_SIGNATURE,
    REJECT_REVIEW,
    REJECT_DOWNGRADE,
    REJECT_LOG,
    REJECT_INSTALL,
    REJECT_WITNESS,
}

VALID_IDS = {
    "V1_metadata_only_open",
    "V2_public_commitment_open",
    "V3_reviewed_content_open",
    "V4_pq_strict_open",
    "V5_chacha20_open",
}
NEGATIVE_IDS = {f"N{i}_" for i in range(1, 28)}


class CBORError(ValueError):
    pass


class PublicPrecheckError(ValueError):
    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage}: {message}")
        self.stage = stage
        self.message = message


def read_len(data: bytes, pos: int, addl: int) -> tuple[int, int]:
    if addl < 24:
        return addl, pos
    if addl == 24:
        if pos >= len(data):
            raise CBORError("truncated uint8")
        value = data[pos]
        if value < 24:
            raise CBORError("non-minimal integer/length")
        return value, pos + 1
    if addl == 25:
        if pos + 2 > len(data):
            raise CBORError("truncated uint16")
        value = int.from_bytes(data[pos : pos + 2], "big")
        if value <= 0xFF:
            raise CBORError("non-minimal integer/length")
        return value, pos + 2
    if addl == 26:
        if pos + 4 > len(data):
            raise CBORError("truncated uint32")
        value = int.from_bytes(data[pos : pos + 4], "big")
        if value <= 0xFFFF:
            raise CBORError("non-minimal integer/length")
        return value, pos + 4
    if addl == 27:
        if pos + 8 > len(data):
            raise CBORError("truncated uint64")
        value = int.from_bytes(data[pos : pos + 8], "big")
        if value <= 0xFFFFFFFF:
            raise CBORError("non-minimal integer/length")
        return value, pos + 8
    raise CBORError("indefinite/reserved additional information forbidden")


def marker(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(marker(item) for item in value)
    if isinstance(value, dict):
        return tuple(sorted((marker(k), marker(v)) for k, v in value.items()))
    if isinstance(value, (bytes, str, int, bool, type(None))):
        return value
    raise CBORError(f"unsupported map key type: {type(value)!r}")


def decode_item(data: bytes, pos: int = 0) -> tuple[Any, int]:
    if pos >= len(data):
        raise CBORError("unexpected end")
    first = data[pos]
    pos += 1
    major = first >> 5
    addl = first & 0x1F

    if major == 0:
        return read_len(data, pos, addl)
    if major == 1:
        raise CBORError("negative integers forbidden")
    if major == 2:
        size, pos = read_len(data, pos, addl)
        if pos + size > len(data):
            raise CBORError("truncated byte string")
        return data[pos : pos + size], pos + size
    if major == 3:
        size, pos = read_len(data, pos, addl)
        if pos + size > len(data):
            raise CBORError("truncated text string")
        try:
            return data[pos : pos + size].decode("utf-8"), pos + size
        except UnicodeDecodeError as exc:
            raise CBORError("invalid utf-8 text string") from exc
    if major == 4:
        size, pos = read_len(data, pos, addl)
        out = []
        for _ in range(size):
            value, pos = decode_item(data, pos)
            out.append(value)
        return out, pos
    if major == 5:
        size, pos = read_len(data, pos, addl)
        out = {}
        seen = set()
        previous_key_encoding: bytes | None = None
        for _ in range(size):
            key_start = pos
            key, pos = decode_item(data, pos)
            key_encoding = data[key_start:pos]
            if previous_key_encoding is not None and key_encoding <= previous_key_encoding:
                raise CBORError("duplicate/unsorted map key")
            previous_key_encoding = key_encoding
            frozen = marker(key)
            if frozen in seen:
                raise CBORError("duplicate map key")
            seen.add(frozen)
            value, pos = decode_item(data, pos)
            out[key] = value
        return out, pos
    if major == 6:
        raise CBORError("CBOR tags forbidden")
    if major == 7:
        if addl == 20:
            return False, pos
        if addl == 21:
            return True, pos
        if addl == 22:
            return None, pos
        raise CBORError("unsupported simple/float value")
    raise CBORError("unreachable CBOR major type")


def loads(data: bytes) -> Any:
    value, pos = decode_item(data, 0)
    if pos != len(data):
        raise CBORError("trailing data")
    return value


def enc_type_len(major: int, value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CBORError("CBOR length/int must be non-negative integer")
    initial = major << 5
    if value < 24:
        return bytes([initial | value])
    if value <= 0xFF:
        return bytes([initial | 24, value])
    if value <= 0xFFFF:
        return bytes([initial | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([initial | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([initial | 27]) + value.to_bytes(8, "big")
    raise CBORError("integer too large")


def dumps(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0:
            raise CBORError("negative integers forbidden")
        return enc_type_len(0, value)
    if isinstance(value, bytes):
        return enc_type_len(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return enc_type_len(3, len(raw)) + raw
    if isinstance(value, list):
        return enc_type_len(4, len(value)) + b"".join(dumps(item) for item in value)
    if isinstance(value, dict):
        encoded_items = sorted((dumps(key), key, item) for key, item in value.items())
        out = enc_type_len(5, len(encoded_items))
        previous_key: bytes | None = None
        for key_bytes, _key, item in encoded_items:
            if previous_key is not None and key_bytes <= previous_key:
                raise CBORError("duplicate/unsorted map key")
            previous_key = key_bytes
            out += key_bytes + dumps(item)
        return out
    raise CBORError(f"unsupported CBOR type: {type(value)!r}")


def hb(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def hc(value: Any) -> bytes:
    return hb(dumps(value))


NULL_HASH = hc(None)
SUITE_ID = hc(
    [
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
    ]
)


def read_hex_file(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    if len(text) % 2 != 0 or not HEX_RE.fullmatch(text):
        raise AssertionError(f"invalid lowercase hex file: {path}")
    return bytes.fromhex(text)


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def assert_no_links(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise AssertionError(f"fixture contains symlink: {path}")
        if path.is_file() and path.stat().st_nlink != 1:
            raise AssertionError(f"fixture file has multiple hardlinks: {path}")


def verify_sha256s(fixture: Path) -> None:
    sums = fixture / "SHA256SUMS.txt"
    listed: set[Path] = set()
    for line_no, line in enumerate(sums.read_text(encoding="ascii").splitlines(), 1):
        digest, rel = line.split(maxsplit=1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise AssertionError(f"bad SHA256 digest on line {line_no}")
        if not rel.startswith("./") or ".." in Path(rel).parts:
            raise AssertionError(f"unsafe SHA256 path on line {line_no}: {rel}")
        path = fixture / rel[2:]
        if not path.is_file():
            raise AssertionError(f"SHA256 path missing: {rel}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise AssertionError(f"SHA256 mismatch: {rel}")
        listed.add(path.resolve())

    for path in fixture.rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        if path.name == "SHA256SUMS.txt":
            continue
        if path.resolve() not in listed:
            raise AssertionError(f"fixture file missing from SHA256SUMS.txt: {path}")


def verify_manifest(vector_dir: Path, group: str) -> dict[str, Any]:
    manifest = load_json(vector_dir / "manifest.json")
    vector_id = vector_dir.name
    if manifest["vector_id"] != vector_id:
        raise AssertionError(f"vector_id mismatch in {vector_dir}")
    if manifest["conformance_level"] != "C1-OPEN-fixture":
        raise AssertionError(f"unexpected conformance level in {vector_id}")
    if manifest["warning"] != WARNING:
        raise AssertionError(f"missing fixture-only warning in {vector_id}")
    if group == "valid":
        if vector_id not in VALID_IDS:
            raise AssertionError(f"unexpected valid vector id: {vector_id}")
        if manifest["expected_result"] != "artifact":
            raise AssertionError(f"valid vector must expect artifact: {vector_id}")
        if manifest["expected_rejection_stage"] is not None:
            raise AssertionError(f"valid vector has rejection stage: {vector_id}")
        if not manifest["private_kem_allowed"] or not manifest["aead_dec_allowed"]:
            raise AssertionError(f"valid vector must allow private open: {vector_id}")
    else:
        if not any(vector_id.startswith(prefix) for prefix in NEGATIVE_IDS):
            raise AssertionError(f"unexpected negative vector id: {vector_id}")
        if manifest["expected_result"] != "bottom":
            raise AssertionError(f"negative vector must expect bottom: {vector_id}")
        if not isinstance(manifest["expected_rejection_stage"], str):
            raise AssertionError(f"negative vector missing rejection stage: {vector_id}")
        if not isinstance(manifest.get("mutation"), dict):
            raise AssertionError(f"negative vector missing mutation: {vector_id}")

    manifest_files = set(manifest["public_files"]) | set(manifest["secret_files"]) | {"manifest.json"}
    actual_files = {path.name for path in vector_dir.iterdir() if path.is_file()}
    if actual_files != manifest_files:
        raise AssertionError(f"manifest file list mismatch in {vector_id}")
    for name in manifest_files:
        if "/" in name or name.startswith("."):
            raise AssertionError(f"unsafe manifest file name in {vector_id}: {name}")
    return manifest


def verify_decoded_vector(vector_dir: Path, manifest: dict[str, Any]) -> None:
    vector_id = vector_dir.name
    public_files = set(manifest["public_files"])
    cbor_files = [name for name in public_files if name.endswith(".cbor.hex")]
    decoded: dict[str, Any] = {}

    for name in cbor_files:
        raw = read_hex_file(vector_dir / name)
        try:
            decoded[name] = loads(raw)
        except CBORError:
            if manifest["expected_rejection_stage"] == "REJECT_PARSE":
                continue
            raise AssertionError(f"CBOR decode failed unexpectedly in {vector_id}: {name}")

    if manifest["expected_rejection_stage"] == "REJECT_PARSE":
        if "omega.cbor.hex" in decoded:
            raise AssertionError(f"parse-reject vector decoded successfully: {vector_id}")
        return

    if "omega.cbor.hex" not in decoded:
        raise AssertionError(f"missing decoded omega in {vector_id}")
    omega = decoded["omega.cbor.hex"]
    if manifest["expected_rejection_stage"] == "REJECT_SCHEMA":
        if not isinstance(omega, dict) or omega.get(0) != "DAYLIGHT-ENVELOPE-v6":
            raise AssertionError(f"schema-reject vector did not preserve parseable omega: {vector_id}")
        return
    if not isinstance(omega, dict) or set(omega) != set(range(7)):
        raise AssertionError(f"omega schema mismatch in {vector_id}")
    if omega[0] != "DAYLIGHT-ENVELOPE-v6":
        raise AssertionError(f"omega magic mismatch in {vector_id}")
    if not isinstance(omega[1], dict) or set(omega[1]) != set(range(18)):
        raise AssertionError(f"header schema mismatch in {vector_id}")
    if not isinstance(omega[2], dict) or set(omega[2]) != set(range(4)):
        raise AssertionError(f"kem block schema mismatch in {vector_id}")
    if not isinstance(omega[3], bytes) or not isinstance(omega[4], bytes):
        raise AssertionError(f"ciphertext/commitment type mismatch in {vector_id}")
    if not isinstance(omega[5], dict) or not isinstance(omega[6], dict):
        raise AssertionError(f"auth/aux type mismatch in {vector_id}")

    expected_components = {
        "header.cbor.hex": omega[1],
        "kem_block.cbor.hex": omega[2],
        "auth_block.cbor.hex": omega[5],
        "aux_block.cbor.hex": omega[6],
    }
    for name, expected in expected_components.items():
        if name in decoded and decoded[name] != expected:
            raise AssertionError(f"component file does not match omega in {vector_id}: {name}")


def verify_transcripts(vector_dir: Path, manifest: dict[str, Any]) -> None:
    public_files = set(manifest["public_files"])
    needed = {"T0.hex", "h0.hex", "T1.hex", "h1.hex", "AuthMsg.hex"}
    if not needed.issubset(public_files):
        return

    t0 = read_hex_file(vector_dir / "T0.hex")
    h0 = read_hex_file(vector_dir / "h0.hex")
    t1 = read_hex_file(vector_dir / "T1.hex")
    h1 = read_hex_file(vector_dir / "h1.hex")
    auth_msg = read_hex_file(vector_dir / "AuthMsg.hex")
    if hashlib.sha3_512(t0).digest() != h0:
        raise AssertionError(f"h0 mismatch in {vector_dir.name}")
    if hashlib.sha3_512(t1).digest() != h1:
        raise AssertionError(f"h1 mismatch in {vector_dir.name}")

    t0_obj = loads(t0)
    t1_obj = loads(t1)
    auth_obj = loads(auth_msg)
    if not isinstance(t0_obj, list) or t0_obj[0] != "daylight.pre.v6":
        raise AssertionError(f"T0 label mismatch in {vector_dir.name}")
    if not isinstance(t1_obj, list) or t1_obj[0] != "daylight.auth.transcript.v6":
        raise AssertionError(f"T1 label mismatch in {vector_dir.name}")
    if (
        not isinstance(auth_obj, list)
        or auth_obj[0] != "daylight.authorization.message.v6"
        or auth_obj[-1] != h1
    ):
        raise AssertionError(f"AuthMsg binding mismatch in {vector_dir.name}")

    if manifest["expected_result"] == "artifact" and "secret_trace.json" in manifest["secret_files"]:
        trace = load_json(vector_dir / "secret_trace.json")
        for key, raw in (("T0", t0), ("h0", h0), ("T1", t1), ("h1", h1), ("AuthMsg", auth_msg)):
            if trace.get(key) != raw.hex():
                raise AssertionError(f"secret_trace mismatch in {vector_dir.name}: {key}")
        if "expected_artifact.hex" in manifest["secret_files"]:
            artifact = read_hex_file(vector_dir / "expected_artifact.hex")
            if trace.get("artifact") != artifact.hex():
                raise AssertionError(f"artifact trace mismatch in {vector_dir.name}")


def is_hash64(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == 64


def is_u64(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**64


def ascii_ok(value: Any, min_len: int = 0, max_len: int = 2**20) -> bool:
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len):
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    return True


def require(condition: bool, stage: str, message: str) -> None:
    if not condition:
        raise PublicPrecheckError(stage, message)


def require_keys(value: Any, keys: range | list[int] | set[int], stage: str, name: str) -> None:
    expected = set(keys)
    require(isinstance(value, dict), stage, f"{name} must be map")
    require(set(value) == expected, stage, f"{name} keys must be exactly {sorted(expected)}")


def key_id(alg_id: str, public_key: bytes, domain_id: Any) -> bytes:
    return hc(["daylight.key-id.v6", alg_id, public_key, domain_id])


def fixture_q_sig(pk_q: bytes, auth_msg: bytes) -> bytes:
    return hb(dumps(["fixture.ml-dsa-87.sig.v6", pk_q, auth_msg, CTX_AUTH]))


def fixture_h_sig(pk_h: bytes, auth_msg: bytes) -> bytes:
    return hb(dumps(["fixture.slh-dsa.sig.v6", pk_h, auth_msg, CTX_AUTH]))


def validate_leak_value(scope: int, leak_value: Any) -> None:
    if scope == CONTENT_METADATA_ONLY:
        require(is_u64(leak_value), REJECT_SCHEMA, "metadata_only leak_value must be u64")
    elif scope in {CONTENT_PUBLIC_COMMITMENT, CONTENT_REVIEWED_CONTENT}:
        require(
            isinstance(leak_value, list) and len(leak_value) == 2,
            REJECT_SCHEMA,
            "committed leak_value shape",
        )
        require(
            is_u64(leak_value[0]) and is_hash64(leak_value[1]),
            REJECT_SCHEMA,
            "committed leak_value types",
        )
    else:
        raise PublicPrecheckError(REJECT_SUITE, "unknown content scope")


def validate_header(header: Any, stage: str = REJECT_SCHEMA) -> None:
    require_keys(header, range(18), stage, "Header_v6")
    require(header[0] == 6, REJECT_SUITE, "version must be 6")
    require(is_hash64(header[1]), REJECT_SUITE, "suite_id must be Hash64")
    require(header[1] == SUITE_ID, REJECT_SUITE, "suite_id mismatch")
    require(header[2] in {PROFILE_D2_HYBRID, PROFILE_D3_ROOT, PROFILE_D2_HYBRID_FROST}, REJECT_SUITE, "bad profile")
    require(header[3] in {0, 1, 2, 3}, REJECT_SUITE, "bad r")
    require(header[4] in {MU_HYBRID, MU_PQ_STRICT}, REJECT_SUITE, "bad mu")
    require(header[5] in {0, 1, 2, 3, 4, 5, 6}, REJECT_SUITE, "bad action")
    require(header[6] in {0, 1, 2}, REJECT_SUITE, "bad content_scope")
    validate_leak_value(header[6], header[7])
    require(header[8] in {1, 2}, REJECT_SUITE, "bad aead_id")
    require(ascii_ok(header[9], 1, 128), stage, "policy_id must be ASCII")
    for index in (10, 11, 13, 14, 15):
        require(is_hash64(header[index]), stage, f"header[{index}] must be Hash64")
    require(header[12] is None or is_hash64(header[12]), stage, "prev_log_head must be null or Hash64")
    require(is_u64(header[16]), stage, "key_epoch must be u64")
    require(header[17] in {1, 2, 3, 4, 5}, stage, "bad conformance_min")


def validate_envelope_shape(env: Any) -> None:
    require_keys(env, range(7), REJECT_SCHEMA, "Envelope_v6")
    require(env[0] == MAGIC, REJECT_SCHEMA, "bad magic")
    validate_header(env[1], REJECT_SCHEMA)
    require(isinstance(env[3], bytes), REJECT_SCHEMA, "ciphertext must be bytes")
    require(isinstance(env[4], bytes) and len(env[4]) == 32, REJECT_SCHEMA, "com_A must be Bytes[32]")


def validate_aux_block(aux: Any) -> None:
    require_keys(aux, range(8), REJECT_SCHEMA, "AuxBlock_v6")
    require(aux[0] is not None, REJECT_SCHEMA, "policy_obj is mandatory")
    require(aux[1] is not None, REJECT_SCHEMA, "keyset_obj is mandatory")
    require(aux[2] is not None, REJECT_SCHEMA, "claims_obj is mandatory")


def object_hash_ok(value: Any, expected: bytes) -> bool:
    if value is None:
        return expected == NULL_HASH
    return hc(value) == expected


def validate_policy_schema(policy: Any) -> None:
    require_keys(policy, range(13), REJECT_POLICY, "Policy_v6")
    require(ascii_ok(policy[0], 1, 128), REJECT_POLICY, "bad policy_id")
    for index, name in (
        (1, "allowed_profiles"),
        (2, "allowed_aeads"),
        (3, "allowed_actions"),
        (5, "allowed_keyset_hashes"),
        (9, "log_required_actions"),
        (10, "allowed_claim_classes"),
    ):
        require(isinstance(policy[index], list), REJECT_POLICY, f"{name} must be array")
        require(policy[index] == sorted(policy[index]), REJECT_POLICY, f"{name} must be sorted")
        if index != 5:
            require(len(policy[index]) == len(set(policy[index])), REJECT_POLICY, f"{name} duplicate entries")
    require(all(value in {1, 2, 3} for value in policy[1]), REJECT_POLICY, "bad allowed profile")
    require(all(value in {1, 2} for value in policy[2]), REJECT_POLICY, "bad allowed AEAD")
    require(all(value in {0, 1, 2, 3, 4, 5, 6} for value in policy[3]), REJECT_POLICY, "bad allowed action")
    require(isinstance(policy[4], dict), REJECT_POLICY, "min_mode_by_action must be map")
    for action, mode in policy[4].items():
        require(action in {0, 1, 2, 3, 4, 5, 6}, REJECT_POLICY, "bad min-mode action")
        require(
            isinstance(mode, list) and len(mode) == 2 and mode[0] in {0, 1, 2, 3} and mode[1] in {1, 2},
            REJECT_POLICY,
            "bad min-mode value",
        )
    require(all(is_hash64(value) for value in policy[5]), REJECT_POLICY, "allowed_keyset_hashes must be Hash64 array")
    require(isinstance(policy[6], bool), REJECT_POLICY, "require_exact_content_approval must be bool")
    require(isinstance(policy[7], bool), REJECT_POLICY, "require_provenance must be bool")
    require(isinstance(policy[8], bool), REJECT_POLICY, "require_witness must be bool")
    require(all(value in {0, 1, 2, 3, 4, 5, 6} for value in policy[9]), REJECT_POLICY, "bad log_required action")
    require(all(value in {0, 1, 2, 3, 4, 5, 6, 7} for value in policy[10]), REJECT_POLICY, "bad allowed claim class")
    require(policy[11] is None or is_u64(policy[11]), REJECT_POLICY, "expiry_epoch must be null or u64")
    require(policy[12] == 6, REJECT_POLICY, "policy_version must be 6")


def validate_keyset_schema(keyset: Any) -> None:
    require_keys(keyset, range(9), REJECT_POLICY, "KeySetPub_v6")
    require(isinstance(keyset[0], bytes) and len(keyset[0]) > 0, REJECT_POLICY, "ek_Q must be bytes")
    require(isinstance(keyset[1], bytes) and len(keyset[1]) > 0, REJECT_POLICY, "pk_C must be bytes")
    require(isinstance(keyset[2], list) and len(keyset[2]) > 0, REJECT_POLICY, "Q_roster must be non-empty array")
    seen = set()
    previous: bytes | None = None
    for entry in keyset[2]:
        require_keys(entry, {0, 1, 2, 3}, REJECT_POLICY, "QRosterEntry_v6")
        require(is_hash64(entry[0]), REJECT_POLICY, "Q key_id must be Hash64")
        require(isinstance(entry[1], bytes) and len(entry[1]) > 0, REJECT_POLICY, "pk_Q must be bytes")
        require(ascii_ok(entry[2], 1, 128), REJECT_POLICY, "domain_id must be ASCII")
        require(previous is None or entry[0] > previous, REJECT_POLICY, "Q_roster must be sorted by key_id")
        require(entry[0] not in seen, REJECT_POLICY, "duplicate Q key_id")
        require(entry[0] == key_id(ALG_MLDSA87, entry[1], entry[2]), REJECT_POLICY, "Q key_id mismatch")
        seen.add(entry[0])
        previous = entry[0]
    require(keyset[3] is None or isinstance(keyset[3], bytes), REJECT_POLICY, "pk_H must be null or bytes")
    require(keyset[4] is None or isinstance(keyset[4], dict), REJECT_POLICY, "frost_pub must be null or map")
    require(isinstance(keyset[5], dict), REJECT_POLICY, "certificates must be map")
    require(isinstance(keyset[6], dict), REJECT_POLICY, "revocation_state must be map")
    require(isinstance(keyset[7], dict), REJECT_POLICY, "policy_keys must be map")
    require_keys(keyset[8], {0, 1, 2, 3}, REJECT_POLICY, "Thresholds_v6")
    require(isinstance(keyset[8][0], int) and keyset[8][0] >= 1, REJECT_POLICY, "t_Q must be >= 1")
    require(isinstance(keyset[8][1], int) and keyset[8][1] >= 1, REJECT_POLICY, "u_Q must be >= 1")


def validate_claims_schema(claims: Any) -> None:
    require(isinstance(claims, list), REJECT_CLAIMS, "Claims_v6 must be array")
    for claim in claims:
        require_keys(claim, {0, 1, 2}, REJECT_CLAIMS, "Claim_v6")
        require(claim[0] in {0, 1, 2, 3, 4, 5, 6, 7}, REJECT_CLAIMS, "bad claim class")
        require(ascii_ok(claim[1], 1, 128), REJECT_CLAIMS, "claim_name must be ASCII")


def validate_kem_block_schema(kem: Any, keyset: dict[int, Any]) -> None:
    require_keys(kem, range(4), REJECT_KEM_BLOCK, "KEMBlock_v6")
    require(is_hash64(kem[0]) and is_hash64(kem[1]), REJECT_KEM_BLOCK, "KEM key ids must be Hash64")
    require(isinstance(kem[2], bytes) and len(kem[2]) > 0, REJECT_KEM_BLOCK, "enc_Q must be bytes")
    require(isinstance(kem[3], bytes) and len(kem[3]) > 0, REJECT_KEM_BLOCK, "enc_C must be bytes")
    require(kem[0] == key_id(ALG_MLKEM, keyset[0], "kem-Q"), REJECT_KEM_BLOCK, "q_kem_key_id mismatch")
    require(kem[1] == key_id(ALG_DHKEM_P384, keyset[1], "kem-C"), REJECT_KEM_BLOCK, "c_kem_key_id mismatch")


def validate_auth_block_schema(auth: Any, profile: int) -> None:
    require_keys(auth, {0, 1, 2}, REJECT_AUTH_BLOCK, "AuthBlock_v6")
    require(isinstance(auth[0], list), REJECT_AUTH_BLOCK, "q_sigs must be array")
    seen = set()
    previous: bytes | None = None
    for qsig in auth[0]:
        require_keys(qsig, {0, 1}, REJECT_AUTH_BLOCK, "QSig_v6")
        require(is_hash64(qsig[0]), REJECT_AUTH_BLOCK, "QSig key_id must be Hash64")
        require(isinstance(qsig[1], bytes), REJECT_AUTH_BLOCK, "QSig sig must be bytes")
        require(previous is None or qsig[0] > previous, REJECT_AUTH_BLOCK, "q_sigs not sorted")
        require(qsig[0] not in seen, REJECT_AUTH_BLOCK, "duplicate q_sig key_id")
        seen.add(qsig[0])
        previous = qsig[0]
    require(auth[1] is None or isinstance(auth[1], bytes), REJECT_AUTH_BLOCK, "h_sig must be null or bytes")
    require(auth[2] is None or isinstance(auth[2], dict), REJECT_AUTH_BLOCK, "frost_auth must be null or map")
    if profile != PROFILE_D2_HYBRID_FROST:
        require(auth[2] is None, REJECT_AUTH_BLOCK, "frost_auth forbidden for non-FROST profile")


def build_t0(header: dict[int, Any]) -> tuple[bytes, bytes]:
    t0 = dumps(["daylight.pre.v6", header])
    return t0, hb(t0)


def build_t1(
    header: dict[int, Any],
    kem_block: dict[int, Any],
    ciphertext: bytes,
    com_a: bytes,
    aux: dict[int, Any],
) -> tuple[bytes, bytes, bytes]:
    _t0, h0 = build_t0(header)
    receipt_hash = hc(aux[4]) if aux[4] is not None else NULL_HASH
    t1 = dumps(["daylight.auth.transcript.v6", h0, hc(kem_block), hb(ciphertext), com_a, receipt_hash])
    h1 = hb(t1)
    auth_msg = dumps(["daylight.authorization.message.v6", CTX_AUTH, h1])
    return t1, h1, auth_msg


def allowed_actions(r_level: int) -> set[int]:
    allowed = {ACTION_RESEARCH, ACTION_PROOF}
    if r_level >= 1:
        allowed.add(ACTION_OPEN)
    if r_level >= 2:
        allowed.update({ACTION_RELEASE, ACTION_INSTALL})
    if r_level >= 3:
        allowed.update({ACTION_ROOT_ROTATE, ACTION_AUDIT_ACCEPT})
    return allowed


def requirements(profile: int, r_level: int, mu: int) -> set[str] | None:
    if profile == PROFILE_D2_HYBRID:
        if mu == MU_HYBRID:
            return {"Q"} if r_level < 3 else {"Q", "H"}
        if mu == MU_PQ_STRICT:
            return {"Q", "H"}
    if profile == PROFILE_D3_ROOT and mu in {MU_HYBRID, MU_PQ_STRICT}:
        return {"Q", "H"}
    if profile == PROFILE_D2_HYBRID_FROST:
        if mu == MU_HYBRID:
            return {"Q", "F"} if r_level < 3 else {"Q", "H", "F"}
        if mu == MU_PQ_STRICT:
            return {"Q", "H", "F"}
    return None


def mode_ok(header: dict[int, Any]) -> bool:
    return requirements(header[2], header[3], header[4]) is not None and header[5] in allowed_actions(header[3])


def static_policy_gate(header: dict[int, Any], policy: dict[int, Any]) -> None:
    require(policy[0] == header[9], REJECT_POLICY, "policy_id mismatch")
    require(header[2] in policy[1], REJECT_POLICY, "profile not allowed")
    require(header[8] in policy[2], REJECT_POLICY, "AEAD not allowed")
    require(header[5] in policy[3], REJECT_POLICY, "action not allowed")
    require(header[11] in policy[5], REJECT_POLICY, "keyset not allowed by policy")
    require(mode_ok(header), REJECT_POLICY, "mode/action invalid")


def allowed_claim_classes_for_r(r_level: int) -> set[int]:
    allowed = {CLAIM_RESEARCH, CLAIM_PROOF}
    if r_level >= 1:
        allowed.add(CLAIM_OPEN_EVIDENCE)
    if r_level >= 2:
        allowed.update({CLAIM_RELEASE_CANDIDATE, CLAIM_INSTALL_EVIDENCE, CLAIM_HYBRID_EVIDENCE})
    if r_level >= 3:
        allowed.update({CLAIM_ROOT_CEREMONY, CLAIM_AUDIT_EVIDENCE})
    return allowed


def claim_ok(header: dict[int, Any], claims: list[Any], policy: dict[int, Any]) -> None:
    validate_claims_schema(claims)
    allowed_for_r = allowed_claim_classes_for_r(header[3])
    policy_allowed = set(policy[10])
    for claim in claims:
        require(claim[0] in allowed_for_r, REJECT_CLAIMS, "claim not allowed at r")
        require(claim[0] in policy_allowed, REJECT_CLAIMS, "claim not allowed by policy")


def provenance_ok(header: dict[int, Any], aux: dict[int, Any], policy: dict[int, Any]) -> None:
    if policy[7] is False:
        require(header[13] == NULL_HASH and aux[3] is None, REJECT_POLICY, "unexpected provenance under no-provenance policy")
    else:
        require(aux[3] is not None, REJECT_POLICY, "provenance required")


def witness_ok(aux: dict[int, Any], policy: dict[int, Any]) -> None:
    if policy[8] is True:
        require(aux[7] is not None, REJECT_WITNESS, "witness required")


def verify_authorization(header: dict[int, Any], keyset: dict[int, Any], auth: dict[int, Any], auth_msg: bytes) -> None:
    reqs = requirements(header[2], header[3], header[4])
    require(reqs is not None, REJECT_AUTH_SIGNATURE, "undefined profile requirements")
    q_by_id = {entry[0]: entry for entry in keyset[2]}
    good_q = []
    for qsig in auth[0]:
        entry = q_by_id.get(qsig[0])
        if entry is None:
            continue
        if qsig[1] == fixture_q_sig(entry[1], auth_msg):
            good_q.append(entry)
    if "Q" in reqs:
        require(len(good_q) >= keyset[8][0], REJECT_AUTH_SIGNATURE, "insufficient Q threshold")
        require(len({entry[2] for entry in good_q}) >= keyset[8][1], REJECT_AUTH_SIGNATURE, "insufficient Q domain count")
    else:
        require(len(auth[0]) == 0, REJECT_AUTH_SIGNATURE, "unexpected Q signatures")

    if "H" in reqs:
        require(keyset[3] is not None, REJECT_AUTH_SIGNATURE, "pk_H absent")
        require(auth[1] is not None, REJECT_AUTH_SIGNATURE, "h_sig absent")
        require(auth[1] == fixture_h_sig(keyset[3], auth_msg), REJECT_AUTH_SIGNATURE, "bad H signature")
    else:
        require(auth[1] is None, REJECT_AUTH_SIGNATURE, "unexpected H signature")

    if "F" in reqs:
        raise PublicPrecheckError(REJECT_AUTH_SIGNATURE, "FROST fixture not implemented for C1")
    require(auth[2] is None, REJECT_AUTH_SIGNATURE, "unexpected FROST auth")


def review_receipt_ok(receipt: Any, header: dict[int, Any], keyset: dict[int, Any]) -> bool:
    if not isinstance(receipt, dict) or set(receipt) != {0, 1, 2}:
        return False
    reviewer_pk = keyset.get(7, {}).get(0) if isinstance(keyset.get(7), dict) else None
    if not isinstance(reviewer_pk, bytes):
        return False
    subject_hash = hb(dumps(["daylight.review.subject.v6", header]))
    expected = hb(dumps(["fixture.review.sig.v6", reviewer_pk, subject_hash, CTX_REVIEW]))
    return receipt[1] == subject_hash and receipt[2] == expected


def content_review_pre_ok(header: dict[int, Any], aux: dict[int, Any], keyset: dict[int, Any], policy: dict[int, Any]) -> None:
    if header[6] == CONTENT_METADATA_ONLY:
        require(policy[6] is False, REJECT_REVIEW, "metadata_only forbidden when exact approval required")
        return
    require(aux[4] is not None, REJECT_REVIEW, "review receipt required")
    require(review_receipt_ok(aux[4], header, keyset), REJECT_REVIEW, "bad review receipt")


def no_downgrade(header: dict[int, Any], policy: dict[int, Any]) -> None:
    action = header[5]
    require(action in policy[4], REJECT_DOWNGRADE, "missing min mode for action")
    r_min, mu_min = policy[4][action]
    require(header[3] >= r_min, REJECT_DOWNGRADE, "r below policy minimum")
    require(header[4] >= mu_min, REJECT_DOWNGRADE, "mu below policy minimum")
    require(header[8] in policy[2], REJECT_DOWNGRADE, "AEAD not allowed")


def log_ok(header: dict[int, Any], aux: dict[int, Any], policy: dict[int, Any]) -> None:
    if header[5] not in set(policy[9]):
        return
    proof = aux[5]
    require(isinstance(proof, dict) and proof.get(0) == b"fixture-log-ok", REJECT_LOG, "missing or bad log proof")


def install_ok(header: dict[int, Any], aux: dict[int, Any]) -> None:
    if header[5] == ACTION_INSTALL:
        require(aux[6] is not None, REJECT_INSTALL, "install manifest required")


def evaluate_public_precheck(omega: bytes) -> str | None:
    try:
        env = loads(omega)
    except CBORError as exc:
        return PublicPrecheckError(REJECT_PARSE, str(exc)).stage

    try:
        validate_envelope_shape(env)
        header = env[1]
        kem_block = env[2]
        ciphertext = env[3]
        com_a = env[4]
        auth_block = env[5]
        aux = env[6]

        validate_aux_block(aux)
        policy = aux[0]
        keyset = aux[1]
        claims = aux[2]
        require(object_hash_ok(policy, header[10]), REJECT_AUX_HASH, "policy_hash mismatch")
        require(object_hash_ok(keyset, header[11]), REJECT_AUX_HASH, "keyset_hash mismatch")
        require(object_hash_ok(claims, header[15]), REJECT_AUX_HASH, "claims_hash mismatch")
        require(object_hash_ok(aux[3], header[13]), REJECT_AUX_HASH, "provenance_hash mismatch")
        require(object_hash_ok(aux[6], header[14]), REJECT_AUX_HASH, "install_manifest_hash mismatch")

        validate_policy_schema(policy)
        validate_keyset_schema(keyset)
        validate_claims_schema(claims)
        static_policy_gate(header, policy)
        claim_ok(header, claims, policy)
        provenance_ok(header, aux, policy)
        witness_ok(aux, policy)
        validate_kem_block_schema(kem_block, keyset)

        _t1, _h1, auth_msg = build_t1(header, kem_block, ciphertext, com_a, aux)
        validate_auth_block_schema(auth_block, header[2])
        verify_authorization(header, keyset, auth_block, auth_msg)
        content_review_pre_ok(header, aux, keyset, policy)
        no_downgrade(header, policy)
        log_ok(header, aux, policy)
        install_ok(header, aux)
    except PublicPrecheckError as exc:
        return exc.stage
    return None


def verify_public_precheck_stage(vector_dir: Path, manifest: dict[str, Any]) -> None:
    stage = evaluate_public_precheck(read_hex_file(vector_dir / "omega.cbor.hex"))
    expected = manifest["expected_rejection_stage"]
    if expected in PUBLIC_REJECTION_STAGES:
        if stage != expected:
            raise AssertionError(f"public precheck stage mismatch in {vector_dir.name}: {stage} != {expected}")
        if manifest["private_kem_allowed"] or manifest["aead_dec_allowed"]:
            raise AssertionError(f"public rejection must not allow private open in {vector_dir.name}")
        return
    if stage is not None:
        raise AssertionError(f"public precheck rejected before private stage in {vector_dir.name}: {stage}")


def verify_results(fixture: Path, manifests: dict[str, dict[str, Any]]) -> None:
    results = load_json(fixture / "TEST_RESULTS.json")
    if results["total"] != 32 or results["passed"] != 32 or results["failed"] != 0:
        raise AssertionError("unexpected fixture TEST_RESULTS summary")
    by_id = {entry["vector_id"]: entry for entry in results["results"]}
    if set(by_id) != set(manifests):
        raise AssertionError("TEST_RESULTS vector set does not match manifests")

    for vector_id, manifest in manifests.items():
        entry = by_id[vector_id]
        actual = entry["actual"]
        if not entry["ok"]:
            raise AssertionError(f"recorded fixture result failed: {vector_id}")
        if entry["expected_result"] != manifest["expected_result"]:
            raise AssertionError(f"expected result mismatch in TEST_RESULTS: {vector_id}")
        if entry["expected_rejection_stage"] != manifest["expected_rejection_stage"]:
            raise AssertionError(f"expected stage mismatch in TEST_RESULTS: {vector_id}")

        if manifest["expected_result"] == "artifact":
            artifact = read_hex_file(fixture / "vectors" / "valid" / vector_id / "expected_artifact.hex")
            if not actual["ok"] or actual["artifact_hex"] != artifact.hex():
                raise AssertionError(f"valid result artifact mismatch: {vector_id}")
            if actual["rejection_stage"] is not None:
                raise AssertionError(f"valid result unexpectedly rejected: {vector_id}")
        else:
            if actual["ok"]:
                raise AssertionError(f"negative result unexpectedly opened: {vector_id}")
            if actual["rejection_stage"] != manifest["expected_rejection_stage"]:
                raise AssertionError(f"negative rejection stage mismatch: {vector_id}")

        if actual["private_kem_called"] != manifest["private_kem_allowed"]:
            raise AssertionError(f"private KEM call flag mismatch: {vector_id}")
        if actual["aead_dec_called"] != manifest["aead_dec_allowed"]:
            raise AssertionError(f"AEAD call flag mismatch: {vector_id}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Statically verify the Daylight v0.6 M1 vector corpus."
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    fixture = Path(os.environ.get("DAYLIGHT_V06_M1_FIXTURE", str(DEFAULT_FIXTURE)))
    if not fixture.is_absolute():
        fixture = REPO / fixture
    fixture = fixture.resolve()

    assert_no_links(fixture)
    verify_sha256s(fixture)

    manifests: dict[str, dict[str, Any]] = {}
    for group, expected_ids in (("valid", VALID_IDS), ("negative", None)):
        group_dir = fixture / "vectors" / group
        vector_dirs = sorted(path for path in group_dir.iterdir() if path.is_dir())
        if group == "valid" and {path.name for path in vector_dirs} != expected_ids:
            raise AssertionError("valid vector set mismatch")
        if group == "negative" and len(vector_dirs) != 27:
            raise AssertionError("negative vector count mismatch")
        for vector_dir in vector_dirs:
            manifest = verify_manifest(vector_dir, group)
            verify_decoded_vector(vector_dir, manifest)
            verify_transcripts(vector_dir, manifest)
            verify_public_precheck_stage(vector_dir, manifest)
            manifests[vector_dir.name] = manifest

    verify_results(fixture, manifests)

    if not args.quiet:
        print(f"daylight-v06-m1-static: verified {len(manifests)} vectors")


if __name__ == "__main__":
    main()
