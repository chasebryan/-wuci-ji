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
            manifests[vector_dir.name] = manifest

    verify_results(fixture, manifests)

    if not args.quiet:
        print(f"daylight-v06-m1-static: verified {len(manifests)} vectors")


if __name__ == "__main__":
    main()
