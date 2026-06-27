#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ModuleNotFoundError as exc:  # pragma: no cover - environment diagnostic
    raise AssertionError("missing optional dependency from daylight-v06-m1 requirements.txt") from exc

import daylight_v06_m1_static_vectors as dv


REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = REPO / "daylight-equation" / "fixtures" / "daylight-v06-m1"

REJECT_DECAP = "REJECT_DECAP"
REJECT_AEAD = "REJECT_AEAD"
REJECT_PAYLOAD = "REJECT_PAYLOAD"
REJECT_COMMIT = "REJECT_COMMIT"
REJECT_LEAK = "REJECT_LEAK"


class OpenError(ValueError):
    def __init__(self, stage: str, message: str):
        super().__init__(f"{stage}: {message}")
        self.stage = stage
        self.message = message


@dataclass
class OpenResult:
    ok: bool
    artifact: bytes | None = None
    rejection_stage: str | None = None
    private_kem_called: bool = False
    aead_dec_called: bool = False
    diagnostics: list[str] = field(default_factory=list)


@dataclass
class PublicContext:
    env: dict[int, Any]
    header: dict[int, Any]
    kem_block: dict[int, Any]
    ciphertext: bytes
    com_a: bytes
    aux: dict[int, Any]
    keyset: dict[int, Any]
    t0: bytes


def load_secrets(vector_dir: Path) -> dict[str, bytes]:
    path = vector_dir / "secrets.json"
    if not path.is_file():
        return {}
    obj = json.loads(path.read_text(encoding="utf-8"))
    return {key: bytes.fromhex(value) for key, value in obj.items()}


def public_context(omega: bytes) -> PublicContext | OpenResult:
    stage = dv.evaluate_public_precheck(omega)
    if stage is not None:
        return OpenResult(False, rejection_stage=stage)
    env = dv.loads(omega)
    header = env[1]
    t0, _h0 = dv.build_t0(header)
    return PublicContext(
        env=env,
        header=header,
        kem_block=env[2],
        ciphertext=env[3],
        com_a=env[4],
        aux=env[6],
        keyset=env[6][1],
        t0=t0,
    )


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha512).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha512).digest()
        out += block
        counter += 1
        if counter > 255:
            raise ValueError("HKDF expand length too large")
    return out[:length]


def hc32(value: Any) -> bytes:
    return hashlib.shake_256(dv.dumps(value)).digest(32)


def fixture_decaps(secret_key: bytes, public_key: bytes, encapsulation: bytes, label: str) -> bytes:
    return dv.hb(dv.dumps(["fixture.decaps.v6", label, secret_key, public_key, encapsulation]))


def derive_keys(ctx: PublicContext, dk_q: bytes, sk_c: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    _t0, h0 = dv.build_t0(ctx.header)
    ss_q = fixture_decaps(dk_q, ctx.keyset[0], ctx.kem_block[2], "ML-KEM-1024")
    ss_c = fixture_decaps(sk_c, ctx.keyset[1], ctx.kem_block[3], "DHKEM-P384")
    kem_context = dv.dumps(
        [
            "daylight.kem.context.v6",
            ctx.header[1],
            ctx.header[2],
            h0,
            ctx.header[11],
            ctx.kem_block[0],
            ctx.kem_block[1],
            ctx.kem_block[2],
            ctx.kem_block[3],
        ]
    )
    salt = hc32(["daylight.kem.salt.v6", ctx.header[1], h0, ctx.header[11], ctx.kem_block[0], ctx.kem_block[1]])
    prk = hkdf_extract(salt, dv.dumps(["daylight.hybrid.ikm.v6", ss_q, ss_c, kem_context]))
    okm = hkdf_expand(
        prk,
        dv.dumps(["daylight.key.schedule.v6", h0, dv.hc(ctx.kem_block), ctx.header[1], ctx.header[2], ctx.header[4], ctx.header[8]]),
        76,
    )
    return okm[:32], okm[32:64], okm[64:76], ss_q + ss_c


def aead_decrypt(aead_id: int, key: bytes, nonce: bytes, ciphertext: bytes, ad: bytes) -> bytes:
    if aead_id == 1:
        return AESGCM(key).decrypt(nonce, ciphertext, ad)
    if aead_id == 2:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)
    raise ValueError(f"unsupported AEAD id: {aead_id}")


def kdf2(secret: bytes, label: str, input_obj: Any, length: int) -> bytes:
    prk = hkdf_extract(dv.hc(["daylight-kdf2-salt.v6", label]), secret)
    return hkdf_expand(prk, dv.dumps(["daylight-kdf2-info.v6", label, input_obj]), length)


def artifact_commitment(k_com: bytes, ctx: PublicContext, artifact: bytes) -> bytes:
    _t0, h0 = dv.build_t0(ctx.header)
    return kdf2(
        k_com,
        "daylight.artifact.commit.v6",
        [h0, dv.hb(ctx.ciphertext), len(artifact), dv.hb(artifact), ctx.header[7]],
        32,
    )


def require(condition: bool, stage: str, message: str) -> None:
    if not condition:
        raise OpenError(stage, message)


def open_independent(omega: bytes, secrets: dict[str, bytes]) -> OpenResult:
    diagnostics: list[str] = []
    private_kem_called = False
    aead_dec_called = False
    ctx_or_result = public_context(omega)
    if isinstance(ctx_or_result, OpenResult):
        return ctx_or_result
    ctx = ctx_or_result
    diagnostics.append("PublicPreOK=1")

    try:
        dk_q = secrets.get("dk_Q") or secrets.get("dk_q")
        sk_c = secrets.get("sk_C") or secrets.get("sk_c")
        require(isinstance(dk_q, bytes) and isinstance(sk_c, bytes), REJECT_DECAP, "missing fixture decapsulation secrets")

        private_kem_called = True
        try:
            k_e, k_com, nonce, _ss = derive_keys(ctx, dk_q, sk_c)
        except Exception as exc:  # defensive conversion to vector stage
            raise OpenError(REJECT_DECAP, str(exc)) from exc

        aead_dec_called = True
        try:
            plaintext = aead_decrypt(ctx.header[8], k_e, nonce, ctx.ciphertext, ctx.t0)
        except (InvalidTag, ValueError) as exc:
            raise OpenError(REJECT_AEAD, "AEAD decrypt failed") from exc

        try:
            payload = dv.loads(plaintext)
        except dv.CBORError as exc:
            raise OpenError(REJECT_PAYLOAD, str(exc)) from exc
        dv.require_keys(payload, {0, 1}, REJECT_PAYLOAD, "PrivatePayload_v6")
        artifact = payload[0]
        review_blind = payload[1]
        require(isinstance(artifact, bytes), REJECT_PAYLOAD, "artifact must be bytes")
        require(review_blind is None or (isinstance(review_blind, bytes) and len(review_blind) == 32), REJECT_PAYLOAD, "bad review_blind")

        require(ctx.com_a == artifact_commitment(k_com, ctx, artifact), REJECT_COMMIT, "artifact commitment mismatch")

        scope = ctx.header[6]
        leak_value = ctx.header[7]
        if scope == dv.CONTENT_METADATA_ONLY:
            require(leak_value == len(artifact), REJECT_LEAK, "metadata_only leak mismatch")
            require(review_blind is None, REJECT_LEAK, "metadata_only review_blind must be null")
        elif scope == dv.CONTENT_PUBLIC_COMMITMENT:
            require(leak_value == [len(artifact), dv.hb(artifact)], REJECT_LEAK, "public_commitment leak mismatch")
            require(review_blind is None, REJECT_LEAK, "public_commitment review_blind must be null")
        elif scope == dv.CONTENT_REVIEWED_CONTENT:
            require(isinstance(review_blind, bytes) and len(review_blind) == 32, REJECT_LEAK, "reviewed_content review_blind required")
            expected_commit = dv.hb(
                dv.dumps(
                    [
                        "daylight.review.hidden.v6",
                        review_blind,
                        len(artifact),
                        dv.hb(artifact),
                        ctx.header[10],
                        ctx.header[15],
                    ]
                )
            )
            require(leak_value == [len(artifact), expected_commit], REJECT_LEAK, "reviewed_content hidden commitment mismatch")
        else:
            raise OpenError(REJECT_PAYLOAD, "unknown content scope")
        return OpenResult(True, artifact=artifact, private_kem_called=private_kem_called, aead_dec_called=aead_dec_called, diagnostics=diagnostics)
    except OpenError as exc:
        diagnostics.append(exc.message)
        return OpenResult(
            False,
            rejection_stage=exc.stage,
            private_kem_called=private_kem_called,
            aead_dec_called=aead_dec_called,
            diagnostics=diagnostics,
        )


def check_vector(vector_dir: Path) -> None:
    manifest = dv.load_json(vector_dir / "manifest.json")
    result = open_independent(dv.read_hex_file(vector_dir / "omega.cbor.hex"), load_secrets(vector_dir))
    expected_result = manifest["expected_result"]
    expected_stage = manifest["expected_rejection_stage"]
    if expected_result == "artifact":
        if not result.ok:
            raise AssertionError(f"{vector_dir.name}: expected artifact, got {result.rejection_stage}")
        expected_artifact = dv.read_hex_file(vector_dir / "expected_artifact.hex")
        if result.artifact != expected_artifact:
            raise AssertionError(f"{vector_dir.name}: artifact mismatch")
    elif expected_result == "bottom":
        if result.ok:
            raise AssertionError(f"{vector_dir.name}: expected bottom, got artifact")
        if result.rejection_stage != expected_stage:
            raise AssertionError(f"{vector_dir.name}: stage mismatch {result.rejection_stage} != {expected_stage}")
    else:
        raise AssertionError(f"{vector_dir.name}: bad expected_result")

    if result.private_kem_called != bool(manifest["private_kem_allowed"]):
        raise AssertionError(f"{vector_dir.name}: private_kem_called mismatch")
    if result.aead_dec_called != bool(manifest["aead_dec_allowed"]):
        raise AssertionError(f"{vector_dir.name}: aead_dec_called mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the independent Daylight v0.6 M1 fixture-profile Open verifier.")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    fixture = Path(os.environ.get("DAYLIGHT_V06_M1_FIXTURE", str(DEFAULT_FIXTURE)))
    if not fixture.is_absolute():
        fixture = REPO / fixture
    fixture = fixture.resolve()
    vector_dirs = sorted(path for group in ("valid", "negative") for path in (fixture / "vectors" / group).iterdir() if path.is_dir())
    if len(vector_dirs) != 32:
        raise AssertionError(f"expected 32 vectors, found {len(vector_dirs)}")
    for vector_dir in vector_dirs:
        check_vector(vector_dir)

    if not args.quiet:
        print(f"daylight-v06-m1-independent-open: verified {len(vector_dirs)} vectors")


if __name__ == "__main__":
    main()
