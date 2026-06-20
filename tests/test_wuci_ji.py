#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import shlex
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("WUCI_JI_BIN", ROOT / "build" / "wuci-ji"))
RUNNER = shlex.split(os.environ.get("WUCI_JI_RUNNER", ""))
ENVELOPE_PREFIX = b"WJSEAL\x01\x01"
ENVELOPE_V2_PREFIX = b"WJSEAL\x02\x01"
ENVELOPE_V3_PREFIX = b"WJSEAL\x03\x01"
ENVELOPE_HEADER_LEN = len(ENVELOPE_PREFIX) + 12
ENVELOPE_V2_KEY_ID_LEN = 16
ENVELOPE_V2_HEADER_LEN = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN + 12
ENVELOPE_V3_PUBLIC_LEN = 32
ENVELOPE_V3_HEADER_LEN = (
    len(ENVELOPE_V3_PREFIX) + ENVELOPE_V3_PUBLIC_LEN + ENVELOPE_V2_KEY_ID_LEN + 12
)
ENVELOPE_TAG_LEN = 16
V3_HKDF_INFO = b"wuci-ji v3 X25519 recipient AEAD key"
ARMOR_HEADER = b"-----BEGIN WUCI-JI ARTIFACT-----"
ARMOR_FOOTER = b"-----END WUCI-JI ARTIFACT-----"
FROST_SHA256_HELPERS = {
    "frost-p256-h4": b"FROST-P256-SHA256-v1msg",
    "frost-p256-h5": b"FROST-P256-SHA256-v1com",
    "frost-secp256k1-h4": b"FROST-secp256k1-SHA256-v1msg",
    "frost-secp256k1-h5": b"FROST-secp256k1-SHA256-v1com",
}
P256_ORDER = int(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16
)
SECP256K1_ORDER = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)
SECP256K1_FIELD_PRIME = int(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16
)
SECP256K1_G = (
    int("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
    int("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
)
FROST_HASH_TO_SCALAR_HELPERS = {
    "frost-p256-h1": (b"FROST-P256-SHA256-v1rho", P256_ORDER),
    "frost-p256-h2": (b"FROST-P256-SHA256-v1chal", P256_ORDER),
    "frost-p256-h3": (b"FROST-P256-SHA256-v1nonce", P256_ORDER),
    "frost-secp256k1-h1": (b"FROST-secp256k1-SHA256-v1rho", SECP256K1_ORDER),
    "frost-secp256k1-h2": (b"FROST-secp256k1-SHA256-v1chal", SECP256K1_ORDER),
    "frost-secp256k1-h3": (b"FROST-secp256k1-SHA256-v1nonce", SECP256K1_ORDER),
}


def run(args: list[str], data: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [*RUNNER, str(BIN), *args],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_sha256(payload: bytes) -> None:
    proc = run(["sha256"], payload)
    expected = hashlib.sha256(payload).hexdigest() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)


def assert_frost_sha256_helpers(payload: bytes) -> None:
    for command, prefix in FROST_SHA256_HELPERS.items():
        proc = run([command], payload)
        expected = hashlib.sha256(prefix + payload).hexdigest() + "\n"
        actual = proc.stdout.decode("ascii")
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert actual == expected, (command, payload[:32], actual, expected)


def expand_message_xmd_sha256(message: bytes, dst: bytes, out_len: int) -> bytes:
    block_len = hashlib.sha256().digest_size
    ell = (out_len + block_len - 1) // block_len
    assert 1 <= ell <= 255
    assert len(dst) <= 255

    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(
        (b"\x00" * 64)
        + message
        + out_len.to_bytes(2, "big")
        + b"\x00"
        + dst_prime
    ).digest()
    blocks = [hashlib.sha256(b0 + b"\x01" + dst_prime).digest()]
    for counter in range(2, ell + 1):
        xored = bytes(left ^ right for left, right in zip(b0, blocks[-1]))
        blocks.append(hashlib.sha256(xored + bytes([counter]) + dst_prime).digest())
    return b"".join(blocks)[:out_len]


def frost_hash_to_scalar_ref(message: bytes, dst: bytes, order: int) -> bytes:
    uniform = expand_message_xmd_sha256(message, dst, 48)
    scalar = int.from_bytes(uniform, "big") % order
    return scalar.to_bytes(32, "big")


def assert_frost_hash_to_scalar_helpers(payload: bytes) -> None:
    for command, (dst, order) in FROST_HASH_TO_SCALAR_HELPERS.items():
        proc = run([command], payload)
        expected = frost_hash_to_scalar_ref(payload, dst, order).hex() + "\n"
        actual = proc.stdout.decode("ascii")
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert actual == expected, (command, payload[:32], actual, expected)


def field_hex(value: int) -> str:
    return f"{value % (1 << 256):064x}"


def scalar_hex(value: int) -> str:
    return f"{value % (1 << 256):064x}"


def assert_secp256k1_scalar_op(command: str, a: int, b: int | None, expected: int) -> None:
    args = [command, scalar_hex(a)]
    if b is not None:
        args.append(scalar_hex(b))
    proc = run(args)
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == f"{expected % SECP256K1_ORDER:064x}\n", (
        command,
        scalar_hex(a),
        None if b is None else scalar_hex(b),
        actual,
        expected,
    )


def assert_secp256k1_scalar_helpers() -> None:
    n = SECP256K1_ORDER
    values = [
        0,
        1,
        2,
        7,
        n - 1,
        int("1234567890abcdef" * 4, 16),
        int("fedcba0987654321" * 4, 16) % n,
    ]

    for a in values:
        if a % n != 0:
            assert_secp256k1_scalar_op("secp256k1-scalar-inv", a, None, pow(a, n - 2, n))
        for b in values:
            assert_secp256k1_scalar_op("secp256k1-scalar-add", a, b, a + b)
            assert_secp256k1_scalar_op("secp256k1-scalar-sub", a, b, a - b)
            assert_secp256k1_scalar_op("secp256k1-scalar-mul", a, b, a * b)


def assert_secp256k1_scalar_rejects_invalid() -> None:
    cases = [
        ["secp256k1-scalar-add", "00", "00" * 32],
        ["secp256k1-scalar-add", "00" * 32, "zz" + ("00" * 31)],
        ["secp256k1-scalar-add", f"{SECP256K1_ORDER:064x}", "00" * 32],
        ["secp256k1-scalar-inv", "00" * 32],
    ]
    for args in cases:
        proc = run(args)
        assert proc.returncode != 0, args
        assert proc.stdout == b"", args


def frost_lagrange_ref(identifier: int, identifiers: list[int]) -> int:
    n = SECP256K1_ORDER
    if identifier == 0 or identifier not in identifiers or len(set(identifiers)) != len(identifiers):
        raise ValueError("invalid lagrange identifiers")
    numerator = 1
    denominator = 1
    for other in identifiers:
        if other == identifier:
            continue
        numerator = (numerator * other) % n
        denominator = (denominator * ((other - identifier) % n)) % n
    return (numerator * pow(denominator, n - 2, n)) % n


def assert_frost_lagrange_helpers() -> None:
    cases = [
        (1, [1]),
        (1, [1, 2]),
        (2, [1, 2]),
        (1, [1, 2, 3]),
        (2, [1, 2, 3]),
        (3, [1, 2, 3]),
    ]
    for identifier, identifiers in cases:
        proc = run(
            [
                "frost-secp256k1-lagrange",
                scalar_hex(identifier),
                *(scalar_hex(item) for item in identifiers),
            ]
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert proc.stdout == f"{frost_lagrange_ref(identifier, identifiers):064x}\n".encode(
            "ascii"
        )

    rejected_cases = [
        [1, [2, 3]],
        [1, [0, 1]],
        [1, [1, 1]],
    ]
    for identifier, identifiers in rejected_cases:
        proc = run(
            [
                "frost-secp256k1-lagrange",
                scalar_hex(identifier),
                *(scalar_hex(item) for item in identifiers),
            ]
        )
        assert proc.returncode != 0
        assert proc.stdout == b""


def secp256k1_compressed_ref(point: tuple[int, int]) -> str:
    x, y = point
    return f"{2 + (y & 1):02x}{x:064x}"


def secp256k1_decompress_ref(encoded: str) -> tuple[int, int]:
    prefix = int(encoded[:2], 16)
    assert prefix in (2, 3)
    x = int(encoded[2:], 16)
    y2 = (pow(x, 3, SECP256K1_FIELD_PRIME) + 7) % SECP256K1_FIELD_PRIME
    y = pow(y2, (SECP256K1_FIELD_PRIME + 1) // 4, SECP256K1_FIELD_PRIME)
    assert (y * y) % SECP256K1_FIELD_PRIME == y2
    if (y & 1) != (prefix & 1):
        y = (-y) % SECP256K1_FIELD_PRIME
    return x, y


def assert_frost_nonce_generate_helper() -> None:
    secret = scalar_hex(7)
    outputs: list[str] = []
    for _ in range(2):
        proc = run(["frost-secp256k1-nonce-generate", secret])
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        actual = proc.stdout.decode("ascii").strip()
        assert len(actual) == 64
        nonce = int(actual, 16)
        assert 0 <= nonce < SECP256K1_ORDER
        outputs.append(actual)
    assert outputs[0] != outputs[1]

    rejected_cases = [
        ["frost-secp256k1-nonce-generate", "00"],
        ["frost-secp256k1-nonce-generate", f"{SECP256K1_ORDER:064x}"],
    ]
    for args in rejected_cases:
        proc = run(args)
        assert proc.returncode != 0
        assert proc.stdout == b""


def assert_frost_commit_helpers() -> None:
    cases = [
        (1, 2),
        (2, 3),
        (SECP256K1_ORDER - 1, 1),
    ]
    for hiding, binding in cases:
        proc = run(
            [
                "frost-secp256k1-commit",
                scalar_hex(hiding),
                scalar_hex(binding),
            ]
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        hiding_point = secp256k1_point_mul_ref(hiding, SECP256K1_G)
        binding_point = secp256k1_point_mul_ref(binding, SECP256K1_G)
        assert hiding_point is not None
        assert binding_point is not None
        expected = (
            f"hiding_nonce_commitment: {secp256k1_compressed_ref(hiding_point)}\n"
            f"binding_nonce_commitment: {secp256k1_compressed_ref(binding_point)}\n"
        )
        assert proc.stdout.decode("ascii") == expected

    rejected_cases = [
        ["frost-secp256k1-commit", scalar_hex(0), scalar_hex(1)],
        ["frost-secp256k1-commit", scalar_hex(1), scalar_hex(0)],
        ["frost-secp256k1-commit", f"{SECP256K1_ORDER:064x}", scalar_hex(1)],
    ]
    for args in rejected_cases:
        proc = run(args)
        assert proc.returncode != 0
        assert proc.stdout == b""


def frost_commitment_hash_ref(commitments: list[tuple[int, str, str]]) -> str:
    encoded = b""
    for identifier, hiding, binding in commitments:
        encoded += bytes.fromhex(scalar_hex(identifier))
        encoded += bytes.fromhex(hiding)
        encoded += bytes.fromhex(binding)
    return hashlib.sha256(b"FROST-secp256k1-SHA256-v1com" + encoded).hexdigest()


def frost_binding_factor_ref(
    group_public_key: str, msg_hash: str, commitment_hash: str, identifier: int
) -> str:
    payload = (
        bytes.fromhex(group_public_key)
        + bytes.fromhex(msg_hash)
        + bytes.fromhex(commitment_hash)
        + bytes.fromhex(scalar_hex(identifier))
    )
    return frost_hash_to_scalar_ref(
        payload, b"FROST-secp256k1-SHA256-v1rho", SECP256K1_ORDER
    ).hex()


def frost_group_commitment_ref(
    rows: list[tuple[int, str, str, int]]
) -> tuple[int, int] | None:
    acc: tuple[int, int] | None = None
    for _, hiding, binding, rho in rows:
        hiding_point = secp256k1_decompress_ref(hiding)
        binding_point = secp256k1_decompress_ref(binding)
        scaled_binding = secp256k1_point_mul_ref(rho, binding_point)
        contribution = hiding_point
        if scaled_binding is not None:
            contribution = secp256k1_point_add_ref(hiding_point, scaled_binding)
        acc = secp256k1_point_add_ref(acc, contribution)
    return acc


def frost_challenge_ref(group_commitment: str, group_public_key: str, message: bytes) -> str:
    payload = bytes.fromhex(group_commitment) + bytes.fromhex(group_public_key) + message
    return frost_hash_to_scalar_ref(
        payload, b"FROST-secp256k1-SHA256-v1chal", SECP256K1_ORDER
    ).hex()


def assert_frost_binding_group_helpers() -> None:
    g1 = secp256k1_compressed_ref(SECP256K1_G)
    g2 = secp256k1_compressed_ref(secp256k1_point_mul_ref(2, SECP256K1_G))
    g3 = secp256k1_compressed_ref(secp256k1_point_mul_ref(3, SECP256K1_G))
    g4 = secp256k1_compressed_ref(secp256k1_point_mul_ref(4, SECP256K1_G))
    group_public_key = secp256k1_compressed_ref(secp256k1_point_mul_ref(5, SECP256K1_G))
    commitments = [(1, g1, g2), (2, g3, g4)]

    commitment_args = [
        "frost-secp256k1-commitment-hash",
        *(item for row in commitments for item in (scalar_hex(row[0]), row[1], row[2])),
    ]
    commitment_hash_proc = run(commitment_args)
    assert commitment_hash_proc.returncode == 0, commitment_hash_proc.stderr.decode(
        "utf-8", "replace"
    )
    commitment_hash = commitment_hash_proc.stdout.decode("ascii").strip()
    assert commitment_hash == frost_commitment_hash_ref(commitments)

    msg_hash = hashlib.sha256(b"FROST-secp256k1-SHA256-v1msg" + b"test").hexdigest()
    rhos: list[int] = []
    for identifier, _, _ in commitments:
        proc = run(
            [
                "frost-secp256k1-binding-factor",
                group_public_key,
                msg_hash,
                commitment_hash,
                scalar_hex(identifier),
            ]
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        actual = proc.stdout.decode("ascii").strip()
        expected = frost_binding_factor_ref(
            group_public_key, msg_hash, commitment_hash, identifier
        )
        assert actual == expected
        rhos.append(int(actual, 16))

    rows = [
        (commitments[0][0], commitments[0][1], commitments[0][2], rhos[0]),
        (commitments[1][0], commitments[1][1], commitments[1][2], rhos[1]),
    ]
    group_proc = run(
        [
            "frost-secp256k1-group-commitment",
            *(item for row in rows for item in (scalar_hex(row[0]), row[1], row[2], scalar_hex(row[3]))),
        ]
    )
    assert group_proc.returncode == 0, group_proc.stderr.decode("utf-8", "replace")
    expected_group = frost_group_commitment_ref(rows)
    assert expected_group is not None
    assert group_proc.stdout.decode("ascii") == (
        f"group_commitment: {secp256k1_compressed_ref(expected_group)}\n"
    )

    rejected_cases = [
        ["frost-secp256k1-commitment-hash", scalar_hex(2), g1, g2, scalar_hex(1), g3, g4],
        ["frost-secp256k1-commitment-hash", scalar_hex(0), g1, g2],
        ["frost-secp256k1-binding-factor", "00" + group_public_key[2:], msg_hash, commitment_hash, scalar_hex(1)],
        ["frost-secp256k1-binding-factor", group_public_key, "00", commitment_hash, scalar_hex(1)],
        ["frost-secp256k1-group-commitment", scalar_hex(2), g1, g2, scalar_hex(1), scalar_hex(1), g3, g4, scalar_hex(2)],
    ]
    for args in rejected_cases:
        proc = run(args)
        assert proc.returncode != 0, args
        assert proc.stdout == b"", args


def assert_frost_challenge_helper() -> None:
    group_commitment = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(7, SECP256K1_G)
    )
    group_public_key = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(5, SECP256K1_G)
    )
    for message in (b"", b"test", b"frost-challenge\0" * 128):
        proc = run(
            ["frost-secp256k1-challenge", group_commitment, group_public_key],
            message,
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert proc.stdout.decode("ascii").strip() == frost_challenge_ref(
            group_commitment, group_public_key, message
        )

    rejected_cases = [
        ["frost-secp256k1-challenge", "00" + group_commitment[2:], group_public_key],
        ["frost-secp256k1-challenge", group_commitment, "02" + ("00" * 31)],
    ]
    for args in rejected_cases:
        proc = run(args, b"test")
        assert proc.returncode != 0
        assert proc.stdout == b""


def frost_signing_share_ref(
    hiding_nonce: int,
    binding_nonce: int,
    binding_factor: int,
    lagrange: int,
    share: int,
    challenge: int,
) -> int:
    n = SECP256K1_ORDER
    return (
        hiding_nonce
        + (binding_nonce * binding_factor)
        + (lagrange * share * challenge)
    ) % n


def assert_frost_signing_share_helper() -> None:
    cases = [
        (1, 2, 3, 4, 5, 6),
        (SECP256K1_ORDER - 1, 2, 3, 4, 5, 6),
        (7, 11, 0, 13, 17, 19),
        (7, 11, 23, 13, 17, 0),
    ]
    for case in cases:
        proc = run(["frost-secp256k1-signing-share", *(scalar_hex(item) for item in case)])
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert proc.stdout.decode("ascii").strip() == (
            f"{frost_signing_share_ref(*case):064x}"
        )

    rejected_cases = [
        (0, 2, 3, 4, 5, 6),
        (1, 0, 3, 4, 5, 6),
        (1, 2, 3, 0, 5, 6),
        (1, 2, 3, 4, 0, 6),
    ]
    for case in rejected_cases:
        proc = run(["frost-secp256k1-signing-share", *(scalar_hex(item) for item in case)])
        assert proc.returncode != 0
        assert proc.stdout == b""

    noncanonical = run(
        [
            "frost-secp256k1-signing-share",
            scalar_hex(1),
            scalar_hex(2),
            scalar_hex(3),
            scalar_hex(4),
            f"{SECP256K1_ORDER:064x}",
            scalar_hex(6),
        ]
    )
    assert noncanonical.returncode != 0
    assert noncanonical.stdout == b""


def assert_frost_aggregate_helper() -> None:
    group_commitment = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(7, SECP256K1_G)
    )
    cases = [
        ([1], 1),
        ([1, 2, 3], 6),
        ([1, SECP256K1_ORDER - 1, 2], 2),
        ([0, 0, 5], 5),
    ]
    for shares, expected in cases:
        proc = run(
            ["frost-secp256k1-aggregate", group_commitment, *(scalar_hex(item) for item in shares)]
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert proc.stdout.decode("ascii") == (
            f"signature_commitment: {group_commitment}\n"
            f"signature_scalar: {expected % SECP256K1_ORDER:064x}\n"
        )

    rejected_cases = [
        ["frost-secp256k1-aggregate", "00" + group_commitment[2:], scalar_hex(1)],
        ["frost-secp256k1-aggregate", group_commitment, f"{SECP256K1_ORDER:064x}"],
    ]
    for args in rejected_cases:
        proc = run(args)
        assert proc.returncode != 0
        assert proc.stdout == b""


def assert_frost_verify_helper() -> None:
    group_public_key = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(5, SECP256K1_G)
    )
    group_commitment = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(7, SECP256K1_G)
    )
    challenge = 3
    signature_scalar = (7 + (5 * challenge)) % SECP256K1_ORDER

    valid = run(
        [
            "frost-secp256k1-verify",
            group_commitment,
            group_public_key,
            scalar_hex(signature_scalar),
            scalar_hex(challenge),
        ]
    )
    assert valid.returncode == 0, valid.stderr.decode("utf-8", "replace")
    assert valid.stdout == b"valid\n"

    zero_challenge = run(
        [
            "frost-secp256k1-verify",
            group_commitment,
            group_public_key,
            scalar_hex(7),
            scalar_hex(0),
        ]
    )
    assert zero_challenge.returncode == 0, zero_challenge.stderr.decode(
        "utf-8", "replace"
    )
    assert zero_challenge.stdout == b"valid\n"

    invalid = run(
        [
            "frost-secp256k1-verify",
            group_commitment,
            group_public_key,
            scalar_hex(signature_scalar + 1),
            scalar_hex(challenge),
        ]
    )
    assert invalid.returncode != 0
    assert invalid.stdout == b"invalid\n"

    rejected_cases = [
        ["frost-secp256k1-verify", "00" + group_commitment[2:], group_public_key, scalar_hex(1), scalar_hex(1)],
        ["frost-secp256k1-verify", group_commitment, group_public_key, f"{SECP256K1_ORDER:064x}", scalar_hex(1)],
    ]
    for args in rejected_cases:
        proc = run(args)
        assert proc.returncode != 0
        assert proc.stdout == b""


def output_labels(stdout: bytes) -> dict[str, str]:
    labels: dict[str, str] = {}
    for line in stdout.decode("ascii").splitlines():
        label, value = line.split(": ", 1)
        labels[label] = value
    return labels


def assert_frost_end_to_end_cli_flow() -> None:
    message = b"wuci-ji frost integration"
    group_public_key = secp256k1_compressed_ref(
        secp256k1_point_mul_ref(5, SECP256K1_G)
    )
    signers = [
        {"id": 1, "share": 12, "hiding": 2, "binding": 3},
        {"id": 2, "share": 19, "hiding": 4, "binding": 5},
    ]

    for signer in signers:
        proc = run(
            [
                "frost-secp256k1-commit",
                scalar_hex(signer["hiding"]),
                scalar_hex(signer["binding"]),
            ]
        )
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        labels = output_labels(proc.stdout)
        signer["D"] = labels["hiding_nonce_commitment"]
        signer["E"] = labels["binding_nonce_commitment"]

    commitment_hash_proc = run(
        [
            "frost-secp256k1-commitment-hash",
            *(item for signer in signers for item in (scalar_hex(signer["id"]), signer["D"], signer["E"])),
        ]
    )
    assert commitment_hash_proc.returncode == 0, commitment_hash_proc.stderr.decode(
        "utf-8", "replace"
    )
    commitment_hash = commitment_hash_proc.stdout.decode("ascii").strip()

    msg_hash_proc = run(["frost-secp256k1-h4"], message)
    assert msg_hash_proc.returncode == 0, msg_hash_proc.stderr.decode("utf-8", "replace")
    msg_hash = msg_hash_proc.stdout.decode("ascii").strip()

    for signer in signers:
        rho_proc = run(
            [
                "frost-secp256k1-binding-factor",
                group_public_key,
                msg_hash,
                commitment_hash,
                scalar_hex(signer["id"]),
            ]
        )
        assert rho_proc.returncode == 0, rho_proc.stderr.decode("utf-8", "replace")
        signer["rho"] = int(rho_proc.stdout.decode("ascii").strip(), 16)

    group_commitment_proc = run(
        [
            "frost-secp256k1-group-commitment",
            *(item for signer in signers for item in (scalar_hex(signer["id"]), signer["D"], signer["E"], scalar_hex(signer["rho"]))),
        ]
    )
    assert group_commitment_proc.returncode == 0, group_commitment_proc.stderr.decode(
        "utf-8", "replace"
    )
    group_commitment = output_labels(group_commitment_proc.stdout)["group_commitment"]

    challenge_proc = run(
        ["frost-secp256k1-challenge", group_commitment, group_public_key],
        message,
    )
    assert challenge_proc.returncode == 0, challenge_proc.stderr.decode("utf-8", "replace")
    challenge = int(challenge_proc.stdout.decode("ascii").strip(), 16)

    for signer in signers:
        lagrange_proc = run(
            [
                "frost-secp256k1-lagrange",
                scalar_hex(signer["id"]),
                *(scalar_hex(item["id"]) for item in signers),
            ]
        )
        assert lagrange_proc.returncode == 0, lagrange_proc.stderr.decode(
            "utf-8", "replace"
        )
        lagrange = int(lagrange_proc.stdout.decode("ascii").strip(), 16)
        share_proc = run(
            [
                "frost-secp256k1-signing-share",
                scalar_hex(signer["hiding"]),
                scalar_hex(signer["binding"]),
                scalar_hex(signer["rho"]),
                scalar_hex(lagrange),
                scalar_hex(signer["share"]),
                scalar_hex(challenge),
            ]
        )
        assert share_proc.returncode == 0, share_proc.stderr.decode("utf-8", "replace")
        signer["z"] = int(share_proc.stdout.decode("ascii").strip(), 16)

    aggregate_proc = run(
        [
            "frost-secp256k1-aggregate",
            group_commitment,
            *(scalar_hex(signer["z"]) for signer in signers),
        ]
    )
    assert aggregate_proc.returncode == 0, aggregate_proc.stderr.decode(
        "utf-8", "replace"
    )
    signature = output_labels(aggregate_proc.stdout)

    verify_proc = run(
        [
            "frost-secp256k1-verify",
            signature["signature_commitment"],
            group_public_key,
            signature["signature_scalar"],
            scalar_hex(challenge),
        ]
    )
    assert verify_proc.returncode == 0, verify_proc.stderr.decode("utf-8", "replace")
    assert verify_proc.stdout == b"valid\n"


def assert_secp256k1_field_op(command: str, a: int, b: int | None, expected: int) -> None:
    args = [command, field_hex(a)]
    if b is not None:
        args.append(field_hex(b))
    proc = run(args)
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == f"{expected % SECP256K1_FIELD_PRIME:064x}\n", (
        command,
        field_hex(a),
        None if b is None else field_hex(b),
        actual,
        expected,
    )


def assert_secp256k1_field_helpers() -> None:
    p = SECP256K1_FIELD_PRIME
    values = [
        0,
        1,
        2,
        7,
        p - 1,
        p,
        p + 1,
        (1 << 256) - 1,
        int("1234567890abcdef" * 4, 16),
        int("fedcba0987654321" * 4, 16),
    ]

    for a in values:
        assert_secp256k1_field_op("secp256k1-field-square", a, None, a * a)
        if a % p != 0:
            assert_secp256k1_field_op("secp256k1-field-inv", a, None, pow(a, p - 2, p))

    for a in values:
        for b in values:
            assert_secp256k1_field_op("secp256k1-field-add", a, b, a + b)
            assert_secp256k1_field_op("secp256k1-field-sub", a, b, a - b)
            assert_secp256k1_field_op("secp256k1-field-mul", a, b, a * b)


def assert_secp256k1_field_rejects_invalid() -> None:
    cases = [
        ["secp256k1-field-add", "00", "00" * 32],
        ["secp256k1-field-add", "00" * 32, "zz" + ("00" * 31)],
        ["secp256k1-field-square", "00" * 31],
    ]
    for args in cases:
        proc = run(args)
        assert proc.returncode != 0, args
        assert proc.stdout == b"", args


def secp256k1_point_add_ref(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    p = SECP256K1_FIELD_PRIME
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        slope = (3 * x1 * x1 * pow(2 * y1, p - 2, p)) % p
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % p, p - 2, p)) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return x3, y3


def secp256k1_point_mul_ref(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    acc: tuple[int, int] | None = None
    base: tuple[int, int] | None = point
    while scalar:
        if scalar & 1:
            acc = secp256k1_point_add_ref(acc, base)
        base = secp256k1_point_add_ref(base, base)
        scalar >>= 1
    return acc


def secp256k1_jacobian_to_affine_ref(point: tuple[int, int, int]) -> tuple[int, int] | None:
    p = SECP256K1_FIELD_PRIME
    x, y, z = point
    if z % p == 0:
        return None
    z_inv = pow(z, p - 2, p)
    z_inv2 = (z_inv * z_inv) % p
    z_inv3 = (z_inv2 * z_inv) % p
    return (x * z_inv2) % p, (y * z_inv3) % p


def point_hex(point: tuple[int, int]) -> tuple[str, str]:
    return f"{point[0]:064x}", f"{point[1]:064x}"


def parse_point_output(output: bytes) -> tuple[int, int] | None:
    text = output.decode("ascii")
    if text == "infinity\n":
        return None
    lines = text.splitlines()
    assert len(lines) == 2, text
    assert lines[0].startswith("x: "), text
    assert lines[1].startswith("y: "), text
    return int(lines[0][3:], 16), int(lines[1][3:], 16)


def parse_jacobian_output(output: bytes) -> tuple[int, int, int] | None:
    text = output.decode("ascii")
    if text == "infinity\n":
        return None
    lines = text.splitlines()
    assert len(lines) == 3, text
    assert lines[0].startswith("x: "), text
    assert lines[1].startswith("y: "), text
    assert lines[2].startswith("z: "), text
    return int(lines[0][3:], 16), int(lines[1][3:], 16), int(lines[2][3:], 16)


def assert_secp256k1_point_helpers() -> None:
    g = SECP256K1_G
    gx, gy = point_hex(g)
    neg_g = (g[0], (-g[1]) % SECP256K1_FIELD_PRIME)
    neg_gx, neg_gy = point_hex(neg_g)
    two_g = secp256k1_point_add_ref(g, g)
    assert two_g is not None
    two_gx, two_gy = point_hex(two_g)
    three_g = secp256k1_point_add_ref(g, two_g)
    assert three_g is not None

    valid = run(["secp256k1-point-validate", gx, gy])
    assert valid.returncode == 0, valid.stderr.decode("utf-8", "replace")
    assert valid.stdout == b"valid\n"

    invalid_y = f"{(g[1] + 1) % SECP256K1_FIELD_PRIME:064x}"
    invalid = run(["secp256k1-point-validate", gx, invalid_y])
    assert invalid.returncode != 0
    assert invalid.stdout == b"invalid\n"

    noncanonical = run(["secp256k1-point-validate", f"{SECP256K1_FIELD_PRIME:064x}", gy])
    assert noncanonical.returncode != 0
    assert noncanonical.stdout == b"invalid\n"

    doubled = run(["secp256k1-point-double", gx, gy])
    assert doubled.returncode == 0, doubled.stderr.decode("utf-8", "replace")
    assert parse_point_output(doubled.stdout) == two_g

    added = run(["secp256k1-point-add", gx, gy, two_gx, two_gy])
    assert added.returncode == 0, added.stderr.decode("utf-8", "replace")
    assert parse_point_output(added.stdout) == three_g

    infinity = run(["secp256k1-point-add", gx, gy, neg_gx, neg_gy])
    assert infinity.returncode == 0, infinity.stderr.decode("utf-8", "replace")
    assert parse_point_output(infinity.stdout) is None

    for scalar in (0, 1, 2, 3):
        proc = run(["secp256k1-basepoint-mul", f"{scalar:064x}"])
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert parse_point_output(proc.stdout) == secp256k1_point_mul_ref(scalar, g)

    doubled_jacobian = run(["secp256k1-jacobian-double", gx, gy, f"{1:064x}"])
    assert doubled_jacobian.returncode == 0, doubled_jacobian.stderr.decode("utf-8", "replace")
    doubled_jacobian_point = parse_jacobian_output(doubled_jacobian.stdout)
    assert doubled_jacobian_point is not None
    assert secp256k1_jacobian_to_affine_ref(doubled_jacobian_point) == two_g

    mixed_added = run(
        [
            "secp256k1-jacobian-mixed-add",
            *(f"{coordinate:064x}" for coordinate in doubled_jacobian_point),
            gx,
            gy,
        ]
    )
    assert mixed_added.returncode == 0, mixed_added.stderr.decode("utf-8", "replace")
    mixed_added_point = parse_jacobian_output(mixed_added.stdout)
    assert mixed_added_point is not None
    assert secp256k1_jacobian_to_affine_ref(mixed_added_point) == three_g

    identity_added = run(
        ["secp256k1-jacobian-mixed-add", f"{0:064x}", f"{0:064x}", f"{0:064x}", gx, gy]
    )
    assert identity_added.returncode == 0, identity_added.stderr.decode("utf-8", "replace")
    identity_added_point = parse_jacobian_output(identity_added.stdout)
    assert identity_added_point is not None
    assert secp256k1_jacobian_to_affine_ref(identity_added_point) == g

    jacobian_infinity = run(["secp256k1-jacobian-double", gx, gy, f"{0:064x}"])
    assert jacobian_infinity.returncode == 0, jacobian_infinity.stderr.decode("utf-8", "replace")
    assert parse_jacobian_output(jacobian_infinity.stdout) is None

    projective_scalars = (
        0,
        1,
        2,
        3,
        17,
        (1 << 255) + 7,
        SECP256K1_ORDER - 1,
        SECP256K1_ORDER,
        SECP256K1_ORDER + 1,
        SECP256K1_ORDER + 2,
        (1 << 256) - 1,
    )
    for scalar in projective_scalars:
        proc = run(["secp256k1-projective-basepoint-mul", f"{scalar:064x}"])
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        assert parse_point_output(proc.stdout) == secp256k1_point_mul_ref(scalar, g)

    compressed = run(["secp256k1-point-encode-compressed", gx, gy])
    assert compressed.returncode == 0, compressed.stderr.decode("utf-8", "replace")
    assert compressed.stdout == bytes.fromhex("02" + gx).hex().encode("ascii") + b"\n"
    decoded_compressed = run(["secp256k1-point-decode", compressed.stdout.decode("ascii").strip()])
    assert decoded_compressed.returncode == 0, decoded_compressed.stderr.decode("utf-8", "replace")
    assert parse_point_output(decoded_compressed.stdout) == g

    compressed_neg = run(["secp256k1-point-encode-compressed", neg_gx, neg_gy])
    assert compressed_neg.returncode == 0, compressed_neg.stderr.decode("utf-8", "replace")
    assert compressed_neg.stdout.startswith(b"03")
    decoded_compressed_neg = run(
        ["secp256k1-point-decode", compressed_neg.stdout.decode("ascii").strip()]
    )
    assert decoded_compressed_neg.returncode == 0, decoded_compressed_neg.stderr.decode(
        "utf-8", "replace"
    )
    assert parse_point_output(decoded_compressed_neg.stdout) == neg_g

    uncompressed = run(["secp256k1-point-encode-uncompressed", gx, gy])
    assert uncompressed.returncode == 0, uncompressed.stderr.decode("utf-8", "replace")
    assert uncompressed.stdout == ("04" + gx + gy + "\n").encode("ascii")
    decoded_uncompressed = run(["secp256k1-point-decode", uncompressed.stdout.decode("ascii").strip()])
    assert decoded_uncompressed.returncode == 0, decoded_uncompressed.stderr.decode("utf-8", "replace")
    assert parse_point_output(decoded_uncompressed.stdout) == g


def assert_secp256k1_point_rejects_invalid() -> None:
    gx, gy = point_hex(SECP256K1_G)
    bad_y = f"{(SECP256K1_G[1] + 1) % SECP256K1_FIELD_PRIME:064x}"
    cases = [
        ["secp256k1-point-double", gx, bad_y],
        ["secp256k1-point-add", gx, gy, gx, bad_y],
        ["secp256k1-basepoint-mul", "00"],
        ["secp256k1-jacobian-double", gx, bad_y, f"{1:064x}"],
        ["secp256k1-jacobian-mixed-add", gx, gy, f"{1:064x}", gx, bad_y],
        ["secp256k1-projective-basepoint-mul", "00"],
        ["secp256k1-point-encode-compressed", gx, bad_y],
        ["secp256k1-point-encode-uncompressed", gx, bad_y],
        ["secp256k1-point-decode", "00" + gx],
        ["secp256k1-point-decode", "02" + gx[:-2]],
        ["secp256k1-point-decode", "02" + f"{SECP256K1_FIELD_PRIME:064x}"],
        ["secp256k1-point-decode", "04" + gx + bad_y],
    ]
    for args in cases:
        proc = run(args)
        assert proc.returncode != 0, args
        assert proc.stdout == b"", args


def assert_hmac_sha256(key: bytes, payload: bytes) -> None:
    proc = run(["hmac-sha256", key.hex()], payload)
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)


def hkdf_sha256_ref(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def x25519_ref(scalar: bytes, u_coordinate: int = 9) -> bytes:
    p = (1 << 255) - 19
    a24 = 121666
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar_int = int.from_bytes(k, "little")

    x1 = u_coordinate
    x2, z2 = 1, 0
    x3, z3 = u_coordinate, 1
    swap = 0
    for bit in range(254, -1, -1):
        bit_value = (scalar_int >> bit) & 1
        swap ^= bit_value
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit_value

        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = ((da + cb) * (da + cb)) % p
        z3 = (x1 * ((da - cb) * (da - cb))) % p
        x2 = (aa * bb) % p
        z2 = (e * (aa + a24 * e)) % p

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, p - 2, p)) % p).to_bytes(32, "little")


def assert_hkdf_sha256(salt: bytes, info: bytes, ikm: bytes) -> None:
    proc = run(["hkdf-sha256", salt.hex(), info.hex()], ikm)
    expected = hkdf_sha256_ref(salt, ikm, info).hex() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (ikm[:32], actual, expected)


def poly1305_ref(key: bytes, message: bytes) -> bytes:
    r = bytearray(key[:16])
    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15
    r[4] &= 252
    r[8] &= 252
    r[12] &= 252
    r_int = int.from_bytes(r, "little")
    s_int = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r_int) % p
    return ((acc + s_int) % (1 << 128)).to_bytes(16, "little")


def assert_poly1305(key: bytes, payload: bytes) -> bytes:
    proc = run(["poly1305", key.hex()], payload)
    expected = poly1305_ref(key, payload).hex() + "\n"
    actual = proc.stdout.decode("ascii")
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert actual == expected, (payload[:32], actual, expected)
    return bytes.fromhex(actual.strip())


def quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    mask = 0xFFFFFFFF

    def rotl32(value: int, bits: int) -> int:
        return ((value << bits) & mask) | (value >> (32 - bits))

    state[a] = (state[a] + state[b]) & mask
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & mask
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & mask
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & mask
    state[b] = rotl32(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    constants = b"expand 32-byte k"
    state = [
        *[int.from_bytes(constants[i : i + 4], "little") for i in range(0, 16, 4)],
        *[int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)],
        counter,
        *[int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)],
    ]
    working = state.copy()
    for _ in range(10):
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)
    return b"".join(
        ((working[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
        for i in range(16)
    )


def chacha20_ref(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    remaining = memoryview(data)
    block_counter = counter
    while remaining:
        block = chacha20_block(key, nonce, block_counter)
        take = min(len(remaining), len(block))
        out.extend(a ^ b for a, b in zip(remaining[:take], block[:take]))
        remaining = remaining[take:]
        block_counter = (block_counter + 1) & 0xFFFFFFFF
    return bytes(out)


def assert_chacha20(key: bytes, nonce: bytes, counter: int, payload: bytes) -> bytes:
    proc = run(["chacha20", key.hex(), nonce.hex(), f"{counter:08x}"], payload)
    expected = chacha20_ref(key, nonce, counter, payload)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert proc.stdout == expected
    return proc.stdout


def pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    return b"" if rem == 0 else b"\0" * (16 - rem)


def aead_tag_ref(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
) -> bytes:
    otk = chacha20_block(key, nonce, 0)[:32]
    mac_data = (
        aad
        + pad16(aad)
        + ciphertext
        + pad16(ciphertext)
        + len(aad).to_bytes(8, "little")
        + len(ciphertext).to_bytes(8, "little")
    )
    return poly1305_ref(otk, mac_data)


def aead_seal_ref(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    ciphertext = chacha20_ref(key, nonce, 1, plaintext)
    return ciphertext + aead_tag_ref(key, nonce, ciphertext, aad)


def assert_aead(key: bytes, nonce: bytes, plaintext: bytes) -> None:
    sealed = run(["aead-seal", key.hex(), nonce.hex()], plaintext)
    expected = aead_seal_ref(key, nonce, plaintext)
    assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
    assert sealed.stdout == expected

    ciphertext, tag = sealed.stdout[:-16], sealed.stdout[-16:]
    opened = run(["aead-open", key.hex(), nonce.hex(), tag.hex()], ciphertext)
    assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
    assert opened.stdout == plaintext

    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    rejected = run(["aead-open", key.hex(), nonce.hex(), bad_tag.hex()], ciphertext)
    assert rejected.returncode != 0
    assert rejected.stdout == b""


def assert_envelope(key: bytes, plaintext: bytes) -> None:
    sealed = run(["seal", key.hex()], plaintext)
    assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
    assert sealed.stdout.startswith(ENVELOPE_PREFIX)
    assert len(sealed.stdout) == ENVELOPE_HEADER_LEN + len(plaintext) + ENVELOPE_TAG_LEN

    nonce = sealed.stdout[len(ENVELOPE_PREFIX) : ENVELOPE_HEADER_LEN]
    body = sealed.stdout[ENVELOPE_HEADER_LEN:]
    assert len(nonce) == 12
    assert body == aead_seal_ref(key, nonce, plaintext)

    opened = run(["open", key.hex()], sealed.stdout)
    assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
    assert opened.stdout == plaintext

    repeated = run(["seal", key.hex()], plaintext)
    assert repeated.returncode == 0, repeated.stderr.decode("utf-8", "replace")
    repeated_nonce = repeated.stdout[len(ENVELOPE_PREFIX) : ENVELOPE_HEADER_LEN]
    assert repeated_nonce != nonce


def assert_inspect_v1(sealed: bytes) -> None:
    nonce = sealed[len(ENVELOPE_PREFIX) : ENVELOPE_HEADER_LEN]
    inspected = run(["inspect"], sealed)
    assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")
    assert inspected.stdout == (
        b"version: 1\n"
        b"algorithm: 1\n"
        b"header-length: 20\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
    )


def assert_manifest_v1(sealed: bytes) -> None:
    nonce = sealed[len(ENVELOPE_PREFIX) : ENVELOPE_HEADER_LEN]
    ciphertext = sealed[ENVELOPE_HEADER_LEN:-ENVELOPE_TAG_LEN]
    ciphertext_len = len(sealed) - ENVELOPE_HEADER_LEN - ENVELOPE_TAG_LEN
    tag = sealed[-ENVELOPE_TAG_LEN:]
    manifested = run(["manifest"], sealed)
    assert manifested.returncode == 0, manifested.stderr.decode("utf-8", "replace")
    assert manifested.stdout == (
        b"version: 1\n"
        b"algorithm: 1\n"
        b"header-length: 20\n"
        + b"artifact-sha256: "
        + hashlib.sha256(sealed).hexdigest().encode("ascii")
        + b"\n"
        + b"ciphertext-length: " + str(ciphertext_len).encode("ascii") + b"\n"
        + b"ciphertext-sha256: "
        + hashlib.sha256(ciphertext).hexdigest().encode("ascii")
        + b"\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
        + b"tag: " + tag.hex().encode("ascii") + b"\n"
    )


def assert_envelope_v2(key: bytes, key_id: bytes, plaintext: bytes) -> bytes:
    sealed = run(["seal-v2", key.hex(), key_id.hex()], plaintext)
    assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
    assert sealed.stdout.startswith(ENVELOPE_V2_PREFIX)
    assert len(sealed.stdout) == (
        ENVELOPE_V2_HEADER_LEN + len(plaintext) + ENVELOPE_TAG_LEN
    )
    key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
    assert sealed.stdout[len(ENVELOPE_V2_PREFIX) : key_id_end] == key_id

    header = sealed.stdout[:ENVELOPE_V2_HEADER_LEN]
    nonce = sealed.stdout[key_id_end:ENVELOPE_V2_HEADER_LEN]
    body = sealed.stdout[ENVELOPE_V2_HEADER_LEN:]
    assert len(nonce) == 12
    assert body == aead_seal_ref(key, nonce, plaintext, header)

    opened = run(["open", key.hex()], sealed.stdout)
    assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
    assert opened.stdout == plaintext

    return sealed.stdout


def assert_inspect_v2(sealed: bytes, key_id: bytes) -> None:
    key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
    nonce = sealed[key_id_end:ENVELOPE_V2_HEADER_LEN]
    inspected = run(["inspect"], sealed)
    assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")
    assert inspected.stdout == (
        b"version: 2\n"
        b"algorithm: 1\n"
        b"header-length: 36\n"
        + b"key-id: " + key_id.hex().encode("ascii") + b"\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
    )


def assert_manifest_v2(sealed: bytes, key_id: bytes) -> None:
    key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
    nonce = sealed[key_id_end:ENVELOPE_V2_HEADER_LEN]
    ciphertext = sealed[ENVELOPE_V2_HEADER_LEN:-ENVELOPE_TAG_LEN]
    ciphertext_len = len(sealed) - ENVELOPE_V2_HEADER_LEN - ENVELOPE_TAG_LEN
    tag = sealed[-ENVELOPE_TAG_LEN:]
    manifested = run(["manifest"], sealed)
    assert manifested.returncode == 0, manifested.stderr.decode("utf-8", "replace")
    assert manifested.stdout == (
        b"version: 2\n"
        b"algorithm: 1\n"
        b"header-length: 36\n"
        + b"key-id: " + key_id.hex().encode("ascii") + b"\n"
        + b"artifact-sha256: "
        + hashlib.sha256(sealed).hexdigest().encode("ascii")
        + b"\n"
        + b"ciphertext-length: " + str(ciphertext_len).encode("ascii") + b"\n"
        + b"ciphertext-sha256: "
        + hashlib.sha256(ciphertext).hexdigest().encode("ascii")
        + b"\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
        + b"tag: " + tag.hex().encode("ascii") + b"\n"
    )


def generate_keypair() -> tuple[bytes, bytes]:
    keypair = run(["keypair"])
    assert keypair.returncode == 0, keypair.stderr.decode("utf-8", "replace")
    lines = keypair.stdout.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith(b"private: ")
    assert lines[1].startswith(b"public: ")

    private_key = bytes.fromhex(lines[0].split(b": ", 1)[1].decode("ascii"))
    public_key = bytes.fromhex(lines[1].split(b": ", 1)[1].decode("ascii"))
    assert len(private_key) == 32
    assert len(public_key) == 32
    assert public_key == x25519_ref(private_key)
    return private_key, public_key


def assert_inspect_v3(sealed: bytes, recipient_public: bytes) -> None:
    key_id_start = len(ENVELOPE_V3_PREFIX) + ENVELOPE_V3_PUBLIC_LEN
    nonce_start = key_id_start + ENVELOPE_V2_KEY_ID_LEN
    ephemeral_public = sealed[len(ENVELOPE_V3_PREFIX) : key_id_start]
    key_id = sealed[key_id_start:nonce_start]
    nonce = sealed[nonce_start:ENVELOPE_V3_HEADER_LEN]
    inspected = run(["inspect"], sealed)
    assert inspected.returncode == 0, inspected.stderr.decode("utf-8", "replace")
    assert key_id == hashlib.sha256(recipient_public).digest()[:16]
    assert inspected.stdout == (
        b"version: 3\n"
        b"algorithm: 1\n"
        b"header-length: 68\n"
        + b"ephemeral-public: " + ephemeral_public.hex().encode("ascii") + b"\n"
        + b"key-id: " + key_id.hex().encode("ascii") + b"\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
    )


def assert_manifest_v3(sealed: bytes, recipient_public: bytes) -> None:
    key_id_start = len(ENVELOPE_V3_PREFIX) + ENVELOPE_V3_PUBLIC_LEN
    nonce_start = key_id_start + ENVELOPE_V2_KEY_ID_LEN
    ephemeral_public = sealed[len(ENVELOPE_V3_PREFIX) : key_id_start]
    key_id = sealed[key_id_start:nonce_start]
    nonce = sealed[nonce_start:ENVELOPE_V3_HEADER_LEN]
    ciphertext = sealed[ENVELOPE_V3_HEADER_LEN:-ENVELOPE_TAG_LEN]
    ciphertext_len = len(sealed) - ENVELOPE_V3_HEADER_LEN - ENVELOPE_TAG_LEN
    tag = sealed[-ENVELOPE_TAG_LEN:]
    manifested = run(["manifest"], sealed)
    assert manifested.returncode == 0, manifested.stderr.decode("utf-8", "replace")
    assert key_id == hashlib.sha256(recipient_public).digest()[:16]
    assert manifested.stdout == (
        b"version: 3\n"
        b"algorithm: 1\n"
        b"header-length: 68\n"
        + b"ephemeral-public: " + ephemeral_public.hex().encode("ascii") + b"\n"
        + b"key-id: " + key_id.hex().encode("ascii") + b"\n"
        + b"artifact-sha256: "
        + hashlib.sha256(sealed).hexdigest().encode("ascii")
        + b"\n"
        + b"ciphertext-length: " + str(ciphertext_len).encode("ascii") + b"\n"
        + b"ciphertext-sha256: "
        + hashlib.sha256(ciphertext).hexdigest().encode("ascii")
        + b"\n"
        + b"nonce: " + nonce.hex().encode("ascii") + b"\n"
        + b"tag: " + tag.hex().encode("ascii") + b"\n"
    )


def assert_open_to_rejects(private_key: bytes, sealed: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        sealed_path = tmp / "sealed.wj"
        opened_path = tmp / "opened.bin"
        sealed_path.write_bytes(sealed)

        rejected = run(
            ["open-to", private_key.hex(), str(sealed_path), str(opened_path)]
        )
        assert rejected.returncode != 0
        assert rejected.stdout == b""
        assert not opened_path.exists()


def assert_recipient_workflow(plaintext: bytes) -> bytes:
    private_key, public_key = generate_keypair()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        plain_path = tmp / "plain.bin"
        sealed_path = tmp / "sealed-v3.wj"
        opened_path = tmp / "opened.bin"
        plain_path.write_bytes(plaintext)

        sealed_proc = run(
            ["seal-to", public_key.hex(), str(plain_path), str(sealed_path)]
        )
        assert sealed_proc.returncode == 0, sealed_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert sealed_proc.stdout == b""

        sealed = sealed_path.read_bytes()
        assert sealed.startswith(ENVELOPE_V3_PREFIX)
        assert len(sealed) == ENVELOPE_V3_HEADER_LEN + len(plaintext) + ENVELOPE_TAG_LEN

        key_id_start = len(ENVELOPE_V3_PREFIX) + ENVELOPE_V3_PUBLIC_LEN
        nonce_start = key_id_start + ENVELOPE_V2_KEY_ID_LEN
        header = sealed[:ENVELOPE_V3_HEADER_LEN]
        ephemeral_public = sealed[len(ENVELOPE_V3_PREFIX) : key_id_start]
        key_id = sealed[key_id_start:nonce_start]
        nonce = sealed[nonce_start:ENVELOPE_V3_HEADER_LEN]
        body = sealed[ENVELOPE_V3_HEADER_LEN:]

        assert ephemeral_public != b"\0" * ENVELOPE_V3_PUBLIC_LEN
        assert key_id == hashlib.sha256(public_key).digest()[:16]
        assert len(nonce) == 12
        shared_secret = x25519_ref(
            private_key,
            int.from_bytes(ephemeral_public, "little"),
        )
        v3_key = hkdf_sha256_ref(hashlib.sha256(header).digest(), shared_secret, V3_HKDF_INFO)
        assert body == aead_seal_ref(v3_key, nonce, plaintext, header)

        assert_inspect_v3(sealed, public_key)
        assert_manifest_v3(sealed, public_key)

        opened = run(
            ["open-to", private_key.hex(), str(sealed_path), str(opened_path)]
        )
        assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
        assert opened.stdout == b""
        assert opened_path.read_bytes() == plaintext

        wrong_private, _ = generate_keypair()
        assert_open_to_rejects(wrong_private, sealed)

        tamper_offsets = [
            len(ENVELOPE_V3_PREFIX),
            key_id_start,
            nonce_start,
            ENVELOPE_V3_HEADER_LEN,
            len(sealed) - 1,
        ]
        for offset in tamper_offsets:
            tampered = bytearray(sealed)
            tampered[offset] ^= 1
            assert_open_to_rejects(private_key, bytes(tampered))

        existing_sealed_path = tmp / "existing-sealed.wj"
        existing_sealed_path.write_bytes(b"do-not-touch")
        rejected_seal = run(
            [
                "seal-to",
                public_key.hex(),
                str(plain_path),
                str(existing_sealed_path),
            ]
        )
        assert rejected_seal.returncode != 0
        assert rejected_seal.stdout == b""
        assert existing_sealed_path.read_bytes() == b"do-not-touch"

        existing_open_path = tmp / "existing-open.bin"
        existing_open_path.write_bytes(b"do-not-touch")
        rejected_open = run(
            ["open-to", private_key.hex(), str(sealed_path), str(existing_open_path)]
        )
        assert rejected_open.returncode != 0
        assert rejected_open.stdout == b""
        assert existing_open_path.read_bytes() == b"do-not-touch"

        missing_out_path = tmp / "missing-seal.wj"
        rejected_missing = run(
            [
                "seal-to",
                public_key.hex(),
                str(tmp / "missing.bin"),
                str(missing_out_path),
            ]
        )
        assert rejected_missing.returncode != 0
        assert rejected_missing.stdout == b""
        assert not missing_out_path.exists()

        small_order_points = [
            "00" * 32,
            "01" + "00" * 31,
            "e0eb7a7c3b41b8ae1656e3faf19fc46a"
            "da098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b"
            "04445cc4581c8e86d8224eddd09f1157",
            "ec" + "ff" * 30 + "7f",
            "ed" + "ff" * 30 + "7f",
            "ee" + "ff" * 30 + "7f",
            "ee" + "ff" * 30 + "ff",
        ]
        for index, small_order_public in enumerate(small_order_points):
            small_order_path = tmp / f"small-order-{index}.wj"
            rejected_small_order = run(
                ["seal-to", small_order_public, str(plain_path), str(small_order_path)]
            )
            assert rejected_small_order.returncode != 0
            assert rejected_small_order.stdout == b""
            assert not small_order_path.exists()

        return sealed


def assert_rejects_inspect(sealed: bytes) -> None:
    rejected = run(["inspect"], sealed)
    assert rejected.returncode != 0
    assert rejected.stdout == b""


def assert_rejects_manifest(sealed: bytes) -> None:
    rejected = run(["manifest"], sealed)
    assert rejected.returncode != 0
    assert rejected.stdout == b""


def assert_artifact_file_commands(
    sealed_v1: bytes,
    sealed_v2: bytes,
    sealed_v3: bytes,
) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        v1_path = tmp / "artifact-v1.wj"
        v2_path = tmp / "artifact-v2.wj"
        v3_path = tmp / "artifact-v3.wj"
        bad_path = tmp / "artifact-bad.wj"
        short_path = tmp / "artifact-short.wj"
        short_v3_path = tmp / "artifact-short-v3.wj"
        missing_path = tmp / "missing.wj"

        v1_path.write_bytes(sealed_v1)
        v2_path.write_bytes(sealed_v2)
        v3_path.write_bytes(sealed_v3)
        bad_path.write_bytes(b"BADSEAL\x01" + sealed_v1[len(ENVELOPE_PREFIX) :])
        short_path.write_bytes(sealed_v2[: ENVELOPE_V2_HEADER_LEN - 1])
        short_v3_path.write_bytes(sealed_v3[: ENVELOPE_V3_HEADER_LEN - 1])

        for stdin_command, file_command in (
            ("inspect", "inspect-file"),
            ("manifest", "manifest-file"),
        ):
            for sealed, artifact_path in (
                (sealed_v1, v1_path),
                (sealed_v2, v2_path),
                (sealed_v3, v3_path),
            ):
                expected = run([stdin_command], sealed)
                actual = run([file_command, str(artifact_path)])
                assert expected.returncode == 0, expected.stderr.decode(
                    "utf-8", "replace"
                )
                assert actual.returncode == 0, actual.stderr.decode(
                    "utf-8", "replace"
                )
                assert actual.stdout == expected.stdout

            for artifact_path in (missing_path, bad_path, short_path, short_v3_path):
                rejected = run([file_command, str(artifact_path)])
                assert rejected.returncode != 0
                assert rejected.stdout == b""


def assert_ascii_armor_file_commands(payload: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        artifact_path = tmp / "artifact.wj"
        armor_path = tmp / "artifact.wj.asc"
        decoded_path = tmp / "decoded.wj"
        artifact_path.write_bytes(payload)

        armored = run(["armor-file", str(artifact_path), str(armor_path)])
        assert armored.returncode == 0, armored.stderr.decode("utf-8", "replace")
        assert armored.stdout == b""

        armor = armor_path.read_bytes()
        lines = armor.splitlines()
        assert lines[0] == ARMOR_HEADER
        assert lines[-1] == ARMOR_FOOTER
        assert lines[1:-1]
        for line in lines[1:-1]:
            assert len(line) <= 64
        assert b"".join(lines[1:-1]) == base64.b64encode(payload)

        decoded = run(["dearmor-file", str(armor_path), str(decoded_path)])
        assert decoded.returncode == 0, decoded.stderr.decode("utf-8", "replace")
        assert decoded.stdout == b""
        assert decoded_path.read_bytes() == payload

        whitespace_path = tmp / "whitespace.asc"
        whitespace_decoded_path = tmp / "whitespace-decoded.wj"
        whitespace_path.write_bytes(armor.replace(b"\n", b"\r\n") + b" \t\n")
        whitespace_decoded = run(
            ["dearmor-file", str(whitespace_path), str(whitespace_decoded_path)]
        )
        assert whitespace_decoded.returncode == 0, whitespace_decoded.stderr.decode(
            "utf-8", "replace"
        )
        assert whitespace_decoded.stdout == b""
        assert whitespace_decoded_path.read_bytes() == payload

        existing_armor_path = tmp / "existing.asc"
        existing_armor_path.write_bytes(b"do-not-touch")
        rejected_armor = run(
            ["armor-file", str(artifact_path), str(existing_armor_path)]
        )
        assert rejected_armor.returncode != 0
        assert rejected_armor.stdout == b""
        assert existing_armor_path.read_bytes() == b"do-not-touch"

        existing_decoded_path = tmp / "existing-decoded.wj"
        existing_decoded_path.write_bytes(b"do-not-touch")
        rejected_dearmor = run(
            ["dearmor-file", str(armor_path), str(existing_decoded_path)]
        )
        assert rejected_dearmor.returncode != 0
        assert rejected_dearmor.stdout == b""
        assert existing_decoded_path.read_bytes() == b"do-not-touch"

        missing_armor_path = tmp / "missing.asc"
        rejected_missing = run(
            ["armor-file", str(tmp / "missing.wj"), str(missing_armor_path)]
        )
        assert rejected_missing.returncode != 0
        assert rejected_missing.stdout == b""
        assert not missing_armor_path.exists()

        malformed_cases = [
            b"BAD\n" + b"\n".join(lines[1:]),
            armor.replace(lines[1][:1], b"!", 1),
            b"\n".join(lines[:-1]) + b"\n",
            ARMOR_HEADER + b"\nAA=A\n" + ARMOR_FOOTER + b"\n",
            ARMOR_HEADER + b"\nA\n" + ARMOR_FOOTER + b"\n",
        ]
        for index, malformed in enumerate(malformed_cases):
            malformed_path = tmp / f"malformed-{index}.asc"
            malformed_out_path = tmp / f"malformed-{index}.wj"
            malformed_path.write_bytes(malformed)
            rejected = run(
                ["dearmor-file", str(malformed_path), str(malformed_out_path)]
            )
            assert rejected.returncode != 0
            assert rejected.stdout == b""
            assert not malformed_out_path.exists()


def assert_rejects_envelope(key: bytes, sealed: bytes) -> None:
    rejected = run(["open", key.hex()], sealed)
    assert rejected.returncode != 0
    assert rejected.stdout == b""


def assert_keyfile_workflow(plaintext: bytes) -> None:
    keygen = run(["keygen"])
    assert keygen.returncode == 0, keygen.stderr.decode("utf-8", "replace")
    assert len(keygen.stdout) == 65
    assert keygen.stdout.endswith(b"\n")

    key_hex = keygen.stdout.strip()
    key = bytes.fromhex(key_hex.decode("ascii"))
    assert len(key) == 32

    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = Path(tmp_dir) / "wuci.key"
        key_path.write_bytes(keygen.stdout)

        sealed = run(["seal-keyfile", str(key_path)], plaintext)
        assert sealed.returncode == 0, sealed.stderr.decode("utf-8", "replace")
        assert sealed.stdout.startswith(ENVELOPE_PREFIX)

        nonce = sealed.stdout[len(ENVELOPE_PREFIX) : ENVELOPE_HEADER_LEN]
        body = sealed.stdout[ENVELOPE_HEADER_LEN:]
        assert body == aead_seal_ref(key, nonce, plaintext)

        opened = run(["open-keyfile", str(key_path)], sealed.stdout)
        assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
        assert opened.stdout == plaintext

        raw_key_path = Path(tmp_dir) / "wuci-raw.key"
        raw_key_path.write_bytes(key_hex)
        raw_opened = run(["open-keyfile", str(raw_key_path)], sealed.stdout)
        assert raw_opened.returncode == 0, raw_opened.stderr.decode("utf-8", "replace")
        assert raw_opened.stdout == plaintext

        key_id = bytes.fromhex("00112233445566778899aabbccddeeff")
        sealed_v2 = run(["seal-keyfile-v2", str(key_path), key_id.hex()], plaintext)
        assert sealed_v2.returncode == 0, sealed_v2.stderr.decode("utf-8", "replace")
        assert sealed_v2.stdout.startswith(ENVELOPE_V2_PREFIX)
        key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
        assert sealed_v2.stdout[len(ENVELOPE_V2_PREFIX) : key_id_end] == key_id

        opened_v2 = run(["open-keyfile", str(key_path)], sealed_v2.stdout)
        assert opened_v2.returncode == 0, opened_v2.stderr.decode("utf-8", "replace")
        assert opened_v2.stdout == plaintext

        bad_key_path = Path(tmp_dir) / "bad.key"
        bad_key_path.write_bytes(key_hex + b"\nextra")
        rejected = run(["seal-keyfile", str(bad_key_path)], plaintext)
        assert rejected.returncode != 0
        assert rejected.stdout == b""


def assert_keyfile_file_workflow(plaintext: bytes, key_id: bytes) -> None:
    keygen = run(["keygen"])
    assert keygen.returncode == 0, keygen.stderr.decode("utf-8", "replace")
    key_hex = keygen.stdout.strip()
    key = bytes.fromhex(key_hex.decode("ascii"))

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        key_path = tmp / "wuci.key"
        plain_path = tmp / "plain.bin"
        sealed_path = tmp / "sealed-keyfile.wj"
        opened_path = tmp / "opened-keyfile.bin"
        key_path.write_bytes(keygen.stdout)
        plain_path.write_bytes(plaintext)

        sealed_proc = run(
            ["seal-file-keyfile", str(key_path), str(plain_path), str(sealed_path)]
        )
        assert sealed_proc.returncode == 0, sealed_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert sealed_proc.stdout == b""
        sealed = sealed_path.read_bytes()
        assert sealed.startswith(ENVELOPE_PREFIX)

        opened = run(
            ["open-file-keyfile", str(key_path), str(sealed_path), str(opened_path)]
        )
        assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
        assert opened.stdout == b""
        assert opened_path.read_bytes() == plaintext

        direct_open = run(["open", key.hex()], sealed)
        assert direct_open.returncode == 0, direct_open.stderr.decode(
            "utf-8", "replace"
        )
        assert direct_open.stdout == plaintext

        sealed_v2_path = tmp / "sealed-keyfile-v2.wj"
        opened_v2_path = tmp / "opened-keyfile-v2.bin"
        sealed_v2_proc = run(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                key_id.hex(),
                str(plain_path),
                str(sealed_v2_path),
            ]
        )
        assert sealed_v2_proc.returncode == 0, sealed_v2_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert sealed_v2_proc.stdout == b""
        sealed_v2 = sealed_v2_path.read_bytes()
        key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
        assert sealed_v2.startswith(ENVELOPE_V2_PREFIX)
        assert sealed_v2[len(ENVELOPE_V2_PREFIX) : key_id_end] == key_id

        opened_v2 = run(
            [
                "open-file-keyfile",
                str(key_path),
                str(sealed_v2_path),
                str(opened_v2_path),
            ]
        )
        assert opened_v2.returncode == 0, opened_v2.stderr.decode(
            "utf-8", "replace"
        )
        assert opened_v2.stdout == b""
        assert opened_v2_path.read_bytes() == plaintext

        existing_path = tmp / "existing.wj"
        existing_path.write_bytes(b"do-not-touch")
        rejected_seal = run(
            ["seal-file-keyfile", str(key_path), str(plain_path), str(existing_path)]
        )
        assert rejected_seal.returncode != 0
        assert rejected_seal.stdout == b""
        assert existing_path.read_bytes() == b"do-not-touch"

        rejected_seal_v2 = run(
            [
                "seal-file-keyfile-v2",
                str(key_path),
                key_id.hex(),
                str(plain_path),
                str(existing_path),
            ]
        )
        assert rejected_seal_v2.returncode != 0
        assert rejected_seal_v2.stdout == b""
        assert existing_path.read_bytes() == b"do-not-touch"

        existing_open_path = tmp / "existing-open.bin"
        existing_open_path.write_bytes(b"do-not-touch")
        rejected_open = run(
            [
                "open-file-keyfile",
                str(key_path),
                str(sealed_path),
                str(existing_open_path),
            ]
        )
        assert rejected_open.returncode != 0
        assert rejected_open.stdout == b""
        assert existing_open_path.read_bytes() == b"do-not-touch"


def assert_file_seal_open_workflow(
    key: bytes,
    key_id: bytes,
    plaintext: bytes,
    v2_sealed: bytes,
    v2_plaintext: bytes,
) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        plain_path = tmp / "plain.bin"
        sealed_path = tmp / "sealed.wj"
        opened_path = tmp / "opened.bin"
        plain_path.write_bytes(plaintext)

        sealed_proc = run(
            ["seal-file", key.hex(), str(plain_path), str(sealed_path)]
        )
        assert sealed_proc.returncode == 0, sealed_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert sealed_proc.stdout == b""
        sealed = sealed_path.read_bytes()
        assert sealed.startswith(ENVELOPE_PREFIX)
        assert len(sealed) == ENVELOPE_HEADER_LEN + len(plaintext) + ENVELOPE_TAG_LEN

        opened = run(["open", key.hex()], sealed)
        assert opened.returncode == 0, opened.stderr.decode("utf-8", "replace")
        assert opened.stdout == plaintext

        opened_proc = run(
            ["open-file", key.hex(), str(sealed_path), str(opened_path)]
        )
        assert opened_proc.returncode == 0, opened_proc.stderr.decode(
            "utf-8", "replace"
        )
        assert opened_proc.stdout == b""
        assert opened_path.read_bytes() == plaintext

        v2_path = tmp / "sealed-v2.wj"
        v2_opened_path = tmp / "opened-v2.bin"
        v2_path.write_bytes(v2_sealed)
        v2_opened = run(
            ["open-file", key.hex(), str(v2_path), str(v2_opened_path)]
        )
        assert v2_opened.returncode == 0, v2_opened.stderr.decode(
            "utf-8", "replace"
        )
        assert v2_opened.stdout == b""
        assert v2_opened_path.read_bytes() == v2_plaintext

        v2_created_path = tmp / "created-v2.wj"
        v2_created_open_path = tmp / "created-v2-open.bin"
        v2_created = run(
            [
                "seal-file-v2",
                key.hex(),
                key_id.hex(),
                str(plain_path),
                str(v2_created_path),
            ]
        )
        assert v2_created.returncode == 0, v2_created.stderr.decode(
            "utf-8", "replace"
        )
        assert v2_created.stdout == b""
        v2_created_bytes = v2_created_path.read_bytes()
        key_id_end = len(ENVELOPE_V2_PREFIX) + ENVELOPE_V2_KEY_ID_LEN
        assert v2_created_bytes.startswith(ENVELOPE_V2_PREFIX)
        assert v2_created_bytes[len(ENVELOPE_V2_PREFIX) : key_id_end] == key_id
        assert len(v2_created_bytes) == (
            ENVELOPE_V2_HEADER_LEN + len(plaintext) + ENVELOPE_TAG_LEN
        )

        v2_created_opened = run(
            ["open-file", key.hex(), str(v2_created_path), str(v2_created_open_path)]
        )
        assert v2_created_opened.returncode == 0, v2_created_opened.stderr.decode(
            "utf-8", "replace"
        )
        assert v2_created_opened.stdout == b""
        assert v2_created_open_path.read_bytes() == plaintext

        existing_sealed_path = tmp / "existing-sealed.wj"
        existing_sealed_path.write_bytes(b"do-not-touch")
        rejected_seal = run(
            ["seal-file", key.hex(), str(plain_path), str(existing_sealed_path)]
        )
        assert rejected_seal.returncode != 0
        assert rejected_seal.stdout == b""
        assert existing_sealed_path.read_bytes() == b"do-not-touch"

        rejected_seal_v2 = run(
            [
                "seal-file-v2",
                key.hex(),
                key_id.hex(),
                str(plain_path),
                str(existing_sealed_path),
            ]
        )
        assert rejected_seal_v2.returncode != 0
        assert rejected_seal_v2.stdout == b""
        assert existing_sealed_path.read_bytes() == b"do-not-touch"

        existing_open_path = tmp / "existing-open.bin"
        existing_open_path.write_bytes(b"do-not-touch")
        rejected_open = run(
            ["open-file", key.hex(), str(sealed_path), str(existing_open_path)]
        )
        assert rejected_open.returncode != 0
        assert rejected_open.stdout == b""
        assert existing_open_path.read_bytes() == b"do-not-touch"

        bad_path = tmp / "bad.wj"
        bad_out_path = tmp / "bad-open.bin"
        bad_path.write_bytes(sealed[:-1] + bytes([sealed[-1] ^ 1]))
        rejected_bad = run(
            ["open-file", key.hex(), str(bad_path), str(bad_out_path)]
        )
        assert rejected_bad.returncode != 0
        assert rejected_bad.stdout == b""
        assert not bad_out_path.exists()

        missing_out_path = tmp / "missing-seal.wj"
        rejected_missing = run(
            ["seal-file", key.hex(), str(tmp / "missing.bin"), str(missing_out_path)]
        )
        assert rejected_missing.returncode != 0
        assert rejected_missing.stdout == b""
        assert not missing_out_path.exists()


def assert_rejects_extra_args(key: bytes, key_id: bytes, sealed: bytes) -> None:
    private_key, public_key = generate_keypair()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        key_path = tmp / "wuci.key"
        plain_path = tmp / "plain.bin"
        artifact_path = tmp / "sealed.wj"
        key_path.write_text(key.hex() + "\n", encoding="ascii")
        plain_path.write_bytes(b"extra-arg-plain")
        artifact_path.write_bytes(sealed)

        seal_file_out = tmp / "extra-seal.wj"
        seal_file_v2_out = tmp / "extra-seal-v2.wj"
        seal_file_keyfile_out = tmp / "extra-seal-keyfile.wj"
        seal_file_keyfile_v2_out = tmp / "extra-seal-keyfile-v2.wj"
        seal_to_out = tmp / "extra-seal-to.wj"
        open_file_out = tmp / "extra-open.bin"
        open_file_keyfile_out = tmp / "extra-open-keyfile.bin"
        open_to_out = tmp / "extra-open-to.bin"
        armor_out = tmp / "extra-armor.asc"
        dearmor_out = tmp / "extra-dearmor.wj"

        cases = [
            (["--help", "extra"], b"", None),
            (["sha256", "extra"], b"abc", None),
            (["frost-p256-h1", "extra"], b"abc", None),
            (["frost-p256-h2", "extra"], b"abc", None),
            (["frost-p256-h3", "extra"], b"abc", None),
            (["frost-p256-h4", "extra"], b"abc", None),
            (["frost-p256-h5", "extra"], b"abc", None),
            (["frost-secp256k1-h1", "extra"], b"abc", None),
            (["frost-secp256k1-h2", "extra"], b"abc", None),
            (["frost-secp256k1-h3", "extra"], b"abc", None),
            (["frost-secp256k1-h4", "extra"], b"abc", None),
            (["frost-secp256k1-h5", "extra"], b"abc", None),
            (["secp256k1-scalar-add", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-scalar-sub", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-scalar-mul", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-scalar-inv", key.hex(), "extra"], b"", None),
            (
                ["frost-secp256k1-lagrange", "01".zfill(64), "01".zfill(64), "extra"],
                b"",
                None,
            ),
            (["frost-secp256k1-nonce-generate", "01".zfill(64), "extra"], b"", None),
            (
                ["frost-secp256k1-commit", "01".zfill(64), "02".zfill(64), "extra"],
                b"",
                None,
            ),
            (
                [
                    "frost-secp256k1-commitment-hash",
                    "01".zfill(64),
                    "02" + key.hex(),
                    "02" + key.hex(),
                    "extra",
                ],
                b"",
                None,
            ),
            (
                [
                    "frost-secp256k1-binding-factor",
                    "02" + key.hex(),
                    key.hex(),
                    key.hex(),
                    "01".zfill(64),
                    "extra",
                ],
                b"",
                None,
            ),
            (
                [
                    "frost-secp256k1-group-commitment",
                    "01".zfill(64),
                    "02" + key.hex(),
                    "02" + key.hex(),
                    "03".zfill(64),
                    "extra",
                ],
                b"",
                None,
            ),
            (
                ["frost-secp256k1-challenge", "02" + key.hex(), "02" + key.hex(), "extra"],
                b"",
                None,
            ),
            (
                [
                    "frost-secp256k1-signing-share",
                    "01".zfill(64),
                    "02".zfill(64),
                    "03".zfill(64),
                    "04".zfill(64),
                    "05".zfill(64),
                    "06".zfill(64),
                    "extra",
                ],
                b"",
                None,
            ),
            (
                ["frost-secp256k1-aggregate", "02" + key.hex(), "01".zfill(64), "extra"],
                b"",
                None,
            ),
            (
                [
                    "frost-secp256k1-verify",
                    "02" + key.hex(),
                    "02" + key.hex(),
                    "01".zfill(64),
                    "02".zfill(64),
                    "extra",
                ],
                b"",
                None,
            ),
            (["secp256k1-field-add", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-field-sub", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-field-mul", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-field-square", key.hex(), "extra"], b"", None),
            (["secp256k1-field-inv", key.hex(), "extra"], b"", None),
            (["secp256k1-point-validate", key.hex(), key.hex(), "extra"], b"", None),
            (["secp256k1-point-double", key.hex(), key.hex(), "extra"], b"", None),
            (
                ["secp256k1-point-add", key.hex(), key.hex(), key.hex(), key.hex(), "extra"],
                b"",
                None,
            ),
            (["secp256k1-basepoint-mul", key.hex(), "extra"], b"", None),
            (["secp256k1-jacobian-double", key.hex(), key.hex(), key.hex(), "extra"], b"", None),
            (
                [
                    "secp256k1-jacobian-mixed-add",
                    key.hex(),
                    key.hex(),
                    key.hex(),
                    key.hex(),
                    key.hex(),
                    "extra",
                ],
                b"",
                None,
            ),
            (["secp256k1-projective-basepoint-mul", key.hex(), "extra"], b"", None),
            (
                ["secp256k1-point-encode-compressed", key.hex(), key.hex(), "extra"],
                b"",
                None,
            ),
            (
                ["secp256k1-point-encode-uncompressed", key.hex(), key.hex(), "extra"],
                b"",
                None,
            ),
            (["secp256k1-point-decode", ("02" + key.hex()), "extra"], b"", None),
            (["keygen", "extra"], b"", None),
            (["keypair", "extra"], b"", None),
            (["selftest", "extra"], b"", None),
            (["hmac-sha256", key.hex(), "extra"], b"abc", None),
            (["seal", key.hex(), "extra"], b"abc", None),
            (
                ["seal-file", key.hex(), str(plain_path), str(seal_file_out), "extra"],
                b"",
                seal_file_out,
            ),
            (
                [
                    "seal-file-v2",
                    key.hex(),
                    key_id.hex(),
                    str(plain_path),
                    str(seal_file_v2_out),
                    "extra",
                ],
                b"",
                seal_file_v2_out,
            ),
            (
                [
                    "seal-file-keyfile",
                    str(key_path),
                    str(plain_path),
                    str(seal_file_keyfile_out),
                    "extra",
                ],
                b"",
                seal_file_keyfile_out,
            ),
            (
                [
                    "seal-file-keyfile-v2",
                    str(key_path),
                    key_id.hex(),
                    str(plain_path),
                    str(seal_file_keyfile_v2_out),
                    "extra",
                ],
                b"",
                seal_file_keyfile_v2_out,
            ),
            (
                [
                    "seal-to",
                    public_key.hex(),
                    str(plain_path),
                    str(seal_to_out),
                    "extra",
                ],
                b"",
                seal_to_out,
            ),
            (["open", key.hex(), "extra"], sealed, None),
            (
                [
                    "open-file",
                    key.hex(),
                    str(artifact_path),
                    str(open_file_out),
                    "extra",
                ],
                b"",
                open_file_out,
            ),
            (
                [
                    "open-file-keyfile",
                    str(key_path),
                    str(artifact_path),
                    str(open_file_keyfile_out),
                    "extra",
                ],
                b"",
                open_file_keyfile_out,
            ),
            (
                [
                    "open-to",
                    private_key.hex(),
                    str(artifact_path),
                    str(open_to_out),
                    "extra",
                ],
                b"",
                open_to_out,
            ),
            (["inspect", "extra"], sealed, None),
            (["inspect-file", str(artifact_path), "extra"], b"", None),
            (["manifest", "extra"], sealed, None),
            (["manifest-file", str(artifact_path), "extra"], b"", None),
            (
                ["armor-file", str(artifact_path), str(armor_out), "extra"],
                b"",
                armor_out,
            ),
            (
                ["dearmor-file", str(artifact_path), str(dearmor_out), "extra"],
                b"",
                dearmor_out,
            ),
            (["seal-keyfile", str(key_path), "extra"], b"abc", None),
            (["open-keyfile", str(key_path), "extra"], sealed, None),
            (["aead-seal", key.hex(), "00" * 12, "extra"], b"abc", None),
        ]

        for args, data, output_path in cases:
            rejected = run(args, data)
            assert rejected.returncode != 0, args
            assert rejected.stdout == b"", args
            if output_path is not None:
                assert not output_path.exists(), args


def assert_help_output() -> None:
    help_proc = run(["--help"])
    assert help_proc.returncode == 0, help_proc.stderr.decode("utf-8", "replace")
    help_text = help_proc.stdout.decode("ascii")

    for snippet in (
        "frost-p256-h1                  RFC9591 FROST(P-256,SHA-256) H1(rho) scalar over stdin",
        "frost-p256-h2                  RFC9591 FROST(P-256,SHA-256) H2(chal) scalar over stdin",
        "frost-p256-h3                  RFC9591 FROST(P-256,SHA-256) H3(nonce) scalar over stdin",
        "frost-p256-h4                  RFC9591 FROST(P-256,SHA-256) H4(msg) over stdin",
        "frost-p256-h5                  RFC9591 FROST(P-256,SHA-256) H5(com) over stdin",
        "frost-secp256k1-h1             RFC9591 FROST(secp256k1,SHA-256) H1(rho) scalar over stdin",
        "frost-secp256k1-h2             RFC9591 FROST(secp256k1,SHA-256) H2(chal) scalar over stdin",
        "frost-secp256k1-h3             RFC9591 FROST(secp256k1,SHA-256) H3(nonce) scalar over stdin",
        "frost-secp256k1-h4             RFC9591 FROST(secp256k1,SHA-256) H4(msg) over stdin",
        "frost-secp256k1-h5             RFC9591 FROST(secp256k1,SHA-256) H5(com) over stdin",
        "secp256k1-scalar-add <a> <b>   add 32-byte hex scalars modulo group order",
        "secp256k1-scalar-sub <a> <b>   subtract 32-byte hex scalars modulo group order",
        "secp256k1-scalar-mul <a> <b>   multiply 32-byte hex scalars modulo group order",
        "secp256k1-scalar-inv <a>       invert a nonzero scalar modulo group order",
        "frost-secp256k1-lagrange <i> <id...> derive RFC9591 interpolation scalar",
        "frost-secp256k1-nonce-generate <secret> derive one RFC9591 nonce with fresh randomness",
        "frost-secp256k1-commit <hiding> <binding> derive compressed round-one commitments",
        "frost-secp256k1-commitment-hash <id D E>... hash sorted commitment triples",
        "frost-secp256k1-binding-factor <PK> <H4> <H5> <id> derive one binding factor",
        "frost-secp256k1-group-commitment <id D E rho>... aggregate group commitment",
        "frost-secp256k1-challenge <R> <PK> derive H2 challenge over R, PK, and stdin",
        "frost-secp256k1-signing-share <d> <e> <rho> <lambda> <share> <c> derive z_i",
        "frost-secp256k1-aggregate <R> <z...> aggregate signature shares",
        "frost-secp256k1-verify <R> <PK> <z> <c> verify z*G = R + c*PK",
        "secp256k1-field-add <a> <b>    add 32-byte hex field elements modulo p",
        "secp256k1-field-sub <a> <b>    subtract 32-byte hex field elements modulo p",
        "secp256k1-field-mul <a> <b>    multiply 32-byte hex field elements modulo p",
        "secp256k1-field-square <a>     square a 32-byte hex field element modulo p",
        "secp256k1-field-inv <a>        invert a 32-byte hex field element modulo p",
        "secp256k1-point-validate <x> <y> validate affine point coordinates",
        "secp256k1-point-double <x> <y> double an affine point; prints x/y or infinity",
        "secp256k1-point-add <x1> <y1> <x2> <y2> add affine points; prints x/y or infinity",
        "secp256k1-basepoint-mul <k>    multiply the secp256k1 basepoint by a 32-byte hex scalar",
        "secp256k1-jacobian-double <x> <y> <z> double a Jacobian point; prints x/y/z or infinity",
        "secp256k1-jacobian-mixed-add <jx> <jy> <jz> <ax> <ay> add Jacobian and affine points",
        "secp256k1-projective-basepoint-mul <k> multiply the basepoint with Jacobian intermediates",
        "secp256k1-point-encode-compressed <x> <y> encode affine point as SEC1 compressed hex",
        "secp256k1-point-encode-uncompressed <x> <y> encode affine point as SEC1 uncompressed hex",
        "secp256k1-point-decode <point> decode SEC1 compressed or uncompressed hex point",
        "keypair                        write random X25519 private/public keys as hex",
        "seal-to <public> <in> <out>    seal v3 file to X25519 public key; no overwrite",
        "seal-file <key> <in> <out>",
        "seal-file-v2 <key> <key-id> <in> <out>",
        "seal-file-keyfile <path> <in> <out>",
        "seal-file-keyfile-v2 <path> <key-id> <in> <out>",
        "open-to <private> <in> <out>   open v3 file with X25519 private key; no overwrite",
        "open-file <key> <in> <out>",
        "open-file-keyfile <path> <in> <out>",
        "manifest                       print metadata, SHA-256 fingerprints, and tag",
        "manifest-file <path>           print file metadata, SHA-256 fingerprints, and tag",
        "armor-file <in> <out>          wrap an artifact in copy/paste ASCII armor; no overwrite",
        "dearmor-file <in> <out>        decode copy/paste ASCII armor; no overwrite",
        "selftest                       run built-in known-answer tests",
    ):
        assert snippet in help_text, snippet


def main() -> None:
    selftest = run(["selftest"])
    assert selftest.returncode == 0, selftest.stderr.decode("utf-8", "replace")
    assert selftest.stdout == b"wuci-ji selftest: PASS\n"
    assert_help_output()

    assert_sha256(b"")
    assert_sha256(b"abc")
    assert_sha256(b"a" * 55)
    assert_sha256(b"a" * 56)
    assert_sha256(b"a" * 57)
    assert_sha256(b"a" * 64)
    assert_sha256(b"a" * 65)
    assert_sha256((b"wuci-ji\0" * 8192) + b"end")
    assert_frost_hash_to_scalar_helpers(b"")
    assert_frost_hash_to_scalar_helpers(b"abc")
    assert_frost_hash_to_scalar_helpers((b"frost-transcript\0" * 4096) + b"end")
    assert_frost_sha256_helpers(b"")
    assert_frost_sha256_helpers(b"abc")
    assert_frost_sha256_helpers((b"frost-transcript\0" * 4096) + b"end")
    assert_secp256k1_scalar_helpers()
    assert_secp256k1_scalar_rejects_invalid()
    assert_frost_lagrange_helpers()
    assert_frost_nonce_generate_helper()
    assert_frost_commit_helpers()
    assert_frost_binding_group_helpers()
    assert_frost_challenge_helper()
    assert_frost_signing_share_helper()
    assert_frost_aggregate_helper()
    assert_frost_verify_helper()
    assert_frost_end_to_end_cli_flow()
    assert_secp256k1_field_helpers()
    assert_secp256k1_field_rejects_invalid()
    assert_secp256k1_point_helpers()
    assert_secp256k1_point_rejects_invalid()

    key = bytes(range(32))
    assert_hmac_sha256(key, b"")
    assert_hmac_sha256(key, b"Hi There")
    assert_hmac_sha256(key, (b"authenticated-data\0" * 4096) + b"end")

    salt = bytes(range(32, 64))
    info = bytes(range(64, 96))
    assert_hkdf_sha256(salt, info, b"")
    assert_hkdf_sha256(salt, info, b"abc")
    assert_hkdf_sha256(salt, info, (b"ikm-material\0" * 4096) + b"end")

    poly_key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    poly_msg = b"Cryptographic Forum Research Group"
    poly_tag = assert_poly1305(poly_key, poly_msg)
    assert poly_tag == bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")
    assert_poly1305(poly_key, b"")
    assert_poly1305(poly_key, b"a" * 15)
    assert_poly1305(poly_key, b"a" * 16)
    assert_poly1305(poly_key, b"a" * 17)
    assert_poly1305(bytes(range(32)), (b"poly1305-data\0" * 4096) + b"end")

    rfc_plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only "
        b"one tip for the future, sunscreen would be it."
    )
    rfc_ciphertext = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    rfc_key = bytes(range(32))
    rfc_nonce = bytes.fromhex("000000000000004a00000000")
    encrypted = assert_chacha20(rfc_key, rfc_nonce, 1, rfc_plaintext)
    assert encrypted == rfc_ciphertext
    decrypted = assert_chacha20(rfc_key, rfc_nonce, 1, encrypted)
    assert decrypted == rfc_plaintext
    assert_chacha20(rfc_key, bytes.fromhex("000000090000004a00000000"), 1, b"x" * 4097)

    assert_aead(rfc_key, rfc_nonce, b"")
    assert_aead(rfc_key, rfc_nonce, b"abc")
    assert_aead(rfc_key, rfc_nonce, rfc_plaintext)
    assert_aead(
        bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0"
                      "473917c1402b80099dca5cbc207075c0"),
        bytes.fromhex("000000000102030405060708"),
        (b"sealed-data\0" * 8192) + b"end",
    )

    assert_envelope(rfc_key, b"")
    assert_envelope(rfc_key, b"abc")
    assert_envelope(rfc_key, (b"envelope-data\0" * 4096) + b"end")
    v2_key_id = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    v2_sealed = assert_envelope_v2(rfc_key, v2_key_id, b"")
    assert_envelope_v2(rfc_key, v2_key_id, b"abc")
    v2_file_plaintext = b"file-v2-artifact"
    v2_file_sealed = assert_envelope_v2(rfc_key, v2_key_id, v2_file_plaintext)
    assert_envelope_v2(rfc_key, v2_key_id, (b"envelope-v2\0" * 4096) + b"end")
    v3_sealed = assert_recipient_workflow((b"recipient-artifact\0" * 257) + b"end")

    sealed_proc = run(["seal", rfc_key.hex()], b"tamper-target")
    assert sealed_proc.returncode == 0, sealed_proc.stderr.decode("utf-8", "replace")
    sealed = sealed_proc.stdout
    assert_inspect_v1(sealed)
    assert_inspect_v2(v2_sealed, v2_key_id)
    assert_manifest_v1(sealed)
    assert_manifest_v2(v2_sealed, v2_key_id)
    assert_artifact_file_commands(sealed, v2_sealed, v3_sealed)
    assert_ascii_armor_file_commands(v3_sealed)
    assert_rejects_extra_args(rfc_key, v2_key_id, sealed)
    assert_rejects_inspect(b"")
    assert_rejects_inspect(sealed[: ENVELOPE_HEADER_LEN - 1])
    assert_rejects_inspect(b"BADSEAL\x01" + sealed[len(ENVELOPE_PREFIX) :])
    assert_rejects_inspect(sealed[:6] + b"\x03" + sealed[7:])
    assert_rejects_inspect(v2_sealed[: len(ENVELOPE_V2_PREFIX) + 8])
    assert_rejects_inspect(v2_sealed[: ENVELOPE_V2_HEADER_LEN - 1])
    assert_rejects_inspect(v3_sealed[: len(ENVELOPE_V3_PREFIX) + 16])
    assert_rejects_inspect(v3_sealed[: ENVELOPE_V3_HEADER_LEN - 1])
    assert_rejects_manifest(b"")
    assert_rejects_manifest(sealed[: ENVELOPE_HEADER_LEN - 1])
    assert_rejects_manifest(b"BADSEAL\x01" + sealed[len(ENVELOPE_PREFIX) :])
    assert_rejects_manifest(sealed[:6] + b"\x03" + sealed[7:])
    assert_rejects_manifest(v2_sealed[: len(ENVELOPE_V2_PREFIX) + 8])
    assert_rejects_manifest(v2_sealed[: ENVELOPE_V2_HEADER_LEN - 1])
    assert_rejects_manifest(v3_sealed[: len(ENVELOPE_V3_PREFIX) + 16])
    assert_rejects_manifest(v3_sealed[: ENVELOPE_V3_HEADER_LEN - 1])
    assert_rejects_envelope(rfc_key, b"")
    assert_rejects_envelope(rfc_key, sealed[: ENVELOPE_HEADER_LEN - 1])
    assert_rejects_envelope(rfc_key, sealed[:-1])
    assert_rejects_envelope(rfc_key, b"BADSEAL\x01" + sealed[len(ENVELOPE_PREFIX) :])
    assert_rejects_envelope(
        rfc_key,
        sealed[:6] + b"\x02" + sealed[7:],
    )
    assert_rejects_envelope(
        rfc_key,
        sealed[:-1] + bytes([sealed[-1] ^ 1]),
    )
    assert_rejects_envelope(rfc_key, v2_sealed[: ENVELOPE_V2_HEADER_LEN - 1])
    assert_rejects_envelope(rfc_key, v2_sealed[:-1])
    assert_rejects_envelope(
        rfc_key,
        v2_sealed[:8] + bytes([v2_sealed[8] ^ 1]) + v2_sealed[9:],
    )
    assert_rejects_envelope(
        rfc_key,
        v2_sealed[:24] + bytes([v2_sealed[24] ^ 1]) + v2_sealed[25:],
    )
    assert_rejects_envelope(
        rfc_key,
        v2_sealed[:-1] + bytes([v2_sealed[-1] ^ 1]),
    )
    assert_rejects_envelope(rfc_key, v3_sealed)
    bad_key_id = run(["seal-v2", rfc_key.hex(), "00"], b"bad-key-id")
    assert bad_key_id.returncode != 0
    assert bad_key_id.stdout == b""

    assert_keyfile_workflow((b"keyfile-artifact\0" * 257) + b"end")
    assert_keyfile_file_workflow(
        (b"keyfile-file-artifact\0" * 257) + b"end",
        v2_key_id,
    )
    assert_file_seal_open_workflow(
        rfc_key,
        v2_key_id,
        (b"file-artifact\0" * 257) + b"end",
        v2_file_sealed,
        v2_file_plaintext,
    )


if __name__ == "__main__":
    main()
