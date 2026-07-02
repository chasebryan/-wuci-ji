from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src import horizon_crypto, horizon_policy, horizon_vault


CURRENT_STATE = "daylight/v17-singularity/examples/state.current.json"
FIXTURE_STATE = "daylight/v17-singularity/examples/state.declaration-fixture.json"
NONCE = bytes.fromhex("000000000000000000000001")


class HorizonVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "vault"
        horizon_vault.init_vault(self.root)
        self.vault = horizon_vault.HorizonVault(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_seal_open_roundtrip_passes_under_current_evidence(self) -> None:
        secret = b"TOP-SECRET-MARKER"
        sealed = self.vault.seal_bytes(name="secret.txt", plaintext=secret, state_path=CURRENT_STATE, nonce=NONCE)
        opened = self.vault.open_bytes(sealed=sealed, state_path=CURRENT_STATE)
        self.assertEqual(opened, secret)

    def test_inspect_never_reveals_plaintext(self) -> None:
        secret = b"TOP-SECRET-MARKER"
        sealed = self.vault.seal_bytes(name="secret.txt", plaintext=secret, state_path=CURRENT_STATE, nonce=NONCE)
        inspected = horizon_vault.inspect_bytes(sealed)
        self.assertNotIn("TOP-SECRET-MARKER", repr(inspected))
        self.assertEqual(inspected["object_type"], "vault")

    def test_tampered_header_rejects(self) -> None:
        sealed = self.vault.seal_bytes(name="secret.txt", plaintext=b"secret", state_path=CURRENT_STATE, nonce=NONCE)
        parsed = horizon_crypto.parse_framed(sealed, magic=horizon_vault.MAGIC)
        header = dict(parsed["header"])
        header["name"] = "tampered.txt"
        header_bytes = horizon_crypto.frame_header(header)
        tampered = horizon_crypto.aad(horizon_vault.MAGIC, header_bytes) + parsed["ciphertext"] + parsed["tag"]
        with self.assertRaises(horizon_vault.HorizonVaultRefused):
            self.vault.open_bytes(sealed=tampered, state_path=CURRENT_STATE)

    def test_tampered_ciphertext_rejects(self) -> None:
        sealed = bytearray(self.vault.seal_bytes(name="secret.txt", plaintext=b"secret", state_path=CURRENT_STATE, nonce=NONCE))
        sealed[-17] ^= 1
        with self.assertRaises(horizon_vault.HorizonVaultRefused):
            self.vault.open_bytes(sealed=bytes(sealed), state_path=CURRENT_STATE)

    def test_stricter_declaration_policy_rejects_seal(self) -> None:
        with self.assertRaises(horizon_vault.HorizonVaultRefused):
            self.vault.seal_bytes(
                name="secret.txt",
                plaintext=b"secret",
                state_path=CURRENT_STATE,
                policy=horizon_policy.policy_for_mode("declaration"),
                nonce=NONCE,
            )

    def test_fixture_policy_rejects_when_allow_fixture_false(self) -> None:
        with self.assertRaises(horizon_vault.HorizonVaultRefused):
            self.vault.seal_bytes(name="secret.txt", plaintext=b"secret", state_path=FIXTURE_STATE, nonce=NONCE)


if __name__ == "__main__":
    unittest.main()
