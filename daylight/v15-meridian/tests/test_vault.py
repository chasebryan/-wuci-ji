from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from src import vault
from src.envelope import EnvelopeRefused
from tests.helpers import PACKAGE_ROOT

EXAMPLES = PACKAGE_ROOT / "examples"
SEED_L = EXAMPLES / "ledger.seed.jsonl"
SEED_C = EXAMPLES / "corpus.seed.jsonl"


class VaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "vault"
        self.work = Path(self._tmp.name) / "work"
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _init(self, **kwargs):
        return vault.init_vault(self.root, **kwargs)

    # -- construction ----------------------------------------------------------

    def test_init_creates_keyfile_vault_and_evidence(self) -> None:
        info = self._init()
        self.assertEqual(info["key_mode"], "keyfile")
        self.assertEqual(info["evidence_final_score_M"], 998900)
        self.assertTrue((self.root / "vault.json").is_file())
        self.assertTrue((self.root / "evidence" / "ledger.jsonl").is_file())
        key = self.root / "vault.key"
        self.assertTrue(key.is_file())
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)

    def test_init_refuses_unsatisfiable_floor(self) -> None:
        # A perfect floor needs external attestation the seed evidence lacks.
        with self.assertRaises(vault.VaultError):
            self._init(min_score_M=1_000_000)

    def test_init_refuses_unknown_required_obligation(self) -> None:
        with self.assertRaises(Exception):
            self._init(required_closed_obligations=["o.q1.does_not_exist"])

    def test_init_refuses_nonempty_root_without_force(self) -> None:
        self._init()
        with self.assertRaises(vault.VaultError):
            self._init()
        # force rebuilds
        self._init(force=True)

    # -- round trip ------------------------------------------------------------

    def test_seal_open_round_trip_keeps_original(self) -> None:
        self._init()
        v = vault.Vault(self.root)
        src = self.work / "secret.txt"
        src.write_bytes(b"top secret payload")
        record = v.seal_file(src)
        self.assertTrue(src.is_file(), "original kept by default")
        self.assertTrue((self.root / "store" / f"{record['name']}.mae").is_file())
        self.assertEqual(v.open_bytes(record["name"]), b"top secret payload")

    def test_seal_remove_original_then_restore(self) -> None:
        self._init()
        v = vault.Vault(self.root)
        src = self.work / "creds"
        src.write_bytes(b"API_KEY=hunter2")
        record = v.seal_file(src, keep_original=False)
        self.assertFalse(src.exists(), "original removed when keep_original=False")
        out = v.open_file(record["name"], restore=True)
        self.assertEqual(out["restored_to"], str(src.resolve()))
        self.assertEqual(src.read_bytes(), b"API_KEY=hunter2")

    def test_passphrase_vault_requires_passphrase(self) -> None:
        self._init(passphrase="correct horse")
        v = vault.Vault(self.root)
        self.assertFalse((self.root / "vault.key").exists())
        record = v.seal_bytes("x", b"data", passphrase="correct horse")
        self.assertEqual(v.open_bytes("x", passphrase="correct horse"), b"data")
        with self.assertRaises(vault.VaultError):
            v.open_bytes("x")  # no passphrase
        with self.assertRaises(EnvelopeRefused):
            v.open_bytes("x", passphrase="wrong")  # wrong key -> fail-closed

    # -- fail-closed on degraded evidence -------------------------------------

    def test_open_fails_closed_when_evidence_tampered(self) -> None:
        self._init()
        v = vault.Vault(self.root)
        v.seal_bytes("e", b"governed")
        # Corrupt the vault's evidence base: the scorecard will no longer verify
        # or reproduce the sealed authorization, so the secret must not open.
        led = self.root / "evidence" / "ledger.jsonl"
        led.write_text(led.read_text(encoding="utf-8").replace("source", "SoUrCe"), encoding="utf-8")
        with self.assertRaises(EnvelopeRefused):
            v.open_bytes("e")

    def test_status_reports_authorized(self) -> None:
        self._init()
        st = vault.Vault(self.root).status()
        self.assertTrue(st["authorized"])
        self.assertTrue(st["evidence_verifies"])
        self.assertEqual(st["evidence_final_score_M"], 998900)

    # -- autoseal --------------------------------------------------------------

    def test_autoseal_seals_existing_targets_only(self) -> None:
        self._init()
        v = vault.Vault(self.root)
        home_ssh = self.work / "id_ed25519"
        home_ssh.write_bytes(b"PRIVATE KEY")
        result = vault.autoseal(v, targets=[str(home_ssh), str(self.work / "absent")])
        self.assertEqual(result["sealed_count"], 1)
        self.assertEqual(result["skipped_patterns"], [str(self.work / "absent")])
        self.assertTrue(home_ssh.is_file())


if __name__ == "__main__":
    unittest.main()
