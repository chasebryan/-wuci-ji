from __future__ import annotations

import json
import unittest
from pathlib import Path

from src import api, envelope, schema_check
from tests.helpers import PACKAGE_ROOT

EXAMPLES = PACKAGE_ROOT / "examples"
SEED_L = EXAMPLES / "ledger.seed.jsonl"
SEED_C = EXAMPLES / "corpus.seed.jsonl"
PERFECT_L = EXAMPLES / "ledger.perfect.jsonl"
KEY = bytes(range(32))
ZERO_NONCE = bytes(12)


class EnvelopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = api.load_registry()
        self.policy = envelope.make_policy(
            self.registry,
            min_score_M=998900,
            required_closed_obligations=["o.q1.master_law_executable", "o.q4.fail_closed_tests"],
        )

    def _seal(self, plaintext: bytes, ledger=SEED_L, corpus=SEED_C, policy=None, nonce=ZERO_NONCE) -> bytes:
        return envelope.seal(
            plaintext=plaintext,
            caller_key=KEY,
            ledger_path=ledger,
            corpus_path=corpus,
            policy=policy or self.policy,
            nonce=nonce,
        )

    def test_round_trip(self) -> None:
        sealed = self._seal(b"meridian secret")
        opened = envelope.open_envelope(envelope=sealed, caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C)
        self.assertEqual(opened, b"meridian secret")

    def test_inspect_is_keyless_and_leaks_no_plaintext(self) -> None:
        sealed = self._seal(b"TOP-SECRET-MARKER")
        info = envelope.inspect(sealed)
        self.assertEqual(info["version"], envelope.ENVELOPE_VERSION)
        self.assertEqual(info["policy"]["min_score_M"], 998900)
        self.assertEqual(info["authorization"]["final_score_M"], 998900)
        self.assertNotIn(b"TOP-SECRET-MARKER", json.dumps(info).encode("utf-8"))

    def test_wrong_key_is_refused(self) -> None:
        sealed = self._seal(b"x")
        with self.assertRaises(envelope.EnvelopeRefused):
            envelope.open_envelope(envelope=sealed, caller_key=bytes([7]) * 32, ledger_path=SEED_L, corpus_path=SEED_C)

    def test_tampered_ciphertext_is_refused(self) -> None:
        sealed = bytearray(self._seal(b"some secret payload"))
        sealed[-1] ^= 1
        with self.assertRaises(envelope.EnvelopeRefused):
            envelope.open_envelope(envelope=bytes(sealed), caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C)

    def test_tampered_header_policy_is_refused(self) -> None:
        sealed = self._seal(b"y").replace(b'"min_score_M":998900', b'"min_score_M":100000')
        with self.assertRaises(envelope.EnvelopeRefused):
            envelope.open_envelope(envelope=sealed, caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C)

    def test_tampered_authorization_tag_is_refused(self) -> None:
        sealed = self._seal(b"z")
        parsed = envelope.parse(sealed)
        real_tag = parsed["header"]["authorization"]["authorization_tag"]
        forged = "0" * len(real_tag)
        tampered = sealed.replace(real_tag.encode(), forged.encode())
        with self.assertRaises(envelope.EnvelopeRefused):
            envelope.open_envelope(envelope=tampered, caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C)

    def test_malformed_envelope_raises(self) -> None:
        with self.assertRaises(envelope.EnvelopeError):
            envelope.inspect(b"not an envelope")

    def test_no_score_no_seal(self) -> None:
        perfect_policy = envelope.make_policy(self.registry, min_score_M=1000000)
        with self.assertRaises(envelope.EnvelopeRefused):
            self._seal(b"x", policy=perfect_policy)  # internal evidence cannot reach 1000000

    def test_required_external_obligation_blocks_seal_from_internal(self) -> None:
        policy = envelope.make_policy(
            self.registry, min_score_M=998900, required_closed_obligations=["o.q11.external_falsification_program"]
        )
        with self.assertRaises(envelope.EnvelopeRefused):
            self._seal(b"x", policy=policy)

    def test_perfect_logic_gate(self) -> None:
        """A secret sealed under a perfect 1,000,000M state opens only with the full
        external-attestation evidence, never with internal-only evidence."""
        perfect_policy = envelope.make_policy(self.registry, min_score_M=1000000)
        sealed = self._seal(b"opens only under perfect meridian", ledger=PERFECT_L, policy=perfect_policy)
        with self.assertRaises(envelope.EnvelopeRefused):
            envelope.open_envelope(envelope=sealed, caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C)
        opened = envelope.open_envelope(envelope=sealed, caller_key=KEY, ledger_path=PERFECT_L, corpus_path=SEED_C)
        self.assertEqual(opened, b"opens only under perfect meridian")

    def test_seal_is_deterministic_with_fixed_nonce(self) -> None:
        self.assertEqual(self._seal(b"determinism"), self._seal(b"determinism"))

    def test_make_policy_rejects_unknown_obligation_and_bad_score(self) -> None:
        with self.assertRaises(envelope.EnvelopeError):
            envelope.make_policy(self.registry, min_score_M=500, required_closed_obligations=["o.nope"])
        with self.assertRaises(envelope.EnvelopeError):
            envelope.make_policy(self.registry, min_score_M=2000000)

    def test_header_matches_schema(self) -> None:
        sealed = self._seal(b"schema check")
        header = envelope.parse(sealed)["header"]
        schema = schema_check.load_schema(PACKAGE_ROOT / "schema" / "envelope-header.v15.schema.json")
        self.assertEqual(schema_check.validate(header, schema), [])

    def test_api_facade_round_trip(self) -> None:
        policy = api.make_policy(self.registry, min_score_M=998900)
        sealed = api.seal_envelope(
            plaintext=b"via api", caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C, policy=policy, nonce=ZERO_NONCE
        )
        self.assertEqual(api.inspect_envelope(sealed)["version"], envelope.ENVELOPE_VERSION)
        self.assertEqual(
            api.open_envelope(envelope=sealed, caller_key=KEY, ledger_path=SEED_L, corpus_path=SEED_C), b"via api"
        )


class CommittedDemoEnvelopeTests(unittest.TestCase):
    def test_committed_demo_opens_and_is_reproducible(self) -> None:
        demo = EXAMPLES / "demo.mae"
        keyfile = EXAMPLES / "demo.key"
        if not demo.is_file() or not keyfile.is_file():
            self.skipTest("committed demo artifact not present")
        key = bytes.fromhex(keyfile.read_text(encoding="utf-8").strip())
        opened = envelope.open_envelope(
            envelope=demo.read_bytes(), caller_key=key, ledger_path=SEED_L, corpus_path=SEED_C
        )
        self.assertIn(b"Meridian", opened)
        info = envelope.inspect(demo.read_bytes())
        reproduced = envelope.seal(
            plaintext=opened,
            caller_key=key,
            ledger_path=SEED_L,
            corpus_path=SEED_C,
            policy=envelope.make_policy(
                api.load_registry(),
                min_score_M=info["policy"]["min_score_M"],
                required_closed_obligations=info["policy"]["required_closed_obligations"],
            ),
            nonce=bytes.fromhex(info["nonce"]),
        )
        self.assertEqual(reproduced, demo.read_bytes())


if __name__ == "__main__":
    unittest.main()
