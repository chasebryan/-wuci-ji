from __future__ import annotations

import unittest
from pathlib import Path

from src import evidence_refs
from src.canonical_json import canonical_sha256, load_json_no_floats

REPO_ROOT = Path(__file__).resolve().parents[3]
V18_EXAMPLES = REPO_ROOT / "daylight" / "v18-bastion" / "examples"
V17_SCORECARD = (
    REPO_ROOT / "daylight" / "v17-singularity" / "examples" / "expected-scorecard.current.v17.json"
)
V15_SCORECARD = (
    REPO_ROOT / "daylight" / "v15-meridian" / "examples" / "expected-scorecard.v15-meridian.json"
)


def make_vector(seed: str, previous: str | None = None) -> dict:
    body: dict = {"version": "test-vector", "subject": seed}
    if previous is not None:
        body["previous_vector_digest"] = previous
    body["vector_digest"] = canonical_sha256(
        {key: value for key, value in body.items()}, evidence_refs.D_V18_VECTOR
    )
    return body


def make_ledger_lines(entry_count: int) -> list[dict]:
    version = "test-ledger-v1"
    genesis_head = canonical_sha256({"genesis": version}, evidence_refs.D_V18_HEAD)
    lines = [{"ledger_version": version, "genesis_head": genesis_head}]
    head = genesis_head
    for index in range(entry_count):
        entry_digest = canonical_sha256({"entry": index}, "TEST-ENTRY:")
        transition_digest = canonical_sha256({"transition": index}, "TEST-TRANSITION:")
        next_head = canonical_sha256(
            {"previous_head": head, "entry_digest": entry_digest}, evidence_refs.D_V18_HEAD
        )
        lines.append(
            {
                "previous_head": head,
                "entry_digest": entry_digest,
                "transition_digest": transition_digest,
                "head": next_head,
            }
        )
        head = next_head
    return lines


def ledger_text(lines: list[dict]) -> str:
    import json

    return "\n".join(json.dumps(line, sort_keys=True, separators=(",", ":")) for line in lines) + "\n"


def make_meridian(
    *,
    final: int = 900,
    perfect: int = 1000,
    open_external: int = 1,
    closed: list[dict] | None = None,
    manual_edit_allowed: bool = False,
    manual_override: bool = False,
    contributions: list[dict] | None = None,
) -> dict:
    return {
        "manual_edit_allowed": manual_edit_allowed,
        "manual_override": manual_override,
        "final_score_M": final,
        "perfect_score_M": perfect,
        "term_contributions_M": (
            contributions if contributions is not None else [{"contribution_M": final}]
        ),
        "open_obligations": [
            {"obligation_id": f"o.ext.{index}", "scope": "external"} for index in range(open_external)
        ],
        "closed_obligations": closed if closed is not None else [
            {"obligation_id": "o.int.1", "scope": "internal"}
        ],
    }


class BinaricVectorChainTests(unittest.TestCase):
    def test_valid_chain_returns_head(self) -> None:
        first = make_vector("one")
        second = make_vector("two", previous=first["vector_digest"])
        head = evidence_refs.check_binaric_vector_chain([first, second])
        self.assertEqual(head, second["vector_digest"])

    def test_vector_digest_mismatch_rejects(self) -> None:
        vector = make_vector("one")
        vector["subject"] = "tampered"
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_binaric_vector_chain([vector])

    def test_broken_previous_vector_chain_rejects(self) -> None:
        first = make_vector("one")
        second = make_vector("two", previous="d" * 64)
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_binaric_vector_chain([first, second])

    def test_missing_chain_link_rejects(self) -> None:
        first = make_vector("one")
        second = make_vector("two")
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_binaric_vector_chain([first, second])

    def test_repo_v18_transition_vectors_chain(self) -> None:
        before = load_json_no_floats(V18_EXAMPLES / "transition.before.v18.json")
        after = load_json_no_floats(V18_EXAMPLES / "transition.after.v18.json")
        head = evidence_refs.check_binaric_vector_chain([before, after])
        self.assertEqual(head, after["vector_digest"])


class TransitionLedgerTests(unittest.TestCase):
    def test_valid_ledger_returns_head(self) -> None:
        lines = make_ledger_lines(2)
        head = evidence_refs.check_transition_ledger(ledger_text(lines))
        self.assertEqual(head, lines[-1]["head"])

    def test_chain_break_rejects(self) -> None:
        lines = make_ledger_lines(2)
        lines[2]["previous_head"] = "e" * 64
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_transition_ledger(ledger_text(lines))

    def test_genesis_mismatch_rejects(self) -> None:
        lines = make_ledger_lines(1)
        lines[0]["genesis_head"] = "f" * 64
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_transition_ledger(ledger_text(lines))

    def test_repo_v18_example_ledger_verifies(self) -> None:
        text = (V18_EXAMPLES / "transition-ledger.v18.json").read_text(encoding="utf-8")
        head = evidence_refs.check_transition_ledger(text)
        self.assertEqual(len(head), 64)


class MeridianScorecardTests(unittest.TestCase):
    def test_internal_ceiling_scorecard_passes(self) -> None:
        summary = evidence_refs.check_meridian_scorecard(make_meridian())
        self.assertEqual(summary["final_score_M"], 900)

    def test_repo_meridian_scorecard_passes(self) -> None:
        summary = evidence_refs.check_meridian_scorecard(load_json_no_floats(V15_SCORECARD))
        self.assertEqual(summary["final_score_M"], 998900)
        self.assertGreater(summary["open_obligation_count"], 0)

    def test_manual_edit_allowed_rejects(self) -> None:
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(make_meridian(manual_edit_allowed=True))

    def test_manual_override_rejects(self) -> None:
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(make_meridian(manual_override=True))

    def test_score_not_matching_contributions_rejects(self) -> None:
        scorecard = make_meridian(final=999, contributions=[{"contribution_M": 900}])
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(scorecard)

    def test_perfect_score_without_external_evidence_rejects(self) -> None:
        scorecard = make_meridian(final=1000, perfect=1000, open_external=0)
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(scorecard)

    def test_perfect_score_with_open_obligations_rejects(self) -> None:
        scorecard = make_meridian(final=1000, perfect=1000, open_external=2)
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(scorecard)

    def test_perfect_score_with_self_signed_attestation_rejects(self) -> None:
        for signer in ("self:red-team", "internal:audit", "wuci-ji:release", "repo:owner"):
            closed = [
                {
                    "obligation_id": "o.ext.red_team",
                    "scope": "external",
                    "attestation": {"signer_id": signer},
                }
            ]
            scorecard = make_meridian(final=1000, perfect=1000, open_external=0, closed=closed)
            with self.assertRaises(evidence_refs.EvidenceRefError, msg=signer):
                evidence_refs.check_meridian_scorecard(scorecard)

    def test_perfect_score_with_self_signed_flag_rejects(self) -> None:
        closed = [
            {
                "obligation_id": "o.ext.red_team",
                "scope": "external",
                "attestation": {"signer_id": "ext:lab", "self_signed": True},
            }
        ]
        scorecard = make_meridian(final=1000, perfect=1000, open_external=0, closed=closed)
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_meridian_scorecard(scorecard)

    def test_perfect_score_with_genuine_external_attestation_passes(self) -> None:
        closed = [
            {
                "obligation_id": "o.ext.red_team",
                "scope": "external",
                "attestation": {"signer_id": "ext:independent-lab"},
            }
        ]
        scorecard = make_meridian(final=1000, perfect=1000, open_external=0, closed=closed)
        summary = evidence_refs.check_meridian_scorecard(scorecard)
        self.assertEqual(summary["final_score_M"], 1000)


class EventHorizonScorecardTests(unittest.TestCase):
    def test_repo_event_horizon_scorecard_passes(self) -> None:
        summary = evidence_refs.check_event_horizon_scorecard(load_json_no_floats(V17_SCORECARD))
        self.assertEqual(len(summary["scorecard_digest"]), 64)

    def test_fixture_claim_usable_rejects(self) -> None:
        scorecard = {"scorecard_digest": "a" * 64, "fixture": True, "claim_usable": True}
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_event_horizon_scorecard(scorecard)

    def test_reserved_perfect_am_plus_rejects(self) -> None:
        scorecard = {"scorecard_digest": "a" * 64, "score_AM_plus": 1_000_000_000}
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_event_horizon_scorecard(scorecard)

    def test_declared_without_agreement_rejects(self) -> None:
        scorecard = {
            "scorecard_digest": "a" * 64,
            "declared": True,
            "cross_verifier_agreement_passed": False,
        }
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_event_horizon_scorecard(scorecard)

    def test_missing_scorecard_digest_rejects(self) -> None:
        with self.assertRaises(evidence_refs.EvidenceRefError):
            evidence_refs.check_event_horizon_scorecard({"fixture": False})


if __name__ == "__main__":
    unittest.main()
