"""Adversarial mutation suite for Daylight v17.1 scorecards."""

from __future__ import annotations

import copy
from typing import Any, Callable

from . import registry as registry_mod
from . import scorecard as scorecard_mod
from . import proof_atoms


MUTATION_CLASSES = [
    "M1 edited score",
    "M2 edited omega",
    "M3 edited field closure",
    "M4 edited debt",
    "M5 edited registry digest",
    "M6 removed proof atom",
    "M7 stale proof reused",
    "M8 fake replay result",
    "M9 forged external review",
    "M10 unsigned external credit",
    "M11 boundary overclaim",
    "M12 manifest mismatch",
    "M13 output ledger mismatch",
    "M14 implementation disagreement",
    "M15 parser ambiguity",
]


def _rejects_scorecard_mutation(
    card: dict[str, Any],
    state: dict[str, Any],
    fields: dict[str, Any],
    atoms: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
) -> bool:
    mutated = copy.deepcopy(card)
    mutate(mutated)
    try:
        scorecard_mod.verify_scorecard_object(mutated, state, fields, atoms)
    except ValueError:
        return True
    return False


def run_fracture_suite(state: dict[str, Any], fields: dict[str, Any], atoms: dict[str, Any], card: dict[str, Any]) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    def add(name: str, passed: bool, outcome: str) -> None:
        results.append({"mutation": name, "passed": passed, "outcome": outcome})

    add("M1 edited score", _rejects_scorecard_mutation(card, state, fields, atoms, lambda c: c.__setitem__("score_AM_plus", c["score_AM_plus"] + 1)), "reject")
    add("M2 edited omega", _rejects_scorecard_mutation(card, state, fields, atoms, lambda c: c.__setitem__("omega_decimal", "999")), "reject")
    add("M3 edited field closure", _rejects_scorecard_mutation(card, state, fields, atoms, lambda c: c["fields"][0].__setitem__("closure_decimal", "1")), "reject")
    add("M4 edited debt", _rejects_scorecard_mutation(card, state, fields, atoms, lambda c: c.__setitem__("debt_uomega", c["debt_uomega"] + 1)), "reject")
    add("M5 edited registry digest", _rejects_scorecard_mutation(card, state, fields, atoms, lambda c: c.__setitem__("proof_registry_digest", "0" * 64)), "reject")

    removed_atoms = copy.deepcopy(atoms)
    removed_atoms["proof_atoms"] = removed_atoms["proof_atoms"][1:]
    try:
        scorecard_mod.verify_scorecard_object(card, state, fields, removed_atoms)
        add("M6 removed proof atom", False, "accepted")
    except ValueError:
        add("M6 removed proof atom", True, "reject")

    stale_atoms = copy.deepcopy(atoms)
    stale_atoms["proof_atoms"][0]["evidence_digest"] = "0" * 64
    try:
        stale_card = scorecard_mod.build_scorecard(state, fields, stale_atoms)
        add("M7 stale proof reused", stale_card["scorecard_digest"] != card["scorecard_digest"], "reject")
    except ValueError:
        add("M7 stale proof reused", True, "reject")

    fake_replay_atoms = copy.deepcopy(atoms)
    fake_replay_atoms["proof_atoms"][0]["replay_required"] = True
    fake_replay_atoms["proof_atoms"][0]["evidence_digest"] = "0" * 64
    try:
        fake_card = scorecard_mod.build_scorecard(state, fields, fake_replay_atoms)
        add("M8 fake replay result", fake_card["scorecard_digest"] != card["scorecard_digest"], "reject")
    except ValueError:
        add("M8 fake replay result", True, "reject")

    forged_review_atoms = copy.deepcopy(atoms)
    forged_review_atoms["proof_atoms"][0]["verifier_command"] = "record-valid-signed-external"
    try:
        forged_card = scorecard_mod.build_scorecard(state, fields, forged_review_atoms)
        add("M9 forged external review", forged_card["scorecard_digest"] != card["scorecard_digest"], "reject")
    except ValueError:
        add("M9 forged external review", True, "reject")

    for name, flag in [
        ("M10 unsigned external credit", "unsigned_external_credit"),
        ("M11 boundary overclaim", "production_overclaim"),
    ]:
        mutated_state = copy.deepcopy(state)
        mutated_state.setdefault("collapse_flags", {})[flag] = True
        mutated_card = scorecard_mod.build_scorecard(mutated_state, fields, atoms)
        add(name, mutated_card["collapse"] and mutated_card["score_AM_plus"] == 0, "collapse")

    manifest_atoms = copy.deepcopy(atoms)
    for atom in manifest_atoms["proof_atoms"]:
        if atom["id"].endswith("artifact_manifest"):
            atom["evidence_digest"] = "0" * 64
            break
    add("M12 manifest mismatch", scorecard_mod.build_scorecard(state, fields, manifest_atoms)["scorecard_digest"] != card["scorecard_digest"], "reject")

    ledger_atoms = copy.deepcopy(atoms)
    for atom in ledger_atoms["proof_atoms"]:
        if atom["id"].endswith("output_ledger"):
            atom["evidence_digest"] = "0" * 64
            break
    add("M13 output ledger mismatch", scorecard_mod.build_scorecard(state, fields, ledger_atoms)["scorecard_digest"] != card["scorecard_digest"], "reject")

    for name, flag in [
        ("M14 implementation disagreement", "implementation_disagreement"),
        ("M15 parser ambiguity", "parser_ambiguity"),
    ]:
        mutated_state = copy.deepcopy(state)
        mutated_state.setdefault("collapse_flags", {})[flag] = True
        mutated_card = scorecard_mod.build_scorecard(mutated_state, fields, atoms)
        add(name, mutated_card["collapse"] and mutated_card["score_AM_plus"] == 0, "collapse")

    return {
        "passed": all(row["passed"] for row in results) and [row["mutation"] for row in results] == MUTATION_CLASSES,
        "results": results,
    }
