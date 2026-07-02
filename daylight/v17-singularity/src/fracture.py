"""Adversarial mutation suite for Daylight v17.1 Event Horizon scorecards."""

from __future__ import annotations

import copy
from typing import Any, Callable

from . import proof_atoms
from . import registry as registry_mod
from . import scorecard as scorecard_mod


MUTATION_CLASSES = list(scorecard_mod.FRACTURE_MUTATIONS)


def _verify_rejects(
    card: dict[str, Any],
    state: dict[str, Any],
    fields: dict[str, Any],
    atoms: dict[str, Any],
) -> bool:
    try:
        scorecard_mod.verify_scorecard_object(card, state, fields, atoms, check_fracture=False)
    except ValueError:
        return True
    return False


def _mutated_scorecard_rejects(
    card: dict[str, Any],
    state: dict[str, Any],
    fields: dict[str, Any],
    atoms: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
    *,
    recompute_digest: bool = True,
) -> bool:
    mutated = copy.deepcopy(card)
    mutate(mutated)
    if recompute_digest:
        mutated["scorecard_digest"] = scorecard_mod.scorecard_digest(mutated)
    return _verify_rejects(mutated, state, fields, atoms)


def _state_mutation_rejects(
    card: dict[str, Any],
    state: dict[str, Any],
    fields: dict[str, Any],
    atoms: dict[str, Any],
    mutate: Callable[[dict[str, Any]], None],
) -> bool:
    mutated_state = copy.deepcopy(state)
    mutate(mutated_state)
    return _verify_rejects(card, mutated_state, fields, atoms)


def run_fracture_suite(
    state: dict[str, Any],
    fields: dict[str, Any],
    atoms: dict[str, Any],
    card: dict[str, Any],
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []

    def add(name: str, rejected: bool) -> None:
        results.append({"mutation": name, "passed": rejected, "outcome": "reject" if rejected else "accepted"})

    add("M1 edited score_AM_plus", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("score_AM_plus", c["score_AM_plus"] + 1)
    ))
    add("M2 edited omega_eff_decimal", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("omega_eff_decimal", "999")
    ))
    add("M3 edited field verified_credit", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c["fields"][0].__setitem__("verified_credit", c["fields"][0]["verified_credit"] - 1)
    ))
    add("M4 edited debt_uomega", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("debt_uomega", c["debt_uomega"] + 1)
    ))
    add("M5 edited fields_digest", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("fields_digest", "0" * 64)
    ))
    add("M6 edited proof_atoms_digest", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("proof_atoms_digest", "0" * 64)
    ))
    add("M7 edited state_digest", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("state_digest", "0" * 64)
    ))

    removed_atoms = copy.deepcopy(atoms)
    removed_atoms["proof_atoms"] = removed_atoms["proof_atoms"][1:]
    add("M8 removed proof atom", _verify_rejects(card, state, fields, removed_atoms))

    add("M9 forged fixture flag", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("fixture", not c["fixture"])
    ))
    add("M10 forged claim_usable flag", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("claim_usable", not c["claim_usable"])
    ))
    add("M11 score_inflation_M changed to nonzero", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("score_inflation_M", 1)
    ))
    add("M12 collapse flag edited", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("collapse", not c["collapse"])
    ))
    add("M13 status edited", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("status", "singularity_declared")
    ))
    add("M14 declared edited", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("declared", not c["declared"])
    ))
    add("M15 scorecard_digest edited", _mutated_scorecard_rejects(
        card, state, fields, atoms, lambda c: c.__setitem__("scorecard_digest", "0" * 64), recompute_digest=False
    ))

    return {
        "passed": all(row["passed"] for row in results) and [row["mutation"] for row in results] == MUTATION_CLASSES,
        "mutation_classes": MUTATION_CLASSES,
        "fracture_digest": scorecard_mod.fracture_digest(),
        "results": results,
    }
