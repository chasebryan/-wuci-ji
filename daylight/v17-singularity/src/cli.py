"""Command-line interface for Daylight v17.1 Event Horizon."""

from __future__ import annotations

import argparse
import sys
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any

from . import __version__
from .canonical_json import json_bytes, load_json_no_floats
from . import event_horizon
from . import fracture
from . import horizon_release
from . import horizon_vault
from . import proof_atoms
from . import registry
from . import scorecard
from . import verifier_vector
from .singularity_math import (
    LN_1E9,
    debt_uomega_to_decimal,
    decimal_text,
    effective_omega,
    field_closure,
    fraction_to_decimal,
    parse_rational,
    parse_rational_alpha,
    require_decimal_runtime,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURRENT_STATE = PACKAGE_ROOT / "examples" / "state.current.json"
DEFAULT_CURRENT_SCORECARD = PACKAGE_ROOT / "examples" / "expected-scorecard.current.v17.json"
DEFAULT_FIXTURE_STATE = PACKAGE_ROOT / "examples" / "state.declaration-fixture.json"
DEFAULT_FIXTURE_SCORECARD = PACKAGE_ROOT / "examples" / "expected-scorecard.declaration-fixture.v17.json"


def _print_json(value: Any) -> None:
    sys.stdout.buffer.write(json_bytes(value))


def _text_summary(card: dict[str, Any]) -> str:
    return (
        "Daylight v17.3 Triangulation Gate\n"
        f"score_AM_plus: {card['score_AM_plus']}\n"
        f"unit: {card['unit']}\n"
        f"omega_sum: {card['omega_sum_decimal']}\n"
        f"omega_weak: {card['omega_weak_decimal']}\n"
        f"omega_eff: {card['omega_eff_decimal']}\n"
        f"residue: {card['residue_decimal']}\n"
        f"declaration_residue_AM_plus: {card['declaration_residue_AM_plus']}\n"
        f"declaration_score_gap_AM_plus: {card['declaration_score_gap_AM_plus']}\n"
        f"omega_gap_to_declaration: {card['omega_gap_to_declaration']}\n"
        f"residue_collapse_factor_to_declaration: {card['residue_collapse_factor_to_declaration']}\n"
        f"declared: {str(card['declared']).lower()}\n"
        f"status: {card['status']}\n"
        f"collapse: {str(card['collapse']).lower()}\n"
        f"fracture_suite_passed: {str(card['fracture_suite_passed']).lower()}\n"
        f"cross_verifier_agreement_passed: {str(card['cross_verifier_agreement_passed']).lower()}\n"
        f"cross_verifier_agreement_status: {card['cross_verifier_agreement_status']}\n"
        f"cross_verifier_quorum: {card['cross_verifier_quorum']}\n"
        f"claim_usable: {str(card['claim_usable']).lower()}\n"
        "boundary: research scoring layer, not certification"
    )


def _write_or_print(card: dict[str, Any], out: str | None, output_format: str) -> None:
    if out:
        Path(out).write_bytes(json_bytes(card))
    if output_format == "json":
        _print_json(card)
    else:
        print(_text_summary(card))


def cmd_score(args: argparse.Namespace) -> int:
    card = scorecard.build_scorecard_from_paths(state_path=args.state, fields_path=args.fields, proof_atoms_path=args.atoms)
    _write_or_print(card, args.out, args.format)
    return 0


def cmd_verify_scorecard(args: argparse.Namespace) -> int:
    scorecard.verify_scorecard_path(scorecard_path=args.scorecard, state_path=args.state, fields_path=args.fields, proof_atoms_path=args.atoms)
    if args.format == "json":
        _print_json({"ok": True, "scorecard": str(args.scorecard)})
    else:
        print("daylight-v17-event-horizon: scorecard verified")
    return 0


def cmd_fracture(args: argparse.Namespace) -> int:
    state = scorecard.load_state(args.state)
    fields = registry.load_fields_registry(args.fields)
    atoms = proof_atoms.load_proof_atom_registry(args.atoms)
    card = scorecard.build_scorecard(state, fields, atoms)
    result = fracture.run_fracture_suite(state, fields, atoms, card)
    if args.format == "json":
        _print_json(result)
    else:
        print("Daylight v17.1 Event Horizon fracture suite")
        print(f"passed: {str(result['passed']).lower()}")
        print(f"mutations: {len(result['results'])}")
    return 0 if result["passed"] else 1


def _load_current_card(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    state = scorecard.load_state(args.state)
    fields = registry.load_fields_registry(args.fields)
    atoms = proof_atoms.load_proof_atom_registry(args.atoms)
    card = scorecard.build_scorecard(state, fields, atoms)
    return card, state, fields, atoms


def cmd_vector(args: argparse.Namespace) -> int:
    card, _state, _fields, _atoms = _load_current_card(args)
    vector = verifier_vector.generate_python_reference_vector(card)
    if args.out:
        Path(args.out).write_bytes(json_bytes(vector))
    if args.format == "json":
        _print_json(vector)
    else:
        print("Daylight v17.2 Cross-Verifier Horizon vector")
        print(f"implementation_family: {vector['implementation_family']}")
        print(f"score_AM_plus: {vector['score_AM_plus']}")
        print(f"residue_AM_plus: {vector['residue_AM_plus']}")
        print(f"omega_eff: {vector['omega_eff_decimal']}")
        print(f"declared: {str(vector['declared']).lower()}")
        print(f"status: {vector['status']}")
    return 0


def cmd_agreement(args: argparse.Namespace) -> int:
    card, state, _fields, _atoms = _load_current_card(args)
    reference = verifier_vector.generate_python_reference_vector(card)
    if args.vectors:
        vectors = verifier_vector.load_vector_bundle(args.vectors)
    else:
        vectors = state.get("verifier_outputs", [])
    result = verifier_vector.verify_vectors_against_reference(vectors, reference)
    if args.format == "json":
        _print_json(result)
    else:
        print("Daylight v17.3 Triangulation Gate agreement")
        print(f"passed: {str(result['passed']).lower()}")
        print(f"agreement_status: {result['agreement_status']}")
        print(f"quorum: {result['quorum']}")
        print(f"vector_count: {result['vector_count']}")
        if result["blockers"]:
            print("blockers:")
            for blocker in result["blockers"]:
                print(f"  - {blocker}")
    return 0 if result["passed"] else 1


def cmd_declaration_gate(args: argparse.Namespace) -> int:
    result = event_horizon.run_declaration_gate(
        state_path=args.state,
        scorecard_path=args.scorecard,
        fields_path=args.fields,
        proof_atoms_path=args.atoms,
    )
    if args.format == "json":
        _print_json(result)
    else:
        print("Daylight v17.3 Triangulation Gate")
        print(f"decision: {result['decision']}")
        print(f"score_AM_plus: {result['score_AM_plus']}")
        print(f"declaration_residue_AM_plus: {result['declaration_residue_AM_plus']}")
        print(f"declaration_score_gap_AM_plus: {result['declaration_score_gap_AM_plus']}")
        print(f"omega_sum: {result['omega_sum_decimal']}")
        print(f"omega_weak: {result['omega_weak_decimal']}")
        print(f"omega_eff: {result['omega_eff_decimal']}")
        print(f"omega_gap_to_declaration: {result['omega_gap_to_declaration']}")
        print(f"residue_collapse_factor_to_declaration: {result['residue_collapse_factor_to_declaration']}")
        print(f"collapse: {str(result['collapse']).lower()}")
        print(f"fracture_suite_passed: {str(result['fracture_suite']['passed']).lower()}")
        print(f"cross_verifier_agreement_passed: {str(result['cross_verifier_agreement_passed']).lower()}")
        print(f"cross_verifier_agreement_status: {result['cross_verifier_agreement_status']}")
        print(f"cross_verifier_quorum: {result['cross_verifier_quorum']}")
        print(f"claim_usable: {str(result['claim_usable']).lower()}")
        print(f"fixture: {str(result['fixture']).lower()}")
        if result["blockers"]:
            print("blockers:")
            for blocker in result["blockers"]:
                print(f"  - {blocker}")
    return 0 if result["allowed"] else 1


def cmd_blockers(args: argparse.Namespace) -> int:
    result = event_horizon.run_declaration_gate(
        state_path=args.state,
        scorecard_path=args.scorecard,
        fields_path=args.fields,
        proof_atoms_path=args.atoms,
    )
    if args.format == "json":
        _print_json(result)
    else:
        print("declaration_gate: " + ("ALLOWED" if result["allowed"] else "REFUSED"))
        print("blockers:")
        for blocker in result["blockers"]:
            print(f"  - {blocker}")
    return 0


def _threshold_credit_needed(field: dict[str, Any]) -> int:
    threshold = fraction_to_decimal(parse_rational(field["threshold"], "field threshold"))
    possible = int(field["possible_credit"])
    verified = int(field["verified_credit"])
    needed = (threshold * Decimal(possible)).to_integral_value(rounding=ROUND_CEILING)
    gap = int(needed) - verified
    return gap if gap > 0 else 0


def _frontier_report(state: dict[str, Any], fields: dict[str, Any], atoms: dict[str, Any]) -> dict[str, Any]:
    card = scorecard.build_scorecard(state, fields, atoms)
    blockers = scorecard.declaration_blockers(card)
    field_rows = {row["id"]: row for row in card["fields"]}
    current_omegas = {field_id: Decimal(row["omega_i_decimal"]) for field_id, row in field_rows.items()}
    current_eff = Decimal(card["omega_eff_decimal"])
    current_sum = Decimal(card["omega_sum_decimal"])
    debt_omega = debt_uomega_to_decimal(state["debt_uomega"], "debt_uomega")
    overclaim_omega = debt_uomega_to_decimal(state["overclaim_debt_uomega"], "overclaim_debt_uomega")
    staleness_omega = debt_uomega_to_decimal(state["staleness_debt_uomega"], "staleness_debt_uomega")
    field_defs = {row["id"]: row for row in fields["fields"]}

    weakest_fields = sorted(
        [
            {
                "id": row["id"],
                "name": row["name"],
                "omega_i_decimal": row["omega_i_decimal"],
                "closure_decimal": row["closure_decimal"],
                "threshold": row["threshold"],
                "open_atom_count": len(row["open_atoms"]),
            }
            for row in card["fields"]
        ],
        key=lambda item: (Decimal(item["omega_i_decimal"]), item["id"]),
    )
    threshold_margins = []
    for row in card["fields"]:
        margin = Decimal(row["closure_decimal"]) - fraction_to_decimal(parse_rational(row["threshold"], "field threshold"))
        threshold_margins.append({
            "id": row["id"],
            "name": row["name"],
            "threshold_margin_decimal": decimal_text(margin),
            "threshold_passed": row["threshold_passed"],
            "credit_needed_to_threshold": _threshold_credit_needed(row),
        })
    threshold_margins.sort(key=lambda item: (Decimal(item["threshold_margin_decimal"]), item["id"]))

    atom_rows = []
    current_blockers_affect_score = (
        "omega_eff below declaration threshold" in blockers
        or "score_AM_plus below declaration target" in blockers
        or "field threshold failure" in blockers
    )
    for atom in card["proof_atoms"]:
        if atom["closed"]:
            continue
        field = field_rows[atom["field_id"]]
        field_def = field_defs[atom["field_id"]]
        current_field_omega = Decimal(field["omega_i_decimal"])
        possible = int(field["possible_credit"])
        verified = int(field["verified_credit"])
        new_verified = min(possible, verified + int(atom["credit"]))
        new_closure = field_closure(
            verified_credit=new_verified,
            possible_credit=possible,
            epsilon_denominator=int(fields["epsilon_denominator"]),
        )
        alpha = fraction_to_decimal(parse_rational_alpha(field_def["alpha"]))
        field_gain = new_closure["omega"] - current_field_omega
        new_sum = current_sum + (alpha * field_gain)
        trial_omegas = dict(current_omegas)
        trial_omegas[atom["field_id"]] = new_closure["omega"]
        new_min = min(trial_omegas.values())
        new_eff = effective_omega(
            omega_sum=new_sum,
            omega_min=new_min,
            debt_omega=debt_omega,
            overclaim_debt_omega=overclaim_omega,
            staleness_debt_omega=staleness_omega,
            kappa=int(fields["kappa"]),
        )["omega_eff"]
        atom_rows.append({
            "id": atom["id"],
            "field_id": atom["field_id"],
            "field_name": field["name"],
            "credit": atom["credit"],
            "verifier_key": atom["verifier_key"],
            "reason": atom["reason"],
            "estimated_field_omega_gain": decimal_text(field_gain),
            "estimated_effective_omega_gain": decimal_text(new_eff - current_eff),
            "affects_declaration_blockers": current_blockers_affect_score and new_eff > current_eff,
        })
    atom_rows.sort(key=lambda item: (Decimal(item["estimated_effective_omega_gain"]), Decimal(item["estimated_field_omega_gain"]), item["id"]), reverse=True)
    return {
        "version": "daylight-v17-triangulation-frontier-v0.1",
        "score_AM_plus": card["score_AM_plus"],
        "declared": card["declared"],
        "omega_eff_decimal": card["omega_eff_decimal"],
        "omega_gap_to_declaration": card["omega_gap_to_declaration"],
        "blockers": blockers,
        "weakest_fields": weakest_fields,
        "threshold_margins": threshold_margins,
        "open_proof_atoms": atom_rows,
    }


def cmd_frontier(args: argparse.Namespace) -> int:
    state = scorecard.load_state(args.state)
    fields = registry.load_fields_registry(args.fields)
    atoms = proof_atoms.load_proof_atom_registry(args.atoms)
    result = _frontier_report(state, fields, atoms)
    if args.format == "json":
        _print_json(result)
    else:
        print("Daylight v17.3 Triangulation frontier")
        print(f"score_AM_plus: {result['score_AM_plus']}")
        print(f"omega_eff: {result['omega_eff_decimal']}")
        print(f"omega_gap_to_declaration: {result['omega_gap_to_declaration']}")
        print("weakest fields:")
        for field in result["weakest_fields"][:5]:
            print(f"  - {field['id']} {field['name']}: omega={field['omega_i_decimal']} open_atoms={field['open_atom_count']}")
        print("open proof atoms:")
        for atom in result["open_proof_atoms"][:10]:
            print(
                f"  - {atom['id']}: field={atom['field_id']} "
                f"field_gain={atom['estimated_field_omega_gain']} "
                f"effective_gain={atom['estimated_effective_omega_gain']} "
                f"affects_blockers={str(atom['affects_declaration_blockers']).lower()}"
            )
    return 0


def cmd_fixture_demo(args: argparse.Namespace) -> int:
    card = scorecard.build_scorecard_from_paths(state_path=args.state, fields_path=args.fields, proof_atoms_path=args.atoms)
    if card["fixture"] is not True or card["claim_usable"] is not False:
        raise ValueError("fixture demo state must be fixture=true and claim_usable=false")
    _write_or_print(card, args.out, args.format)
    return 0


def _print_result(result: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        _print_json(result)
    else:
        for key, value in result.items():
            if isinstance(value, (dict, list)):
                continue
            print(f"{key}: {value}")


def cmd_horizon_vault_init(args: argparse.Namespace) -> int:
    result = horizon_vault.init_vault(args.root, force=args.force)
    _print_result(result, args.format)
    return 0


def cmd_horizon_vault_seal(args: argparse.Namespace) -> int:
    vault = horizon_vault.HorizonVault(args.root)
    result = vault.seal_file(
        input_path=args.input,
        output_path=args.out,
        state_path=args.state,
        policy_path=args.policy,
        mode=args.mode,
        nonce_hex=args.nonce_hex,
    )
    _print_result(result, args.format)
    return 0


def cmd_horizon_vault_open(args: argparse.Namespace) -> int:
    vault = horizon_vault.HorizonVault(args.root)
    result = vault.open_file(input_path=args.input, output_path=args.out, state_path=args.state)
    _print_result(result, args.format)
    return 0


def cmd_horizon_vault_inspect(args: argparse.Namespace) -> int:
    result = horizon_vault.inspect_file(args.input)
    _print_result(result, args.format)
    return 0


def cmd_horizon_release_prepare(args: argparse.Namespace) -> int:
    result = horizon_release.prepare_release(
        artifact_path=args.artifact,
        output_path=args.out,
        state_path=args.state,
        policy_path=args.policy,
        mode=args.mode,
    )
    _print_result(result, args.format)
    return 0


def cmd_horizon_release_verify(args: argparse.Namespace) -> int:
    result = horizon_release.verify_release(release_path=args.release, artifact_path=args.artifact, state_path=args.state)
    _print_result(result, args.format)
    return 0 if result["verified"] else 1


def cmd_horizon_release_gate(args: argparse.Namespace) -> int:
    result = horizon_release.gate_release(release_path=args.release, artifact_path=args.artifact, state_path=args.state)
    _print_result(result, args.format)
    return 0 if result["gate_allowed"] else 1


def cmd_explain(args: argparse.Namespace) -> int:
    card = load_json_no_floats(args.scorecard)
    if args.format == "json":
        _print_json(card)
    else:
        print(_text_summary(card))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    require_decimal_runtime()
    fields_registry = registry.load_fields_registry(args.fields)
    atom_registry = proof_atoms.load_proof_atom_registry(args.atoms)
    payload = {
        "ok": True,
        "decimal_ln_exp": True,
        "alpha_sum": f"{registry.alpha_sum(fields_registry).numerator}/{registry.alpha_sum(fields_registry).denominator}",
        "omega_threshold_decimal": decimal_text(LN_1E9),
        "fields_digest": registry.fields_digest(fields_registry),
        "proof_atoms_digest": proof_atoms.proof_atoms_digest(atom_registry),
    }
    if args.format == "json":
        _print_json(payload)
    else:
        print("daylight-v17-event-horizon: doctor pass")
        print(f"alpha_sum: {payload['alpha_sum']}")
        print(f"omega_threshold_decimal: {payload['omega_threshold_decimal']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="daylight-v17-event-horizon")
    parser.add_argument("--version", action="version", version=f"daylight-v17-event-horizon {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    score_cmd = sub.add_parser("score")
    score_cmd.add_argument("--state", required=True)
    score_cmd.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    score_cmd.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    score_cmd.add_argument("--out")
    score_cmd.add_argument("--format", choices=("text", "json"), default="text")
    score_cmd.set_defaults(func=cmd_score)

    verify = sub.add_parser("verify-scorecard")
    verify.add_argument("scorecard")
    verify.add_argument("--state", required=True)
    verify.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    verify.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    verify.add_argument("--format", choices=("text", "json"), default="text")
    verify.set_defaults(func=cmd_verify_scorecard)

    fracture_cmd = sub.add_parser("fracture")
    fracture_cmd.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    fracture_cmd.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    fracture_cmd.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    fracture_cmd.add_argument("--format", choices=("text", "json"), default="text")
    fracture_cmd.set_defaults(func=cmd_fracture)

    vector = sub.add_parser("vector")
    vector.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    vector.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    vector.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    vector.add_argument("--out")
    vector.add_argument("--format", choices=("text", "json"), default="text")
    vector.set_defaults(func=cmd_vector)

    agreement = sub.add_parser("agreement")
    agreement.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    agreement.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    agreement.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    agreement.add_argument("--vectors")
    agreement.add_argument("--format", choices=("text", "json"), default="text")
    agreement.set_defaults(func=cmd_agreement)

    gate = sub.add_parser("declaration-gate")
    gate.add_argument("--scorecard", default=str(DEFAULT_CURRENT_SCORECARD))
    gate.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    gate.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    gate.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    gate.add_argument("--format", choices=("text", "json"), default="text")
    gate.set_defaults(func=cmd_declaration_gate)

    blockers = sub.add_parser("blockers")
    blockers.add_argument("--scorecard", default=str(DEFAULT_CURRENT_SCORECARD))
    blockers.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    blockers.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    blockers.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    blockers.add_argument("--format", choices=("text", "json"), default="text")
    blockers.set_defaults(func=cmd_blockers)

    frontier = sub.add_parser("frontier")
    frontier.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    frontier.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    frontier.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    frontier.add_argument("--format", choices=("text", "json"), default="text")
    frontier.set_defaults(func=cmd_frontier)

    fixture = sub.add_parser("fixture-demo")
    fixture.add_argument("--state", default=str(DEFAULT_FIXTURE_STATE))
    fixture.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    fixture.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    fixture.add_argument("--out", default=str(DEFAULT_FIXTURE_SCORECARD))
    fixture.add_argument("--format", choices=("text", "json"), default="text")
    fixture.set_defaults(func=cmd_fixture_demo)

    hvault = sub.add_parser("horizon-vault")
    hvault_sub = hvault.add_subparsers(dest="horizon_vault_command", required=True)
    hvault_init = hvault_sub.add_parser("init")
    hvault_init.add_argument("--root", default=str(horizon_vault.DEFAULT_ROOT))
    hvault_init.add_argument("--force", action="store_true")
    hvault_init.add_argument("--format", choices=("text", "json"), default="text")
    hvault_init.set_defaults(func=cmd_horizon_vault_init)

    hvault_seal = hvault_sub.add_parser("seal")
    hvault_seal.add_argument("--root", default=str(horizon_vault.DEFAULT_ROOT))
    hvault_seal.add_argument("--in", dest="input", required=True)
    hvault_seal.add_argument("--out", required=True)
    hvault_seal.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    hvault_seal.add_argument("--policy")
    hvault_seal.add_argument("--mode", choices=("research", "declaration", "production"), default="research")
    hvault_seal.add_argument("--nonce-hex")
    hvault_seal.add_argument("--format", choices=("text", "json"), default="text")
    hvault_seal.set_defaults(func=cmd_horizon_vault_seal)

    hvault_open = hvault_sub.add_parser("open")
    hvault_open.add_argument("--root", default=str(horizon_vault.DEFAULT_ROOT))
    hvault_open.add_argument("--in", dest="input", required=True)
    hvault_open.add_argument("--out", required=True)
    hvault_open.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    hvault_open.add_argument("--format", choices=("text", "json"), default="text")
    hvault_open.set_defaults(func=cmd_horizon_vault_open)

    hvault_inspect = hvault_sub.add_parser("inspect")
    hvault_inspect.add_argument("--root", default=str(horizon_vault.DEFAULT_ROOT))
    hvault_inspect.add_argument("--in", dest="input", required=True)
    hvault_inspect.add_argument("--format", choices=("text", "json"), default="text")
    hvault_inspect.set_defaults(func=cmd_horizon_vault_inspect)

    hrelease = sub.add_parser("horizon-release")
    hrelease_sub = hrelease.add_subparsers(dest="horizon_release_command", required=True)
    hprepare = hrelease_sub.add_parser("prepare")
    hprepare.add_argument("--artifact", required=True)
    hprepare.add_argument("--out")
    hprepare.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    hprepare.add_argument("--policy")
    hprepare.add_argument("--mode", choices=("research", "declaration", "production"), default="research")
    hprepare.add_argument("--format", choices=("text", "json"), default="text")
    hprepare.set_defaults(func=cmd_horizon_release_prepare)

    hverify = hrelease_sub.add_parser("verify")
    hverify.add_argument("--release", required=True)
    hverify.add_argument("--artifact")
    hverify.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    hverify.add_argument("--format", choices=("text", "json"), default="text")
    hverify.set_defaults(func=cmd_horizon_release_verify)

    hgate = hrelease_sub.add_parser("gate")
    hgate.add_argument("--release", required=True)
    hgate.add_argument("--artifact")
    hgate.add_argument("--state", default=str(DEFAULT_CURRENT_STATE))
    hgate.add_argument("--format", choices=("text", "json"), default="text")
    hgate.set_defaults(func=cmd_horizon_release_gate)

    explain = sub.add_parser("explain")
    explain.add_argument("--scorecard", required=True)
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.set_defaults(func=cmd_explain)

    doctor = sub.add_parser("doctor")
    doctor.add_argument("--fields", default=str(registry.DEFAULT_FIELDS_PATH))
    doctor.add_argument("--atoms", default=str(proof_atoms.DEFAULT_PROOF_ATOMS_PATH))
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.set_defaults(func=cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (
        OSError,
        KeyError,
        ValueError,
        horizon_vault.HorizonVaultRefused,
        horizon_release.HorizonReleaseError,
    ) as exc:
        print(f"daylight-v17-event-horizon: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
