#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path


ABS_LOAD_RE = re.compile(r"\bmov\w*\s+0x([0-9a-f]+),%[a-z0-9]+")
FUNC_LABEL_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9.]*)\b(.*)$")


def run_tool(argv: list[str]) -> str:
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr or f"{argv[0]} failed with {proc.returncode}")
    return proc.stdout


def watched_lengths(nm_output: str) -> dict[int, list[str]]:
    watched: dict[int, list[str]] = {}
    for line in nm_output.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1].lower() != "a":
            continue
        name = parts[2]
        if not name.endswith("_len"):
            continue
        watched.setdefault(int(parts[0], 16), []).append(name)
    return watched


def find_function_lines(disassembly: str, name: str) -> list[str] | None:
    lines: list[str] = []
    in_function = False
    for line in disassembly.splitlines():
        label = FUNC_LABEL_RE.match(line)
        if label:
            if in_function:
                break
            in_function = label.group(2) == name
            if in_function:
                lines.append(line)
            continue
        if in_function:
            lines.append(line)
    return lines or None


def iter_function_lines(disassembly: str):
    name: str | None = None
    lines: list[str] = []
    for line in disassembly.splitlines():
        label = FUNC_LABEL_RE.match(line)
        if label:
            if name is not None:
                yield name, lines
            name = label.group(2)
            lines = [line]
            continue
        if name is not None:
            lines.append(line)
    if name is not None:
        yield name, lines


def branch_target(rest: str) -> int | None:
    match = re.search(r"\b([0-9a-f]+)\s+<", rest)
    return None if match is None else int(match.group(1), 16)


def relocation_call_targets(lines: list[str]) -> set[str]:
    targets: set[str] = set()
    for line in lines:
        targets.update(re.findall(r"R_X86_64_[A-Z0-9_]+\s+([A-Za-z0-9_]+)-", line))
        match = INSN_RE.match(line)
        if match:
            targets.update(re.findall(r"<([A-Za-z0-9_]+)>", match.group(3)))
    return targets


def local_branch_lines(lines: list[str]) -> list[str]:
    branches: list[str] = []
    for line in lines:
        match = INSN_RE.match(line)
        if match and match.group(2).startswith("j"):
            branches.append(line.strip())
    return branches


def fixed_loop_branch_offenders(lines: list[str], name: str) -> list[str]:
    loop_back_edges = 0
    offenders: list[str] = []
    for line in lines:
        match = INSN_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        rest = match.group(3)
        if not mnemonic.startswith("j"):
            continue
        target = branch_target(rest)
        if mnemonic == "jne" and target is not None and target < address:
            loop_back_edges += 1
            continue
        offenders.append(line.strip())
    if loop_back_edges != 1:
        offenders.append(f"{name} must contain exactly one fixed loop back-edge")
    return offenders


def check_projective_scalar_loop(disassembly: str) -> bool:
    body = find_function_lines(disassembly, "secp256k1_projective_basepoint_mul_limbs")
    if body is None:
        return False
    call_targets = relocation_call_targets(body)
    saw_back_edge = False
    loop_back_edges = 0
    offenders: list[str] = []

    if "secp256k1_jacobian_double_limbs" in call_targets:
        offenders.append(
            "projective scalar loop must not call secp256k1_jacobian_double_limbs"
        )
    if "secp256k1_jacobian_mixed_add_limbs" in call_targets:
        offenders.append(
            "projective scalar loop must not call secp256k1_jacobian_mixed_add_limbs"
        )

    for line in body:
        match = INSN_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        rest = match.group(3)
        if mnemonic.startswith("call"):
            continue
        if not mnemonic.startswith("j"):
            continue
        target = branch_target(rest)
        if mnemonic == "jne" and target is not None and target < address:
            saw_back_edge = True
            loop_back_edges += 1
            continue
        if not saw_back_edge:
            offenders.append(line.strip())

    if loop_back_edges != 1:
        raise SystemExit(
            "expected exactly one fixed loop back-edge in "
            "secp256k1_projective_basepoint_mul_limbs"
        )
    if "secp256k1_jacobian_double_finite_limbs" not in call_targets:
        raise SystemExit(
            "secp256k1_projective_basepoint_mul_limbs must call "
            "secp256k1_jacobian_double_finite_limbs"
        )
    if "secp256k1_jacobian_mixed_add_masked_limbs" not in call_targets:
        raise SystemExit(
            "secp256k1_projective_basepoint_mul_limbs must call "
            "secp256k1_jacobian_mixed_add_masked_limbs"
        )
    masked_add = find_function_lines(disassembly, "secp256k1_jacobian_mixed_add_masked_limbs")
    if masked_add is None:
        raise SystemExit("secp256k1_jacobian_mixed_add_masked_limbs not found")
    masked_add_branches = local_branch_lines(masked_add)
    if masked_add_branches:
        offenders.extend(
            f"masked mixed-add helper contains branch: {line}"
            for line in masked_add_branches
        )
    if offenders:
        print(
            "projective scalar-loop audit failed:",
            file=sys.stderr,
        )
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)
    return True


def check_field_inversion_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    field_mul = "secp256k1_field_mul_limbs"
    field_inverse = "secp256k1_field_inverse_limbs"
    field_sqrt = "secp256k1_field_sqrt_limbs"
    found_mul = False
    found_inverse = False
    found_sqrt = False
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        mul_body = find_function_lines(disassembly, field_mul)
        if mul_body is not None:
            found_mul = True
            offenders.extend(
                f"{field_mul} branch outside fixed loop: {line}"
                for line in fixed_loop_branch_offenders(mul_body, field_mul)
            )

        inverse_body = find_function_lines(disassembly, field_inverse)
        if inverse_body is not None:
            found_inverse = True
            call_targets = relocation_call_targets(inverse_body)
            if field_mul not in call_targets:
                offenders.append(f"{field_inverse} must call {field_mul}")
            if "secp256k1_field_select_mask" not in call_targets:
                offenders.append(f"{field_inverse} must call secp256k1_field_select_mask")
            offenders.extend(
                f"{field_inverse} branch outside fixed loop: {line}"
                for line in fixed_loop_branch_offenders(inverse_body, field_inverse)
            )

        sqrt_body = find_function_lines(disassembly, field_sqrt)
        if sqrt_body is not None:
            found_sqrt = True
            call_targets = relocation_call_targets(sqrt_body)
            if field_mul not in call_targets:
                offenders.append(f"{field_sqrt} must call {field_mul}")
            if "secp256k1_field_select_mask" not in call_targets:
                offenders.append(f"{field_sqrt} must call secp256k1_field_select_mask")
            offenders.extend(
                f"{field_sqrt} branch outside fixed loop: {line}"
                for line in fixed_loop_branch_offenders(sqrt_body, field_sqrt)
            )

    if not found_mul:
        raise SystemExit(f"{field_mul} not found in object disassembly")
    if not found_inverse:
        raise SystemExit(f"{field_inverse} not found in object disassembly")
    if not found_sqrt:
        raise SystemExit(f"{field_sqrt} not found in object disassembly")
    if offenders:
        print("field exponentiation audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_scalar_inversion_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    scalar_mul = "secp256k1_scalar_mul_limbs"
    scalar_inverse = "secp256k1_scalar_inverse_limbs"
    found_mul = False
    found_inverse = False
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        mul_body = find_function_lines(disassembly, scalar_mul)
        if mul_body is not None:
            found_mul = True
            offenders.extend(
                f"{scalar_mul} branch outside fixed loop: {line}"
                for line in fixed_loop_branch_offenders(mul_body, scalar_mul)
            )

        inverse_body = find_function_lines(disassembly, scalar_inverse)
        if inverse_body is None:
            continue
        found_inverse = True
        call_targets = relocation_call_targets(inverse_body)
        if scalar_mul not in call_targets:
            offenders.append(f"{scalar_inverse} must call {scalar_mul}")
        if "secp256k1_field_select_mask" not in call_targets:
            offenders.append(f"{scalar_inverse} must call secp256k1_field_select_mask")
        offenders.extend(
            f"{scalar_inverse} branch outside fixed loop: {line}"
            for line in fixed_loop_branch_offenders(inverse_body, scalar_inverse)
        )

    if not found_mul:
        raise SystemExit(f"{scalar_mul} not found in object disassembly")
    if not found_inverse:
        raise SystemExit(f"{scalar_inverse} not found in object disassembly")
    if offenders:
        print("scalar inversion audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_scalar_arithmetic_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    branchless_helpers = {
        "secp256k1_scalar_add_limbs",
        "secp256k1_scalar_sub_limbs",
        "secp256k1_scalar_conditional_sub_n",
    }
    scalar_mul = "secp256k1_scalar_mul_limbs"
    signing_share = "run_frost_secp256k1_signing_share"
    aggregate = "run_frost_secp256k1_aggregate"
    scalar_add = "secp256k1_scalar_add_limbs"
    scalar_mul_allowed_callers = {
        "run_secp256k1_scalar_mul",
        "run_frost_secp256k1_lagrange",
        signing_share,
        "secp256k1_scalar_inverse_limbs",
    }
    scalar_add_allowed_callers = {
        "run_secp256k1_scalar_add",
        signing_share,
        aggregate,
        scalar_mul,
    }
    aggregate_forbidden = {
        "frost_secp256k1_commit_scalar",
        "secp256k1_jacobian_to_affine_finite_limbs",
        "secp256k1_jacobian_to_affine_limbs",
        "secp256k1_point_add_limbs",
        "secp256k1_point_mul_limbs",
        "secp256k1_projective_basepoint_mul_limbs",
        "secp256k1_public_point_mul_limbs",
        "secp256k1_scalar_inverse_limbs",
        "secp256k1_scalar_mul_limbs",
    }
    found_helpers: set[str] = set()
    found_signing_share = False
    found_aggregate = False
    observed_scalar_mul_callers: set[str] = set()
    observed_scalar_add_callers: set[str] = set()
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        for function_name, body in iter_function_lines(disassembly):
            call_targets = relocation_call_targets(body)
            if scalar_mul in call_targets:
                observed_scalar_mul_callers.add(function_name)
            if scalar_add in call_targets:
                observed_scalar_add_callers.add(function_name)

        for helper in branchless_helpers:
            body = find_function_lines(disassembly, helper)
            if body is None:
                continue
            found_helpers.add(helper)
            offenders.extend(
                f"{helper} contains branch: {line}"
                for line in local_branch_lines(body)
            )

        mul_body = find_function_lines(disassembly, scalar_mul)
        if mul_body is not None:
            found_helpers.add(scalar_mul)
            offenders.extend(
                f"{scalar_mul} branch outside fixed loop: {line}"
                for line in fixed_loop_branch_offenders(mul_body, scalar_mul)
            )

        signing_body = find_function_lines(disassembly, signing_share)
        if signing_body is not None:
            found_signing_share = True
            call_targets = relocation_call_targets(signing_body)
            if scalar_add not in call_targets:
                offenders.append(f"{signing_share} must call {scalar_add}")
            if scalar_mul not in call_targets:
                offenders.append(f"{signing_share} must call {scalar_mul}")

        aggregate_body = find_function_lines(disassembly, aggregate)
        if aggregate_body is not None:
            found_aggregate = True
            call_targets = relocation_call_targets(aggregate_body)
            if "load_secp256k1_compressed_point_arg" not in call_targets:
                offenders.append(
                    f"{aggregate} must call load_secp256k1_compressed_point_arg"
                )
            if scalar_add not in call_targets:
                offenders.append(f"{aggregate} must call {scalar_add}")
            for forbidden in sorted(aggregate_forbidden & call_targets):
                offenders.append(f"{aggregate} must not call {forbidden}")

    missing_helpers = sorted((branchless_helpers | {scalar_mul}) - found_helpers)
    unexpected_mul_callers = sorted(observed_scalar_mul_callers - scalar_mul_allowed_callers)
    unexpected_add_callers = sorted(observed_scalar_add_callers - scalar_add_allowed_callers)
    if missing_helpers:
        raise SystemExit(
            "scalar arithmetic helpers not found in object disassembly: "
            + ", ".join(missing_helpers)
        )
    if not found_signing_share:
        raise SystemExit(f"{signing_share} not found in object disassembly")
    if not found_aggregate:
        raise SystemExit(f"{aggregate} not found in object disassembly")
    if unexpected_mul_callers:
        offenders.append(
            f"{scalar_mul} has unclassified callers: "
            + ", ".join(unexpected_mul_callers)
        )
    if unexpected_add_callers:
        offenders.append(
            f"{scalar_add} has unclassified callers: "
            + ", ".join(unexpected_add_callers)
        )
    if offenders:
        print("scalar arithmetic boundary audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_public_affine_mul_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    public_wrapper = "secp256k1_public_point_mul_limbs"
    affine_mul = "secp256k1_point_mul_limbs"
    projective_basepoint = "secp256k1_projective_basepoint_mul_limbs"
    commit_helper = "frost_secp256k1_commit_scalar"
    public_decode_helpers = {
        "load_secp256k1_compressed_point_arg",
        public_wrapper,
        affine_mul,
    }
    public_callers = {
        "run_secp256k1_basepoint_mul",
        "run_frost_secp256k1_group_commitment",
        "run_frost_secp256k1_verify",
    }
    secret_scalar_callers = {
        commit_helper,
        "run_frost_secp256k1_commit",
        "run_frost_secp256k1_signing_share",
    }
    found_public_wrapper = False
    found_public_callers: set[str] = set()
    found_secret_scalar_callers: set[str] = set()
    observed_wrapper_callers: set[str] = set()
    observed_affine_callers: set[str] = set()
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        for function_name, body in iter_function_lines(disassembly):
            call_targets = relocation_call_targets(body)
            if public_wrapper in call_targets:
                observed_wrapper_callers.add(function_name)
            if affine_mul in call_targets:
                observed_affine_callers.add(function_name)

        wrapper_body = find_function_lines(disassembly, public_wrapper)
        if wrapper_body is not None:
            found_public_wrapper = True
            wrapper_targets = relocation_call_targets(wrapper_body)
            if affine_mul not in wrapper_targets:
                offenders.append(f"{public_wrapper} must jump to {affine_mul}")

        for caller in public_callers:
            body = find_function_lines(disassembly, caller)
            if body is None:
                continue
            found_public_callers.add(caller)
            call_targets = relocation_call_targets(body)
            if public_wrapper not in call_targets:
                offenders.append(f"{caller} must call {public_wrapper}")
            if affine_mul in call_targets:
                offenders.append(f"{caller} must not call {affine_mul} directly")

        for caller in secret_scalar_callers:
            body = find_function_lines(disassembly, caller)
            if body is None:
                continue
            found_secret_scalar_callers.add(caller)
            call_targets = relocation_call_targets(body)
            if caller == commit_helper and projective_basepoint not in call_targets:
                offenders.append(f"{commit_helper} must call {projective_basepoint}")
            if caller == "run_frost_secp256k1_commit" and commit_helper not in call_targets:
                offenders.append(f"run_frost_secp256k1_commit must call {commit_helper}")
            for forbidden in public_decode_helpers:
                if forbidden in call_targets:
                    offenders.append(f"{caller} must not call {forbidden}")

    unexpected_wrapper_callers = sorted(observed_wrapper_callers - public_callers)
    unexpected_affine_callers = sorted(observed_affine_callers - {public_wrapper})
    missing_public = sorted(public_callers - found_public_callers)
    missing_secret = sorted(secret_scalar_callers - found_secret_scalar_callers)
    if not found_public_wrapper:
        raise SystemExit(f"{public_wrapper} not found in object disassembly")
    if missing_public:
        raise SystemExit(
            "public affine-mul callers not found in object disassembly: "
            + ", ".join(missing_public)
        )
    if missing_secret:
        raise SystemExit(
            "secret scalar FROST callers not found in object disassembly: "
            + ", ".join(missing_secret)
        )
    if unexpected_wrapper_callers:
        offenders.append(
            f"{public_wrapper} has unclassified callers: "
            + ", ".join(unexpected_wrapper_callers)
        )
    if unexpected_affine_callers:
        offenders.append(
            f"{affine_mul} has unclassified direct callers: "
            + ", ".join(unexpected_affine_callers)
        )
    if offenders:
        print("public affine-mul boundary audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_secret_frost_path_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    projective_basepoint = "secp256k1_projective_basepoint_mul_limbs"
    public_wrapper = "secp256k1_public_point_mul_limbs"
    affine_mul = "secp256k1_point_mul_limbs"
    finite_affine = "secp256k1_jacobian_to_affine_finite_limbs"
    generic_affine = "secp256k1_jacobian_to_affine_limbs"
    commit_helper = "frost_secp256k1_commit_scalar"

    required_calls = {
        "run_frost_secp256k1_nonce_generate": {
            "fill_random",
            "frost_hash_to_scalar_mem",
            "store_le4_to_be32",
        },
        "run_frost_secp256k1_commit": {
            commit_helper,
        },
        commit_helper: {
            finite_affine,
            projective_basepoint,
            "store_le4_to_be32",
        },
        "run_frost_secp256k1_signing_share": {
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_mul_limbs",
        },
    }
    point_or_public_forbidden = {
        "load_secp256k1_compressed_point_arg",
        "secp256k1_point_add_limbs",
        public_wrapper,
        affine_mul,
    }
    forbidden_calls = {
        "run_frost_secp256k1_nonce_generate": point_or_public_forbidden
        | {
            commit_helper,
            finite_affine,
            generic_affine,
            projective_basepoint,
            "encode_secp256k1_compressed_point",
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_inverse_limbs",
            "secp256k1_scalar_mul_limbs",
        },
        "run_frost_secp256k1_commit": point_or_public_forbidden
        | {
            finite_affine,
            generic_affine,
            projective_basepoint,
            "encode_secp256k1_compressed_point",
        },
        commit_helper: point_or_public_forbidden
        | {
            generic_affine,
        },
        "run_frost_secp256k1_signing_share": point_or_public_forbidden
        | {
            commit_helper,
            finite_affine,
            generic_affine,
            projective_basepoint,
            "encode_secp256k1_compressed_point",
            "secp256k1_scalar_inverse_limbs",
        },
    }
    projective_allowed_callers = {
        "run_secp256k1_projective_basepoint_mul",
        commit_helper,
        "run_frost_secp256k1_verify",
    }
    found_roots: set[str] = set()
    observed_projective_callers: set[str] = set()
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        for function_name, body in iter_function_lines(disassembly):
            call_targets = relocation_call_targets(body)
            if projective_basepoint in call_targets:
                observed_projective_callers.add(function_name)

        for root, required in required_calls.items():
            body = find_function_lines(disassembly, root)
            if body is None:
                continue
            found_roots.add(root)
            call_targets = relocation_call_targets(body)
            for target in sorted(required - call_targets):
                offenders.append(f"{root} must call {target}")
            for target in sorted(forbidden_calls[root] & call_targets):
                offenders.append(f"{root} must not call {target}")

    missing_roots = sorted(set(required_calls) - found_roots)
    unexpected_projective_callers = sorted(
        observed_projective_callers - projective_allowed_callers
    )
    if missing_roots:
        raise SystemExit(
            "secret-bearing FROST audit roots not found in object disassembly: "
            + ", ".join(missing_roots)
        )
    if unexpected_projective_callers:
        offenders.append(
            f"{projective_basepoint} has unclassified callers: "
            + ", ".join(unexpected_projective_callers)
        )
    if offenders:
        print("secret-bearing FROST path audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_frost_hash_scalar_loading_boundary(
    disassemblies: list[tuple[Path, str]],
) -> None:
    scalar_loader = "load_secp256k1_scalar_arg"
    hash_mem = "frost_hash_to_scalar_mem"
    hash_stdin = "frost_hash_to_scalar_stdin"
    hash_prefixed_stdin = "frost_hash_to_scalar_prefixed_stdin"
    nonce_generate = "run_frost_secp256k1_nonce_generate"
    binding_factor = "run_frost_secp256k1_binding_factor"
    challenge = "run_frost_secp256k1_challenge"
    signing_share = "run_frost_secp256k1_signing_share"

    required_calls = {
        nonce_generate: {
            scalar_loader,
            "fill_random",
            "store_le4_to_be32",
            hash_mem,
        },
        binding_factor: {
            "load_secp256k1_compressed_point_arg",
            "hex32_decode",
            scalar_loader,
            "store_le4_to_be32",
            hash_mem,
        },
        challenge: {
            "load_secp256k1_compressed_point_arg",
            hash_prefixed_stdin,
        },
        signing_share: {
            scalar_loader,
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_mul_limbs",
        },
        scalar_loader: {
            "hex32_decode",
            "load_be32_to_le4",
            "secp256k1_scalar_is_canonical_limbs",
        },
    }
    forbidden_calls = {
        nonce_generate: {
            hash_stdin,
            hash_prefixed_stdin,
            "frost_secp256k1_commit_scalar",
            "load_secp256k1_compressed_point_arg",
            "secp256k1_jacobian_to_affine_finite_limbs",
            "secp256k1_jacobian_to_affine_limbs",
            "secp256k1_projective_basepoint_mul_limbs",
            "secp256k1_public_point_mul_limbs",
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_inverse_limbs",
            "secp256k1_scalar_mul_limbs",
        },
        binding_factor: {
            hash_stdin,
            hash_prefixed_stdin,
            "frost_secp256k1_commit_scalar",
            "secp256k1_point_add_limbs",
            "secp256k1_point_mul_limbs",
            "secp256k1_projective_basepoint_mul_limbs",
            "secp256k1_public_point_mul_limbs",
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_inverse_limbs",
            "secp256k1_scalar_mul_limbs",
        },
        challenge: {
            scalar_loader,
            hash_mem,
            hash_stdin,
            "fill_random",
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_inverse_limbs",
            "secp256k1_scalar_mul_limbs",
        },
        signing_share: {
            hash_mem,
            hash_stdin,
            hash_prefixed_stdin,
            "fill_random",
            "frost_secp256k1_commit_scalar",
            "load_secp256k1_compressed_point_arg",
            "secp256k1_jacobian_to_affine_finite_limbs",
            "secp256k1_jacobian_to_affine_limbs",
            "secp256k1_projective_basepoint_mul_limbs",
            "secp256k1_public_point_mul_limbs",
        },
        scalar_loader: {
            hash_mem,
            hash_stdin,
            hash_prefixed_stdin,
            "fill_random",
            "frost_secp256k1_commit_scalar",
            "load_secp256k1_compressed_point_arg",
            "secp256k1_point_add_limbs",
            "secp256k1_point_mul_limbs",
            "secp256k1_projective_basepoint_mul_limbs",
            "secp256k1_public_point_mul_limbs",
            "secp256k1_scalar_add_limbs",
            "secp256k1_scalar_inverse_limbs",
            "secp256k1_scalar_mul_limbs",
        },
    }
    scalar_loader_allowed_callers = {
        "run_frost_secp256k1_aggregate",
        binding_factor,
        "run_frost_secp256k1_commit",
        "run_frost_secp256k1_commitment_hash",
        "run_frost_secp256k1_group_commitment",
        "run_frost_secp256k1_lagrange",
        nonce_generate,
        signing_share,
        "run_frost_secp256k1_verify",
        "run_secp256k1_basepoint_mul",
        "run_secp256k1_is_zero",
        "run_secp256k1_scalar_add",
        "run_secp256k1_scalar_inv",
        "run_secp256k1_scalar_mul",
        "run_secp256k1_scalar_sub",
    }
    hash_mem_allowed_callers = {
        binding_factor,
        nonce_generate,
        hash_stdin,
        hash_prefixed_stdin,
    }
    hash_stdin_allowed_callers = {
        "frost_hash_stdin",
        "run_frost_p256_h1",
        "run_frost_p256_h2",
        "run_frost_p256_h3",
        "run_frost_secp256k1_h1",
        "run_frost_secp256k1_h2",
        "run_frost_secp256k1_h3",
    }
    hash_prefixed_allowed_callers = {
        challenge,
        hash_stdin,
    }

    observed_scalar_loader_callers: set[str] = set()
    observed_hash_mem_callers: set[str] = set()
    observed_hash_stdin_callers: set[str] = set()
    observed_hash_prefixed_callers: set[str] = set()
    found_roots: set[str] = set()
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        for function_name, body in iter_function_lines(disassembly):
            call_targets = relocation_call_targets(body)
            if scalar_loader in call_targets:
                observed_scalar_loader_callers.add(function_name)
            if hash_mem in call_targets:
                observed_hash_mem_callers.add(function_name)
            if hash_stdin in call_targets:
                observed_hash_stdin_callers.add(function_name)
            if hash_prefixed_stdin in call_targets:
                observed_hash_prefixed_callers.add(function_name)

        for root, required in required_calls.items():
            body = find_function_lines(disassembly, root)
            if body is None:
                continue
            found_roots.add(root)
            call_targets = relocation_call_targets(body)
            for target in sorted(required - call_targets):
                offenders.append(f"{root} must call {target}")
            for target in sorted(forbidden_calls[root] & call_targets):
                offenders.append(f"{root} must not call {target}")

    missing_roots = sorted(set(required_calls) - found_roots)
    if missing_roots:
        raise SystemExit(
            "FROST hash/scalar-loading audit roots not found in object disassembly: "
            + ", ".join(missing_roots)
        )

    unexpected_scalar_loader_callers = sorted(
        observed_scalar_loader_callers - scalar_loader_allowed_callers
    )
    unexpected_hash_mem_callers = sorted(
        observed_hash_mem_callers - hash_mem_allowed_callers
    )
    unexpected_hash_stdin_callers = sorted(
        observed_hash_stdin_callers - hash_stdin_allowed_callers
    )
    unexpected_hash_prefixed_callers = sorted(
        observed_hash_prefixed_callers - hash_prefixed_allowed_callers
    )
    if unexpected_scalar_loader_callers:
        offenders.append(
            f"{scalar_loader} has unclassified callers: "
            + ", ".join(unexpected_scalar_loader_callers)
        )
    if unexpected_hash_mem_callers:
        offenders.append(
            f"{hash_mem} has unclassified callers: "
            + ", ".join(unexpected_hash_mem_callers)
        )
    if unexpected_hash_stdin_callers:
        offenders.append(
            f"{hash_stdin} has unclassified callers: "
            + ", ".join(unexpected_hash_stdin_callers)
        )
    if unexpected_hash_prefixed_callers:
        offenders.append(
            f"{hash_prefixed_stdin} has unclassified callers: "
            + ", ".join(unexpected_hash_prefixed_callers)
        )
    if offenders:
        print("FROST hash/scalar-loading boundary audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def check_finite_affine_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    finite_helper = "secp256k1_jacobian_to_affine_finite_limbs"
    generic_helper = "secp256k1_jacobian_to_affine_limbs"
    required_callers = {
        "run_secp256k1_projective_basepoint_mul",
        "frost_secp256k1_commit_scalar",
        "run_frost_secp256k1_verify",
    }
    found_callers: set[str] = set()
    saw_finite_helper = False
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
        finite_body = find_function_lines(disassembly, finite_helper)
        if finite_body is not None:
            saw_finite_helper = True
            offenders.extend(
                f"{finite_helper} contains branch: {line}"
                for line in local_branch_lines(finite_body)
            )

        for caller in required_callers:
            body = find_function_lines(disassembly, caller)
            if body is None:
                continue
            found_callers.add(caller)
            call_targets = relocation_call_targets(body)
            if generic_helper in call_targets:
                offenders.append(f"{caller} must not call {generic_helper}")
            if finite_helper not in call_targets:
                offenders.append(f"{caller} must call {finite_helper}")

    missing_callers = sorted(required_callers - found_callers)
    if not saw_finite_helper:
        raise SystemExit(f"{finite_helper} not found in object disassembly")
    if missing_callers:
        raise SystemExit(
            "finite affine boundary callers not found in object disassembly: "
            + ", ".join(missing_callers)
        )
    if offenders:
        print("finite affine-conversion audit failed:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_asm_immediates.py <object> [<object> ...]")

    nm = os.environ.get("NM", "nm")
    objdump = os.environ.get("OBJDUMP", "objdump")
    disassemblies: list[tuple[Path, str]] = []
    saw_lengths = False

    for arg in sys.argv[1:]:
        obj = Path(arg)
        lengths = watched_lengths(run_tool([nm, "-a", str(obj)]))
        saw_lengths = saw_lengths or bool(lengths)
        disassembly = run_tool([objdump, "-dr", str(obj)])
        disassemblies.append((obj, disassembly))

        offenders: list[str] = []
        for line in disassembly.splitlines():
            match = ABS_LOAD_RE.search(line)
            if not match:
                continue
            value = int(match.group(1), 16)
            if value in lengths:
                names = ", ".join(sorted(lengths[value]))
                offenders.append(f"{obj}: {line.strip()}  ; {names}")

        if offenders:
            print(
                "absolute memory reads found for assembly length constants:",
                file=sys.stderr,
            )
            for offender in offenders:
                print(f"  {offender}", file=sys.stderr)
            raise SystemExit(1)

    if not saw_lengths:
        raise SystemExit("no absolute *_len symbols found to check")

    for _obj, disassembly in disassemblies:
        if check_projective_scalar_loop(disassembly):
            break
    else:
        raise SystemExit(
            "secp256k1_projective_basepoint_mul_limbs not found in object disassembly"
        )

    check_finite_affine_boundary(disassemblies)
    check_field_inversion_boundary(disassemblies)
    check_scalar_inversion_boundary(disassemblies)
    check_scalar_arithmetic_boundary(disassemblies)
    check_public_affine_mul_boundary(disassemblies)
    check_secret_frost_path_boundary(disassemblies)
    check_frost_hash_scalar_loading_boundary(disassemblies)


if __name__ == "__main__":
    main()
