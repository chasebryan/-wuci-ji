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


def branch_target(rest: str) -> int | None:
    match = re.search(r"\b([0-9a-f]+)\s+<", rest)
    return None if match is None else int(match.group(1), 16)


def relocation_call_targets(lines: list[str]) -> set[str]:
    text = "\n".join(lines)
    relocation_targets = set(
        re.findall(r"R_X86_64_[A-Z0-9_]+\s+([A-Za-z0-9_]+)-", text)
    )
    resolved_targets = set(re.findall(r"<([A-Za-z0-9_]+)>", text))
    return relocation_targets | resolved_targets


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


def check_public_affine_mul_boundary(disassemblies: list[tuple[Path, str]]) -> None:
    public_wrapper = "secp256k1_public_point_mul_limbs"
    affine_mul = "secp256k1_point_mul_limbs"
    public_callers = {
        "run_secp256k1_basepoint_mul",
        "run_frost_secp256k1_group_commitment",
        "run_frost_secp256k1_verify",
    }
    secret_bearing_callers = {
        "frost_secp256k1_commit_scalar",
        "run_frost_secp256k1_commit",
        "run_frost_secp256k1_signing_share",
        "run_frost_secp256k1_aggregate",
    }
    found_public_wrapper = False
    found_public_callers: set[str] = set()
    found_secret_bearing_callers: set[str] = set()
    offenders: list[str] = []

    for _obj, disassembly in disassemblies:
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

        for caller in secret_bearing_callers:
            body = find_function_lines(disassembly, caller)
            if body is None:
                continue
            found_secret_bearing_callers.add(caller)
            call_targets = relocation_call_targets(body)
            for forbidden in (public_wrapper, affine_mul):
                if forbidden in call_targets:
                    offenders.append(f"{caller} must not call {forbidden}")

    missing_public = sorted(public_callers - found_public_callers)
    missing_secret = sorted(secret_bearing_callers - found_secret_bearing_callers)
    if not found_public_wrapper:
        raise SystemExit(f"{public_wrapper} not found in object disassembly")
    if missing_public:
        raise SystemExit(
            "public affine-mul callers not found in object disassembly: "
            + ", ".join(missing_public)
        )
    if missing_secret:
        raise SystemExit(
            "secret-bearing FROST callers not found in object disassembly: "
            + ", ".join(missing_secret)
        )
    if offenders:
        print("public affine-mul boundary audit failed:", file=sys.stderr)
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
    check_public_affine_mul_boundary(disassemblies)


if __name__ == "__main__":
    main()
