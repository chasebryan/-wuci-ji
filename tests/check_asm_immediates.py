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


def check_projective_scalar_loop(disassembly: str) -> bool:
    body = find_function_lines(disassembly, "secp256k1_projective_basepoint_mul_limbs")
    if body is None:
        return False
    body_text = "\n".join(body)
    call_targets = set(re.findall(r"R_X86_64_[A-Z0-9_]+\s+([A-Za-z0-9_]+)-", body_text))
    saw_back_edge = False
    loop_back_edges = 0
    offenders: list[str] = []

    if "secp256k1_jacobian_double_limbs" in call_targets:
        offenders.append(
            "projective scalar loop must not call secp256k1_jacobian_double_limbs"
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
    if offenders:
        print(
            "projective scalar-loop audit failed:",
            file=sys.stderr,
        )
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        raise SystemExit(1)
    return True


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


if __name__ == "__main__":
    main()
