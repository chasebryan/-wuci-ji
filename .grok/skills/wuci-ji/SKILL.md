---
name: wuci-ji
description: Deeply integrated expert for the -wuci-ji (WUCI) project. Activate for any work involving the assembly binary, src/*.s, tools/*.zig, tests/, make targets, witness bundles, Gate contracts, self-release proofs, CAGE/QCAGE/HARDEN/INSTALL, or AGENTS.md rules. Use when the user mentions wuci-ji, wuci, make test, witness, gate, cage, or works in this repo. Always enforce the strict defensive boundaries.
---

# WUCI-JI Local Integration

You are now operating as a native collaborator inside the `-wuci-ji` project (repo root: `/home/ckb/-wuci-ji`, use relative paths like `src/sys.s`, `tools/wuci_witness.zig`, `tests/wuci_aead_boundary.py`).

The project root `AGENTS.md` (and its component-specific sections) are **mandatory** and take highest precedence. Re-read them at the start of any non-trivial task. You must follow every rule exactly.

## Mandatory Rules (condensed from AGENTS.md)

**WUCI-CAGE / QCAGE / HARDEN / INSTALL** (and all work):
- Strictly **defensive only**. Never add exploit generation, vulnerability reproduction, offensive scanning, jailbreaks, malware, or network attack logic.
- Do **not** claim runtime sandboxing, OS containment, no-network enforcement, quantum-safety from classical crypto (secp256k1, X25519, etc.), or production authority from fixtures.
- Prefer: deterministic fixtures, tempdirs, stdlib-only Python, no `shell=True`/`eval`, atomic writes, symlink/hardlink rejection in public evidence.
- **Always** run targeted tests (e.g. the relevant `make *-test`, `make gate-contract-asm`, `make witness-zig-test`, `python3 tests/xxx.py`) before any "done" / final response on changes.
- Fixture FROST and authority roots are **test-only**. Never treat as production.

**Assembly core (src/*.s + include/wuci.inc)**:
- Changes must keep `make` builds + `tests/check_asm_immediates.py` + selftest + policy matrices passing.
- Pay extreme attention to immediates, zeroization, O_NOFOLLOW | O_EXCL | O_CLOEXEC, auth-before-plaintext, exit-time scrubbing.
- Current WIP area (as of recent work): streaming authenticated open (temp + RENAME_NOREPLACE path prepared in `sys.s` / `write_open_plaintext`; full streaming read loop still TODO).

**Zig tools** (`tools/*.zig`):
- Use current Zig (0.17+ dev on this machine). `@splat` and modern patterns are expected.
- Active lanes: `wuci_witness.zig`, `wuci_ledger.zig`, `wuci_gate_contract.zig`, `wuci_install.py` (Python orchestration), etc.

**Python tests & harness**:
- `make test` runs the full suite (CPython).
- Individual: `python3 tests/<name>.py` (some support `--quiet`).
- Policy matrices and attestation tamper tests are the gold standard for boundary enforcement.

## Essential Commands & Workflows

**Build & basic verification**:
- `make` (or `make clean && make`) — native Linux x86_64
- `make selftest`
- `make test`
- `make build-linux` (cross from non-Linux)
- `./build/wuci-ji selftest`
- `./build/wuci-ji <command> ...` (see full list with `./build/wuci-ji`)

**High-signal proof targets** (run before claiming a proof is complete):
- `make gate-contract-asm gate-contract-zig`
- `make witness-zig witness-zig-test witness-archive-test`
- `make self-release-asm-contract-proof self-release-anchored-proof self-release-witness-bundle`
- `make zig-release-*` equivalents
- `make harden-proof harden0-*`
- `make cage-proof qcage-proof`
- `make ledger-proof-test ledger-asm-test`
- `make authority-root-check authority-anchor-test`
- `make install-proof` (after copying install root key)

**Zig-built tools** (after relevant `make`):
- `build/wuci-witness`
- `build/wuci-ledger-tool`
- `build/wuci-gate-contract` (if present)

**Common safe patterns**:
- Use file-based commands (`-file`, `-keyfile`) for no-overwrite semantics.
- For open paths that write files: always verify no plaintext appears on final path until tag check + rename succeeds.
- When touching public evidence (witness bundles, archives): strictly enforce the documented file sets; reject private material, symlinks, wrong mtimes, etc.

## Your Behavior When Working Here

1. **At the start of any task** that touches code/tests/proofs: explicitly acknowledge the AGENTS.md rules and state which targeted verification you will run.
2. **Before editing**: understand the current boundary (read relevant test + json policy file + the asm handler).
3. **After changes**:
   - Rebuild (`make` or targeted).
   - Run the narrowest relevant test(s) + at least one broader matrix if the change affects policy.
   - For assembly: `tests/check_asm_immediates.py` where applicable.
4. Use `run_terminal_command` for builds/tests (never fake results).
5. When pushing or committing: the change must be minimal, well-described, and accompanied by passing targeted checks.
6. Prefer deterministic, local, stdlib, fixture-based approaches.
7. If something would require relaxing a rule in AGENTS.md, stop and surface the conflict.

## Useful Files to Reference Quickly

- `AGENTS.md` — the law
- `README.md` — high-level commands and self-release flows
- `docs/SECURITY_BOUNDARY.md`, `docs/THREAT_MODEL.md`
- `Makefile` — authoritative list of targets
- `tests/check_asm_immediates.py` — disassembly guard
- `docs/wuci_gate_boundary.json`, `docs/wuci_ledger_format.json`, etc. — policy contracts
- `src/sys.s`, `src/wuci-ji.s`, `src/main.s` — I/O, AEAD, dispatch
- `tools/wuci_witness.zig`, `tools/wuci_ledger.zig` — current active Zig verifiers

You are now fully integrated. Use `/wuci-ji` (or just mention the project) to activate this context in future turns. When the user asks you to do something in this tree, act as a careful, rule-following native developer of the project.

# Continuous Improvement
- Streaming file open: direct file paths, Gate-authorized file paths, and
  file manifest/warrant SHA lanes are streamed; stdin/display/v3 recipient
  paths remain bounded where documented.
- Full native `make test` requires BMI2+AVX for the current X25519 helper;
  use `make test-linux` with qemu-user on hosts without those CPU features.
- Before handoff, rerun targeted AEAD/Gate/CAGE tests and the relevant
  cross-built harness.
