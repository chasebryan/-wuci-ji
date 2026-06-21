<img width="2172" height="724" alt="wsj-banner-github" src="https://github.com/user-attachments/assets/3e20bf66-1376-46b0-9f25-0ec619bf7224" />
# -wuci-ji
无此机(Wuci-ji)是一个专为 x86_64 架构机器设计的汇编语言项目，旨在探索机器码、底层执行、系统边界以及精确控制。

## Build and test

The `src/*.s` sources build an x86_64 Linux assembly program. Native `make`,
`make selftest`, and `make test` require a Linux x86_64 host with GNU `as`/`ld`.

On macOS or other non-Linux hosts with Zig installed, build the Linux ELF with:

```sh
make build-linux
```

To run the Zig-built Gate and self-release proofs on a Linux x86_64 host:

```sh
make gate-contract-asm
make self-release-asm-contract-proof
make gate-contract-zig
make zig-release-proof
make zig-release-contract-proof
```

`make gate-contract-asm` checks the native assembly flat-contract Gate command:
`gate-contract-verify <artifact> <contract>` and
`open-authorized-contract <keyfile> <artifact> <contract> <out>`.
`make self-release-asm-contract-proof` seals the native binary, warrants it,
emits a flat receipt contract, verifies and opens through the assembly Gate
command, compares the opened copy byte-for-byte, executes it, writes an
attestation, and verifies that attestation. `make gate-contract-zig` builds
`tools/wuci_gate_contract.zig` into
`build/wuci-gate-contract`, then uses the Zig-built Linux ELF to verify and
open through the fixed flat WUCI-GATE receipt contract. `make zig-release-proof`
builds `build/wuci-ji-linux-x86_64`, seals that binary with itself, warrants
it, passes WUCI-GATE, opens a byte-identical executable copy, writes an
attestation, and verifies the attestation. `make zig-release-contract-proof`
uses the same self-release loop but emits a flat receipt contract and opens the
binary through the Zig contract verifier instead of Python Gate open. On a
Linux host that needs user-mode QEMU to run the Zig-built ELF, pass:

```sh
make gate-contract-zig RELEASE_RUNNER=qemu-x86_64
make zig-release-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-contract-proof RELEASE_RUNNER=qemu-x86_64
```

To run the full test suite, use an x86_64 Linux environment and run:

```sh
make test
```

Repeated test runs reuse existing object files when assembly sources have not
changed. A local or system PyPy interpreter can run the Python harness:

```sh
make test-pypy
# or
make test PYTHON=/path/to/pypy3
```

On a Linux host with user-mode QEMU for x86_64 installed, the same suite can run
through:

```sh
make test-linux
```

Homebrew's macOS `qemu` formula provides `qemu-system-x86_64`, which boots whole
machines and does not run this Linux user-space ELF directly.

For a machine handoff checkpoint, see [BUILD_NOTES.md](BUILD_NOTES.md).

## Envelope commands

`seal <key>` reads plaintext from stdin and writes a framed ChaCha20-Poly1305
artifact containing a magic/version header, random nonce, ciphertext, and tag.

`open <key>` reads that artifact from stdin, verifies it, and writes plaintext
only after authentication succeeds.

## WUCI-FROST demo

WUCI-FROST / 无此签 / No Such Quorum is the authorization direction for this
machine: FROST should sign stable artifact manifests that decide whether an
artifact may be opened, released, trusted, or published. It is not an encryption
replacement; artifact secrecy stays in the ChaCha20-Poly1305 envelope.

The current FROST surface is a deterministic, non-production secp256k1 demo
that exercises the assembly primitives without accepting arbitrary signer
material:

```sh
make frost-demo
python3 tools/frost_secp256k1_workflow.py --print-fixture-manifest
python3 tools/frost_secp256k1_workflow.py --message "authorize manifest" --print-transcript-manifest
python3 tools/frost_secp256k1_workflow.py --message "authorize manifest" --json
```

`--fixture-manifest` accepts only the exact built-in fixture manifest and
rejects modified signer shares, nonces, production flags, missing fields, and
extra fields before any signing-share primitive runs. `--transcript-manifest`
requires an exact unspent transcript manifest for the selected message and
commitment set, and `--update-transcript-manifest` marks it spent after a
successful verified run.

## WUCI-WARRANT receipts

WUCI-WARRANT / 无此令 / No Such Warrant binds a FROST quorum receipt to one
artifact manifest and one requested action. It only generates and verifies
authorization receipts; it does not open or release artifacts.

```sh
make frost-authz
make frost-authz-demo
build/wuci-ji warrant-message-file open build/frost-authz-demo/sealed.wj
python3 tools/wuci_frost_authorize.py --artifact build/frost-authz-demo/sealed.wj --action open --print-auth-message
python3 tools/wuci_frost_authorize.py --artifact build/frost-authz-demo/sealed.wj --action open --verify-receipt build/frost-authz-demo/auth-receipt.json
```

`make frost-authz` runs the regression workflow. `make frost-authz-demo` creates
a disposable sealed artifact, assembly authorization message, transcript, and
receipt under `build/frost-authz-demo/`, which keeps demo files out of the
tracked workspace. Receipts are anchored to the assembly `warrant-message-file`
output, a canonical authorization-message SHA-256, and the public FROST
verification equation.

## WUCI-GATE

WUCI-GATE / 无此门 / No Such Gate verifies a WUCI-WARRANT receipt before
allowing a controlled no-overwrite open path. Python still derives and verifies
the full WUCI-WARRANT JSON receipt. The fixed flat receipt contract is the
assembly boundary: `gate-contract-verify` parses and verifies it natively, and
`open-authorized-contract` refuses to create plaintext unless the contract,
artifact hash, manifest hash, warrant-message hash, FROST challenge, FROST
signature, key, and output path all pass. Assembly does not parse receipt JSON
or accept arbitrary signer material.

```sh
make gate-workflow
make gate-policy-matrix
make gate-receipt-contract
make gate-contract-asm
make gate-contract-zig
make gate-demo
build/wuci-ji gate-contract-verify build/wuci-gate-demo/sealed.wj build/wuci-gate-demo/receipt-contract.txt
build/wuci-ji open-authorized-contract build/wuci-gate-demo/artifact.key build/wuci-gate-demo/sealed.wj build/wuci-gate-demo/receipt-contract.txt build/wuci-gate-demo/opened-asm.txt
python3 tools/wuci_gate.py check --artifact build/wuci-gate-demo/sealed.wj --action open --receipt build/wuci-gate-demo/auth-receipt.json
python3 tools/wuci_gate.py open --artifact build/wuci-gate-demo/sealed.wj --action open --receipt build/wuci-gate-demo/auth-receipt.json --keyfile build/wuci-gate-demo/artifact.key --out build/wuci-gate-demo/opened-copy.txt
```

`make gate-policy-matrix` checks the boundary rejection contract from
`docs/wuci_gate_boundary.json`. `make gate-receipt-contract` checks the
Python-derived flat receipt contract from
`docs/wuci_gate_receipt_contract.json`. `make gate-contract-asm` checks the
assembly flat-contract verifier/open command, including malformed contracts,
tampered hashes, bad challenge/signature fields, wrong keys, and output path
failures with no plaintext release. `make gate-contract-zig` keeps the Zig
bridge covered by calling the assembly binary for manifest, warrant, FROST
challenge/verification, and envelope open. `make gate-demo` creates a
disposable artifact, open warrant, gate decision, and opened plaintext under
`build/wuci-gate-demo/`.
Invalid receipts, wrong actions, tampered artifacts, bad signatures, wrong
keys, private-material markers, and existing output paths do not release
plaintext.

```text
WARRANT proves authorization.
GATE enforces authorization.
ENVELOPE preserves secrecy.
```

## Self-release demo

Wuci-ji can seal its own Linux x86_64 binary, bind it to an assembly artifact
manifest, issue a WUCI-WARRANT receipt, pass WUCI-GATE, and open to a
byte-identical executable copy.

```sh
make self-release-demo
make self-release-bundle
make self-release-contract-bundle
make self-release-asm-contract-proof
make verify-self-release-bundle
make self-release-attestation-test
make zig-release-proof
make zig-release-contract-proof
```

`make self-release-bundle` adds `attestation.json` beside the sealed artifact,
manifest, warrant message, receipt, and opened binary. The attestation records
the relevant SHA-256 values, Gate decision fields, byte-identity check,
executable check, and current boundary statement. `make
verify-self-release-bundle` recomputes those checks from the bundle files.
`make self-release-contract-bundle` also writes `receipt-contract.txt`, opens
through the Zig flat-contract verifier, and records the contract hash plus Zig
contract verification checks in the attestation.
`make self-release-asm-contract-proof` runs the stronger native contract lane:
it verifies and opens the self-sealed binary through `open-authorized-contract`
and records assembly contract checks in the attestation.
`make self-release-attestation-test` checks that tampered attestations,
manifests, warrant messages, receipts, sealed artifacts, artifact keys, and
opened binaries fail verification.

Python still derives the flat receipt contract from the JSON WUCI-WARRANT
receipt. Zig remains a portable verifier bridge, while assembly now enforces
the `open` contract path itself.

## License

NO SUCH MACHINE — ALL RIGHTS RESERVED. See [LICENSE](LICENSE).
