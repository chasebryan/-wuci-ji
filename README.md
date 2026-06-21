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
make authority-root-check
make gate-contract-asm
make self-release-asm-contract-proof
make self-release-anchored-proof
make self-release-rooted-proof
make self-release-publish-bundle
make self-release-witness-bundle
make witness-zig
make witness-zig-test
make gate-contract-zig
make zig-release-proof
make zig-release-contract-proof
make zig-release-asm-contract-proof
make zig-release-anchored-proof
make zig-release-rooted-proof
make zig-release-release-contract-proof
make zig-release-publish-bundle
make zig-release-witness-bundle
```

`make authority-root-check` regenerates the deterministic fixture authority
roots under `build/`, compares them against the committed anchors in
`authority/`, and verifies their SHA-256 sidecars.
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
binary through the Zig contract verifier instead of Python Gate open.
`make zig-release-asm-contract-proof` seals the Zig-built ELF and then verifies
and opens it through that ELF's own assembly `open-authorized-contract` path,
recording assembly contract checks in the attestation.
`make self-release-anchored-proof` and `make zig-release-anchored-proof` use
the pre-existing WUCI-ANCHOR file `authority/wuci-root.fixture.txt`, require the
receipt contract to answer to that trusted quorum key, require the binary's assembly
`authority-root-verify`, `gate-contract-verify-rooted`, and
`open-authorized-rooted` paths, and bind the authority hash and trusted group
key into the attestation. `make self-release-rooted-proof` and
`make zig-release-rooted-proof` are compatibility aliases for the anchored lane.
`make zig-release-release-contract-proof` seals the Zig-built ELF, derives a
release warrant and flat contract, and requires that ELF's own assembly
`release-authorized-contract` path to approve the release decision.
`make self-release-publish-bundle` and `make zig-release-publish-bundle`
promote that release decision into WUCI-PUBLISH using the pre-existing
release-only anchor `authority/wuci-release-root.fixture.txt`: a rooted assembly
`release-authorized-rooted` check, deterministic
`release-decision.txt`, and `attestation.json` that binds the authority,
contract, decision, receipt, warrant, manifest, and sealed artifact hashes. On
`make self-release-witness-bundle` and `make zig-release-witness-bundle`
produce the public WUCI-WITNESS profile: no `artifact.key`, no opened binary,
no transcript material, plus a fixed `publish-index.txt` and
`attestation.json` that can be verified with:

```sh
python3 tools/wuci_witness.py verify --bundle build/wuci-witness-bundle
make witness-zig
build/wuci-witness verify build/wuci-witness-bundle
```

On a Linux host that needs user-mode QEMU to run the Zig-built ELF, pass:

```sh
make gate-contract-zig RELEASE_RUNNER=qemu-x86_64
make zig-release-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-contract-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-asm-contract-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-rooted-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-release-contract-proof RELEASE_RUNNER=qemu-x86_64
make zig-release-publish-bundle RELEASE_RUNNER=qemu-x86_64
make zig-release-witness-bundle RELEASE_RUNNER=qemu-x86_64
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
assembly boundary: `gate-contract-verify` parses and verifies the open contract
natively, `open-authorized-contract` refuses to create plaintext unless the
contract, artifact hash, manifest hash, warrant-message hash, FROST challenge,
FROST signature, key, and output path all pass, and
`release-authorized-contract` verifies a release contract before printing a
release decision. WUCI-ROOT adds a flat authority file that pins the contract
`group-public-key` to a trusted quorum key; `open-authorized-rooted` requires
that authority before opening, and `release-authorized-rooted` requires a
release-enabled authority before approving release. Assembly does not parse
receipt JSON or accept arbitrary signer material. WUCI-ANCHOR / 无此锚 / No
Such Anchor pins the normal rooted proof to committed authority files in
`authority/` before any receipt contract is produced; `emit --contract` remains
available for test fixtures and negative cases, but the anchored proof does not
derive its authority from the contract it is checking.

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
assembly flat-contract verifier/open command and the rooted authority lane,
including malformed contracts, malformed authority roots, authority group-key
mismatches, tampered hashes, bad challenge/signature fields, wrong keys, and
output path failures with no plaintext release. `make gate-contract-zig` keeps the Zig
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
make authority-root-check
make self-release-demo
make self-release-bundle
make self-release-contract-bundle
make self-release-asm-contract-proof
make self-release-anchored-proof
make self-release-rooted-proof
make self-release-release-contract-proof
make self-release-publish-bundle
make self-release-witness-bundle
make witness-zig
make verify-self-release-bundle
make self-release-attestation-test
make authority-anchor-test
make publish-attestation-test
make witness-attestation-test
make witness-zig-test
make zig-release-proof
make zig-release-contract-proof
make zig-release-asm-contract-proof
make zig-release-anchored-proof
make zig-release-rooted-proof
make zig-release-release-contract-proof
make zig-release-publish-bundle
make zig-release-witness-bundle
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
`make zig-release-asm-contract-proof` runs that same assembly-enforced contract
lane against the Zig-built Linux ELF, proving the portable release artifact can
open itself through its own assembly Gate.
`make self-release-anchored-proof` and `make zig-release-anchored-proof` use
the committed open anchor `authority/wuci-root.fixture.txt`, require the trusted
group key to match the receipt contract, open through `open-authorized-rooted`,
and record
`authority_root_sha256`, `authority_group_public_key`, `rooted_gate_check`, and
`rooted_gate_open` in the attestation. The older rooted proof target names now
route through that anchored path.
`make self-release-release-contract-proof` and
`make zig-release-release-contract-proof` prove the native and Zig-built
binaries can verify their own release warrant through assembly
`release-authorized-contract` and emit a deterministic release decision.
`make self-release-publish-bundle` and `make zig-release-publish-bundle` copy
the committed release anchor `authority/wuci-release-root.fixture.txt` into the
bundle as `authority-root.txt`, require assembly `release-authorized-rooted`,
write `release-decision.txt`, and attest the
publish bundle with `release_authority_root_sha256`,
`release_authority_group_public_key`, `release_contract_sha256`,
`release_decision_sha256`, `rooted_release_check`, and
`publish_bundle_complete`.
`make self-release-witness-bundle` and `make zig-release-witness-bundle` turn
that publish proof into WUCI-WITNESS / 无此证 / No Such Witness: a keyless public
bundle containing only `wuci-ji.self.wj`, `manifest.txt`,
`warrant-message.txt`, `release-receipt.json`, `receipt-contract.txt`,
`authority-root.txt`, `release-decision.txt`, `publish-index.txt`, and
`attestation.json`. The witness verifier recomputes the artifact hash, manifest
and release warrant bytes, receipt contract, release anchor, rooted assembly
release decision, and attestation; it rejects demo keys, opened binaries,
transcripts, malformed indexes, and mismatched public evidence.
`make witness-zig` builds `tools/wuci_witness.zig` into `build/wuci-witness`
and verifies an existing public bundle through the same assembly
`release-authorized-rooted` boundary without invoking the Python witness
entrypoint.
`make self-release-attestation-test` checks that tampered attestations,
manifests, warrant messages, receipts, sealed artifacts, artifact keys, and
opened binaries fail verification. `make publish-attestation-test` checks that
tampered release decisions, release contracts, and authority roots fail
publish-bundle verification. `make witness-attestation-test` checks the public
witness profile, including forbidden private files and index, manifest, warrant,
decision, authority, receipt, and contract tampering. `make witness-zig-test`
checks that the Zig verifier rejects private files plus index, decision, and
attestation tampering. `make
authority-anchor-test` checks that anchored mode accepts the committed fixture
root, rejects self-derived authority paths, and rejects malformed or
policy-invalid authority roots.

Python still derives the flat receipt contract from the JSON WUCI-WARRANT
receipt. Normal rooted proofs use committed authority anchors instead of
emitting authority from the just-created contract. Zig remains a portable
verifier bridge, while assembly now enforces the `open`, rooted `open`,
`release`, and rooted `release` contract paths itself.

## License

NO SUCH MACHINE — ALL RIGHTS RESERVED. See [LICENSE](LICENSE).
