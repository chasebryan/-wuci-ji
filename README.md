<img width="2172" height="724" alt="wsj-banner-github" src="https://github.com/user-attachments/assets/3e20bf66-1376-46b0-9f25-0ec619bf7224" />
# -wuci-ji
无此机(Wuci-ji)是一个专为 x86_64 架构机器设计的汇编语言项目，旨在探索机器码、底层执行、系统边界以及精确控制。

**Research/proof artifact. Not production crypto. Not a runtime sandbox. Not
post-quantum secure. Not independently audited.**

Wuci-ji explores a small x86_64 assembly artifact machine: seal artifacts,
derive manifests and warrant messages, enforce flat Gate contracts, anchor
release/open decisions to fixture roots, build public witness bundles, and
commit those bundles into a Merkle ledger. The current FROST authority is
deterministic fixture material for tests and proofs, not production signing
authority.

## Current Maturity

The strongest current claim is mechanical, not production trust: the repo can
build a Linux x86_64 binary, seal it, warrant it, verify flat contracts through
assembly and Zig lanes, produce public witness evidence, append ledger history,
emit local SBOM/provenance evidence, and audit a signed local install. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
[docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md),
and [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) for the exact split
between assembly, Zig, Python, Makefile, CI, and fixture authority.

## Minimal Build And Test

Native `make` and `make selftest` require Linux x86_64 with GNU `as`/`ld`.
The full native `make test` lane also requires BMI2 and AVX for the current
assembly X25519 helper. On Linux hosts without those CPU features, use
`make test-linux` with user-mode `qemu-x86_64` for the cross-built ELF's
Python harness. That target defaults to `QEMU_CPU=Haswell-v4`, which provides
the BMI2/AVX instruction surface needed by the current X25519 helper under
QEMU. Run the non-X25519 native proof targets directly on older x86_64 hosts.

```sh
make test
make install-test
```

On non-Linux hosts with Zig installed, cross-build the Linux ELF:

```sh
make build-linux
```

Detailed proof targets live in [docs/BUILD_TARGETS.md](docs/BUILD_TARGETS.md).
Contributor setup details live in
[docs/CONTRIBUTOR_BOOTSTRAP.md](docs/CONTRIBUTOR_BOOTSTRAP.md), and CI scope is
documented in [docs/CI_SCOPE.md](docs/CI_SCOPE.md).
Release requirements are in [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md),
and fuzzing/adversarial parser work is tracked in [docs/FUZZING.md](docs/FUZZING.md).

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

## WUCI-LEDGER

WUCI-LEDGER / 无此录 / No Such Ledger is the hash-only transparency layer for
publish history. Assembly owns the Merkle commitment core:
`ledger-empty-root` prints `SHA256("")`, `ledger-leaf-file <entry>` prints
`SHA256(0x00 || entry-bytes)`, and `ledger-node <left> <right>` prints
`SHA256(0x01 || left || right)` after decoding the two child hashes from
64-hex arguments. `tools/wuci_ledger.zig` builds `build/wuci-ledger-tool`,
which now owns the active append-only log lane on top of those primitives.

```sh
make ledger-asm-test
make ledger-proof-test
make ledger-asm-demo
make self-release-ledger-bundle
make zig-release-ledger-bundle
build/wuci-ledger-tool init --ledger build/wuci-ledger
build/wuci-ledger-tool append --ledger build/wuci-ledger --witness-bundle build/wuci-witness-bundle
build/wuci-ledger-tool prove-inclusion --ledger build/wuci-ledger --sequence 0 --out build/wuci-ledger/inclusion-proof.txt
build/wuci-ledger-tool verify-inclusion --entry build/wuci-ledger/ledger-entry.txt --proof build/wuci-ledger/inclusion-proof.txt --head build/wuci-ledger/ledger-head.txt
build/wuci-ledger-tool prove-consistency --ledger build/wuci-ledger --from-head build/wuci-ledger/previous-ledger-head.txt --to-head build/wuci-ledger/ledger-head.txt --out build/wuci-ledger/consistency-proof.txt
build/wuci-ledger-tool verify-consistency --proof build/wuci-ledger/consistency-proof.txt
build/wuci-ledger-tool verify-history --ledger build/wuci-ledger
```

The fixed format boundary lives in `docs/wuci_ledger_format.json`. The Python
ledger tool remains as a regression/reference harness, but the active
self-release ledger proof uses Zig for init, append, inclusion proofs,
consistency proofs, and full local history verification.

## WUCI-HARDEN-0

WUCI-HARDEN-0 hardens the current proof chain before adding CAGE/QCAGE. It pins
verifier identity in strict mode, adds safe file I/O, rejects symlink/hardlink
public evidence, quarantines deterministic fixture authority as test-only,
denies reserved trust/publish actions by default, and adds ledger history
verification.

```sh
make harden0-policy-matrix
make harden0-safeio-test
make harden0-verifier-identity-test
make harden0-witness-safeio-test
make harden0-fixture-quarantine-test
make harden0-action-policy-test
make harden0-proof
```

Fixture FROST is test-only. Release is not publish or trust. HARDEN-0 does not
claim runtime sandboxing or quantum safety. CAGE/QCAGE should sit above this
perimeter-hardening layer.

## WUCI-CAGE

WUCI-CAGE / 无此笼 / No Such Cage is the artifact airlock: it verifies sealed,
warranted, rooted, witnessed, and ledger-ready evidence before trust. CAGE v1
does not claim OS runtime sandboxing. It denies general run requests until
runtime sandbox enforcement exists.

```sh
make cage-policy-matrix
make cage-bundle-test
make cage-proof
python3 tools/wuci_cage.py attest --bundle build/wuci-witness-bundle --out build/wuci-cage-attestation.json
python3 tools/wuci_cage.py verify --bundle build/wuci-witness-bundle --attestation build/wuci-cage-attestation.json
python3 tools/wuci_cage.py deny-run --artifact build/wuci-witness-bundle/wuci-ji.self.wj --out build/wuci-cage-run-denied.txt
```

CAGE v1 is not an exploit tool, fuzzer, scanner, jailbreak harness, malware
sandbox, or OS containment layer. It validates public witness bundles, rejects
private/demo files and private material markers, writes deterministic CAGE
attestations, emits ledger-ready CAGE entries, and refuses runtime execution
claims that Wuci-ji does not yet enforce.

## WUCI-QCAGE

WUCI-QCAGE / 无此量笼 / No Such Quantum Cage adds quantum-aware evidence checks
to WUCI-CAGE.

QCAGE v1 does not claim post-quantum security by default. It keeps current
WUCI-FROST/secp256k1 evidence as compatibility evidence, marks it
quantum-vulnerable under a CRQC threat model, adds SHA-384/SHA-512 public
evidence digests, emits a cryptographic inventory, records build graph
evidence, computes quantum migration debt, and rejects false quantum-safe
claims.

```sh
make qcage-model-test
make qcage-policy-matrix
make qcage-crypto-inventory
make qcage-build-graph
make qcage-attestation-test
make qcage-proof
python3 tools/wuci_qcage.py risk --T-migrate 3 --T-trust 10 --T-CRQC 10
```

Modes:

```text
compat:
  Current WUCI-CAGE evidence can pass with quantum_safe=false.

hybrid-required:
  Requires existing WUCI evidence and real PQ signature verification.
  In v1 this fails closed unless a real verifier is implemented.

pq-required:
  Requires real PQ signature verification.
  Classical-only authority is insufficient.
```

## WUCI-HARDEN

WUCI-HARDEN / 无此固 / No Such Soft Spot hardens the proof chain around
WUCI-GATE, WUCI-WARRANT, WUCI-WITNESS, and WUCI-LEDGER.

It does not add offensive tooling. It prevents fixture authority from being
mistaken for production trust, pins verifier identity in strict mode, rejects
reserved trust/publish actions by default, rejects symlink and hardlink
surprises in public evidence, strengthens local ledger mutation detection, and
prevents runtime or quantum-safety overclaims.

```sh
make harden-policy-matrix
make harden-safeio-test
make harden-verifier-identity-test
make harden-witness-symlink-test
make harden-fixture-quarantine-test
make harden-action-policy-test
make harden-ledger-mutation-test
make harden-proof
```

## WUCI-INSTALL

WUCI-INSTALL / 无此装 / No Such Install is the zero-prompt signed installer
for Wuci-ji. It requires a local copied install root key before installation,
then verifies the detached OpenSSH manifest signature, digest vector, selftest,
HARDEN, CAGE, QCAGE, witness, and ledger proof gates before writing an atomic
install receipt. During the proof-gate wait, the installer displays a
WUCI-INSTALL ticker with the active phase until completion.

```sh
mkdir -p ~/.config/wuci-ji
cp install/wuci-install-root.v1.pub ~/.config/wuci-ji/install-root.pub
make install-proof INSTALL_ROOT_KEY=$HOME/.config/wuci-ji/install-root.pub INSTALL_PREFIX=$HOME/.local
~/.local/bin/wuci-ji-audit
```

The audit command starts with:

```text
无此机 / Wuci-ji systems nominal.
Version 0.1 installed.
Install status: nominal
```

WUCI-INSTALL does not use `curl | sh`, does not prompt interactively, does not
accept unsigned manifests, and does not install without the copied local root
key. It does not claim runtime sandboxing or quantum safety. For production
use, confirm the install root key fingerprint out of band before copying it
from a checkout.

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
make self-release-witness-archive
make ledger-asm-test
make ledger-proof-test
make self-release-ledger-bundle
make cage-policy-matrix
make cage-bundle-test
make cage-proof
make qcage-model-test
make qcage-policy-matrix
make qcage-proof
make harden-proof
make high-attestation-profile
make high-attestation-proof
make sbom-provenance
make sbom-provenance-test
make carrot-policy
make kernel-sandbox-proof
make pq-verifier-detect
make pq-verifier-test
make production-readiness-gates
make crypto-self-audit
make crypto-self-audit-test
make witness-zig
make verify-self-release-bundle
make self-release-attestation-test
make authority-anchor-test
make publish-attestation-test
make witness-attestation-test
make witness-zig-test
make witness-archive-test
make zig-release-proof
make zig-release-contract-proof
make zig-release-asm-contract-proof
make zig-release-anchored-proof
make zig-release-rooted-proof
make zig-release-release-contract-proof
make zig-release-publish-bundle
make zig-release-witness-bundle
make zig-release-witness-archive
make zig-release-ledger-bundle
```

`make self-release-bundle` adds `attestation.json` beside the sealed artifact,
manifest, warrant message, receipt, and opened binary. The attestation records
the relevant SHA-256 values, Gate decision fields, byte-identity check,
executable check, and current boundary statement. `make
verify-self-release-bundle` recomputes those checks from the bundle files.
`make high-attestation-profile` validates the local defensive baseline in
`docs/wuci_high_attestation_profile.json`; `make high-attestation-proof`
composes that baseline with the pinned qemu X25519 lane, assembly checks,
HARDEN, CAGE/QCAGE, CARROT seccomp/namespace no-network proof, PQ verifier
detection, crypto self-audit, production-readiness gates, Gate contract, and
full Linux CLI harness. This is a local evidence-strengthening lane, not a
claim of general runtime sandboxing, quantum safety, production authority, or
vulnerability absence.
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
`make witness-zig` builds `tools/wuci_witness.zig` into `build/wuci-witness`.
The active witness bundle lane uses that Zig tool to write `publish-index.txt`,
write `attestation.json`, and verify the public bundle through the same
assembly `release-authorized-rooted` boundary without invoking the Python
witness entrypoint.
`make self-release-witness-archive` writes `build/wuci-witness-bundle.tar` and
`build/wuci-witness-bundle.tar.sha256` with fixed file order, root
`wuci-publish-bundle-v1/`, mtime zero, uid/gid zero, and mode `0644`, then
extracts and verifies the public bundle. `make zig-release-witness-archive`
does the same for the Zig-built ELF and also verifies the extracted bundle
through `build/wuci-witness`.
`make self-release-attestation-test` checks that tampered attestations,
manifests, warrant messages, receipts, sealed artifacts, artifact keys, and
opened binaries fail verification. `make publish-attestation-test` checks that
tampered release decisions, release contracts, and authority roots fail
publish-bundle verification. `make witness-attestation-test` checks the public
witness profile, including forbidden private files and index, manifest, warrant,
decision, authority, receipt, and contract tampering. `make witness-zig-test`
checks that the Zig verifier rejects private files plus index, decision, and
attestation tampering. `make witness-archive-test` checks deterministic archive
bytes, sidecar mismatches, missing files, forbidden files, nonzero mtimes, and
tampered archived decisions. `make
authority-anchor-test` checks that anchored mode accepts the committed fixture
root, rejects self-derived authority paths, and rejects malformed or
policy-invalid authority roots.

The active self-release witness/ledger lane now uses Zig tools for deterministic
fixture warrant receipts, flat receipt-contract emission, public witness
index/attestation, witness verification, and ledger append/proof/history
operations. Python remains available for reference tests and older preview
lanes. Normal rooted proofs use committed authority anchors instead of emitting
authority from the just-created contract, while assembly enforces the `open`,
rooted `open`, `release`, and rooted `release` contract paths itself.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
