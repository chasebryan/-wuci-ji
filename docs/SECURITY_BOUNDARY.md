# WUCI Security Boundary

This file separates enforced implementation boundaries from policy and test
claims. It is intentionally blunt: a boundary is only listed as enforced when
the current repository has code and tests for that behavior.

| Boundary | What It Checks | Owner | Current Status |
| --- | --- | --- | --- |
| Envelope secrecy boundary | ChaCha20-Poly1305 envelope parse/open, tag verification before final file output, bounded stdin/inspect reads, no-overwrite output | Assembly | Enforced; file opens stream through temp files, stdin/inspect paths stay bounded |
| WUCI-DAYLIGHT bridge boundary | WJSEAL v1/v2/v3 public envelope classification, digest binding, Daylight v0.6 8250 zero-claim boundary, Gate-required plaintext release | Daylight Rust crate plus root Make target | Deterministic bridge evidence; does not decrypt, verify tags, accept keys, replace Gate, or create production authority |
| Warrant authorization boundary | Deterministic fixture FROST receipt generation and receipt JSON checks | Python/Zig emitters plus assembly helpers | Demo/reference; fixture-only authority |
| Flat Gate contract boundary | Fixed-order ASCII contract parse, artifact hash, manifest hash, warrant-message hash, challenge, signature, output safety | Assembly | Enforced for open/release paths |
| Root authority boundary | Authority root parse, authority ID, action allow bits, contract group key equals authority group key | Assembly plus fixture anchor files | Enforced for rooted open/release; publish has a fail-closed decision command; trust remains unimplemented and fixture roots are test-only |
| Witness public evidence boundary | Public bundle file set, forbidden private files, publish index, attestation, deterministic archive profile | Zig/Python | Verifier bridge; public profile excludes keys/opened binaries/transcripts |
| Ledger public history boundary | Domain-separated Merkle leaf/node hashes, inclusion/consistency/history orchestration | Assembly hash core, Zig/Python orchestration | Append-only local history proof, not a public operated log service |
| HARDEN boundary | Verifier identity, safe I/O, fixture quarantine, reserved-action denial, witness symlink/hardlink rejection, ledger mutation checks | Python policy/tests plus assembly no-follow flags | Defensive perimeter hardening |
| CAGE boundary | Public witness bundle legitimacy, no private material, deny general runtime execution | Python policy/tooling | Artifact airlock; not OS sandboxing |
| QCAGE boundary | Digest vectors, crypto inventory, build graph evidence, quantum migration debt, no false PQ claim | Python policy/tooling | Quantum-aware metadata; not PQ security |
| CARROT runtime policy boundary | Policy says no network, FROST/Gate may attest policy only, seccomp denies network syscalls, user+network namespace entry is checked | Python policy plus assembly seccomp probe and Rust wrapper source | Local no-network syscall proof lane on supporting kernels; not general sandboxing or VM containment |
| INSTALL boundary | Copied local install root key, OpenSSH signed manifest, digest vector, proof gates, atomic install, audit receipt | Python installer plus existing proof lanes | Signed zero-prompt install lane; no runtime/PQ claim |
| WJ* composition boundary | Golden Lock v1 transcript, 3-of-5 normal authority target, 4-of-5 ceremony target, Gate policy, Merkle evidence, witness root mapping | Formal model, Golden Lock policy matrix, plus existing proof lanes | Target composition model; fixture FROST remains test-only |
| WJ-GOLD acceptance boundary | Canonical transcript target, one golden authorization hash, pressure/PQ modes, threshold and custody-domain checks, public evidence presence, fail-closed claims | JSON model plus Python model validator | Falsifiable model gate; not production cryptography, host security, runtime sandboxing, production authority, or PQ system security |
| WJ-next transcript boundary | Canonical transcript, digest vector, one authorization hash, typed verifier predicate, PQ mode discipline | Formal model plus parser hardening replay | Target transcript model; pq-secure remains false until earned |

See `docs/wuci_wjstar_model.md` for the formal target composition:
`WJ* = GoldenLock_v1(AEAD + FROST_(3/5,4/5) + H-Merkle + G + R)`.
See `docs/wuci_golden_lock_model.md` for WJ-GOLD:
`canonical transcript -> one golden authorization hash -> typed verifier predicate`.
See `docs/wuci_wjnext_model.md` for the canonical transcript target:
`canonical transcript -> one authorization hash -> typed verifier predicate`.

## Artifact Size Boundary

Plain `open-file*` paths use streaming authenticated decryption: read the
header, lseek for ciphertext length, update Poly1305 and ChaCha20 by chunk
while writing plaintext to a sibling 0600 temp file opened with
`O_EXCL|O_NOFOLLOW`, verify the final tag, then `RENAME_NOREPLACE` to the
requested output path. On authentication or I/O failure, the temp path is
unlinked. No plaintext reaches the requested output path until the tag
succeeds.

Gate-authorized file opens use the same streamed artifact hash/ciphertext hash
and temp-file open lane. The authorized output path is committed only after the
flat or rooted Gate contract verifies; failed Gate verification unlinks the
temp. This is final-path authorization, not OS containment: a private 0600 temp
plaintext file exists transiently before the Gate commit step.

`manifest-file`, `warrant-message-file`, and assembly release decisions now
stream artifact and ciphertext SHA-256 computation for file inputs, so large
sealed artifacts can be warranted and released without the old
`AEAD_OPEN_MAX` full-buffer read.

Stdin `open`, stdin `manifest`, `inspect`, `inspect-file`, `open-to`,
armor/dearmor, and raw `aead-open` still use the bounded in-memory read paths
where they need authenticate-before-stdout behavior, display-only simplicity,
or v3 recipient-key processing.

## Variable-Time Public Primitive

`secp256k1-basepoint-mul-variable-time-public-only` routes to the affine
variable-time multiplication helper and branches on scalar bits. It exists as a
developer/public test primitive only. Secret scalar paths must use the
projective fixed-loop path or an explicitly audited replacement.

## Python and Zig

Python and Zig are not hidden from the trust story. Python remains a reference,
fixture, policy, and installer layer. Zig is the current portable public
verifier bridge. Assembly owns the narrow Gate/root/open/release enforcement
boundary.
