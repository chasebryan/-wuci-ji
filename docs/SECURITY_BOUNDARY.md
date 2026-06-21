# WUCI Security Boundary

This file separates enforced implementation boundaries from policy and test
claims. It is intentionally blunt: a boundary is only listed as enforced when
the current repository has code and tests for that behavior.

| Boundary | What It Checks | Owner | Current Status |
| --- | --- | --- | --- |
| Envelope secrecy boundary | ChaCha20-Poly1305 envelope parse/open, tag verification before plaintext output, bounded artifact reads, no-overwrite output | Assembly | Enforced for current in-memory artifact size cap |
| Warrant authorization boundary | Deterministic fixture FROST receipt generation and receipt JSON checks | Python/Zig emitters plus assembly helpers | Demo/reference; fixture-only authority |
| Flat Gate contract boundary | Fixed-order ASCII contract parse, artifact hash, manifest hash, warrant-message hash, challenge, signature, output safety | Assembly | Enforced for open/release paths |
| Root authority boundary | Authority root parse, authority ID, action allow bits, contract group key equals authority group key | Assembly plus fixture anchor files | Enforced for rooted open/release; fixture roots are test-only |
| Witness public evidence boundary | Public bundle file set, forbidden private files, publish index, attestation, deterministic archive profile | Zig/Python | Verifier bridge; public profile excludes keys/opened binaries/transcripts |
| Ledger public history boundary | Domain-separated Merkle leaf/node hashes, inclusion/consistency/history orchestration | Assembly hash core, Zig/Python orchestration | Append-only local history proof, not a public operated log service |
| HARDEN boundary | Verifier identity, safe I/O, fixture quarantine, reserved-action denial, witness symlink/hardlink rejection, ledger mutation checks | Python policy/tests plus assembly no-follow flags | Defensive perimeter hardening |
| CAGE boundary | Public witness bundle legitimacy, no private material, deny general runtime execution | Python policy/tooling | Artifact airlock; not OS sandboxing |
| QCAGE boundary | Digest vectors, crypto inventory, build graph evidence, quantum migration debt, no false PQ claim | Python policy/tooling | Quantum-aware metadata; not PQ security |
| INSTALL boundary | Copied local install root key, OpenSSH signed manifest, digest vector, proof gates, atomic install, audit receipt | Python installer plus existing proof lanes | Signed zero-prompt install lane; no runtime/PQ claim |

## Artifact Size Boundary

The current envelope open path is bounded by `AEAD_OPEN_MAX` and reads the
artifact into memory before authentication. This keeps failure behavior simple:
malformed or oversized artifacts fail before plaintext output is created.

TODO: implement streaming authenticated open to a temporary file, verify the
final tag, then atomically rename while preserving no-overwrite behavior.

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
