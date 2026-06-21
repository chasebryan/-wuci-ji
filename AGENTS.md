# WUCI-CAGE Development Note

For WUCI-CAGE work, do not add exploit generation, vulnerability reproduction,
offensive scanning, jailbreak harnesses, or network attack logic.

Do not claim no-network or runtime sandboxing unless kernel-level or equivalent
enforcement is implemented and tested. CAGE v1 verifies artifact legitimacy; it
does not enforce OS containment.

Prefer deterministic fixtures, tempdirs, no network, stdlib-only Python, and
the existing assembly boundaries. Run targeted CAGE tests before final response.

# WUCI-QCAGE Development Note

For WUCI-QCAGE work, do not add offensive quantum exploitation tooling.

Do not claim quantum-safe status from classical-only signatures. Do not treat
secp256k1, ECDSA, RSA, DH, ECDH, or X25519 as quantum-safe.

Do not implement PQ stubs that pass as real verifiers. Any future PQ verifier
must be real, pinned, deterministic, tested, and clearly identified.

Keep QCAGE v1 stdlib-only unless explicitly adding a reviewed PQ verifier lane.
Prefer SHA-384 and SHA-512 for long-lived public evidence, while preserving
SHA-256 compatibility for existing assembly surfaces.

# WUCI-HARDEN Development Note

For WUCI-HARDEN-0, keep the pass narrow: verifier identity, safe I/O, fixture
quarantine, reserved-action denial, witness public-file hardening, and ledger
history verification. Do not use HARDEN-0 as a reason to add CAGE/QCAGE,
production authority, runtime sandboxing, or new cryptography.

WUCI-HARDEN work must be defensive only. Do not add exploit payloads,
vulnerability reproduction, offensive scanning, malware logic, or network attack
logic.

Do not treat fixture FROST as production authority. Do not claim publish or
trust authority until assembly-enforced publish/trust Gate commands exist.

Do not claim runtime sandboxing until real OS-level enforcement exists. Do not
claim quantum safety from classical-only evidence.

Prefer stdlib-only Python and deterministic tests. Reject symlinks and hardlinks
in public evidence. Keep existing Gate, Witness, Ledger, CAGE, and QCAGE proof
lanes passing.
