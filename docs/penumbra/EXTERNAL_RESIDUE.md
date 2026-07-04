# Penumbra External Residue

Penumbra v1 can complete the code path for deterministic transcript-gated AEAD envelopes, but the repository must not self-certify a deployment's confidentiality strength.

Reserved external facts:

- Independent cryptographic review of this integration, not only the upstream primitives.
- A signed post-quantum posture statement. The honest figure for this symmetric envelope is about 128-bit key-search work under Grover; stronger statements are out of scope here.
- Per-deployment attestation of `H∞(secret_component)` from an actor other than the sealing party.
- A production Meridian transcript re-derivation lane, if a deployment wants the CLI file-witness adapter replaced with direct evidence re-derivation.

The built tool may state the AEAD component and the `min(AEAD, H∞(τ))` boundary. It must not print or document an absolute deployment strength unless the external facts above are supplied by review or attestation outside this repository.
