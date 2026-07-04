# Wuci Penumbra

Rust implementation of the Penumbra v1 `WJSEAL` envelope described in `docs/penumbra/SPEC.md`.

Implemented surfaces:

- `wuci_penumbra` library: canonical wire codec, `seal`, `open`, `inspect`, and a `TranscriptVerifier` trait.
- `penumbra` CLI: `seal`, `open`, and `inspect`.
- Vetted primitives from RustCrypto: ChaCha20-Poly1305, HKDF-SHA-256, SHA-256, plus `getrandom` and `zeroize`.

The CLI uses `FileTranscriptVerifier`, a deterministic adapter for local fixtures and build tests. A witness file has this exact shape:

```text
WJ-PENUMBRA-WITNESS-v1
policy_sha256:<sha256 of policy bytes>
canon_descriptor_sha256:<sha256 of canon descriptor bytes>
base_transcript_hex:<hex canonical transcript bytes>
```

This adapter verifies that the witness is pinned to the policy and canon descriptor, then returns the transcript bytes used for key derivation. It is not a production Meridian evidence re-deriver. Production deployments should provide a `TranscriptVerifier` that re-derives the transcript directly from pinned Meridian evidence.

Run:

```sh
make penumbra-test
```
