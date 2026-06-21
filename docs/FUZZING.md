# WUCI Fuzzing Plan

Wuci-ji does not yet have a native coverage-guided fuzzer in CI. This document
defines the seed corpus layout and initial adversarial harness targets.

## Seed Corpora

Seed files live under `tests/corpus/`:

- `tests/corpus/envelope/` for envelope v1/v2/v3 bytes.
- `tests/corpus/gate-contract/` for flat receipt contracts.
- `tests/corpus/authority-root/` for WUCI-ROOT files.
- `tests/corpus/ledger-entry/` for WUCI-LEDGER entries.
- `tests/corpus/armor/` for ASCII armor/dearmor samples.

## Current Harness

The initial harness is regression-oriented and stdlib-only:

```sh
make parser-adversarial-test
make aead-boundary-test
```

Those tests mutate known-good contracts/artifacts and require fail-closed
behavior with no plaintext output on open failure.

## Future Native Fuzz Lane

Add a native fuzzer when the project is ready to accept a dependency or a
toolchain-specific target. Good first targets:

- Envelope header/version/length parsing.
- Gate contract parser.
- Authority root parser.
- Ledger entry/head/proof parser.
- Armor/dearmor parser.
- SEC1 point decoding.

The future CI lane should store crashing inputs under the matching
`tests/corpus/` directory and replay them in `make test`.
