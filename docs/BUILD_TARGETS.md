# WUCI Build Targets

Native build and most targeted tests require Linux x86_64 with GNU `as`/`ld`.
The full native `make test` target also requires BMI2 and AVX because the
current assembly X25519 helper uses those instructions. On Linux hosts without
those CPU features, use `make test-linux` for the cross-built ELF's Python
harness and run targeted non-X25519 proof lanes natively.

## Minimal

```sh
make build-linux
make test
make install-test
make parser-adversarial-test
make aead-boundary-test
make secret-path-isolation-test
```

## Native Proof Lanes

```sh
make authority-root-check
make gate-contract-asm
make self-release-asm-contract-proof
make self-release-anchored-proof
make self-release-rooted-proof
make self-release-publish-bundle
make self-release-witness-bundle
make self-release-witness-archive
make ledger-asm-test
make ledger-proof-test
make self-release-ledger-bundle
make harden0-proof
make harden-proof
make cage-proof
make qcage-proof
make witness-zig
make witness-zig-test
make witness-archive-test
make reproducible-build-metadata
```

## Zig Proof Lanes

```sh
make gate-contract-zig
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

On a Linux host that needs user-mode QEMU for the Zig-built ELF, pass
`RELEASE_RUNNER=qemu-x86_64`.

## CI Mirrors

```sh
make ci-native
make ci-zig
```

`check-asm-immediates` is a legacy static disassembly audit. It remains
available as an opt-in target:

```sh
make check-asm-immediates
```
