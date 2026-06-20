# Build Notes

Updated: 2026-06-20

This file is the machine-handoff checkpoint for `-wuci-ji`.

## Platform contract

`src/wuci-ji.s` is an x86_64 Linux program. It defines `_start` directly and uses
Linux syscall numbers, so it is not a macOS-native or arm64-native executable.

Native build and execution require:

- x86_64 Linux
- GNU-style `as` and `ld`
- Python 3 for the test harness

Cross-building from macOS or other non-Linux hosts currently uses Zig.

## Fresh-machine commands

On an x86_64 Linux machine:

```sh
make clean
make test
```

On macOS or another non-Linux machine with Zig installed:

```sh
make clean
make build-linux
file build/wuci-ji-linux-x86_64
```

`make build-linux` keeps `src/wuci-ji.s` in GNU `as` form and writes a generated
Zig/LLVM-compatible assembly copy to `build/wuci-ji.zig.s`.

On a Linux host with user-mode QEMU for x86_64:

```sh
make clean
make test-linux
```

If `qemu-x86_64` is not on `PATH`, pass it explicitly:

```sh
make test-linux QEMU_X86_64=/path/to/qemu-x86_64
```

## Test harness overrides

`tests/test_wuci_ji.py` can run a different binary or runner without editing the
test file:

```sh
WUCI_JI_BIN=/path/to/wuci-ji WUCI_JI_RUNNER=qemu-x86_64 python3 tests/test_wuci_ji.py
```

Leave `WUCI_JI_RUNNER` unset when running a native Linux binary directly.

## Current checkpoint

Observed host on 2026-06-20:

- Linux x86_64
- GNU `as`, `ld`, `nm`, and `objdump` are available.
- Python 3 is available.

Verified on this host:

- `make clean && make test` succeeds.
- `make test` now includes the native-object disassembly regression guard in
  `tests/check_asm_immediates.py`.
- `./build/wuci-ji selftest` succeeds as part of the Python test harness.
- `.github/workflows/ci.yml` now runs the same native Linux x86_64 suite on
  Ubuntu with `make clean && make test`.

Fixes made while executing this checkpoint:

- The native object rule now assembles `$(SOURCE)` explicitly instead of using
  `$<`, because `check-native` is the first prerequisite.
- GNU `as` Intel-syntax `.set` length constants are loaded with
  `OFFSET FLAT:` so status and error writes use immediates rather than absolute
  memory reads.
- Exit-time zeroization scrubs the process-global BSS working range, including
  key, nonce, HMAC, HKDF, Poly1305, ChaCha20, AEAD, IO, and envelope buffers.
- Practical inner-routine scrubbing now wipes stack temporaries in the
  SHA-256 transform, Poly1305 final/block multiply, and ChaCha20 block
  functions. The ChaCha20 keystream block is also cleared after streaming XOR
  use and after deriving AEAD Poly1305 one-time keys.
- Malformed-envelope coverage includes empty input, truncated header,
  truncated tag/body, bad magic, bad version, and bad tag rejection.
- The native test path disassembles `build/wuci-ji.o` and fails if known
  absolute `*_len` assembly constants are encoded as absolute memory reads
  instead of immediate loads.
- The sealed-artifact CLI now has a key-file workflow: `keygen` emits a random
  32-byte key as 64 hex characters plus newline, while `seal-keyfile <path>`
  and `open-keyfile <path>` load 64 hex key files with an optional trailing
  newline. The Python harness covers generated key files, raw 64-byte key
  files, malformed key-file rejection, and sealed/opened artifact round trips.

The native build artifact is:

```text
build/wuci-ji: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

## Previous cross-build note

A previous Darwin arm64 checkpoint found that Zig could cross-build the x86_64
Linux ELF, but Homebrew `qemu` provided `qemu-system-x86_64` rather than Linux
user-mode `qemu-x86_64`, so that host could not run the ELF test suite directly.
After the Linux checkpoint restored GNU `OFFSET FLAT:` immediates for native
correctness, the Darwin cross-build path was adjusted to translate those
immediates only in the generated `build/wuci-ji.zig.s` source.

## Next pickup

1. From Linux, keep using `make clean && make test` as the runtime proof before
   each push when practical.
2. If the envelope format grows beyond the current prefix, nonce, ciphertext,
   and tag layout, add malformed-envelope tests before changing `open`.
3. If this becomes a long-lived artifact format, consider explicit key IDs or
   associated-data metadata in a versioned envelope extension before adding
   more command variants.
