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

- Darwin arm64
- Zig is available and can cross-build the x86_64 Linux ELF.
- Homebrew `qemu` provides `qemu-system-x86_64`, not Linux user-mode
  `qemu-x86_64`, so it cannot run this user-space ELF directly on macOS.

Verified on this host:

- `make build-linux` succeeds.
- `python3 -m py_compile tests/test_wuci_ji.py` succeeds.
- `git diff --check` succeeds.
- `make` fails intentionally with the native Linux x86_64 requirement.
- `make test-linux` fails intentionally until Linux user-mode `qemu-x86_64` is
  available.

The produced cross-build artifact is:

```text
build/wuci-ji-linux-x86_64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
```

## Next pickup

1. Run the full suite on an x86_64 Linux machine with `make clean && make test`.
2. If that passes, add an Ubuntu x86_64 CI workflow that runs `make test`.
3. After CI is green, continue with crypto behavior work rather than more host
   setup.
