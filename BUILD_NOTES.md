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
- The v2 sealed-artifact envelope adds authenticated key ID metadata:
  `seal-v2 <key> <key-id>` and `seal-keyfile-v2 <path> <key-id>` write a v2
  frame, while `open <key>` and `open-keyfile <path>` still accept both v1 and
  v2 frames. The v2 header is fed to Poly1305 as associated data before any
  ciphertext bytes, so key ID, version, algorithm, and nonce tampering fail
  authentication.
- `inspect` reads a v1 or v2 envelope from stdin without requiring secret key
  material and prints fixed metadata fields: version, algorithm, header length,
  nonce, and the v2 key ID when present. It rejects malformed or truncated
  frames before printing any metadata.
- `manifest` is also keyless and emits the stable artifact metadata needed for
  cataloging: version, algorithm, header length, v2 key ID when present,
  artifact SHA-256, ciphertext length, ciphertext SHA-256, nonce, and the raw
  trailing authentication tag. `artifact-sha256` covers the complete stored
  envelope bytes, while `ciphertext-sha256` covers ciphertext bytes only,
  excluding header metadata and the trailing tag. It uses the same
  malformed/truncated frame rejection boundaries as `inspect`.
- `inspect-file <path>` and `manifest-file <path>` provide file-path
  convenience variants for cataloging stored artifacts without shell
  redirection. They reuse the same parser/output paths as stdin `inspect` and
  `manifest`, reject unreadable files separately, and preserve the same
  malformed/truncated envelope boundaries.
- `seal-file <key> <in> <out>`, `seal-file-v2 <key> <key-id> <in> <out>`, and
  `open-file <key> <in> <out>` provide no-overwrite file round trips for stored
  artifacts. `seal-file` streams the input file into a newly created v1
  envelope, `seal-file-v2` does the same with authenticated key ID metadata, and
  `open-file` authenticates the complete artifact before creating the plaintext
  output. All three commands refuse to overwrite existing output paths.
- `seal-file-keyfile <path> <in> <out>`,
  `seal-file-keyfile-v2 <path> <key-id> <in> <out>`, and
  `open-file-keyfile <path> <in> <out>` provide the same no-overwrite file
  workflows while loading the 32-byte key from a 64-hex key file with optional
  trailing newline.
- Fixed-form commands now enforce exact argument counts. Extra positional
  arguments are rejected with usage instead of being silently ignored, including
  stdin-streaming, file-path, metadata, key-file, and help commands.
- The Python harness now asserts the built-in help surface for the current
  file workflow commands and manifest ciphertext SHA-256 wording.

## Envelope layouts

All multi-byte metadata fields currently used by the envelope are byte strings;
there are no integer length fields in either frame.

v1 frame:

```text
offset  size  field
0       6     ASCII "WJSEAL"
6       1     version = 0x01
7       1     algorithm = 0x01
8       12    random ChaCha20-Poly1305 nonce
20      N     ciphertext
20+N    16    Poly1305 tag over ciphertext with zero-length associated data
```

v2 frame:

```text
offset  size  field
0       6     ASCII "WJSEAL"
6       1     version = 0x02
7       1     algorithm = 0x01
8       16    caller-supplied key ID metadata
24      12    random ChaCha20-Poly1305 nonce
36      N     ciphertext
36+N    16    Poly1305 tag over header-associated data and ciphertext
```

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
2. If v2 grows again, keep adding malformed-envelope tests before changing
   `open`; current tests cover truncated v2 headers, truncated bodies/tags,
   authenticated key ID tampering, nonce tampering, and tag tampering.
3. The direct-key and key-file-backed no-overwrite file workflows are now both
   covered. Next file-surface work should focus on reducing command-name length
   or adding explicit docs/examples rather than adding more aliases.
