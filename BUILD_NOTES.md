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
- The native build path assembles `src/wuci-ji.s` and `src/x25519.s`; it no
  longer compiles or links a C helper.
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
- The first FROST RFC 9591 lane is intentionally narrow:
  `frost-p256-h4`, `frost-p256-h5`, `frost-secp256k1-h4`, and
  `frost-secp256k1-h5` compute the SHA-256 transcript hashes
  `H(contextString || "msg" || stdin)` and
  `H(contextString || "com" || stdin)` for the P-256 and secp256k1
  ciphersuites. These are transcript primitives only; no threshold signing API
  is exposed until the build has constant-time prime-order group operations,
  scalar serialization/deserialization, hash-to-field for H1/H2/H3, and
  participant share/commitment validation.
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
- The all-assembly v3 recipient envelope adds X25519 file sealing. `keypair`
  emits random private/public X25519 keys as hex. `seal-to <public> <in> <out>`
  writes a no-overwrite v3 artifact with an ephemeral X25519 public key, and
  `open-to <private> <in> <out>` verifies and opens that artifact with the
  recipient private key. The v3 key ID is `SHA256(recipient-public)[:16]`.
  The AEAD key is derived with HKDF-SHA256 from the X25519 shared secret using
  `SHA256(v3-header)` as salt and `wuci-ji v3 X25519 recipient AEAD key` as
  info. The complete v3 header is Poly1305 associated data, so version,
  algorithm, ephemeral public key, recipient key ID, and nonce tampering fail
  authentication or pre-authentication key-ID checks. Known low-order X25519
  public encodings are rejected before scalar multiplication and before opening
  the output path.
- `inspect` reads a v1, v2, or v3 envelope from stdin without requiring secret
  key material and prints fixed metadata fields: version, algorithm, header
  length, nonce, v2/v3 key ID when present, and the v3 ephemeral public key
  when present. It rejects malformed or truncated frames before printing any
  metadata.
- `manifest` is also keyless and emits the stable artifact metadata needed for
  cataloging: version, algorithm, header length, v2/v3 key ID when present, v3
  ephemeral public key when present, artifact SHA-256, ciphertext length,
  ciphertext SHA-256, nonce, and the raw trailing authentication tag.
  `artifact-sha256` covers the complete stored envelope bytes, while
  `ciphertext-sha256` covers ciphertext bytes only, excluding header metadata
  and the trailing tag. It uses the same malformed/truncated frame rejection
  boundaries as `inspect`.
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
- `armor-file <in> <out>` and `dearmor-file <in> <out>` provide copy/paste
  ASCII wrapping for stored artifacts without changing the cryptographic
  envelope. The encoder writes a fixed WUCI-JI armor header, standard base64
  body lines wrapped at 64 characters, and a fixed footer. The decoder accepts
  ASCII whitespace around body lines and after the footer, validates padding and
  footer presence before opening the output path, and refuses to overwrite
  existing output files.
- Fixed-form commands now enforce exact argument counts. Extra positional
  arguments are rejected with usage instead of being silently ignored, including
  stdin-streaming, file-path, metadata, recipient, key-file, and help commands.
- The Python harness now asserts the built-in help surface for the current
  file workflow commands, recipient workflow commands, armor commands, and
  manifest ciphertext SHA-256 wording.

## Envelope layouts

All multi-byte metadata fields currently used by the envelope are byte strings;
there are no integer length fields in any frame.

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

v3 frame:

```text
offset  size  field
0       6     ASCII "WJSEAL"
6       1     version = 0x03
7       1     algorithm = 0x01
8       32    ephemeral X25519 public key
40      16    recipient key ID = SHA256(recipient public key)[:16]
56      12    random ChaCha20-Poly1305 nonce
68      N     ciphertext
68+N    16    Poly1305 tag over header-associated data and ciphertext
```

ASCII armor frame:

```text
-----BEGIN WUCI-JI ARTIFACT-----
<standard base64 of the complete stored artifact, wrapped at 64 columns>
-----END WUCI-JI ARTIFACT-----
```

Armor is only a transport wrapper. It can contain v1, v2, or v3 artifact bytes,
and dearmoring restores the exact original bytes.

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
2. If v2 or v3 grows again, keep adding malformed-envelope tests before changing
   `open`/`open-to`; current tests cover truncated headers, truncated
   bodies/tags, authenticated key ID tampering, nonce tampering, and tag
   tampering.
3. The FROST lane currently stops at RFC 9591 H4/H5 transcript hashing. Next
   FROST work should add a real prime-order Schnorr group backend before any
   key-share, nonce, signing-share, or aggregation commands are exposed.
4. `src/x25519.s` is the current assembly X25519 helper. A future cleanup can
   hand-tune or merge it into `src/wuci-ji.s`, but keep the Python X25519
   reference tests as the compatibility guard.
