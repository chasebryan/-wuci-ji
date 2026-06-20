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

`make build-linux` keeps `src/*.s` in GNU `as` form and writes generated
Zig/LLVM-compatible assembly copies to `build/*.zig.s`.

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
- The native build path assembles the files listed in `ASM_SOURCES`; it no
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
- The first FROST RFC 9591 lane is intentionally narrow but now covers the
  ciphersuite hash primitives for P-256 and secp256k1. `frost-*-h1`,
  `frost-*-h2`, and `frost-*-h3` run SHA-256 `expand_message_xmd` with
  RFC 9591 DSTs, reduce the 48-byte uniform output modulo the ciphersuite
  group order, and print a 32-byte scalar. `frost-*-h4` and `frost-*-h5`
  compute the transcript SHA-256 helpers `H(contextString || "msg" || stdin)`
  and `H(contextString || "com" || stdin)`. These are primitives only; no
  threshold signing API is exposed until the build has constant-time
  prime-order group operations and participant share/commitment validation.
- The FROST(secp256k1,SHA-256) scalar backbone is now exposed for testing:
  `secp256k1-scalar-add`, `secp256k1-scalar-sub`,
  `secp256k1-scalar-mul`, and `secp256k1-scalar-inv` operate modulo the
  secp256k1 group order and reject noncanonical 32-byte scalar encodings.
  `frost-secp256k1-lagrange <i> <id...>` implements RFC 9591 interpolation
  for nonzero, unique participant identifiers and rejects lists that do not
  include `i`. This provides the scalar arithmetic required for signing-share
  generation and aggregation, but it is not yet a complete FROST signing API.
- FROST(secp256k1,SHA-256) round-one primitives now include
  `frost-secp256k1-nonce-generate <secret>`, which implements RFC 9591
  `nonce_generate` with 32 bytes from `getrandom` and the H3 nonce DST, and
  `frost-secp256k1-commit <hiding> <binding>`, which rejects zero/noncanonical
  nonce scalars and emits compressed SEC1 hiding and binding commitments. This
  is enough to build and test signer commitment shares, but signing-share
  generation remains intentionally withheld until the remaining group-operation
  exceptional branches and participant validation are tightened.
- FROST(secp256k1,SHA-256) transcript and aggregation primitives now include
  `frost-secp256k1-commitment-hash <id D E>...`, which hashes a sorted
  RFC 9591 encoded commitment list with H5;
  `frost-secp256k1-binding-factor <PK> <H4> <H5> <id>`, which derives one H1
  binding factor from the group public key, message hash, commitment hash, and
  participant identifier; and
  `frost-secp256k1-group-commitment <id D E rho>...`, which aggregates
  `D_i + rho_i * E_i` over sorted participant rows and emits a compressed SEC1
  group commitment. These commands reject malformed compressed points and
  nonzero identifier lists that are not strictly ascending.
- FROST(secp256k1,SHA-256) challenge computation now includes
  `frost-secp256k1-challenge <R> <PK>`, which validates compressed SEC1 group
  commitment and group public-key encodings, prepends them to stdin, and runs
  RFC 9591 H2/chal hash-to-scalar. This completes the public transcript scalar
  path needed before signing-share generation.
- FROST(secp256k1,SHA-256) signing-share scalar generation now includes
  `frost-secp256k1-signing-share <d> <e> <rho> <lambda> <share> <c>`, which
  computes `d_i + rho_i * e_i + lambda_i * s_i * c` modulo the secp256k1 group
  order. It rejects zero nonce scalars, interpolation factors, and secret
  shares, while allowing zero hash-derived `rho` or challenge scalars.
- FROST(secp256k1,SHA-256) aggregate signatures now include
  `frost-secp256k1-aggregate <R> <z...>`, which validates the compressed group
  commitment, sums canonical signature-share scalars modulo the group order,
  and emits `signature_commitment` plus `signature_scalar`.
- FROST(secp256k1,SHA-256) verification now includes
  `frost-secp256k1-verify <R> <PK> <z> <c>`, which checks the Schnorr/FROST
  equation `z*G = R + c*PK` over validated compressed SEC1 group commitment and
  public-key encodings. Use `frost-secp256k1-challenge` to derive `c` from
  `R || PK || message`.
- The Python test suite now includes a 2-of-2 FROST(secp256k1,SHA-256)
  integration proof that composes commitment generation, commitment hashing,
  binding factors, group commitment, challenge derivation, Lagrange
  interpolation, signing shares, aggregation, and verification through the CLI.
- The first assembly modularization checkpoint split the SHA-256 core into
  `src/sha256.s`, linked as `build/sha256.o` beside the main and X25519
  objects. The Makefile now uses assembly source lists for native linking and
  generates Zig-compatible transformed sources for every assembly file. Native
  `make test` passes after the split. With Zig 0.16.0 installed,
  `make -B build-linux` also emits a static x86_64 Linux ELF, and that
  cross-built artifact passes both `selftest` and the Python CLI test suite
  when selected through `WUCI_JI_BIN`.
- The second assembly modularization checkpoint split low-level syscall and
  file helpers into `src/sys.s`: `write_all`, `fill_random`, key/artifact file
  readers, seal/open file descriptor helpers, output file creation, and
  plaintext output routing. Shared constants now live in `include/wuci.inc`,
  and the Makefile native/Zig source lists include `src/sys.s`.
- The third assembly modularization checkpoint split `_start`, command
  dispatch, help/usage exits, command names, and the usage text into
  `src/main.s`. Dispatch now uses a compact command table that maps command
  strings to the exported `run_*` handlers still owned by `src/wuci-ji.s`.
- The fourth assembly modularization checkpoint split hex/Base64 and output
  formatting helpers into `src/encoding.s`: `hex_encode`, fixed-width hex
  decoders, `hex_u32_decode`, Base64 quad encode/decode helpers, decimal
  output, manifest SHA-256 label output, and the hex/Base64 alphabet tables.
  The shared scratch buffers remain owned by `src/wuci-ji.s`.
- The secp256k1 group backend has started at the field layer. The CLI exposes
  `secp256k1-field-add`, `secp256k1-field-sub`, `secp256k1-field-mul`, and
  `secp256k1-field-square` for 32-byte hex field elements modulo
  `p = 2^256 - 2^32 - 977`; `secp256k1-field-inv` uses fixed-exponent
  inversion by `p - 2`. Multiplication currently uses a fixed 256-iteration
  double-and-add path over normalized limbs, which keeps the test surface simple
  while the group backend is still being built.
- The secp256k1 point layer now has affine correctness scaffolding:
  `secp256k1-point-validate`, `secp256k1-point-double`,
  `secp256k1-point-add`, and `secp256k1-basepoint-mul`. These commands reject
  noncanonical affine coordinates, print `infinity` for neutral results, and are
  covered against Python reference formulas. This is still not a signing surface;
  the next cryptographic hardening step is audited constant-time scalar handling
  and point selection before any secret-bearing signing API is exposed.
- The secp256k1 group backend now includes Jacobian/projective scaffolding:
  `secp256k1-jacobian-double`, `secp256k1-jacobian-mixed-add`, and
  `secp256k1-projective-basepoint-mul`. The projective basepoint path avoids
  affine inversion inside the 256-bit scalar loop and converts back to affine at
  the end. The same checkpoint adds SEC1-compatible point helpers:
  `secp256k1-point-encode-compressed`,
  `secp256k1-point-encode-uncompressed`, and `secp256k1-point-decode`.
  Decoding validates canonical field coordinates and curve membership, and the
  Python harness checks Jacobian outputs by converting them back to affine
  reference points. This is a correctness and structure milestone, not a final
  constant-time FROST signing backend.
- The projective secp256k1 basepoint scalar loop now computes the double and
  add candidates on every bit and mask-selects the next Jacobian accumulator
  instead of branching directly on scalar bits or accumulator-infinity state.
  `tests/check_asm_immediates.py` also disassembles the native object and fails
  if a branch appears before the fixed loop back-edge in
  `secp256k1_projective_basepoint_mul_limbs`. This narrows the scalar-loop
  leakage shape, but it is still not a production signing backend: the current
  mixed-add and doubling formulas still contain exceptional-case branches that
  should be replaced or isolated before any secret-bearing FROST operation is
  exposed.
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
3. The FROST lane currently exposes RFC 9591 H1/H2/H3 hash-to-scalar and
   H4/H5 transcript primitives for P-256 and secp256k1, plus secp256k1 field
   arithmetic, scalar arithmetic modulo the group order, Lagrange interpolation,
   nonce generation, nonce commitment, binding-factor derivation,
   group-commitment aggregation, challenge computation, signing-share scalar
   generation, signature-share aggregation, affine point validation/add/double,
   signature verification, projective basepoint multiplication, and controlled
   SEC1 point encoding/decoding. Next FROST work should wrap these primitives
   into a safer end-to-end workflow only after the remaining assembly split and
   constant-time group-operation audit.
4. Continue the assembly split before adding much more FROST signing code.
   `src/main.s`, `src/encoding.s`, `src/sha256.s`, and `src/sys.s` are already
   separate; next split candidates are `hmac_hkdf.s` for hash/KDF command glue
   and `secp256k1.s`/`frost.s` for curve and FROST primitives. Keep the native
   and Zig source lists together.
5. `src/x25519.s` is the current assembly X25519 helper. A future cleanup can
   hand-tune or merge it into `src/wuci-ji.s`, but keep the Python X25519
   reference tests as the compatibility guard.
