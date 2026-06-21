# Build Notes

Updated: 2026-06-21

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
- PyPy 3.11 is installed locally at `.tools/bin/pypy3` on this workstation for
  opt-in harness runs; `.tools/` is intentionally ignored.

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

- The native object rule keeps `check-native` as an order-only prerequisite, so
  the phony host check does not force object files to rebuild on every test
  run.
- `make test-pypy` runs the Python harness with PyPy when `.tools/bin/pypy3`
  exists, while the default `make test` remains CPython for portable CI.
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
- The native test path disassembles all native assembly objects and fails if
  known absolute `*_len` assembly constants are encoded as absolute memory
  reads instead of immediate loads.
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
- The fifth assembly modularization checkpoint split the HMAC-SHA256 and
  HKDF-SHA256 CLI handlers plus `hmac_prepare_sha256_key32` into
  `src/hmac_hkdf.s`. HMAC/HKDF scratch buffers remain owned by `src/wuci-ji.s`
  so the existing process-global zeroization range still covers them.
- The sixth assembly modularization checkpoint split the secp256k1 scalar
  backbone into `src/secp256k1_scalar.s`: scalar add/sub/mul/inv CLI handlers,
  FROST Lagrange interpolation, canonical scalar loading/comparison, scalar
  arithmetic modulo the group order, and scalar output formatting. Scalar
  scratch buffers remain owned by `src/wuci-ji.s` so the existing
  process-global zeroization range still covers them while the FROST and curve
  layers continue to share the scalar helpers. The secp256k1 group-order
  constants are now exported by `src/frost.s`.
- The seventh assembly modularization checkpoint split the secp256k1 field
  backbone into `src/secp256k1_field.s`: field add/sub/mul/square/inv CLI
  handlers, field output formatting, big-endian/little-endian conversion,
  limb copy/select helpers, canonical field parsing/comparison, modular
  add/sub/mul, inversion, and square-root exponentiation for compressed-point
  recovery. Field scratch buffers and field constants remain owned by
  `src/wuci-ji.s` so the existing process-global zeroization range still
  covers them while point, scalar, and FROST code import the shared field
  helpers.
- The eighth assembly modularization checkpoint split the secp256k1 point,
  Jacobian, and group backend into `src/secp256k1_point.s`: affine point CLI
  handlers, SEC1 encode/decode helpers, point output formatting,
  compressed-point load/encode, affine add/double/mul, Jacobian
  to-affine/double/mixed-add, projective basepoint multiplication, and the
  FROST commitment point adapter. Point and Jacobian scratch buffers remain
  owned by `src/wuci-ji.s` so existing zeroization still covers them while the
  remaining FROST transcript code imports the point helpers.
- The ninth assembly modularization checkpoint split the FROST transcript and
  round helper layer into `src/frost.s`: P-256 and secp256k1 H1/H2/H3/H4/H5
  commands, nonce generation, nonce commitment, commitment hash, binding
  factor, group commitment, challenge, signing share, aggregate, verify,
  hash-to-scalar, hash-memory, 48-byte scalar reduction, FROST labels/DSTs, and
  FROST-specific error handlers. FROST scratch buffers remain owned by
  `src/wuci-ji.s` so the existing exit-path zeroization still covers them.
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
  `tests/check_asm_immediates.py` also disassembles the native objects and
  fails if a branch appears before the fixed loop back-edge in
  `secp256k1_projective_basepoint_mul_limbs`. This narrows the scalar-loop
  leakage shape, but it is still not a production signing backend.
- The first constant-time group hardening checkpoint split a
  finite-assumption Jacobian double helper,
  `secp256k1_jacobian_double_finite_limbs`, and made the projective basepoint
  scalar loop use it instead of the generic Jacobian double path. The loop's
  explicit accumulator-infinity mask now controls double-result selection, and
  the disassembly guard fails if the scalar loop regresses to calling
  `secp256k1_jacobian_double_limbs`. This removes the generic double helper's
  infinity/Y-zero branches from the scalar loop, but mixed-add exceptional-case
  branches and final affine conversion remain to be remediated before treating
  FROST commitment generation as constant-time.
- The second constant-time group hardening checkpoint split
  `secp256k1_jacobian_mixed_add_masked_limbs` for the projective basepoint
  scalar loop. It computes distinct-add and duplicate-add candidates, selects
  the affine basepoint for an infinity input, and masks the infinity result
  without branching on the accumulator state, `H == 0`, or `R == 0`. The public
  `secp256k1_jacobian_mixed_add_limbs` helper remains unchanged for CLI-visible
  exceptional cases, while the disassembly guard now fails if the scalar loop
  regresses to calling it directly or if the masked helper gains a branch. The
  Python harness includes `n + 2` as a projective scalar case so the
  duplicate-candidate path is selected, not just computed and discarded.
- The third constant-time group hardening checkpoint split
  `secp256k1_jacobian_to_affine_finite_limbs` from the generic
  `secp256k1_jacobian_to_affine_limbs` wrapper. The generic helper still owns
  CLI-visible infinity handling, while the projective basepoint CLI adapter,
  `frost_secp256k1_commit_scalar`, and `frost-secp256k1-verify` now call the
  finite helper only after `secp256k1_projective_basepoint_mul_limbs` has
  returned a non-infinity result. The disassembly guard fails if these adapters
  call the generic affine converter directly or if the finite helper gains a
  local branch. This narrows the final conversion boundary, but the broader
  field inversion and FROST signing workflow still need review before treating
  this as a production constant-time signing backend.
- The fourth constant-time group hardening checkpoint removed the fixed-exponent
  skip-multiply branch from `secp256k1_field_inverse_limbs`. Field inversion now
  computes the multiply candidate on every one of the 256 exponent rounds,
  mask-selects it according to the public `p - 2` exponent bit, and then squares
  the base. The disassembly guard now checks that `secp256k1_field_mul_limbs`
  and `secp256k1_field_inverse_limbs` contain only their fixed loop back-edge,
  and that inversion calls `secp256k1_field_select_mask`. This hardens the
  finite affine conversion dependency, but remaining inversion-style helpers and
  the full FROST workflow still need review.
- The fifth constant-time group hardening checkpoint mirrored the fixed-loop
  exponentiation shape into `secp256k1_scalar_inverse_limbs` and
  `secp256k1_field_sqrt_limbs`. Scalar inversion now computes every multiply
  candidate and mask-selects it with the public `n - 2` exponent bit, while the
  SEC1 compressed-point square-root path does the same with the public
  `(p + 1) / 4` exponent. The disassembly guard now checks
  `secp256k1_scalar_mul_limbs`, `secp256k1_scalar_inverse_limbs`, and
  `secp256k1_field_sqrt_limbs` for exactly one fixed loop back-edge and requires
  the mask-select helper in both exponentiation routines. Decode still has
  public input-validation and parity-selection branches, so keep it treated as a
  public parsing surface rather than a secret-bearing scalar path.
- The sixth constant-time group hardening checkpoint added an explicit
  `secp256k1_public_point_mul_limbs` wrapper for the remaining affine
  double-and-add point multiplier. Public CLI basepoint multiplication,
  `frost-secp256k1-group-commitment`, and `frost-secp256k1-verify` now call the
  wrapper, while secret-bearing FROST commitment/signing/aggregation paths are
  guarded from calling either the wrapper or `secp256k1_point_mul_limbs`
  directly. This keeps public decode/error-handling branches and the branchy
  affine verifier multiplier labeled as public-only plumbing while the
  secret-bearing commitment path stays on the projective basepoint backend.
- The seventh constant-time group hardening checkpoint made the public-affine
  multiplier decision executable in the disassembly audit. The guard now
  enumerates every object function that reaches `secp256k1_public_point_mul_limbs`
  or raw `secp256k1_point_mul_limbs`, fails on unclassified callers, and requires
  `frost_secp256k1_commit_scalar` to call the projective basepoint helper. The
  secret scalar FROST command surfaces are also checked against compressed-point
  decode and public affine-multiplier helpers. For now the branchy affine
  multiplier remains isolated as verifier/public aggregation plumbing because
  those inputs are public; do not reuse it for nonce commitments or signing
  shares.
- The eighth constant-time group hardening checkpoint added a focused
  secret-bearing FROST path audit to `tests/check_asm_immediates.py`. The guard
  requires nonce generation to stay on `fill_random` plus H3 hash-to-scalar,
  requires `run_frost_secp256k1_commit` to enter the commitment helper instead
  of point machinery directly, requires `frost_secp256k1_commit_scalar` to use
  projective basepoint multiplication plus the finite affine converter, and
  requires signing-share generation to stay scalar-only. It also classifies
  every direct caller of `secp256k1_projective_basepoint_mul_limbs`, so new
  secret or public point paths have to be explicitly reviewed.
- The ninth constant-time group hardening checkpoint added scalar arithmetic
  guardrails to the same disassembly audit. `secp256k1_scalar_add_limbs`,
  `secp256k1_scalar_sub_limbs`, and
  `secp256k1_scalar_conditional_sub_n` are now required to stay branchless,
  while `secp256k1_scalar_mul_limbs` is rechecked for a single fixed loop
  back-edge. The guard also classifies direct scalar add/mul callers and treats
  `run_frost_secp256k1_aggregate` as public scalar-share aggregation: it may
  decode the public group commitment and add scalar shares, but it must not
  call point multiplication, projective basepoint multiplication, affine
  conversion, scalar multiplication, or scalar inversion.
- The tenth constant-time group hardening checkpoint added a FROST
  hash-to-scalar and scalar-loading boundary audit to
  `tests/check_asm_immediates.py`. The guard requires nonce generation,
  binding-factor derivation, challenge derivation, signing-share generation,
  and canonical secp256k1 scalar argument loading to call only their reviewed
  helper sets, and it classifies every direct caller of
  `load_secp256k1_scalar_arg`, `frost_hash_to_scalar_mem`,
  `frost_hash_to_scalar_stdin`, and `frost_hash_to_scalar_prefixed_stdin`.
  This keeps hash-derived scalars, random nonce material, canonical scalar
  parsing, and scalar-only signing-share arithmetic on explicit paths before
  the project accepts arbitrary signer material.
- The first FROST workflow checkpoint promoted the deterministic
  FROST(secp256k1,SHA-256) 2-of-2 CLI integration path into
  `tests/frost_secp256k1_workflow.py` and the `make frost-workflow` target.
  The harness composes nonce commitments, commitment hashing, binding factors,
  group commitment aggregation, challenge generation, Lagrange coefficients,
  signing shares, aggregation, and verification through the existing guarded CLI
  primitives, then returns the public signature fields. `make test` now runs
  this workflow target as a first-class regression before the broader Python
  suite, while still avoiding a new broad signing API surface.
- The second FROST workflow checkpoint added
  `tools/frost_secp256k1_workflow.py` and `make frost-demo`. This is a
  user-facing deterministic 2-of-2 demo transcript over the assembly CLI
  primitives, not a production threshold-signing API. `make frost-workflow`
  now compares the helper output against the direct Python regression path so
  the demo cannot drift away from the guarded primitive sequence.
- The third FROST workflow checkpoint hardened the demo helper boundary with
  `--print-fixture-manifest` and `--fixture-manifest`. The manifest contract is
  intentionally exact: it must declare the FROST secp256k1 suite, fixture mode,
  `production: false`, the non-production warning, the built-in group secret,
  and the two built-in signer shares/nonces. Modified signer material,
  production flags, missing fields, and extra fields are rejected before the
  helper reaches the assembly signing-share primitive.
- Product direction considered: WUCI-FROST / 无此签 / No Such Quorum should be
  a threshold authorization layer over Wuci-ji artifacts, not a replacement
  for envelope encryption. The encryption path stays ChaCha20-Poly1305; FROST
  should authorize manifest-bound actions such as open, release, trust, or
  publish by signing stable artifact metadata. Before any `open`-gating mode,
  prioritize RFC test vectors, random nonce handling, nonce-commitment
  tracking, and constant-time boundaries. Future ciphersuite work can evaluate
  FROST(Ed25519,SHA-512) or FROST(ristretto255,SHA-512), while the current
  assembly lane remains FROST(secp256k1,SHA-256) until its safety boundary is
  stronger.
- The fourth FROST workflow checkpoint surfaced that product direction in the
  README and helper help text. The user-facing copy keeps the same boundary:
  WUCI-FROST / 无此签 / No Such Quorum is manifest authorization over encrypted
  artifacts, while the current helper is only a deterministic non-production
  fixture. The workflow regression asserts the helper help keeps that boundary
  visible.
- The fifth FROST workflow checkpoint added a transcript-manifest gate to
  `tools/frost_secp256k1_workflow.py`. `--print-transcript-manifest` emits an
  exact unspent manifest binding the selected message bytes, H4 message hash,
  round-one signer commitments, H5 commitment hash, H1 binding factors,
  Lagrange factors, group commitment, H2 challenge, and
  `signing_shares_emitted: false`. `--transcript-manifest` requires that exact
  unspent transcript before the helper reaches `frost-secp256k1-signing-share`,
  and `--update-transcript-manifest` atomically marks it spent after a verified
  run. The workflow regression rejects mismatched messages, tampered commitment
  hashes, and already-spent manifests.
- The sixth FROST workflow checkpoint added WUCI-WARRANT / 无此令 / No Such
  Warrant receipt generation and verification in
  `tools/wuci_frost_authorize.py`. The tool derives a canonical authorization
  message from `manifest-file` output plus an action (`open`, `release`,
  `trust`, or `publish`), requires an unspent FROST transcript manifest before
  writing a receipt, and verifies receipts by recomputing the artifact
  manifest, authorization-message SHA-256, H2 challenge, and public
  `frost-secp256k1-verify` equation. `make frost-authz` runs the receipt-only
  regression, including action mismatch, artifact tamper, receipt metadata
  tamper, signature-scalar tamper, spent-transcript rejection, and a public
  receipt check that excludes fixture secrets and nonce scalars.
- The seventh FROST workflow checkpoint moved the canonical WUCI-WARRANT
  authorization-message surface into assembly with
  `warrant-message-file <action> <path>`. The command validates
  `open`/`release`/`trust`/`publish`, validates the artifact before writing,
  emits the warrant header, and then appends the existing assembly
  `manifest-file` body. The Python receipt tool now consumes those assembly
  bytes instead of owning canonical message serialization. The same checkpoint
  added `docs/wuci_gate_boundary.json` and `make gate-boundary` to lock the
  future `open-authorized` / `release-authorized` policy boundary as
  preview-only: policy inputs, display-only fields, rejection classes,
  forbidden private material, and explicit non-goals are tested while the
  assembly enforcement commands remain absent.
- The eighth FROST workflow checkpoint added WUCI-GATE / 无此门 / No Such Gate
  as a Python preview wrapper in `tools/wuci_gate.py`. The wrapper verifies a
  WUCI-WARRANT receipt against an artifact and action with the existing
  assembly-owned `warrant-message-file`, `frost-secp256k1-challenge`, and
  `frost-secp256k1-verify` surfaces, then calls assembly `open-file-keyfile`
  only for a valid `open` decision and only to a new output path. `make
  gate-workflow` checks valid opens, release receipts rejected for opening,
  tampered artifacts, tampered receipt metadata, tampered signature scalars,
  wrong keys after a valid gate, no-overwrite behavior, absence of private
  material in decisions, and byte equality between assembly warrant messages
  and the Python warrant tool's consumed bytes. `make gate-demo` writes a
  disposable end-to-end demo under `build/wuci-gate-demo/`.
- The ninth FROST workflow checkpoint added the Gate policy matrix in
  `tests/wuci_gate_policy_matrix.py` and `make gate-policy-matrix`. The matrix
  is driven by `docs/wuci_gate_boundary.json` rejection classes and proves that
  malformed receipts, unsupported schema or suite values, production receipts,
  wrong actions, artifact-manifest digest and field mismatches,
  authorization-message digest mismatches, challenge mismatches, invalid
  signatures, private-material markers, release receipts used for open, wrong
  keys after authorization, and existing output paths all fail without creating
  or overwriting plaintext. Gate now scans raw receipt JSON for forbidden
  private-material markers before shape validation.
- The tenth FROST workflow checkpoint hardened WUCI-GATE output path handling.
  The preview wrapper now rejects existing filesystem entries with
  `os.path.lexists`, so dangling symlinks are treated as occupied output paths,
  and it rejects missing output parents or parents that are not directories
  before invoking assembly `open-file-keyfile`. The workflow and policy matrix
  cover existing files, directories, dangling symlinks, missing parents, and
  non-directory parents without creating or overwriting plaintext.
- The eleventh FROST workflow checkpoint added `make self-release-demo`, a
  one-command preview release proof that seals the built `wuci-ji` binary as a
  v2 artifact, writes its manifest and assembly warrant message, issues an
  open WUCI-WARRANT receipt, verifies and opens it through the Python
  WUCI-GATE preview wrapper, compares the opened copy byte-for-byte against
  `build/wuci-ji`, and runs `--help` on the opened executable. This keeps the
  strong demo path inside the current boundary: no assembly `open-authorized`
  command, no assembly receipt JSON parsing, and no arbitrary signer material.
- The twelfth FROST workflow checkpoint added `tools/wuci_self_release.py`,
  `make self-release-bundle`, and `make verify-self-release-bundle`.
  `self-release-bundle` runs the self-release demo, writes
  `attestation.json`, and immediately verifies it. The attestation records
  SHA-256 values for the original binary, artifact key, sealed artifact,
  manifest, warrant message, receipt, and opened binary; the Gate decision
  hashes; the byte-identical and executable checks; the reproduced Gate open;
  and the current boundary statement. Verification recomputes manifest and
  warrant bytes from assembly, rechecks the WUCI-WARRANT receipt through
  WUCI-GATE, opens the artifact through Gate to a temporary copy, compares the
  opened bytes, and runs the opened executable. This makes the self-release
  proof independently auditable while staying in the Python preview wrapper
  lane.
- The thirteenth FROST workflow checkpoint added
  `tests/wuci_self_release_attestation.py` and
  `make self-release-attestation-test`, now included in `make test`. The test
  builds a temporary self-release bundle, writes and verifies an attestation,
  then proves verification fails after tampering with attestation fields,
  boundary fields, Gate decision hashes, `manifest.txt`,
  `warrant-message.txt`, `auth-receipt.json`, `wuci-ji.self.wj`,
  `artifact.key`, and `opened-wuci-ji`. This turns the screenshot-grade proof
  into a guarded regression lane before any assembly `open-authorized` design
  work.
- The fourteenth FROST workflow checkpoint added
  `docs/wuci_gate_receipt_contract.json`, `tools/wuci_receipt_contract.py`,
  `tests/wuci_receipt_contract.py`, and `make gate-receipt-contract`, now
  included in `make test`. The tool verifies an existing WUCI-WARRANT receipt
  through WUCI-GATE, derives a fixed-order ASCII contract with only the fields
  a future assembly parser should need, and verifies that contract back against
  the receipt, artifact, and action. The regression lane rejects reordered or
  malformed contract text, digest drift, bad SEC1 encodings, private-material
  receipt markers, tampered signatures, and tampered artifacts while still
  avoiding assembly `open-authorized`, assembly receipt JSON parsing, and
  arbitrary signer material.
- Receipt and contract verification now require `signature_commitment` /
  `signature-commitment` to match the group commitment used for challenge
  derivation. This keeps H2 challenge binding and the public Schnorr/FROST
  verification equation on the same commitment before any Gate proof can pass.
- The first Zig release lane added `RELEASE_BIN`, `RELEASE_RUNNER`, and
  `make zig-release-proof`. The self-release proof can now target either the
  native `build/wuci-ji` binary or the Zig-built
  `build/wuci-ji-linux-x86_64` binary while keeping the same
  seal/warrant/Gate/open/attest/verify loop. The Python orchestration tools
  honor `WUCI_JI_RUNNER`, so the same proof can run a cross-built Linux ELF
  through user-mode QEMU when the host needs it.
- The first Zig Gate bridge added `tools/wuci_gate_contract.zig`,
  `tests/wuci_gate_contract_zig.py`, and `make gate-contract-zig`. The lane
  builds a small Zig verifier for the fixed flat WUCI-GATE receipt contract,
  checks canonical field shape and digest bindings, calls the assembly binary
  for manifest, warrant-message, FROST challenge, FROST verification, and
  `open-file-keyfile`, and rejects tampered contracts, receipts, artifacts,
  commitments, challenges, and signatures. Python still emits the canonical
  contract, and assembly `open-authorized` remains intentionally absent.
- The second Zig release lane added `make self-release-contract-bundle` and
  `make zig-release-contract-proof`. The proof seals the Zig-built Linux ELF,
  warrants it, emits `receipt-contract.txt`, verifies and opens through
  `tools/wuci_gate_contract.zig`, compares the opened copy byte-for-byte,
  executes it, and writes a self-release attestation that records the contract
  hash and `zig-flat-contract-preview` boundary. This is now the strongest
  self-release proof before any assembly `open-authorized` command exists:
  Python still derives the flat contract, while Zig enforces the contract and
  delegates manifest, warrant, FROST, and envelope operations to assembly.
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
   Use `make gate-contract-zig`, `make zig-release-proof`, and
   `make zig-release-contract-proof` as the portable Zig Gate/release proofs
   for the Zig-built Linux x86_64 ELF. On hosts that need user-mode QEMU, pass
   `RELEASE_RUNNER=qemu-x86_64`.
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
   into a safer end-to-end workflow only after the constant-time
   group-operation audit.
4. Continue the security hardening before adding much more FROST signing code.
   `src/main.s`, `src/encoding.s`, `src/hmac_hkdf.s`,
   `src/frost.s`, `src/secp256k1_field.s`, `src/secp256k1_point.s`,
   `src/secp256k1_scalar.s`, `src/sha256.s`, and `src/sys.s` are already
   separate. The first WUCI-GATE enforcement wrapper now lives in Python while
   canonical authorization bytes and envelope opening stay in assembly. The
   assembly-friendly receipt contract is now documented and guarded by
   `make gate-receipt-contract` plus the Zig `make gate-contract-zig` bridge;
   use that contract bridge before promoting any assembly `open-authorized`
   command.
   Use `make self-release-contract-bundle` as the current strongest
   end-to-end release proof, and `make self-release-attestation-test` as the
   tamper-rejection guard. Wuci-ji sealed itself, warranted itself, emitted a
   flat receipt contract, passed the Zig contract verifier, opened to a
   byte-identical executable copy, emitted a verifiable attestation, and rejects
   tampered proof bundles.
   Keep private nonce and signing-share paths on projective basepoint helpers,
   leave public verifier aggregation behind `secp256k1_public_point_mul_limbs`,
   and keep the native and Zig source lists together.
5. `src/x25519.s` is the current assembly X25519 helper. A future cleanup can
   hand-tune or merge it into `src/wuci-ji.s`, but keep the Python X25519
   reference tests as the compatibility guard.
