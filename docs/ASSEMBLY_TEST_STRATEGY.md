# Assembly-First Test Strategy

This repo should move toward assembly-owned verification without turning the
test suite into one opaque mega-test. The goal is fast, deterministic,
production-grade mechanics for the metal boundary while preserving the current
research-only crypto and fixture-authority warnings.

## Direction

- Put cryptographic known-answer tests, parser invariants, manifest/warrant
  layout checks, Gate contract checks, and ledger hash checks as close to the
  assembly implementation as practical.
- Keep Python out of claimed verifier logic. Python may remain useful for
  corpus generation, filesystem setup, mutation enumeration, and readable
  failure reporting while assembly coverage catches up.
- Prefer checked-in deterministic corpus files over runtime-generated Python
  fixtures when the bytes are stable.
- Keep tests small enough to diagnose. A single command may run the full
  assembly regression, but internally it should be split by proof lane.

## Test Tiers

1. `selftest`: pure assembly, no filesystem fixture setup. This is the fast
   crypto KAT lane for SHA-256, HMAC/HKDF, Poly1305, ChaCha20, AEAD internals,
   scalar/point primitives, and any future core primitive that can be tested
   from embedded vectors.
2. `asm-regression`: assembly-owned boundary tests over embedded vectors and,
   over time, stable repo corpus files. The first slice covers ledger
   empty-root, leaf, and node hash vectors. Future slices should cover
   envelope parsing, manifest text, warrant-message text, authority-root
   parsing, flat/rooted Gate contract parsing, and release decision text.
3. `asm-smoke` (Make orchestration): no Python business logic; only build,
   temporary directories, `printf`, command invocation, and `cmp`/`test` style
   checks around `wuci-ji selftest` and `wuci-ji asm-regression`.
4. Python policy suites: retained for high-cardinality mutation matrices,
   fixture emitters, install/CAGE/QCAGE orchestration, and regression cases
   not yet promoted into corpus-driven assembly checks.

## Why Not One Huge Assembly Test

A single massive assembly file would be harder to audit than the current
Python wrappers. It would mix crypto KATs, filesystem lifecycle checks, JSON or
ASCII fixture mutation, command dispatch, and policy assertions in one place.
That reduces diagnostic quality and increases the chance that the test harness
becomes less trustworthy than the code under test.

The better shape is one user-visible fast command backed by named internal
lanes. Example:

```text
wuci-ji asm-regression
  crypto-extra
  envelope-corpus
  manifest-corpus
  gate-contract-corpus
  ledger-corpus
```

The user gets one fast proof target; maintainers get focused labels and narrow
failure sites.

## First Implementation Slice

1. Keep extending `src/regression.s` instead of growing the already-large
   command handlers.
2. Add the next embedded or checked-in vectors that require no fixture
   emitters: SHA/HMAC/HKDF/Poly/ChaCha extra KATs, then minimal
   envelope/manifest corpus validation.
3. Move one Python assertion group at a time behind the assembly target. When a
   Python test becomes only an orchestration wrapper around an assembly-owned
   invariant, replace it with corpus bytes plus the assembly lane.

## Promotion Rule

A Python check is ready to promote when:

- the input bytes are deterministic and stable;
- the expected output is deterministic and stable;
- the assertion does not depend on Python-only JSON object construction,
  temporary path topology, or host-specific filesystem behavior;
- the failure can be reported by an assembly lane with a short label and a
  nonzero exit code.

Python should stay when it is testing host safe-I/O behavior, symlink/hardlink
fixtures, install atomicity, archive traversal, CAGE/QCAGE policy documents, or
large mutation matrices that are still changing quickly.

## Boundary

This strategy improves test ownership and speed. It does not by itself make
Wuci-ji production crypto, a runtime sandbox, a production authority system, or
post-quantum secure.
