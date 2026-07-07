# Deep Security Remediation Report - 2026-07-07

## Repository

- Repository name: `-wuci-ji`
- Branch: `security/deep-remediation-20260707-030717`
- Starting commit: `9f7c3a3de401f04e72a32192cdeff31eab14c933`
- Final commit: `RECORDED_IN_FINAL_RESPONSE_AFTER_COMMIT`
- Report generated UTC: `2026-07-07T07:47:21Z`; continuation validation updated UTC: `2026-07-07T08:14:36Z`; toolchain closeout updated UTC: `2026-07-07T08:56:11Z`
- Scope: full repository working tree, excluding generated build output, dependency caches, and `.git` for manual grep review.

Note: the final Git commit cannot embed its own hash without changing that hash. The exact final commit is recorded in the final response after this report is committed.

## Scanner And Tool Matrix

| Tool/check | Result |
| --- | --- |
| `gitleaks detect` | skipped: `gitleaks` not installed. Fallback: concrete secret regex sweep for private-key headers and common cloud/API token formats. |
| `trufflehog filesystem` | skipped: `trufflehog` not installed. Fallback: concrete secret regex sweep. |
| `semgrep` | skipped: not installed. Fallback: manual SAST grep plus targeted code review. |
| `bandit` | skipped: not installed. Fallback: Python security grep for subprocess, eval/exec, deserialization, path, archive, TLS, and network defaults. |
| `pip-audit` | skipped: not installed. |
| `safety` | skipped: not installed. |
| `npm audit --audit-level=moderate` | passed on final rerun with approved network access: `found 0 vulnerabilities`. |
| `pnpm audit` | skipped: `pnpm` not installed and no `pnpm-lock.yaml`. |
| `yarn audit` | skipped: `yarn` not installed and no `yarn.lock`. |
| `cargo audit` | skipped: cargo subcommand not installed; `PATH=.tools/bin:$PATH cargo audit --version` returned `error: no such command: audit`. |
| `cargo fmt` | blocked for `cargo fmt --check` targets: `cargo-fmt` is present only as `/home/chasebryan/.cargo/bin/cargo-fmt` and rustup has no default toolchain configured. |
| `cargo clippy` | blocked: `cargo-clippy` is present only as `/home/chasebryan/.cargo/bin/cargo-clippy` and rustup has no default toolchain configured. |
| `cargo test` | passed for available Rust crates listed below; fresh ZP1 bridge test passed after restoring the declared pinned submodule. |
| `go test`, `gosec`, `govulncheck` | skipped: no Go module/tooling detected; tools not installed. |
| `mvn test`, `mvn dependency-check`, `gradle test` | skipped: Maven/Gradle not installed and no Java build root detected. |
| `shellcheck` | skipped: not installed. Fallback: grep review of shell scripts, CI, and dangerous shell patterns. |
| `hadolint` | skipped: not installed; no Dockerfile found in repo scan. |
| `trivy fs` | skipped: not installed. |
| `ruff`, `mypy`, `pytest` | skipped: not installed. Fallback: `unittest` suites and repo-native Python tests. |
| `npm run build` | passed: `site build: OK`. |
| `make test` | passed. |
| `make wucios-validate` | passed with one documented human-approval warning from the validator. |
| `make site-validate` | passed. |
| `make check`, `make validate` | skipped: no such make targets. |

Tool availability command:

```sh
for tool in gitleaks trufflehog semgrep bandit pip-audit safety npm pnpm yarn cargo gosec govulncheck mvn gradle shellcheck hadolint trivy ruff mypy pytest node python3 make; do if PATH=.tools/bin:$PATH command -v "$tool" >/dev/null 2>&1; then printf '%s: present (%s)\n' "$tool" "$(PATH=.tools/bin:$PATH command -v "$tool")"; else printf '%s: missing\n' "$tool"; fi; done
```

Available tools from the original matrix command: `npm`, `cargo`, `node`, `python3`, `make`.

Fresh continuation availability recheck also found `cargo-clippy`, `rustdoc`, `rustfmt`, and local Rust tool wrappers, but `cargo fmt --version` and `cargo clippy --version` both fail through rustup because no default toolchain is configured.

## Findings Summary Before Remediation

Validated repo-controlled findings remediated in this pass:

- HIGH: release gate accepted substring-style ledger evidence instead of reconstructing ledger inclusion proof.
- MEDIUM: duplicate-key JSON could create ambiguous policy/evidence interpretation across Gate, Witness, CAGE, QCAGE, release, Daylight, and install paths.
- MEDIUM: public evidence and release artifact reads were not consistently symlink/hardlink safe.
- MEDIUM: release bundle privacy binding could become stale and did not explicitly bind copied artifacts to scanned digests.
- MEDIUM: raw ISO/OVA privacy scanning was ambiguous; uninspected container payloads now fail closed unless exact prior inspection evidence is bound.
- MEDIUM: install lane could read/copy proof and binary material without enough link and post-copy identity checks.
- MEDIUM: external audit and production-authority lanes could treat unsigned/local evidence too strongly.
- MEDIUM: Daylight v16 Zenith accepted self-declared runtime containment and quantum-safety fields.
- MEDIUM: WuciOS source-kit manifest exposed host-local source paths and could include untracked local files.
- LOW/MEDIUM: Debian trial build probe used an HTTP mirror URL.
- LOW/MEDIUM: public documentation and status JSON contained unsupported or scanner-denied security claim wording without enough qualification.

No live private key, cloud token, GitHub token, Slack token, AWS key, OpenAI key, or bearer token was found by the concrete secret fallback sweep. Private-key header hits are detector constants or negative-test fixtures.

## Remediations Performed

- Added duplicate-key JSON rejection helpers to `tools/wuci_safeio.py` and adopted them across release, witness, ledger, CAGE, QCAGE, install, KAIJU, and Daylight parsers.
- Hardened public and evidence reads with regular-file, symlink, hardlink, fstat identity, and size checks.
- Reworked `tools/wuci_release_gate.py` to verify real ledger inclusion using `tools/wuci_ledger.py`, not text substring evidence.
- Bound release signature evidence to exact schema/status/manifest/ISO/signature digests and ledger inclusion state.
- Hardened release privacy auditing for tar/zip limits and raw container fail-closed behavior.
- Hardened release bundle copying, output parent checks, privacy digest freshness, build-tool identity restrictions, and raw-container prior-inspection binding.
- Hardened witness archive pack/verify against unsafe sidecars, hardlinks, oversize archives, unsafe extraction paths, and member limits.
- Hardened install root-key, manifest, proof, and installed-binary handling with link rejection, atomic writes, and recomputed proof audit records.
- Hardened external-audit and production-authority tooling so unsigned local review remains non-production and pinned verifier identity is enforced.
- Hardened KAIJU JSON size/duplicate-key handling, symlinked roots, and output roots.
- Hardened v15/v16/v19 Daylight path, JSON, capsule, public artifact, and firewall handling.
- Made v16 Zenith fail closed for runtime containment and post-quantum safety until real pinned verifier lanes exist.
- Hardened WuciOS source-kit generation to omit host paths and include only tracked source files.
- Changed WuciOS Debian build probe mirror from HTTP to HTTPS.
- Updated claim scanner coverage for JSON/YAML and repeated occurrences, then qualified unsupported public security claims.
- Added a narrow allowlist for the v20 status JSON non-claim phrase required to match its committed source capsule.

## Tests Added Or Changed

New or updated regression coverage includes:

- `tests/wuci_release_gate.py`: real ledger proof, stale signature evidence, substring-only ledger rejection.
- `tests/wuci_safeio.py`: duplicate-key JSON rejection.
- `tests/wuci_ledger_mutation_hardening.py`: hardlinked ledger entry rejection.
- `tests/wuci_witness_symlink_hardening.py`, `tests/wuci_cage_bundle.py`: symlinked bundle/root rejection.
- `tests/wuci_witness_archive.py`: sidecar symlink/hardlink and oversize archive/member rejection.
- `tests/wuci_release_privacy_audit.py`: raw ISO fail-closed and archive limits.
- `tests/wuci_release_bundle.py`: privacy binding, stale privacy, duplicate JSON, symlink output parent, repo build tool identity, uninspected raw container rejection.
- `tests/wuci_install_audit.py`: receipt-only/non-fully-verified install proof audit assertions.
- `tests/wuci_external_audit.py`, `tests/wuci_production_authority.py`: unsigned evidence remains non-production.
- `tests/wuci_kaiju.py`: duplicate JSON, oversized manifest, symlinked ISO/disk workspace root.
- `tests/daylight_legacy_ledger_duplicate_keys.py`: duplicate-key JSONL ledger rejection.
- Daylight v15/v16/v19 tests: duplicate JSON, bounded headers, safe vault names, gate evidence requirements, self-declared runtime/PQ rejection, path-safety hardening.
- `tests/daylight_public_evidence_firewall.py`: manifest traversal rejection.
- `tests/wucios_build_probe.py`: symlink/hardlink rootfs archive rejection and HTTPS Debian mirror command.
- `tests/wuci_os.py`: source-kit host path omission and untracked file exclusion.

## Validation Commands And Results

### Fresh Post-Remediation Continuation Validation

The following pass was run from current HEAD `dd3605078178d683d053a9398039797a64ead33a`, not from the earlier round-10 scan state.

Repository state printed before report update:

```sh
git branch --show-current
# security/deep-remediation-20260707-030717

git rev-parse HEAD
# dd3605078178d683d053a9398039797a64ead33a

git status --short
# no output

git submodule status --recursive
#  ee1b853abe99ee8dadfa57bc356fdf5abce1d816 third_party/zp1 (ee1b853)

ls -la third_party
# third_party contains checked-out directory zp1

ls -la third_party/zp1
# contains .git, Cargo.lock, Cargo.toml, PROVIDERS.md, README.md, SECURITY.md, SPEC.md, src/, tests/, tools/, and related upstream files
```

ZP1 bridge blocker investigation:

- `.gitmodules` declares `third_party/zp1` as a submodule with URL `https://github.com/chasebryan/ZP-1.git`.
- `git ls-tree HEAD third_party/zp1` records gitlink `ee1b853abe99ee8dadfa57bc356fdf5abce1d816`.
- `tools/wuciji-zp1-bridge/Cargo.toml` depends on `zp1 = { path = "../../third_party/zp1", features = ["test-utils"] }`.
- `docs/ZP1_WUCIJI_COUPLING.md` and `docs/ZP1_WUCIJI_COUPLING.v1.json` describe ZP1 as a pinned research/test-utils dependency, not production authority or production cryptography.
- Conclusion: `third_party/zp1` is a required declared pinned git submodule for the ZP1 research bridge lane. It is not a stale test expectation and not an optional undeclared dependency.

ZP1 submodule restoration and bridge validation:

```sh
git submodule update --init --recursive
# sandboxed attempt failed:
# error: could not lock config file .git/config: Read-only file system
# fatal: Failed to register url for submodule path 'third_party/zp1'

git submodule update --init --recursive
# approved escalated rerun succeeded:
# Submodule path 'third_party/zp1': checked out 'ee1b853abe99ee8dadfa57bc356fdf5abce1d816'

PATH=.tools/bin:$PATH make zp1-wuciji-bridge-test
# sandboxed attempt failed before repo logic because crates.io could not be resolved.

PATH=.tools/bin:$PATH make zp1-wuciji-bridge-test
# approved network rerun passed, but `cargo generate-lockfile` updated Cargo.lock to newer compatible crates.
# The lockfile was restored to the checked-in state before final proof.

RUSTC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=.tools/bin:$PATH cargo test --manifest-path tools/wuciji-zp1-bridge/Cargo.toml --locked
# passed: 2 integration tests passed; doctests completed with 0 tests.

PYTHONPATH=. python3 tools/check_zp1_wuciji_coupling.py
# ZP1/WuciJi coupling check passed
```

Fresh required validation commands:

```sh
PATH=.tools/bin:$PATH npm audit --audit-level=moderate
# sandboxed attempt failed with DNS EAI_AGAIN; approved network rerun passed: found 0 vulnerabilities.

PYTHONPATH=. python3 tests/wuci_safeio.py
# wuci safeio: PASS

PYTHONPATH=. python3 tests/wuci_cage_bundle.py
# wuci cage bundle: PASS

git diff --check
# passed, no output

git diff --cached --check
# passed, no output

PATH=.tools/bin:$PATH make test
# passed

PATH=.tools/bin:$PATH make wucios-validate
# passed; emitted the known human-approval-boundary warning from the validator

PATH=.tools/bin:$PATH make site-validate
# passed: site-daylight-status OK and site build OK

PATH=.tools/bin:$PATH npm run build
# passed: site build OK
```

Fresh ZP1 aggregate/upstream target status:

```sh
RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-upstream-test
# failed at `cd "third_party/zp1" && cargo fmt --check`
# error: rustup could not choose a version of cargo-fmt to run, because one wasn't specified explicitly, and no default is configured.

RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-wuciji-coupling-test
# same failure at the `zp1-upstream-test` prerequisite before repo coupling logic runs.
```

Fresh scanner/tool status:

| Tool | Found | Command attempted | Result | Fallback |
| --- | --- | --- | --- | --- |
| `gitleaks` | not found | `command -v gitleaks` | missing | concrete secret regex sweep |
| `trufflehog` | not found | `command -v trufflehog` | missing | concrete secret regex sweep |
| `semgrep` | not found | `command -v semgrep` | missing | manual SAST grep plus targeted code review |
| `bandit` | not found | `command -v bandit` | missing | Python security grep and targeted review |
| `pip-audit` | not found | `command -v pip-audit` | missing | repo-native Python tests; no pip-audit DB result available |
| `safety` | not found | `command -v safety` | missing | repo-native Python tests; no safety DB result available |
| `npm` | found at `.tools/bin/npm` | `PATH=.tools/bin:$PATH npm audit --audit-level=moderate` | passed with approved network access: `found 0 vulnerabilities` | not needed |
| `pnpm` | not found | `command -v pnpm` | missing | no `pnpm-lock.yaml` |
| `yarn` | not found | `command -v yarn` | missing | no `yarn.lock` |
| `cargo` | found at `.tools/bin/cargo` | `cargo test` for repo crates and ZP1 bridge | passed for run lanes listed above | not needed for tests run |
| `cargo-audit` | not found as cargo subcommand | `PATH=.tools/bin:$PATH cargo audit --version` | failed: `error: no such command: audit` | no Rust advisory DB result available |
| `cargo-fmt` | found at `/home/chasebryan/.cargo/bin/cargo-fmt` | `PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH cargo fmt --version` | failed: rustup has no default toolchain | direct `rustfmt --version` works, but Makefile upstream target invokes `cargo fmt` |
| `cargo-clippy` | found at `/home/chasebryan/.cargo/bin/cargo-clippy` | `PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH cargo clippy --version` | failed: rustup has no default toolchain | no clippy result available |
| `gosec` | not found | `command -v gosec` | missing | no Go module detected |
| `govulncheck` | not found | `command -v govulncheck` | missing | no Go module detected |
| `mvn` | not found | `command -v mvn` | missing | no Java build root detected |
| `gradle` | not found | `command -v gradle` | missing | no Java build root detected |
| `shellcheck` | not found | `command -v shellcheck` | missing | shell-danger grep review |
| `hadolint` | not found | `command -v hadolint` | missing | no Dockerfile found |
| `trivy` | not found | `command -v trivy` | missing | manual dependency/tool review only |
| `ruff` | not found | `command -v ruff` | missing | repo-native Python tests |
| `mypy` | not found | `command -v mypy` | missing | repo-native Python tests |
| `pytest` | not found | `command -v pytest` | missing | unittest/direct Python test scripts |
| `node` | found at `.tools/bin/node` | `PATH=.tools/bin:$PATH npm run build` | passed | not needed |
| `python3` | found at `/usr/bin/python3` | direct Python tests listed above | passed for run lanes | not needed |
| `make` | found at `.tools/bin/make` | `make test`, `make wucios-validate`, `make site-validate` | passed | not needed |
| `rustc` | found at `.tools/bin/rustc` | `rustc -vV`; ZP1 bridge with pinned `RUSTC` | version available; bridge passed | used explicit compiler for Cargo child process |
| `rustdoc` | found at `/home/chasebryan/.cargo/bin/rustdoc`; direct pkgroot binary `/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc` used for bridge | `rustdoc --version`; ZP1 bridge with pinned `RUSTDOC` | version available; bridge doctests completed | used explicit rustdoc for Cargo child process |
| `rustfmt` | found at `/home/chasebryan/.cargo/bin/rustfmt` | `PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH rustfmt --version` | passed: `rustfmt 1.9.0-stable (31fca3adb2 2026-06-26)` | does not unblock `cargo fmt` subcommand |

Fresh fallback sweep results:

- Secret regex sweep: hits were private-key detector constants and negative-test fixtures in `tools/daylight_public_evidence_firewall.py`, `daylight/v20-aperture-singularity/src/public_artifact.py`, `daylight/v19-aperture-bastion/tests/test_firewall.py`, `daylight/v19-aperture-bastion/tests/test_capsule.py`, and `daylight/v19-aperture-bastion/src/cli.py`; no live private key, cloud token, GitHub token, Slack token, AWS key, OpenAI key, or bearer token was found.
- Dangerous execution sweep: `subprocess.Popen` callsites in `tools/wuci_progress.py` and `tools/wuci_black_ice.py` use argv lists and no shell; policy/documentation hits mention forbidden `shell=True`/`eval`; no runtime `shell=True`, `eval`, or `os.system` path was found.
- Weak crypto/randomness sweep: hits are CSPRNG/provider interfaces (`getrandom`, `os.urandom`, ZP1 provider `fill_random`) and one SHA-1 stale-commit test fixture; no new weak production crypto finding was identified.
- Archive extraction sweep: no `tarfile.extract(` or `extractall(` matches in scoped source search.
- Network-default sweep: hits are URL detectors, XML/schema namespaces, localhost allowances, redirect tests, or reviewed repo-source command construction; the Debian trial mirror remains HTTPS after remediation.
- World-writable file sweep: no output.

Passed:

```sh
PYTHONPATH=. python3 tests/wuci_safeio.py
PYTHONPATH=. python3 tests/wuci_ledger_mutation_hardening.py
PYTHONPATH=. python3 tests/wuci_witness_symlink_hardening.py
PYTHONPATH=. python3 tests/wuci_cage_bundle.py
PYTHONPATH=. python3 tests/wuci_release_gate.py
PYTHONPATH=. python3 tests/wuci_witness_archive.py --bundle build/wuci-witness-bundle --bin build/wuci-ji
PYTHONPATH=. python3 tests/wuci_release_privacy_audit.py
PYTHONPATH=. python3 tests/wuci_release_bundle.py
PYTHONPATH=. python3 tests/wuci_install_audit.py
PYTHONPATH=. python3 tests/wuci_external_audit.py
PYTHONPATH=. python3 tests/wuci_production_authority.py
PYTHONPATH=. python3 tests/wuci_kaiju.py
PYTHONPATH=. python3 tests/wuci_os.py --quiet
PYTHONPATH=. python3 tests/daylight_public_evidence_firewall.py
PYTHONPATH=. python3 tests/wucios_build_probe.py
PYTHONPATH=. python3 tests/daylight_legacy_ledger_duplicate_keys.py
```

Passed package suites:

```sh
PYTHONPATH=. python3 -m unittest discover tests  # daylight/v15-meridian, 113 tests
PYTHONPATH=. python3 -m unittest discover tests  # daylight/v15-solstice, 6 tests
PYTHONPATH=. python3 -m unittest discover tests  # daylight/v16-analemma, 14 tests
PYTHONPATH=. python3 -m unittest discover tests  # daylight/v16-zenith, 15 tests
PYTHONPATH=. python3 -m unittest discover tests  # daylight/v19-aperture-bastion, 89 tests
PYTHONPATH=daylight/v20-aperture-singularity python3 -m unittest discover -s daylight/v20-aperture-singularity/tests -t daylight/v20-aperture-singularity  # 192 tests
```

Passed Rust checks:

```sh
PATH=.tools/bin:$PATH cargo test --tests --bins --lib  # penumbra, 12 tests
PATH=.tools/bin:$PATH cargo test --tests --bins        # tools/wuci-pq-fips204-verify
PATH=.tools/bin:$PATH cargo test --tests --bins --lib  # daylight-equation/rust/daylight-model, 12 tests
PATH=.tools/bin:$PATH cargo test --tests --bins --lib  # daylight-equation/rust/daylight-crypto, 61 passed, 1 ignored
PATH=.tools/bin:$PATH cargo test --tests --bins        # daylight/v17-singularity/rust/event-horizon-verifier, 3 tests
```

Passed repo-native validation:

```sh
PATH=.tools/bin:$PATH npm run build
python3 tools/wucios/scan_claims.py
PATH=.tools/bin:$PATH make test
PATH=.tools/bin:$PATH make wucios-validate
PATH=.tools/bin:$PATH make site-validate
git diff --check
```

Skipped/unavailable validation:

```sh
PATH=.tools/bin:$PATH make check      # no such target
PATH=.tools/bin:$PATH make validate   # no such target
RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-upstream-test  # superseded in toolchain closeout: passed
RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-wuciji-coupling-test  # superseded in toolchain closeout: passed
PATH=.tools/bin:$PATH npm audit --audit-level=moderate # passed: found 0 vulnerabilities
```

Manual review commands:

```sh
rg -n -I --with-filename --hidden --glob '!build/**' --glob '!**/target/**' --glob '!node_modules/**' --glob '!.git/**' --glob '!security/reports/**' -- '-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----|sk-proj-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9_-]{20,}\b|github_pat_[A-Za-z0-9_]{20,}|\bgh[opsru]_[A-Za-z0-9_]{20,}|\bAKIA[0-9A-Z]{16}\b|xox[baprs]-[A-Za-z0-9-]{20,}|Authorization: Bearer [A-Za-z0-9._~+/-]{20,}'
rg -n -I --with-filename --hidden --glob '!build/**' --glob '!**/target/**' --glob '!node_modules/**' --glob '!.git/**' --glob '!security/reports/**' -- 'shell=True|eval\(|exec\(|os\.system|popen\(|subprocess\.Popen|child_process|Runtime\.exec|ProcessBuilder'
rg -n -I --with-filename --glob '*.py' --glob '*.rs' --glob '*.js' --glob '*.mjs' --glob '*.sh' --glob '*.zig' --glob '*.toml' --glob '!build/**' --glob '!**/target/**' --glob '!node_modules/**' --glob '!.git/**' --glob '!security/reports/**' -- '\bmd5\b|\bsha1\b|sha-1|\bDES\b|\bRC4\b|\bECB\b|Math\.random|random\('
rg -n -I --with-filename --glob '*.py' --glob '*.rs' --glob '*.js' --glob '*.mjs' --glob '*.sh' --glob '*.zig' --glob '!build/**' --glob '!**/target/**' --glob '!node_modules/**' --glob '!.git/**' --glob '!security/reports/**' -- 'tarfile\.extract\(|extractall\('
rg -n -I --with-filename --glob '*.py' --glob '*.rs' --glob '*.js' --glob '*.mjs' --glob '*.sh' --glob '*.zig' --glob '!build/**' --glob '!**/target/**' --glob '!node_modules/**' --glob '!.git/**' --glob '!security/reports/**' -- '0\.0\.0\.0|verify=False|rejectUnauthorized\s*[:=]\s*false|ssl_verify\s*=\s*false|http://'
find . -path './.git' -prune -o -path './build' -prune -o -path '*/target' -prune -o -path './node_modules' -prune -o -type f -perm -0002 -print
```

Manual review result:

- Secret-like concrete signatures: no live secrets found; hits were detector constants and negative test fixtures.
- Dangerous execution: no `shell=True`, `eval`, or `os.system` runtime path found. `Popen` hits use argv lists and no shell.
- Deserialization: no unsafe pickle/yaml/marshal load found in scoped code search.
- Weak crypto/randomness: `getrandom` and `os.urandom` are CSPRNG uses; one SHA-1 hit is a test-only stale commit digest fixture.
- Archive extraction: no direct `tarfile.extract` or `extractall` use found in scoped code search.
- Network defaults: HTTP Debian mirror remediated to HTTPS; remaining HTTP strings are redirect tests, XML/schema namespaces, localhost allowances, or URL detectors.
- File permissions: no world-writable tracked files found outside excluded generated/dependency directories.

## Toolchain Closeout

Starting classification for this closeout: `FALSE_BLOCKED_EXTERNAL`.

Rust blocker cause:

- Global rustup shims existed for `cargo-fmt` and `cargo-clippy`, but the prior run had no active default toolchain for the relevant rustup state.
- After setting the global default, the exact ZP1 make command still failed because `.tools/bin/cargo` exports `RUSTUP_HOME=/home/chasebryan/-wuci-ji/.tools/rustup-home`; that repo-local rustup home initially had no installed/default toolchain.
- After installing stable into `.tools/rustup-home`, `make zp1-upstream-test` reached clippy but failed once with mixed Rust metadata: upstream tests compiled with the `.tools` Fedora `rustc`, while clippy came from rustup stable.
- Local ignored tooling fix: `.tools/bin/cargo` was adjusted to use the repo-local rustup stable `rustc`, `rustdoc`, `cargo-fmt`, and `cargo-clippy` consistently. This changed only ignored local tool-wrapper state; no tracked source file changed.

Start-state commands:

```sh
git status --short
# no output
git branch --show-current
# security/deep-remediation-20260707-030717
git rev-parse HEAD
# de56f1f655cc2ceb53c51ee4609db31247088344
git submodule status third_party/zp1
#  ee1b853abe99ee8dadfa57bc356fdf5abce1d816 third_party/zp1 (ee1b853)
```

Rust state and toolchain fix commands:

```sh
which rustup || true
# /home/chasebryan/.cargo/bin/rustup
which cargo || true
# /home/chasebryan/.cargo/bin/cargo
which rustc || true
# /home/chasebryan/.cargo/bin/rustc
which rustfmt || true
# /home/chasebryan/.cargo/bin/rustfmt
which cargo-fmt || true
# /home/chasebryan/.cargo/bin/cargo-fmt
which cargo-clippy || true
# /home/chasebryan/.cargo/bin/cargo-clippy
rustup show || true
# stable-x86_64-unknown-linux-gnu active/default
rustup toolchain list || true
# stable-x86_64-unknown-linux-gnu (active, default)

rustup default stable
# sandboxed attempt failed writing /home/chasebryan/.rustup/settings.toml; approved rerun passed and left stable unchanged
rustup component add rustfmt clippy
# rustfmt and clippy were up to date

RUSTUP_HOME=/home/chasebryan/-wuci-ji/.tools/rustup-home CARGO_HOME=/home/chasebryan/-wuci-ji/.tools/cargo-home rustup default stable
# sandboxed attempt failed DNS fetching static.rust-lang.org; approved network rerun installed stable 1.96.1 under .tools/rustup-home
RUSTUP_HOME=/home/chasebryan/-wuci-ji/.tools/rustup-home CARGO_HOME=/home/chasebryan/-wuci-ji/.tools/cargo-home rustup component add rustfmt clippy
# rustfmt and clippy were up to date

cargo fmt --version
# rustfmt 1.9.0-stable (31fca3adb2 2026-06-26)
cargo clippy --version
# clippy 0.1.96 (31fca3adb2 2026-06-26)
rustfmt --version
# rustfmt 1.9.0-stable (31fca3adb2 2026-06-26)
PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH cargo fmt --version
# rustfmt 1.9.0-stable (31fca3adb2 2026-06-26)
PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH cargo clippy --version
# clippy 0.1.96 (31fca3adb2 2026-06-26)
```

Previously blocked ZP1 lanes:

```sh
RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-upstream-test
# first rerun after rustup setup failed at clippy with incompatible rustc metadata; after local .tools cargo-wrapper consistency fix and cargo clean, passed

RUSTC=/home/chasebryan/-wuci-ji/.tools/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=/home/chasebryan/-wuci-ji/.tools/bin:$PATH make zp1-wuciji-coupling-test
# sandboxed attempt passed upstream prerequisite and failed at bridge lockfile crates.io DNS; approved network rerun passed
```

The aggregate ZP1 target's `cargo generate-lockfile` temporarily updated `tools/wuciji-zp1-bridge/Cargo.lock` from `zerocopy`/`zerocopy-derive` 0.8.52 to 0.8.53. That lockfile drift was inspected, was not required for the remediation, and was restored to the tracked 0.8.52 state before final validation.

Final validation commands:

```sh
npm audit --audit-level=moderate
# default PATH failed: npm not found
PATH=.tools/bin:$PATH npm audit --audit-level=moderate
# sandboxed attempt failed DNS; approved network rerun passed: found 0 vulnerabilities

PYTHONPATH=. python3 tests/wuci_safeio.py
# wuci safeio: PASS
PYTHONPATH=. python3 tests/wuci_cage_bundle.py
# wuci cage bundle: PASS
RUSTC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustc RUSTDOC=/home/chasebryan/-wuci-ji/.tools/pkgroot/usr/bin/rustdoc PATH=.tools/bin:$PATH cargo test --manifest-path tools/wuciji-zp1-bridge/Cargo.toml --locked
# passed: 2 integration tests; doctests completed with 0 tests
PYTHONPATH=. python3 tools/check_zp1_wuciji_coupling.py
# ZP1/WuciJi coupling check passed
make test
# passed
make wucios-validate
# passed with the documented Phase 3B human-approval-boundary warning
make site-validate
# default PATH failed: node not found
PATH=.tools/bin:$PATH make site-validate
# passed: site-daylight-status OK; site build OK
npm run build
# default PATH failed: npm not found
PATH=.tools/bin:$PATH npm run build
# passed: site build OK
git diff --check
# passed, no output
git diff --cached --check
# passed, no output
git status --short
# no output after generated bridge target cleanup
git submodule status third_party/zp1
#  ee1b853abe99ee8dadfa57bc356fdf5abce1d816 third_party/zp1 (ee1b853)
```

Closeout classification: `TRUE_REMEDIATION_COMPLETE_TOOLCHAIN_BLOCKERS_CLEARED`.

## Remaining Accepted Risks

- The repository still contains intentional fixture secrets, private-key marker strings, and negative-test material. These are test fixtures or detector constants, not production credentials.
- Classical cryptography remains clearly documented as not quantum-safe where applicable.
- Runtime containment and production authority are not claimed without pinned/kernel-level evidence.
- The v20 status JSON keeps the committed source capsule non-claim phrase `not externally certified`; this is allowlisted narrowly because it is a denial and must match the capsule.

## Blocked External Items

- The ZP1 bridge blocker caused by missing `third_party/zp1` is resolved: the declared submodule restored successfully at pinned commit `ee1b853abe99ee8dadfa57bc356fdf5abce1d816`, the bridge test passed with `--locked`, and `tools/check_zp1_wuciji_coupling.py` passed.
- The broader ZP1 upstream/coupling aggregate make targets are no longer blocked: `make zp1-upstream-test` and `make zp1-wuciji-coupling-test` passed after repo-local rustup stable setup and local ignored tool-wrapper consistency repair.
- Non-actionable scanner/tool gaps from the broader scan environment remain documented: `gitleaks`, `trufflehog`, `semgrep`, `bandit`, `pip-audit`, `safety`, `cargo-audit`, `gosec`, `govulncheck`, `shellcheck`, `hadolint`, `trivy`, `ruff`, `mypy`, and `pytest` were not installed. These are not remaining blockers for this bounded Rust toolchain closeout.

## Final Worktree Status

Final worktree status is recorded after report commit in the final response. At report creation time the worktree contained only intentional remediation and this report.

## Final Classification

`TRUE_REMEDIATION_COMPLETE_TOOLCHAIN_BLOCKERS_CLEARED`

All repo-controlled CRITICAL, HIGH, and MEDIUM findings identified in this pass were remediated or documented with narrow false-positive/accepted-risk rationale. The fresh current-HEAD pass proves the ZP1 bridge dependency is a declared pinned submodule, the narrow WuciJi/ZP1 bridge lane passes, the upstream ZP1 make target passes, the aggregate ZP1 coupling target passes, and the prior core validation set passes after clearing the local Rust toolchain blocker.
