# Deep Security Remediation Report - 2026-07-07

## Repository

- Repository name: `-wuci-ji`
- Branch: `security/deep-remediation-20260707-030717`
- Starting commit: `9f7c3a3de401f04e72a32192cdeff31eab14c933`
- Final commit: `RECORDED_IN_FINAL_RESPONSE_AFTER_COMMIT`
- Report generated UTC: `2026-07-07T07:47:21Z`
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
| `cargo audit` | skipped: cargo subcommand not installed. |
| `cargo clippy` | skipped: cargo subcommand not installed. |
| `cargo test` | passed for available Rust crates listed below; ZP1 bridge blocked by missing `third_party/zp1`. |
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

Available tools: `npm`, `cargo`, `node`, `python3`, `make`.

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
PATH=.tools/bin:$PATH cargo test --tests --bins --lib  # tools/wuciji-zp1-bridge blocked: missing third_party/zp1/Cargo.toml
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

## Remaining Accepted Risks

- The repository still contains intentional fixture secrets, private-key marker strings, and negative-test material. These are test fixtures or detector constants, not production credentials.
- Classical cryptography remains clearly documented as not quantum-safe where applicable.
- Runtime containment and production authority are not claimed without pinned/kernel-level evidence.
- The v20 status JSON keeps the committed source capsule non-claim phrase `not externally certified`; this is allowlisted narrowly because it is a denial and must match the capsule.

## Blocked External Items

- `tools/wuciji-zp1-bridge` cargo test is blocked by missing local external dependency `third_party/zp1/Cargo.toml`. This dependency is not present in the repository.
- Many requested scanners are not installed on this machine: `gitleaks`, `trufflehog`, `semgrep`, `bandit`, `pip-audit`, `safety`, `cargo-audit`, `gosec`, `govulncheck`, `shellcheck`, `hadolint`, `trivy`, `ruff`, `mypy`, and `pytest`.

## Final Worktree Status

Final worktree status is recorded after report commit in the final response. At report creation time the worktree contained only intentional remediation and this report.

## Final Classification

`REPO_SECURITY_REMEDIATION_BLOCKED_BY_EXTERNAL_REQUIREMENTS`

All repo-controlled CRITICAL, HIGH, and MEDIUM findings identified in this pass were remediated or documented with narrow false-positive/accepted-risk rationale. The repository cannot honestly be classified TRUE because one local external Rust dependency validation and multiple optional scanner lanes are blocked by environment/dependency availability outside repository control.
