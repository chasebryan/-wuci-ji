# Wuci-Ji Deep Security Remediation Ledger

## Source Audit
- report path: security/reports/deep-security-scan-2026-07-06.md
- generated report path: /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/report.md
- pre-scan commit: 1d420abb2788027cb6c0febb928269e8d9bd96e5
- evidence baseline commit: f937b1540279fccb0379c93ddf86ca6a09d42824
- starting classification: WUCI_JI_NATIONAL_SECURITY_DEFENSE_AUDIT_FALSE
- starting finding count: 38 total; 9 high, 26 medium, 3 low

## Finding Ledger
### CAN-R01-001: Daylight v16 Analemma accepts self-supplied HMAC root keys as signed external review evidence

- finding ID: CAN-R01-001
- severity: high
- area: Crypto
- file(s):
  - daylight/v16-analemma/src/cli.py:99-104
  - daylight/v16-analemma/src/cli.py:107-112
  - daylight/v16-analemma/src/analemma.py:114-119
  - daylight/v16-analemma/src/analemma.py:123-130
  - daylight/v16-analemma/src/analemma.py:257-268
  - daylight/v16-analemma/rules/proof-units.v1.json:220-229
- issue summary: The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-001.
- required remediation: Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.
- patch status: pending
- verification command: targeted tests for CAN-R01-001; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-003: Credential and session stores are present inside the resolved local scan scope

- finding ID: CAN-R01-003
- severity: high
- area: Secrets
- file(s):
  - .wrangler/config/.wrangler/config/default.toml:1
  - .wrangler/config/.wrangler/config/default.toml:3
  - .wrangler/config/.wrangler/config/default.toml:4
  - package.json:12-15
  - .gitignore:14
  - .wrangler/cache/wrangler-account.json:1
  - external-ssd-export-20260705/README.txt:24-27
  - external-ssd-export-20260705/00-MANIFESTS/COPY_NOTES.txt:18-21
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.codex/auth.json:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.claude/.credentials.json:1
  - external-ssd-export-20260705/09-Backups-Restore/restore-staging/20260703T111113Z/home/wj/.claude/.credentials.json:1
  - tools/daylight_public_evidence_firewall.py:39-61
  - tools/daylight_public_evidence_firewall.py:140-181
  - tools/wuci_release_privacy_audit.py:54-111
  - tools/wuci_release_privacy_audit.py:194-236
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.claude/.credentials.json:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.claude.json:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.codex/auth.json:4-8
  - external-ssd-export-20260705/09-Backups-Restore/restore-staging/20260703T111113Z/home/wj/.config/gh/hosts.yml:4
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.config/gh/hosts.yml:4
  - external-ssd-export-20260705/09-Backups-Restore/restore-backups/20260703T111113Z/.mozilla/firefox/7g02nmco.default-default/signedInUser.json:1
  - external-ssd-export-20260705/09-Backups-Restore/restore-staging/20260703T111113Z/home/wj/.mozilla/firefox/n7vqgpvu.default-default/signedInUser.json:1
  - .wrangler/cache/wrangler-account.json:2-4
  - tools/daylight_public_evidence_firewall.py:39-61
- issue summary: Credential-bearing and session-store paths were present under the resolved scan target. Values were not printed or tested, but the file types and fields are sensitive. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-003.
- required remediation: Remove credential and session stores from the repository workspace, rotate any potentially exposed credentials, keep local app state outside the checkout, and extend release/public-evidence scanners to reject the observed credential-store formats without printing values.
- patch status: pending
- verification command: targeted tests for CAN-R01-003; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-008: Generated grok build can send XAI_API_KEY to caller-controlled XAI_API_BASE

- finding ID: CAN-R01-008
- severity: high
- area: Code
- file(s):
  - tools/wuci_os.py:9423-9431
  - tools/wuci_os.py:9443-9452
  - tools/wuci_os.py:10901-10904
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-008.
- required remediation: Avoid passing secrets through command arguments or mutable endpoint environment variables; use stdin, protected config files, host pinning, and explicit allowlists for credential destinations.
- patch status: pending
- verification command: targeted tests for CAN-R01-008; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-010: Wuci-OS source-kit fallback can package ignored credential files when git enumeration fails

- finding ID: CAN-R01-010
- severity: high
- area: Release
- file(s):
  - .wrangler/config/.wrangler/config/default.toml:1
  - tools/wuci_os.py:3922-3927
  - tools/wuci_os.py:3974-4024
  - tools/wuci_os.py:4127-4137
  - tools/wuci_os.py:14383
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.codex/auth.json:4-8
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.claude/.credentials.json:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.config/gh/hosts.yml:4
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-010.
- required remediation: Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.
- patch status: pending
- verification command: targeted tests for CAN-R01-010; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-011: Wuci-OS release privacy audit misses source-kit credential formats and final ISO payload contents

- finding ID: CAN-R01-011
- severity: high
- area: Release
- file(s):
  - tools/wuci_release_privacy_audit.py:25-35
  - tools/wuci_release_privacy_audit.py:54-93
  - tools/wuci_release_privacy_audit.py:95-110
  - tools/wuci_release_privacy_audit.py:239-260
  - .wrangler/config/.wrangler/config/default.toml:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.claude/.credentials.json:1
  - external-ssd-export-20260705/10-Dotfiles-App-Config/.codex/auth.json:4-8
  - tools/wuci_release_privacy_audit.py:25-35
  - tools/wuci_release_privacy_audit.py:210-221
  - tools/wuci_release_privacy_audit.py:348-352
  - tests/wuci_release_privacy_audit.py:78-87
  - tools/wuci_release_bundle.py:235-259
  - tools/wuci_release_bundle.py:292-304
  - tools/wuci_release_bundle.py:364-366
  - docs/WUCI_OS_RELEASE_RUNBOOK.md:32-38
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-011.
- required remediation: Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.
- patch status: pending
- verification command: targeted tests for CAN-R01-011; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-017: Wuci-OS debugfs overlay commands interpolate unquoted rootfs paths into command files

- finding ID: CAN-R02-017
- severity: high
- area: Code
- file(s):
  - tools/wuci_os.py:11925-12001
  - tools/wuci_os.py:12008-12021
  - tools/wuci_os.py:12032-12050
  - tools/wuci_os.py:12102-12117
  - tools/wuci_os.py:13446-13485
  - tools/wuci_os.py:13897-13905
  - tests/wuci_os.py:1799-1802
  - tools/wuci_os.py:2986-3030
  - tools/wuci_os.py:11925-11930
  - tools/wuci_os.py:11999-12001
  - tools/wuci_os.py:12008-12021
  - tools/wuci_os.py:12032-12105
  - tools/wuci_os.py:13446-13485
  - tools/wuci_os.py:13897-13905
  - tools/wuci_os.py:14370-14384
  - tools/wuci_os.py:14205-14208
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-017.
- required remediation: Stop interpolating caller-controlled paths into shell or debugfs command text; pass arguments through structured APIs or quote with a reviewed escaping routine, and add malicious-path regression tests.
- patch status: pending
- verification command: targeted tests for CAN-R02-017; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-034: meridian-install embeds unescaped installer-supplied paths into generated shell launchers and helpers

- finding ID: CAN-R03-034
- severity: high
- area: Supply Chain
- file(s):
  - meridian-install:70-80
  - meridian-install:141-145
  - meridian-install:148-153
  - meridian-install:213-223
- issue summary: The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-034.
- required remediation: Stop interpolating caller-controlled paths into shell or debugfs command text; pass arguments through structured APIs or quote with a reviewed escaping routine, and add malicious-path regression tests.
- patch status: pending
- verification command: targeted tests for CAN-R03-034; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R04-036: Daylight v16 Analemma production-authority proof accepts unsigned valid=true evidence

- finding ID: CAN-R04-036
- severity: high
- area: Crypto
- file(s):
  - daylight/v16-analemma/src/analemma.py:271-273
  - daylight/v16-analemma/src/analemma.py:349-360
  - daylight/v16-analemma/rules/proof-units.v1.json:232-240
- issue summary: The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-036.
- required remediation: Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.
- patch status: pending
- verification command: targeted tests for CAN-R04-036; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R04-037: Daylight v16 Zenith accepts self-supplied HMAC root keys for review, transparency, and falsification evidence

- finding ID: CAN-R04-037
- severity: high
- area: Crypto
- file(s):
  - daylight/v16-zenith/src/zenith_verifier.py:60-64
  - daylight/v16-zenith/src/zenith_verifier.py:121-127
  - daylight/v16-zenith/src/zenith_verifier.py:134-164
  - daylight/v16-zenith/src/zenith_verifier.py:261-290
  - daylight/v16-zenith/src/zenith_verifier.py:293-306
  - daylight/v16-zenith/src/zenith_verifier.py:532-545
  - daylight/v16-zenith/src/zenith_verifier.py:47-64
  - daylight/v16-zenith/src/zenith_verifier.py:121-127
  - daylight/v16-zenith/src/zenith_verifier.py:134-164
  - daylight/v16-zenith/src/zenith_verifier.py:261-306
  - daylight/v16-zenith/src/zenith_verifier.py:432-557
  - daylight/v16-zenith/src/cli.py:45-90
- issue summary: The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-037.
- required remediation: Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.
- patch status: pending
- verification command: targeted tests for CAN-R04-037; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-002: Daylight v15 Meridian private writes use predictable temp paths without nofollow or exclusive creation

- finding ID: CAN-R01-002
- severity: medium
- area: Code
- file(s):
  - daylight/v15-meridian/src/vault.py:75-88
  - daylight/v15-meridian/src/vault.py:175-180
  - daylight/v15-meridian/src/vault.py:199-201
  - daylight/v15-meridian/src/vault.py:272-274
  - daylight/v15-meridian/src/vault.py:349-379
  - daylight/v15-meridian/src/cli.py:493-508
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-002.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R01-002; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-004: CAGE proof-output writers follow caller-controlled paths and symlinks for evidence outputs

- finding ID: CAN-R01-004
- severity: medium
- area: Code
- file(s):
  - tools/wuci_cage.py:471-497
  - tools/wuci_cage.py:140-151
  - tools/wuci_cage.py:145
  - tools/wuci_cage.py:390-398
  - tools/wuci_cage.py:418-427
  - tools/wuci_cage.py:431-449
  - tools/wuci_safeio.py:187-224
  - tools/wuci_cage.py:140-145
  - tools/wuci_cage.py:390-398
  - tools/wuci_cage.py:418-427
  - tools/wuci_cage.py:431-448
  - tools/wuci_safeio.py:187-211
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-004.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R01-004; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-005: QCAGE proof and evidence paths bypass safe-I/O link and snapshot controls

- finding ID: CAN-R01-005
- severity: medium
- area: Code
- file(s):
  - tools/wuci_qcage.py:69-79
  - tools/wuci_qcage.py:108-124
  - tools/wuci_qcage.py:462-472
  - tools/wuci_qcage.py:506-525
  - tools/wuci_cage.py:198-220
  - tools/wuci_qcage.py:86-97
  - tools/wuci_qcage.py:740-746
  - tools/wuci_qcage.py:750-753
  - tools/wuci_qcage.py:757-763
  - tools/wuci_qcage.py:767-782
  - tools/wuci_qcage.py:849-877
  - tools/wuci_safeio.py:187-224
  - tools/wuci_qcage.py:69-79
  - tools/wuci_qcage.py:869-887
  - tools/wuci_qcage.py:506-524
  - tools/wuci_qcage.py:786-807
  - tools/wuci_safeio.py:102-145
  - tools/wuci_qcage.py:69-79
  - tools/wuci_qcage.py:86-99
  - tools/wuci_qcage.py:493-524
  - tools/wuci_qcage.py:740-781
  - tools/wuci_qcage.py:786-807
  - tools/wuci_safeio.py:102-126
  - tools/wuci_safeio.py:187-211
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-005.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R01-005; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-006: Standalone WITNESS verification only rejects hardlinked public bundle files in strict proof mode

- finding ID: CAN-R01-006
- severity: medium
- area: Tests
- file(s):
  - tools/wuci_witness.py:184-218
  - tools/wuci_witness.py:222-251
  - tools/wuci_witness.py:662-675
  - tests/wuci_witness_symlink_hardening.py:96-116
- issue summary: The validator/test proof lane does not enforce the claimed hardening invariant under all supported modes. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-006.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R01-006; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-007: Meridian vault restore trusts mutable original_path metadata for plaintext writes

- finding ID: CAN-R01-007
- severity: medium
- area: Code
- file(s):
  - daylight/v15-meridian/src/cli.py:504-508
  - daylight/v15-meridian/src/vault.py:170-173
  - daylight/v15-meridian/src/vault.py:202-215
  - daylight/v15-meridian/src/vault.py:262-274
  - daylight/v15-meridian/src/vault.py:75-88
  - daylight/v15-meridian/src/vault.py:372-379
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-007.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R01-007; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-009: Generated network-connect helper exposes Wi-Fi passwords through subprocess arguments

- finding ID: CAN-R01-009
- severity: medium
- area: Code
- file(s):
  - tools/wuci_os.py:8511-8516
  - tools/wuci_os.py:8570-8584
  - tools/wuci_os.py:8590-8593
  - tools/wuci_os.py:10873-10877
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-009.
- required remediation: Avoid passing secrets through command arguments or mutable endpoint environment variables; use stdin, protected config files, host pinning, and explicit allowlists for credential destinations.
- patch status: pending
- verification command: targeted tests for CAN-R01-009; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R01-012: Wuci-OS release gate proof reads use lstat-then-reopen TOCTOU patterns

- finding ID: CAN-R01-012
- severity: medium
- area: Release
- file(s):
  - tools/wuci_release_gate.py:75-91
  - tools/wuci_release_gate.py:109-115
  - tools/wuci_release_gate.py:145-156
  - tools/wuci_release_gate.py:184-227
  - tools/wuci_release_gate.py:238-288
  - tools/wuci_release_gate.py:294-323
  - tools/wuci_safeio.py:102-145
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-012.
- required remediation: Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.
- patch status: pending
- verification command: targeted tests for CAN-R01-012; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-013: Backup evidence archive can be written after preverification but before restore/open verification catches a raced source path

- finding ID: CAN-R02-013
- severity: medium
- area: Release
- file(s):
  - tools/wuci_backup_evidence.py:77-96
  - tools/wuci_backup_evidence.py:102-117
  - tools/wuci_backup_evidence.py:123-145
  - tools/wuci_backup_evidence.py:148-165
  - tools/wuci_backup_evidence.py:77-96
  - tools/wuci_backup_evidence.py:102-117
  - tools/wuci_backup_evidence.py:148-158
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-013.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R02-013; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-014: Non-strict WUCI_JI_RUNNER indirection can affect Witness, Ledger, Gate, and compatibility proof lanes

- finding ID: CAN-R02-014
- severity: medium
- area: Release
- file(s):
  - tools/wuci_verifier_identity.py:42-57
  - tools/wuci_verifier_identity.py:93-99
  - tools/wuci_witness.py:22-25
  - tools/wuci_witness.py:306-320
  - tools/wuci_witness.py:628-672
  - docs/wuci_threat_model.json:13
  - tools/wuci_ledger.py:19-22
  - tools/wuci_ledger.py:163-186
  - tools/wuci_ledger.py:473-525
  - tools/wuci_ledger.py:896-900
  - tools/wuci_gate.py:19-21
  - tools/wuci_gate.py:150-169
  - tools/wuci_gate.py:288-297
  - tools/wuci_gate_contract_compat.py:51-54
  - tools/wuci_gate_contract_compat.py:57-82
  - tools/wuci_gate_contract_compat.py:163-215
  - tools/wuci_gate_contract_compat.py:335-350
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-014.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R02-014; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-015: Public evidence firewall follows symlinked roots and reopens paths after lstat checks

- finding ID: CAN-R02-015
- severity: medium
- area: Website
- file(s):
  - tools/daylight_public_evidence_firewall.py:140-173
  - tools/daylight_public_evidence_firewall.py:174-181
  - tools/daylight_public_evidence_firewall.py:199-206
  - tools/daylight_public_evidence_firewall.py:215-236
  - daylight/v20-aperture-singularity/src/public_artifact.py:817-858
  - tools/daylight_public_evidence_firewall.py:104-109
  - tools/daylight_public_evidence_firewall.py:140-162
  - tools/daylight_public_evidence_firewall.py:209-215
  - tools/daylight_public_evidence_firewall.py:319-325
  - tests/daylight_public_evidence_firewall.py:88-99
  - daylight/v20-aperture-singularity/src/public_artifact.py:810-821
- issue summary: The public website/evidence surface can consume local artifact state without fully preserving the intended public-evidence trust boundary. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-015.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R02-015; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-016: Public evidence scanners can record oversize violations only after reading full file contents

- finding ID: CAN-R02-016
- severity: medium
- area: Code
- file(s):
  - daylight/v20-aperture-singularity/src/public_artifact.py:192-205
  - daylight/v20-aperture-singularity/src/public_artifact.py:824-863
  - daylight/v20-aperture-singularity/src/firewall_profile.py:18-33
  - tools/daylight_public_evidence_firewall.py:165-179
  - daylight/v20-aperture-singularity/src/public_artifact.py:852-859
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-016.
- required remediation: Check file size and type through descriptor-relative, nofollow-safe opens before reading contents, and enforce hard byte caps before marker scanning.
- patch status: pending
- verification command: targeted tests for CAN-R02-016; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-018: Horizon vault and release artifact symlink checks resolve paths before testing links

- finding ID: CAN-R02-018
- severity: medium
- area: Code
- file(s):
  - daylight/v17-singularity/src/horizon_vault.py:46-54
  - daylight/v17-singularity/src/horizon_vault.py:109-111
  - daylight/v17-singularity/src/horizon_vault.py:223-228
  - daylight/v17-singularity/src/horizon_vault.py:239-242
  - daylight/v17-singularity/src/horizon_crypto.py:52-60
  - daylight/v17-singularity/src/horizon_crypto.py:63-71
  - daylight/v17-singularity/src/horizon_release.py:32-40
  - daylight/v17-singularity/src/horizon_release.py:71-80
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-018.
- required remediation: Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.
- patch status: pending
- verification command: targeted tests for CAN-R02-018; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R02-019: Crypto self-audit proof reads follow linked audit and source files

- finding ID: CAN-R02-019
- severity: medium
- area: Crypto
- file(s):
  - tools/wuci_crypto_audit.py:42-54
  - tools/wuci_crypto_audit.py:73-81
  - tools/wuci_crypto_audit.py:87-95
- issue summary: The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-019.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R02-019; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-020: Daylight v20 public and external evidence readers lstat then reopen public files

- finding ID: CAN-R03-020
- severity: medium
- area: Code
- file(s):
  - daylight/v20-aperture-singularity/src/pathsafe.py:49-58
  - daylight/v20-aperture-singularity/src/pathsafe.py:63-79
  - daylight/v20-aperture-singularity/src/external_evidence.py:1039-1042
  - daylight/v20-aperture-singularity/src/rebuild_receipts.py:366-369
  - daylight/v20-aperture-singularity/src/verifier_quorum.py:328-331
  - daylight/v20-aperture-singularity/src/public_artifact.py:817-858
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-020.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-020; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-021: PQ verifier evidence writers use predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-021
- severity: medium
- area: Code
- file(s):
  - tools/wuci_pq_verifier.py:129-133
  - tools/wuci_pq_verifier.py:136-143
  - tools/wuci_pq_verifier.py:332-343
  - tools/wuci_pq_verifier.py:347-396
  - tools/wuci_pq_verifier.py:129-133
  - tools/wuci_pq_verifier.py:136-142
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-021.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-021; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-022: CARROT runtime attestation uses predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-022
- severity: medium
- area: Code
- file(s):
  - tools/wuci_carrot.py:146-150
  - tools/wuci_carrot.py:160-179
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-022.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-022; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-023: Golden Lock evidence emitters use predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-023
- severity: medium
- area: Code
- file(s):
  - tools/wuci_golden_lock.py:44-48
  - tools/wuci_golden_lock.py:336-343
  - tools/wuci_golden_lock_model.py:130-134
  - tools/wuci_golden_lock_model.py:435-447
  - tools/wuci_golden_lock_model.py:452-458
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-023.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-023; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-025: Backup evidence archive and report writers use predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-025
- severity: medium
- area: Release
- file(s):
  - tools/wuci_backup_evidence.py:102-117
  - tools/wuci_backup_evidence.py:177-180
  - tools/wuci_backup_evidence.py:184-204
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-025.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-025; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-026: Provenance and SBOM evidence writers use predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-026
- severity: medium
- area: Release
- file(s):
  - tools/wuci_provenance.py:81-85
  - tools/wuci_provenance.py:310-319
  - tools/wuci_provenance.py:336-348
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-026.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-026; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-027: Publish and self-release attestation writers use predictable hidden temp files without nofollow or exclusive creation

- finding ID: CAN-R03-027
- severity: medium
- area: Release
- file(s):
  - tools/wuci_publish_attest.py:93-106
  - tools/wuci_publish_attest.py:365-372
  - tools/wuci_self_release.py:131-144
  - tools/wuci_self_release.py:300-319
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-027.
- required remediation: Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.
- patch status: pending
- verification command: targeted tests for CAN-R03-027; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-028: Daylight Meridian seal/open output paths can follow caller-selected final symlinks

- finding ID: CAN-R03-028
- severity: medium
- area: Code
- file(s):
  - daylight/v15-meridian/src/cli.py:404-429
  - daylight/v15-meridian/src/cli.py:435-448
  - daylight/v15-meridian/src/cli.py:632-659
  - daylight/v15-meridian/src/cli.py:426-429
  - daylight/v15-meridian/src/cli.py:435-447
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-028.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-028; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-029: Daylight v14/v15 ledger writers overwrite symlinked ledger outputs directly

- finding ID: CAN-R03-029
- severity: medium
- area: Code
- file(s):
  - daylight/v14c-plus/src/ledger.py:110-113
  - daylight/v15-meridian/src/ledger.py:132-135
  - daylight/v15-solstice/src/ledger.py:132-135
  - daylight/v15-meridian/src/cli.py:59-79
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-029.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-029; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-032: Penumbra CLI writes sealed envelopes and authenticated plaintext directly to caller-selected paths

- finding ID: CAN-R03-032
- severity: medium
- area: Code
- file(s):
  - penumbra/src/main.rs:72-77
  - penumbra/src/main.rs:84-103
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-032.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-032; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-033: meridian-install removes and copies through installer-controlled share/bin paths without symlink or hardlink quarantine

- finding ID: CAN-R03-033
- severity: medium
- area: Supply Chain
- file(s):
  - meridian-install:70-80
  - meridian-install:88-90
  - meridian-install:131-136
  - meridian-install:141-154
- issue summary: The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-033.
- required remediation: Quarantine installer-controlled paths, reject symlink and hardlink traversals, pin trusted verifier executables or require absolute configured paths, and generate launcher/helper scripts with safe escaping.
- patch status: pending
- verification command: targeted tests for CAN-R03-033; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R04-035: Installer signature verification resolves ssh-keygen from ambient PATH by default

- finding ID: CAN-R04-035
- severity: medium
- area: Supply Chain
- file(s):
  - tools/wuci_install.py:412-424
  - tools/wuci_install.py:457-475
  - tests/wuci_install_no_shell.py:1-120
- issue summary: The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-035.
- required remediation: Quarantine installer-controlled paths, reject symlink and hardlink traversals, pin trusted verifier executables or require absolute configured paths, and generate launcher/helper scripts with safe escaping.
- patch status: pending
- verification command: targeted tests for CAN-R04-035; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R04-038: Shared safe-I/O writers can follow symlinked output parent directories

- finding ID: CAN-R04-038
- severity: medium
- area: Code
- file(s):
  - tools/wuci_safeio.py:187-211
  - tools/wuci_safeio.py:248-270
  - daylight/v19-aperture-bastion/src/pathsafe.py:81-99
  - daylight/v20-aperture-singularity/src/pathsafe.py:83-101
  - tools/wuci_safeio.py:195-198
  - tools/wuci_safeio.py:256-270
  - tools/wuci_witness.py:159-168
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-038.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R04-038; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-024: Crypto self-audit report writer uses a predictable sibling temp file without nofollow or exclusive creation

- finding ID: CAN-R03-024
- severity: low
- area: Code
- file(s):
  - tools/wuci_crypto_audit.py:73-77
  - tools/wuci_crypto_audit.py:80-83
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-024.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-024; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-030: Posture and privacy report emitters use predictable sibling temp files without nofollow or exclusive creation

- finding ID: CAN-R03-030
- severity: low
- area: Release
- file(s):
  - daylight/ssv/v1/daylight_ssv/report.py:66-71
  - daylight/ssv/v1/daylight_ssv/cli.py:36-43
  - tools/wuci_release_privacy_audit.py:371-375
  - tools/wuci_release_privacy_audit.py:391-398
- issue summary: The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-030.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-030; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

### CAN-R03-031: VirtualBox appliance manifest and forced outputs can follow or overwrite unsafe output paths

- finding ID: CAN-R03-031
- severity: low
- area: Code
- file(s):
  - tools/wuci_virtualbox.py:236-249
  - tools/wuci_virtualbox.py:251-278
  - tools/wuci_virtualbox.py:280-307
  - tools/wuci_virtualbox.py:336-346
- issue summary: A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-031.
- required remediation: Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.
- patch status: pending
- verification command: targeted tests for CAN-R03-031; `git diff --check`; `make ci-native`; `make ci-zig`; `make daylight-npt-ci`; post-remediation `$codex-security:deep-security-scan`
- re-scan status: pending
- final status: unresolved

## Remaining TRUE Blockers
- All original findings are unresolved at ledger creation time: 9 high, 26 medium, 3 low.
- Credential/session stores under the resolved workspace still require repository-controlled cleanup and out-of-band rotation by the secret owner; rotation cannot be performed by Codex.
- A new full deep security re-scan has not yet been run after remediation.
- National-security defense readiness still requires evidence that no high or medium finding remains and that no public claim exceeds repository evidence.

## External Validation Blockers
- Credential liveness and rotation status require account-owner/provider-side verification; repository changes can only remove exposure paths and add scanners.
- Formal national-security, government, third-party, red-team, or production certification is not present in this repository and must not be claimed unless real external evidence is added.

## Final Remediation Classification
WUCI_JI_SECURITY_REMEDIATION_LEDGER_CREATED_REMEDIATION_PENDING
