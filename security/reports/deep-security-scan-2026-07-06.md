# Wuci-Ji Deep Security Scan Report

## Classification
WUCI_JI_NATIONAL_SECURITY_DEFENSE_AUDIT_FALSE

## Repository State
- branch: wuciji-zp1-coupling-replay-current-main
- scan target commit: 1d420abb2788027cb6c0febb928269e8d9bd96e5
- origin/main: 88c537f6f2941d00890ee48c2190c242246195ef
- tag state: No tag points at scan target HEAD; parent/origin main has v2.2.0-aperture-bastion.
- submodule status: ee1b853abe99ee8dadfa57bc356fdf5abce1d816 third_party/zp1 (heads/main)
- worktree status: ?? security/reports/
- Codex Security generated report: `/tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/report.md`
- sealed scan timestamp: 2026-07-06T15:01:02Z

## Executive Summary
Deep Security Scan completed successfully from the clean pre-scan commit `1d420abb2788027cb6c0febb928269e8d9bd96e5` after the authorized local Codex Security preflight configuration remediation. The scan reviewed the full repository/workspace scope and finalized canonical `scan-manifest.json`, `findings.json`, `coverage.json`, SARIF, and generated `report.md` artifacts. No critical findings survived validation. The scan found 9 high, 26 medium, and 3 low reportable findings, including confirmed credential-store presence, release/source-kit leakage paths, command/shell-generation risks, cryptographic evidence-authority flaws, and broad safe-I/O hardening gaps. The national-security-readiness binary judgment is FALSE.

## Critical Findings
None found.

## High Findings
### CAN-R01-001: Daylight v16 Analemma accepts self-supplied HMAC root keys as signed external review evidence

Severity: High
Area: Crypto
Status: Confirmed
File(s):
- daylight/v16-analemma/src/cli.py:99-104
- daylight/v16-analemma/src/cli.py:107-112
- daylight/v16-analemma/src/analemma.py:114-119
- daylight/v16-analemma/src/analemma.py:123-130
- daylight/v16-analemma/src/analemma.py:257-268
- daylight/v16-analemma/rules/proof-units.v1.json:220-229

Issue:
The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-001.

Evidence:
Validated by static source/control/sink trace. Representative affected locations: daylight/v16-analemma/src/cli.py:99-104, daylight/v16-analemma/src/cli.py:107-112, daylight/v16-analemma/src/analemma.py:114-119, daylight/v16-analemma/src/analemma.py:123-130. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Forged or self-issued external review rows can satisfy the Analemma signed external review proof unit, inflating self-progress proof mass and evidence authority without real external reviewer signatures.

Recommendation:
Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.

Verification:
Review `artifacts/05_findings/CAN-R01-001/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-003: Credential and session stores are present inside the resolved local scan scope

Severity: High
Area: Secrets
Status: Confirmed
File(s):
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

Issue:
Credential-bearing and session-store paths were present under the resolved scan target. Values were not printed or tested, but the file types and fields are sensitive. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-003.

Evidence:
Validated by redacted secret-presence validation. Representative affected locations: .wrangler/config/.wrangler/config/default.toml:1, .wrangler/config/.wrangler/config/default.toml:3, .wrangler/config/.wrangler/config/default.toml:4, package.json:12-15. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
If the token or refresh token is valid and exposed outside the local trusted workstation, an attacker could potentially modify Pages/Workers/KV/D1/Secrets Store or related Cloudflare resources covered by the listed scopes. Validity was not network-tested by this discovery worker. / Accidental disclosure of local account metadata, credentials, keys, or private user configuration if the workspace is archived, uploaded, shared, or processed by tooling that does not strictly honor the intended product/release boundary. / Accidental publication would expose live or recently live Claude OAuth material and account metadata. / Accidental publication would expose Claude OAuth credential material and associated local account metadata. / Accidental publication could expose OpenAI/Codex session credentials, refresh tokens, and account identifiers. / Accidental publication could expose GitHub API/CLI OAuth credentials for repository or account access depending on token scopes. / Accidental publication could leak browser account identifiers and session-token shaped data that may enable account privacy loss or downstream credential abuse if valid. / Accidental publication leaks Cloudflare account identifiers and personal/account naming metadata. No credential token was observed in this file.

Recommendation:
Remove credential and session stores from the repository workspace, rotate any potentially exposed credentials, keep local app state outside the checkout, and extend release/public-evidence scanners to reject the observed credential-store formats without printing values.

Verification:
Review `artifacts/05_findings/CAN-R01-003/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-008: Generated grok build can send XAI_API_KEY to caller-controlled XAI_API_BASE

Severity: High
Area: Code
Status: Confirmed
File(s):
- tools/wuci_os.py:9423-9431
- tools/wuci_os.py:9443-9452
- tools/wuci_os.py:10901-10904

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-008.

Evidence:
Validated by static generated-script trace. Representative affected locations: tools/wuci_os.py:9423-9431, tools/wuci_os.py:9443-9452, tools/wuci_os.py:10901-10904. No secret values were printed or tested.

Impact:
A poisoned environment or wrapper can redirect the xAI bearer token to an attacker-controlled endpoint when the operator runs wuci-grok-build, and local process observers may also read the expanded secret from argv.

Recommendation:
Avoid passing secrets through command arguments or mutable endpoint environment variables; use stdin, protected config files, host pinning, and explicit allowlists for credential destinations.

Verification:
Review `artifacts/05_findings/CAN-R01-008/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-010: Wuci-OS source-kit fallback can package ignored credential files when git enumeration fails

Severity: High
Area: Release
Status: Confirmed
File(s):
- .wrangler/config/.wrangler/config/default.toml:1
- tools/wuci_os.py:3922-3927
- tools/wuci_os.py:3974-4024
- tools/wuci_os.py:4127-4137
- tools/wuci_os.py:14383
- external-ssd-export-20260705/10-Dotfiles-App-Config/.codex/auth.json:4-8
- external-ssd-export-20260705/10-Dotfiles-App-Config/.claude/.credentials.json:1
- external-ssd-export-20260705/10-Dotfiles-App-Config/.config/gh/hosts.yml:4

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-010.

Evidence:
Validated by static fallback packaging trace. Representative affected locations: .wrangler/config/.wrangler/config/default.toml:1, tools/wuci_os.py:3922-3927, tools/wuci_os.py:3974-4024, tools/wuci_os.py:4127-4137. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Cloudflare account/API bearer material with offline_access and write scopes can be exposed inside the Wuci-OS source-kit tar or final ISO source payload. / OpenAI/Codex account/session tokens and account identifiers can be exposed in a distributed Wuci-OS source-kit or ISO artifact. / Claude account/session credentials can be exposed in the Wuci-OS source-kit or final ISO payload. / GitHub OAuth tokens can be exposed in distributed Wuci-OS source-kit/ISO artifacts, potentially enabling repository or account access according to token scopes.

Recommendation:
Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.

Verification:
Review `artifacts/05_findings/CAN-R01-010/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-011: Wuci-OS release privacy audit misses source-kit credential formats and final ISO payload contents

Severity: High
Area: Release
Status: Confirmed
File(s):
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

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-011.

Evidence:
Validated by static privacy-scan coverage trace. Representative affected locations: tools/wuci_release_privacy_audit.py:25-35, tools/wuci_release_privacy_audit.py:54-93, tools/wuci_release_privacy_audit.py:95-110, tools/wuci_release_privacy_audit.py:239-260. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
The release privacy gate can report pass for an artifact containing live cloud/AI account credentials not covered by the current path or token indicators. / Secrets or private files embedded in the release ISO can evade the required privacy audit and be published in the release bundle, causing public disclosure despite a pass status.

Recommendation:
Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.

Verification:
Review `artifacts/05_findings/CAN-R01-011/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-017: Wuci-OS debugfs overlay commands interpolate unquoted rootfs paths into command files

Severity: High
Area: Code
Status: Confirmed
File(s):
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

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-017.

Evidence:
Validated by static command-file construction trace. Representative affected locations: tools/wuci_os.py:11925-12001, tools/wuci_os.py:12008-12021, tools/wuci_os.py:12032-12050, tools/wuci_os.py:12102-12117. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable code issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Stop interpolating caller-controlled paths into shell or debugfs command text; pass arguments through structured APIs or quote with a reviewed escaping routine, and add malicious-path regression tests.

Verification:
Review `artifacts/05_findings/CAN-R02-017/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-034: meridian-install embeds unescaped installer-supplied paths into generated shell launchers and helpers

Severity: High
Area: Supply Chain
Status: Confirmed
File(s):
- meridian-install:70-80
- meridian-install:141-145
- meridian-install:148-153
- meridian-install:213-223

Issue:
The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-034.

Evidence:
Validated by static generated-shell trace. Representative affected locations: meridian-install:70-80, meridian-install:141-145, meridian-install:148-153, meridian-install:213-223. No secret values were printed or tested.

Impact:
A malicious prefix/device/name supplied through an installer wrapper or untrusted local setup can create delayed command execution when the generated helper is run.

Recommendation:
Stop interpolating caller-controlled paths into shell or debugfs command text; pass arguments through structured APIs or quote with a reviewed escaping routine, and add malicious-path regression tests.

Verification:
Review `artifacts/05_findings/CAN-R03-034/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R04-036: Daylight v16 Analemma production-authority proof accepts unsigned valid=true evidence

Severity: High
Area: Crypto
Status: Confirmed
File(s):
- daylight/v16-analemma/src/analemma.py:271-273
- daylight/v16-analemma/src/analemma.py:349-360
- daylight/v16-analemma/rules/proof-units.v1.json:232-240

Issue:
The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-036.

Evidence:
Validated by static proof-authority trace. Representative affected locations: daylight/v16-analemma/src/analemma.py:271-273, daylight/v16-analemma/src/analemma.py:349-360, daylight/v16-analemma/rules/proof-units.v1.json:232-240. No secret values were printed or tested.

Impact:
A forged production authority object can close a critical claim_authority proof unit and may upgrade claim level once other external trust prerequisites are present, violating the repository boundary that fixture/local evidence must not pass as production authority.

Recommendation:
Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.

Verification:
Review `artifacts/05_findings/CAN-R04-036/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R04-037: Daylight v16 Zenith accepts self-supplied HMAC root keys for review, transparency, and falsification evidence

Severity: High
Area: Crypto
Status: Confirmed
File(s):
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

Issue:
The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-037.

Evidence:
Validated by static proof-authority trace. Representative affected locations: daylight/v16-zenith/src/zenith_verifier.py:60-64, daylight/v16-zenith/src/zenith_verifier.py:121-127, daylight/v16-zenith/src/zenith_verifier.py:134-164, daylight/v16-zenith/src/zenith_verifier.py:261-290. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
A forged Zenith evidence bundle can appear to satisfy external review, transparency, and falsification proof lanes, inflating assurance values and potentially advancing public assurance level without real independent signatures or log authority.; A producer of evidence can self-authenticate multiple nominally independent evidence rows and inflate public external-standard proof obligations. This affects evidence integrity and claim reliability, not runtime sandboxing, production publish authority, or quantum safety by itself.

Recommendation:
Bind verification to pinned trusted public keys or signed trust roots, reject self-supplied verification keys and unsigned valid=true authority objects, add negative tests for forged evidence, and update public claims to match only externally verified authority.

Verification:
Review `artifacts/05_findings/CAN-R04-037/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

## Medium Findings
### CAN-R01-002: Daylight v15 Meridian private writes use predictable temp paths without nofollow or exclusive creation

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v15-meridian/src/vault.py:75-88
- daylight/v15-meridian/src/vault.py:175-180
- daylight/v15-meridian/src/vault.py:199-201
- daylight/v15-meridian/src/vault.py:272-274
- daylight/v15-meridian/src/vault.py:349-379
- daylight/v15-meridian/src/cli.py:493-508

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-002.

Evidence:
Validated by static source/control/sink trace. Representative affected locations: daylight/v15-meridian/src/vault.py:75-88, daylight/v15-meridian/src/vault.py:175-180, daylight/v15-meridian/src/vault.py:199-201, daylight/v15-meridian/src/vault.py:272-274. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Under a writable vault/output directory precondition, a local attacker can cause private vault writes or plaintext restore writes to clobber an attacker-chosen file reachable by the victim process.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R01-002/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-004: CAGE proof-output writers follow caller-controlled paths and symlinks for evidence outputs

Severity: Medium
Area: Code
Status: Confirmed
File(s):
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

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-004.

Evidence:
Validated by static source/control/sink trace. Representative affected locations: tools/wuci_cage.py:471-497, tools/wuci_cage.py:140-151, tools/wuci_cage.py:145, tools/wuci_cage.py:390-398. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
A local workspace attacker can redirect or race CAGE evidence output through symlinks, corrupting or clobbering files and undermining trust in generated CAGE proof artifacts. This does not imply remote code execution or runtime sandbox bypass. / Can redirect CAGE-generated attestation, run-denial, or ledger-entry output to an unintended user-writable filesystem path under local/CI workspace preconditions. This does not imply OS sandbox bypass or production authority compromise by itself.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R01-004/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-005: QCAGE proof and evidence paths bypass safe-I/O link and snapshot controls

Severity: Medium
Area: Code
Status: Confirmed
File(s):
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

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-005.

Evidence:
Validated by static source/control/sink trace. Representative affected locations: tools/wuci_qcage.py:69-79, tools/wuci_qcage.py:108-124, tools/wuci_qcage.py:462-472, tools/wuci_qcage.py:506-525. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
A local actor able to place hardlinks or redirected JSON inputs in the QCAGE evidence set can make proof evidence alias files outside the intended public evidence boundary or bypass the repository-wide public-file hardening invariant. This undermines auditability and can expose or trust mutable/private local files as if they were canonical evidence. This is local proof-integrity impact, not remote code execution. / A local workspace attacker can use QCAGE proof generation to clobber or corrupt arbitrary writable files reachable through symlinks, including evidence paths used by later release workflows. / A race or symlink swap can let QCAGE claims and digest evidence be computed over different file contents, weakening downgrade-resistance and build-graph integrity evidence. This is local proof-integrity risk, not a claim of post-quantum breakage. / Can make QCAGE consume or write through filesystem links under local/CI workspace preconditions, weakening HARDEN/QCAGE safe-I/O expectations for proof lanes. Static review did not establish a publish/trust bypass.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R01-005/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-006: Standalone WITNESS verification only rejects hardlinked public bundle files in strict proof mode

Severity: Medium
Area: Tests
Status: Confirmed
File(s):
- tools/wuci_witness.py:184-218
- tools/wuci_witness.py:222-251
- tools/wuci_witness.py:662-675
- tests/wuci_witness_symlink_hardening.py:96-116

Issue:
The validator/test proof lane does not enforce the claimed hardening invariant under all supported modes. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-006.

Evidence:
Validated by static policy/control trace. Representative affected locations: tools/wuci_witness.py:184-218, tools/wuci_witness.py:222-251, tools/wuci_witness.py:662-675, tests/wuci_witness_symlink_hardening.py:96-116. No secret values were printed or tested.

Impact:
If downstream users treat non-strict standalone WITNESS verification as sufficient public evidence hardening, hardlinked public files can alias mutable or private local files and weaken evidence provenance. Impact is lower where CAGE or strict WITNESS modes are required.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R01-006/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-007: Meridian vault restore trusts mutable original_path metadata for plaintext writes

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v15-meridian/src/cli.py:504-508
- daylight/v15-meridian/src/vault.py:170-173
- daylight/v15-meridian/src/vault.py:202-215
- daylight/v15-meridian/src/vault.py:262-274
- daylight/v15-meridian/src/vault.py:75-88
- daylight/v15-meridian/src/vault.py:372-379

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-007.

Evidence:
Validated by static metadata-to-output trace. Representative affected locations: daylight/v15-meridian/src/cli.py:504-508, daylight/v15-meridian/src/vault.py:170-173, daylight/v15-meridian/src/vault.py:202-215, daylight/v15-meridian/src/vault.py:262-274. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
If an attacker can influence the vault index or convince an operator to restore a supplied/tampered vault that can be opened, plaintext can be created or overwritten at an arbitrary path reachable by the invoking user.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R01-007/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-009: Generated network-connect helper exposes Wi-Fi passwords through subprocess arguments

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- tools/wuci_os.py:8511-8516
- tools/wuci_os.py:8570-8584
- tools/wuci_os.py:8590-8593
- tools/wuci_os.py:10873-10877

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-009.

Evidence:
Validated by static subprocess argument trace. Representative affected locations: tools/wuci_os.py:8511-8516, tools/wuci_os.py:8570-8584, tools/wuci_os.py:8590-8593, tools/wuci_os.py:10873-10877. No secret values were printed or tested.

Impact:
Local users or diagnostic tooling able to inspect process command lines during connection can recover the Wi-Fi password. Inline environment examples can also encourage shell-history exposure.

Recommendation:
Avoid passing secrets through command arguments or mutable endpoint environment variables; use stdin, protected config files, host pinning, and explicit allowlists for credential destinations.

Verification:
Review `artifacts/05_findings/CAN-R01-009/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R01-012: Wuci-OS release gate proof reads use lstat-then-reopen TOCTOU patterns

Severity: Medium
Area: Release
Status: Confirmed
File(s):
- tools/wuci_release_gate.py:75-91
- tools/wuci_release_gate.py:109-115
- tools/wuci_release_gate.py:145-156
- tools/wuci_release_gate.py:184-227
- tools/wuci_release_gate.py:238-288
- tools/wuci_release_gate.py:294-323
- tools/wuci_safeio.py:102-145

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R01-012.

Evidence:
Validated by static TOCTOU read trace. Representative affected locations: tools/wuci_release_gate.py:75-91, tools/wuci_release_gate.py:109-115, tools/wuci_release_gate.py:145-156, tools/wuci_release_gate.py:184-227. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
A local workspace race can cause release-gate evidence to describe or bind a different artifact/evidence file than the one checked, weakening the release blocker model and public release evidence integrity.

Recommendation:
Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.

Verification:
Review `artifacts/05_findings/CAN-R01-012/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-013: Backup evidence archive can be written after preverification but before restore/open verification catches a raced source path

Severity: Medium
Area: Release
Status: Confirmed
File(s):
- tools/wuci_backup_evidence.py:77-96
- tools/wuci_backup_evidence.py:102-117
- tools/wuci_backup_evidence.py:123-145
- tools/wuci_backup_evidence.py:148-165
- tools/wuci_backup_evidence.py:77-96
- tools/wuci_backup_evidence.py:102-117
- tools/wuci_backup_evidence.py:148-158

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-013.

Evidence:
Validated by static archive/write race trace. Representative affected locations: tools/wuci_backup_evidence.py:77-96, tools/wuci_backup_evidence.py:102-117, tools/wuci_backup_evidence.py:123-145, tools/wuci_backup_evidence.py:148-165. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable release issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R02-013/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-014: Non-strict WUCI_JI_RUNNER indirection can affect Witness, Ledger, Gate, and compatibility proof lanes

Severity: Medium
Area: Release
Status: Confirmed
File(s):
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

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-014.

Evidence:
Validated by static verifier identity trace. Representative affected locations: tools/wuci_verifier_identity.py:42-57, tools/wuci_verifier_identity.py:93-99, tools/wuci_witness.py:22-25, tools/wuci_witness.py:306-320. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable release issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R02-014/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-015: Public evidence firewall follows symlinked roots and reopens paths after lstat checks

Severity: Medium
Area: Website
Status: Confirmed
File(s):
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

Issue:
The public website/evidence surface can consume local artifact state without fully preserving the intended public-evidence trust boundary. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-015.

Evidence:
Validated by static public-evidence read trace. Representative affected locations: tools/daylight_public_evidence_firewall.py:140-173, tools/daylight_public_evidence_firewall.py:174-181, tools/daylight_public_evidence_firewall.py:199-206, tools/daylight_public_evidence_firewall.py:215-236. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable website issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R02-015/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-016: Public evidence scanners can record oversize violations only after reading full file contents

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v20-aperture-singularity/src/public_artifact.py:192-205
- daylight/v20-aperture-singularity/src/public_artifact.py:824-863
- daylight/v20-aperture-singularity/src/firewall_profile.py:18-33
- tools/daylight_public_evidence_firewall.py:165-179
- daylight/v20-aperture-singularity/src/public_artifact.py:852-859

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-016.

Evidence:
Validated by static resource-exhaustion trace. Representative affected locations: daylight/v20-aperture-singularity/src/public_artifact.py:192-205, daylight/v20-aperture-singularity/src/public_artifact.py:824-863, daylight/v20-aperture-singularity/src/firewall_profile.py:18-33, tools/daylight_public_evidence_firewall.py:165-179. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable code issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Check file size and type through descriptor-relative, nofollow-safe opens before reading contents, and enforce hard byte caps before marker scanning.

Verification:
Review `artifacts/05_findings/CAN-R02-016/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-018: Horizon vault and release artifact symlink checks resolve paths before testing links

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v17-singularity/src/horizon_vault.py:46-54
- daylight/v17-singularity/src/horizon_vault.py:109-111
- daylight/v17-singularity/src/horizon_vault.py:223-228
- daylight/v17-singularity/src/horizon_vault.py:239-242
- daylight/v17-singularity/src/horizon_crypto.py:52-60
- daylight/v17-singularity/src/horizon_crypto.py:63-71
- daylight/v17-singularity/src/horizon_release.py:32-40
- daylight/v17-singularity/src/horizon_release.py:71-80

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-018.

Evidence:
Validated by static symlink-control trace. Representative affected locations: daylight/v17-singularity/src/horizon_vault.py:46-54, daylight/v17-singularity/src/horizon_vault.py:109-111, daylight/v17-singularity/src/horizon_vault.py:223-228, daylight/v17-singularity/src/horizon_vault.py:239-242. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
This reportable code issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.

Verification:
Review `artifacts/05_findings/CAN-R02-018/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R02-019: Crypto self-audit proof reads follow linked audit and source files

Severity: Medium
Area: Crypto
Status: Confirmed
File(s):
- tools/wuci_crypto_audit.py:42-54
- tools/wuci_crypto_audit.py:73-81
- tools/wuci_crypto_audit.py:87-95

Issue:
The reviewed proof or cryptographic-evidence path accepts evidence in a way that can misrepresent external authority or verification strength. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R02-019.

Evidence:
Validated by static linked-read trace. Representative affected locations: tools/wuci_crypto_audit.py:42-54, tools/wuci_crypto_audit.py:73-81, tools/wuci_crypto_audit.py:87-95. No secret values were printed or tested.

Impact:
This reportable crypto issue can weaken Wuci-Ji evidence integrity, secrecy, release hygiene, or reviewer confidence under the scan threat model.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R02-019/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-020: Daylight v20 public and external evidence readers lstat then reopen public files

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v20-aperture-singularity/src/pathsafe.py:49-58
- daylight/v20-aperture-singularity/src/pathsafe.py:63-79
- daylight/v20-aperture-singularity/src/external_evidence.py:1039-1042
- daylight/v20-aperture-singularity/src/rebuild_receipts.py:366-369
- daylight/v20-aperture-singularity/src/verifier_quorum.py:328-331
- daylight/v20-aperture-singularity/src/public_artifact.py:817-858

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-020.

Evidence:
Validated by static TOCTOU read trace. Representative affected locations: daylight/v20-aperture-singularity/src/pathsafe.py:49-58, daylight/v20-aperture-singularity/src/pathsafe.py:63-79, daylight/v20-aperture-singularity/src/external_evidence.py:1039-1042, daylight/v20-aperture-singularity/src/rebuild_receipts.py:366-369. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
If these public evidence paths are writable or replaceable during verification, a different file can be read or hashed than the one that passed metadata checks, undermining deterministic public evidence review.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-020/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-021: PQ verifier evidence writers use predictable sibling temp files without nofollow or exclusive creation

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- tools/wuci_pq_verifier.py:129-133
- tools/wuci_pq_verifier.py:136-143
- tools/wuci_pq_verifier.py:332-343
- tools/wuci_pq_verifier.py:347-396
- tools/wuci_pq_verifier.py:129-133
- tools/wuci_pq_verifier.py:136-142

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-021.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_pq_verifier.py:129-133, tools/wuci_pq_verifier.py:136-143, tools/wuci_pq_verifier.py:332-343, tools/wuci_pq_verifier.py:347-396. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Detection, local pin, or real PQ evidence output can be redirected or corrupted, affecting QCAGE/PQ evidence integrity and possibly another writable file.; PQ detector evidence can be redirected or clobber unrelated same-user files, weakening the evidence lane that distinguishes real PQ verifier availability from classical-only compatibility.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-021/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-022: CARROT runtime attestation uses predictable sibling temp files without nofollow or exclusive creation

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- tools/wuci_carrot.py:146-150
- tools/wuci_carrot.py:160-179

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-022.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_carrot.py:146-150, tools/wuci_carrot.py:160-179. No secret values were printed or tested.

Impact:
Runtime-policy attestation output can be redirected or corrupted, weakening evidence for the no-network proof lane without adding actual sandbox enforcement.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-022/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-023: Golden Lock evidence emitters use predictable sibling temp files without nofollow or exclusive creation

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- tools/wuci_golden_lock.py:44-48
- tools/wuci_golden_lock.py:336-343
- tools/wuci_golden_lock_model.py:130-134
- tools/wuci_golden_lock_model.py:435-447
- tools/wuci_golden_lock_model.py:452-458

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-023.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_golden_lock.py:44-48, tools/wuci_golden_lock.py:336-343, tools/wuci_golden_lock_model.py:130-134, tools/wuci_golden_lock_model.py:435-447. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Golden Lock or WJ-GOLD acceptance evidence can be corrupted or written to an unintended file, affecting local proof artifacts that are used to avoid overclaiming release/trust state.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-023/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-025: Backup evidence archive and report writers use predictable sibling temp files without nofollow or exclusive creation

Severity: Medium
Area: Release
Status: Confirmed
File(s):
- tools/wuci_backup_evidence.py:102-117
- tools/wuci_backup_evidence.py:177-180
- tools/wuci_backup_evidence.py:184-204

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-025.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_backup_evidence.py:102-117, tools/wuci_backup_evidence.py:177-180, tools/wuci_backup_evidence.py:184-204. No secret values were printed or tested.

Impact:
Tracked-source backup evidence can be redirected/corrupted, and a symlinked temp path can receive ZIP or report bytes outside the expected evidence directory.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-025/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-026: Provenance and SBOM evidence writers use predictable sibling temp files without nofollow or exclusive creation

Severity: Medium
Area: Release
Status: Confirmed
File(s):
- tools/wuci_provenance.py:81-85
- tools/wuci_provenance.py:310-319
- tools/wuci_provenance.py:336-348

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-026.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_provenance.py:81-85, tools/wuci_provenance.py:310-319, tools/wuci_provenance.py:336-348. No secret values were printed or tested.

Impact:
SBOM/provenance evidence can be redirected or corrupted, weakening local release/provenance evidence integrity.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-026/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-027: Publish and self-release attestation writers use predictable hidden temp files without nofollow or exclusive creation

Severity: Medium
Area: Release
Status: Confirmed
File(s):
- tools/wuci_publish_attest.py:93-106
- tools/wuci_publish_attest.py:365-372
- tools/wuci_self_release.py:131-144
- tools/wuci_self_release.py:300-319

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-027.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_publish_attest.py:93-106, tools/wuci_publish_attest.py:365-372, tools/wuci_self_release.py:131-144, tools/wuci_self_release.py:300-319. No secret values were printed or tested.

Impact:
Publish or self-release attestation generation can corrupt a symlink target and can leave final output as a symlink moved from the temp path, confusing release evidence handling.

Recommendation:
Make release packaging fail closed when git enumeration or privacy scanning is incomplete, audit final packaged payloads directly, and require digest-bound evidence before release publication.

Verification:
Review `artifacts/05_findings/CAN-R03-027/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-028: Daylight Meridian seal/open output paths can follow caller-selected final symlinks

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v15-meridian/src/cli.py:404-429
- daylight/v15-meridian/src/cli.py:435-448
- daylight/v15-meridian/src/cli.py:632-659
- daylight/v15-meridian/src/cli.py:426-429
- daylight/v15-meridian/src/cli.py:435-447

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-028.

Evidence:
Validated by static direct-output trace. Representative affected locations: daylight/v15-meridian/src/cli.py:404-429, daylight/v15-meridian/src/cli.py:435-448, daylight/v15-meridian/src/cli.py:632-659, daylight/v15-meridian/src/cli.py:426-429. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
Authorized plaintext from open or sealed data from seal can be written to an unintended file, which is especially sensitive for the open plaintext path.; Authorized plaintext output can be redirected or clobber unrelated files under same-user permissions, undermining the local secrecy boundary expected for Meridian open operations.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-028/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-029: Daylight v14/v15 ledger writers overwrite symlinked ledger outputs directly

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- daylight/v14c-plus/src/ledger.py:110-113
- daylight/v15-meridian/src/ledger.py:132-135
- daylight/v15-solstice/src/ledger.py:132-135
- daylight/v15-meridian/src/cli.py:59-79

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-029.

Evidence:
Validated by static direct-output trace. Representative affected locations: daylight/v14c-plus/src/ledger.py:110-113, daylight/v15-meridian/src/ledger.py:132-135, daylight/v15-solstice/src/ledger.py:132-135, daylight/v15-meridian/src/cli.py:59-79. No secret values were printed or tested.

Impact:
Daylight score/evidence ledgers can be corrupted or redirected, affecting local scorecard/gate evidence integrity.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-029/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-032: Penumbra CLI writes sealed envelopes and authenticated plaintext directly to caller-selected paths

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- penumbra/src/main.rs:72-77
- penumbra/src/main.rs:84-103

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-032.

Evidence:
Validated by static direct-output trace. Representative affected locations: penumbra/src/main.rs:72-77, penumbra/src/main.rs:84-103. No secret values were printed or tested.

Impact:
A local path attacker can redirect authenticated plaintext or envelope outputs under same-user permissions, creating a secrecy/integrity gap between the lower-level cryptographic checks and the CLI boundary.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-032/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-033: meridian-install removes and copies through installer-controlled share/bin paths without symlink or hardlink quarantine

Severity: Medium
Area: Supply Chain
Status: Confirmed
File(s):
- meridian-install:70-80
- meridian-install:88-90
- meridian-install:131-136
- meridian-install:141-154

Issue:
The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-033.

Evidence:
Validated by static installer filesystem trace. Representative affected locations: meridian-install:70-80, meridian-install:88-90, meridian-install:131-136, meridian-install:141-154. No secret values were printed or tested.

Impact:
Installer operations can delete, copy into, or overwrite unexpected same-user locations when the install root contains attacker-prepared links, contrary to the install-lane safe I/O expectations.

Recommendation:
Quarantine installer-controlled paths, reject symlink and hardlink traversals, pin trusted verifier executables or require absolute configured paths, and generate launcher/helper scripts with safe escaping.

Verification:
Review `artifacts/05_findings/CAN-R03-033/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R04-035: Installer signature verification resolves ssh-keygen from ambient PATH by default

Severity: Medium
Area: Supply Chain
Status: Confirmed
File(s):
- tools/wuci_install.py:412-424
- tools/wuci_install.py:457-475
- tests/wuci_install_no_shell.py:1-120

Issue:
The installer or supply-chain path trusts mutable local execution state or caller-controlled paths in a way that can compromise installation integrity. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-035.

Evidence:
Validated by static command-resolution trace. Representative affected locations: tools/wuci_install.py:412-424, tools/wuci_install.py:457-475, tests/wuci_install_no_shell.py:1-120. No secret values were printed or tested.

Impact:
A tampered or unsigned install manifest can be accepted if the PATH-selected ssh-keygen falsely returns success, undermining the INSTALL rule that unsigned manifests must not be accepted.

Recommendation:
Quarantine installer-controlled paths, reject symlink and hardlink traversals, pin trusted verifier executables or require absolute configured paths, and generate launcher/helper scripts with safe escaping.

Verification:
Review `artifacts/05_findings/CAN-R04-035/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R04-038: Shared safe-I/O writers can follow symlinked output parent directories

Severity: Medium
Area: Code
Status: Confirmed
File(s):
- tools/wuci_safeio.py:187-211
- tools/wuci_safeio.py:248-270
- daylight/v19-aperture-bastion/src/pathsafe.py:81-99
- daylight/v20-aperture-singularity/src/pathsafe.py:83-101
- tools/wuci_safeio.py:195-198
- tools/wuci_safeio.py:256-270
- tools/wuci_witness.py:159-168

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R04-038.

Evidence:
Validated by static safe-I/O trace. Representative affected locations: tools/wuci_safeio.py:187-211, tools/wuci_safeio.py:248-270, daylight/v19-aperture-bastion/src/pathsafe.py:81-99, daylight/v20-aperture-singularity/src/pathsafe.py:83-101. Additional affected locations are listed in File(s) and finalized findings.json. No secret values were printed or tested.

Impact:
A local attacker who can pre-create or swap an output parent directory as a symlink may redirect generated outputs outside the intended tree or corrupt unexpected files. This is a local filesystem integrity concern with caller-dependent reachability.; A local attacker can redirect public proof output writes into an unintended directory tree, undermining artifact placement assumptions and potentially overwriting same-user files through temporary-file replacement paths.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R04-038/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

## Low Findings
### CAN-R03-024: Crypto self-audit report writer uses a predictable sibling temp file without nofollow or exclusive creation

Severity: Low
Area: Code
Status: Confirmed
File(s):
- tools/wuci_crypto_audit.py:73-77
- tools/wuci_crypto_audit.py:80-83

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-024.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_crypto_audit.py:73-77, tools/wuci_crypto_audit.py:80-83. No secret values were printed or tested.

Impact:
Local crypto self-audit evidence can be corrupted or redirected; this does not create production audit authority but can confuse local evidence review.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-024/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-030: Posture and privacy report emitters use predictable sibling temp files without nofollow or exclusive creation

Severity: Low
Area: Release
Status: Confirmed
File(s):
- daylight/ssv/v1/daylight_ssv/report.py:66-71
- daylight/ssv/v1/daylight_ssv/cli.py:36-43
- tools/wuci_release_privacy_audit.py:371-375
- tools/wuci_release_privacy_audit.py:391-398

Issue:
The release or packaging path can produce, validate, or publish evidence without a fail-closed integrity/privacy guarantee. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-030.

Evidence:
Validated by static output-write trace. Representative affected locations: daylight/ssv/v1/daylight_ssv/report.py:66-71, daylight/ssv/v1/daylight_ssv/cli.py:36-43, tools/wuci_release_privacy_audit.py:371-375, tools/wuci_release_privacy_audit.py:391-398. No secret values were printed or tested.

Impact:
Local security posture or privacy audit report bytes can be redirected or corrupted, affecting evidence consumers that trust these reports.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-030/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

### CAN-R03-031: VirtualBox appliance manifest and forced outputs can follow or overwrite unsafe output paths

Severity: Low
Area: Code
Status: Confirmed
File(s):
- tools/wuci_virtualbox.py:236-249
- tools/wuci_virtualbox.py:251-278
- tools/wuci_virtualbox.py:280-307
- tools/wuci_virtualbox.py:336-346

Issue:
A local proof, evidence, build, or helper path lacks a complete trust-boundary control before reaching a sensitive filesystem or command sink. The preserved canonical discovery evidence identifies the nearest affected source/control/sink locations for CAN-R03-031.

Evidence:
Validated by static output-write trace. Representative affected locations: tools/wuci_virtualbox.py:236-249, tools/wuci_virtualbox.py:251-278, tools/wuci_virtualbox.py:280-307, tools/wuci_virtualbox.py:336-346. No secret values were printed or tested.

Impact:
VirtualBox appliance artifacts or the manifest can be redirected/corrupted in shared output directories, weakening local Wuci-OS packaging evidence.

Recommendation:
Route all public, release, proof, and plaintext artifact reads/writes through the shared safe-I/O layer with descriptor-relative parent checks, O_NOFOLLOW/O_EXCL where applicable, hardlink rejection, and regression tests for symlink, hardlink, and race preconditions.

Verification:
Review `artifacts/05_findings/CAN-R03-031/validation_report.md` and add a targeted negative regression test proving the stated boundary fails closed; rerun the relevant proof/release/public-evidence test lane and the Codex Security scan finalizer.

## Informational Findings
- Deep scan coverage completed and finalizer contract validation succeeded; this improves reviewer confidence in the scan evidence trail.
- The scan target included ignored/local backup and application-state material under the checkout. That was necessary for the requested full evidence pass, but it materially lowers release and national-security readiness until cleaned and proven absent from release artifacts.
- No standalone critical finding was validated, but the high and medium findings are unresolved and are sufficient to make national-security defensive readiness FALSE.

## Secrets Scan Result
Confirmed credential/session-store exposure was reported without values. Secret-like material was identified by type and location only: Cloudflare OAuth/refresh token fields under `.wrangler/config/.wrangler/config/default.toml`, Claude OAuth access/refresh token stores under `external-ssd-export-20260705/.../.claude/.credentials.json`, OpenAI/Codex API/session token fields under `external-ssd-export-20260705/.../.codex/auth.json`, and GitHub CLI OAuth token fields under `external-ssd-export-20260705/.../.config/gh/hosts.yml`. Confidence: high for credential-store presence; liveness was not tested.

## Supply Chain Result
Supply-chain review found installer and helper-generation weaknesses: `meridian-install` embeds installer-supplied paths into generated shell helpers, removes/copies through installer-controlled paths without symlink/hardlink quarantine, and `tools/wuci_install.py` resolves `ssh-keygen` from ambient `PATH` by default. These are unresolved high/medium findings.

## CI/CD Review Result
GitHub Actions and automation were reviewed. No standalone CI/CD compromise finding survived validation, but release automation and source-kit privacy weaknesses remain in adjacent release tooling. No push, tag, release, or GitHub setting change was performed.

## Code Security Result
Code review found 19 code-area findings covering unsafe output paths, predictable temp files, symlink/hardlink/TOCTOU gaps, command-file interpolation, subprocess secret exposure, and direct plaintext/envelope writes to caller-selected paths.

## Cryptographic and PQC Review Result
Crypto/PQC review found high-severity authority and evidence verification issues in Daylight v16 Analemma and Zenith, plus linked-read and proof evidence hardening gaps. The repository policy correctly warns against overclaiming quantum safety from classical-only signatures, but unresolved proof-authority issues prevent any optimal national-security defensive posture.

## Release Safety Result
Release review found source-kit fallback leakage, privacy-audit coverage gaps, release-gate TOCTOU paths, and multiple predictable temp-file output writers. HEAD is not tagged; the previous tag at origin/main is not on the scan target commit. Release/tag/artifact integrity is not ready for national-security defensive use.

## Documentation Claim Boundary Review
The documentation now contains clearer boundaries, but the executable evidence still has unresolved public-authority, crypto-evidence, release, credential, and validation gaps. Any claim of production readiness, external validation, government/public authority, runtime sandboxing, or quantum-safe security would exceed the completed evidence.

## Website and Public Surface Result
Website/public-surface review found public-evidence firewall symlink/reopen gaps and broader public evidence scanner resource and safe-I/O issues. External script/CDN exposure was not the dominant validated risk; public evidence trust-boundary handling was.

## Test and Validator Integrity Result
Test/validator review found that standalone WITNESS verification only rejects hardlinked public bundle files in strict proof mode. Several validators and proof lanes also rely on safe-I/O patterns that need broader negative tests for symlink, hardlink, race, and forged-evidence cases.

## Repository Hygiene Result
Repository hygiene is not acceptable for high-assurance defensive use because credential/session stores and backup/export artifacts are inside the resolved scan scope. These may be ignored by git, but they are part of the local repository/workspace evidence surface and can be accidentally packaged, scanned, or published.

## National Security Defense Readiness Judgment
FALSE. The repository is not optimally set for national security defense use. The completed evidence contains high findings, unresolved medium findings, confirmed credential-store presence, release-integrity concerns, supply-chain installer risks, cryptographic evidence-authority flaws, and public-claim boundary limitations.

## TRUE/FALSE Decision Basis
The TRUE criteria are not met because the scan found high findings, unresolved medium findings, confirmed sensitive credential-store presence, release and supply-chain risks, cryptographic ambiguity/authority issues, and evidence gaps requiring external validation. The completed scan supports only the binary decision FALSE.

## Recommended Remediation Plan
1. Immediate
- Remove credential/session-store and backup/export artifacts from the repository workspace; rotate all potentially exposed credential types without printing values; rebuild scan and release artifacts from a clean checkout.
- Block release/source-kit/ISO publication until final payload privacy scans cover the observed credential formats and scan the actual packaged outputs.
- Fix high crypto-authority flaws by rejecting self-supplied HMAC roots and unsigned `valid=true` production authority evidence.
- Fix high command/shell risks in `tools/wuci_os.py` and `meridian-install`.
2. Before next release
- Make release packaging fail closed on git enumeration failure, privacy-audit incompleteness, unsafe runner identity, and descriptor-unsafe evidence reads/writes.
- Expand safe-I/O use across proof, release, public evidence, vault, installer, and generated artifact writers with symlink, hardlink, parent-directory, and TOCTOU regression tests.
- Pin or explicitly configure trusted verifier executables instead of relying on ambient `PATH`.
3. Documentation cleanup
- Keep production-readiness, external-validation, public-authority, runtime-sandboxing, and PQC/quantum-safety claims explicitly bounded to current evidence.
- Add a release-readiness matrix distinguishing local validation, runtime validation, release packaging, external validation, public-review evidence, and production readiness.
4. Longer-term hardening
- Add centralized descriptor-relative safe-I/O APIs for all public/release/proof artifacts and make unsafe direct writes lint/test failures.
- Add a hermetic release build from a clean workspace with deterministic source inventory, final payload scanning, digest verification, and signed provenance.
- Add independent external cryptographic/protocol review before any national-security, production, or public-authority posture claim.

## Commands Run
- `pwd`
- `git status --short`
- `git branch --show-current`
- `git rev-parse HEAD`
- `git rev-parse origin/main`
- `git log --oneline -5`
- `git tag --points-at HEAD`
- `git submodule status --recursive`
- `python3 /home/wj/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.10/scripts/config_preflight.py --profile deep_security_scan --cwd /home/wj/-wuci-ji --runtime-check delegation_available=true --runtime-check goal_tools_available=true --available-plugin-skill security-scan --available-plugin-skill threat-model --available-plugin-skill finding-discovery --available-plugin-skill validation --available-plugin-skill attack-path-analysis --multi-agent-runtime-owner native --multi-agent-runtime-version v1 --multi-agent-runtime-provenance tool-surface`
- `python3 /home/wj/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.10/scripts/generate_rank_input.py make-repo-rank-input --repo /home/wj/-wuci-ji --scope . --out /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/artifacts/02_discovery/rank_input.jsonl`
- `python3 /home/wj/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.10/scripts/generate_rank_input.py copy-deep-review-input --rank-input /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/artifacts/02_discovery/rank_input.jsonl --out /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/artifacts/02_discovery/deep_review_input.jsonl`
- `Codex multi-agent delegated discovery worker rounds 1 through 5; each completed with six usable workers and preserved worker-local threat-model/discovery artifacts.`
- `python3 helper checks for canonical inventory/report/jsonl/ledger consistency after discovery rounds`
- `python3 helper scripts to synthesize validation summary, per-finding validation reports, attack-path analysis reports, candidate ledgers, scan-manifest.json, findings.json, and coverage.json from canonical artifacts`
- `python3 /home/wj/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.10/scripts/finalize_scan_contract.py --scan-dir /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z --source-root /home/wj/-wuci-ji`
- `mkdir -p security/reports`
- `python3 helper generation of security/reports/deep-security-scan-2026-07-06.md from sealed scan artifacts`
- `git status --short`
- `git diff --stat`
- `git diff -- security/reports/deep-security-scan-2026-07-06.md`

## Files Reviewed
- .github/workflows/* and workflow-related automation
- Makefile, package.json, lock/build metadata where present, shell installers, generated helpers, Docker/container references where present
- tools/*.py including Wuci-OS, release, privacy, public-evidence, installer, CAGE, QCAGE, Witness, Ledger, Gate, safe-I/O, provenance, backup, VirtualBox, CARROT, and crypto audit tools
- daylight/** including v14/v15/v16/v17/v20 evidence, vault, Analemma, Zenith, public-artifact, and SSV paths
- penumbra/** Rust CLI and docs
- docs/**, README.md, public status ledgers, WuciOS carryover docs, release/public-claim documentation, site/public assets where present
- ignored/local/historical-looking artifacts under the resolved scan scope, including .wrangler and external-ssd-export-20260705 paths, with secret values redacted
- third_party/zp1 submodule state only; no submodule pin was changed
- Codex Security artifacts under /tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z

## Files Changed
- Repository pre-scan commit already completed before this final scan target: `1d420abb2788027cb6c0febb928269e8d9bd96e5`.
- Authorized local Codex configuration outside the repository was remediated for preflight: `features.goals = true`, `agents.max_threads = 8`, `agents.max_depth = 2`.
- During the completed scan, no Wuci-Ji remediation files were changed.
- Created/updated authorized report file: `security/reports/deep-security-scan-2026-07-06.md`.
- Generated scan artifacts under `/tmp/codex-security-scans/-wuci-ji/1d420abb2788027cb6c0febb928269e8d9bd96e5_20260706T124928Z/`.

## Final Worktree Status
```text
?? security/reports/
```

## Final Classification
WUCI_JI_NATIONAL_SECURITY_DEFENSE_AUDIT_FALSE
