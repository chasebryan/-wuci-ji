"""Interpret collected DaylightSSV facts into scored checks."""

from __future__ import annotations

from typing import Any

from .model import CheckResult, Evidence


def _ev(evidence_type: str, source: str, summary: str, sha256: str | None = None) -> Evidence:
    return Evidence(type=evidence_type, source=source, value_summary=summary, sha256=sha256)


def _check(
    domain: str,
    check_id: str,
    severity: str,
    result: str,
    evidence_quality: str,
    reason: str,
    hint: str,
    evidence: list[Evidence] | None = None,
    flags: set[str] | None = None,
) -> CheckResult:
    return CheckResult(
        id=check_id,
        domain_id=domain,
        severity=severity,
        result=result,
        evidence_quality=evidence_quality,
        evidence=tuple(evidence or []),
        reason=reason,
        safe_remediation_hint=hint,
        flags=frozenset(flags or set()),
    )


def build_checks(facts: dict[str, Any]) -> list[CheckResult]:
    checks: list[CheckResult] = []
    platform = facts.get("platform", {})
    filesystem = facts.get("filesystem", {})
    repo = facts.get("repo", {})
    network = facts.get("network", {})
    process = facts.get("process", {})
    daylight = facts.get("daylight", {})

    paths = filesystem.get("paths", {})
    checks.append(
        _check(
            "identity_privilege_control",
            "identity.running_as_root",
            "high",
            "fail" if platform.get("is_root") else "pass",
            "strong",
            "The validator observed whether the current process has root effective privileges.",
            "Run routine posture checks as an unprivileged user unless root is explicitly required.",
            [_ev("config_value", "system:euid", "root effective uid observed" if platform.get("is_root") else "non-root effective uid observed")],
        )
    )
    sudoers = paths.get("etc_sudoers", {})
    sudoers_quality = "medium" if sudoers.get("exists") else "missing"
    sudoers_result = "fail" if filesystem.get("sudoers_has_nopasswd") else ("pass" if filesystem.get("sudoers_has_nopasswd") is False else "unknown")
    checks.append(
        _check(
            "identity_privilege_control",
            "identity.sudoers_nopasswd_marker",
            "high",
            sudoers_result,
            sudoers_quality,
            "Sudoers NOPASSWD marker evidence is scored only when the file is safely readable.",
            "Review sudoers entries and avoid broad passwordless privilege grants.",
            [_ev("file_content", "system:/etc/sudoers", "NOPASSWD marker present" if sudoers_result == "fail" else "NOPASSWD marker not observed" if sudoers_result == "pass" else "sudoers content unavailable")],
        )
    )
    sensitive_world = [name for name, info in paths.items() if name in {"etc_passwd", "etc_shadow", "etc_sudoers"} and info.get("world_writable")]
    checks.append(
        _check(
            "identity_privilege_control",
            "identity.sensitive_paths_world_writable",
            "critical",
            "fail" if sensitive_world else "pass",
            "strong",
            "Common sensitive identity files were checked for world-writable mode bits.",
            "Remove world-writable permissions from sensitive identity and privilege files.",
            [_ev("config_value", "system:sensitive-path-modes", f"world_writable_sensitive_count={len(sensitive_world)}")],
        )
    )
    account_summary = filesystem.get("account_summary")
    checks.append(
        _check(
            "identity_privilege_control",
            "identity.account_enumeration_summary",
            "low",
            "pass" if account_summary else "unknown",
            "medium" if account_summary else "missing",
            "Account enumeration is summarized only as counts, without usernames or shell values.",
            "Keep local account inventory reviewable without exposing account names in public reports.",
            [_ev("file_content", "system:/etc/passwd", f"accounts={account_summary['accounts']}; login_shells={account_summary['login_shells']}" if account_summary else "account summary unavailable")],
        )
    )

    known = repo.get("known_files", {})
    checks.append(
        _check(
            "update_install_integrity",
            "update.package_metadata_presence",
            "medium",
            "pass" if repo.get("manifests") else "unknown",
            "strong" if repo.get("manifests") else "missing",
            "Package or build manifests provide update/install metadata evidence.",
            "Keep package manifests tracked with reviewable version and build metadata.",
            [_ev("file_presence", "repo:package-manifests", f"manifest_count={len(repo.get('manifests', []))}")],
        )
    )
    install_manifest = known.get("wuci_install_manifest", {})
    install_signature = known.get("wuci_install_signature", {})
    checks.append(
        _check(
            "update_install_integrity",
            "update.install_manifest_signature_evidence",
            "high",
            "pass" if install_manifest.get("exists") and install_signature.get("exists") else "unknown",
            "strong" if install_manifest.get("exists") and install_signature.get("exists") else "missing",
            "WUCI install integrity evidence requires a local manifest and signature file.",
            "Keep signed install manifests and local root-key verification evidence in the install lane.",
            [_ev("file_presence", "repo:install/wuci-install-manifest.v1", f"manifest_exists={bool(install_manifest.get('exists'))}"), _ev("file_presence", "repo:install/wuci-install-manifest.v1.sig", f"signature_exists={bool(install_signature.get('exists'))}")],
        )
    )
    unsafe_pipelines = repo.get("unsafe_pipeline_markers", [])
    checks.append(
        _check(
            "update_install_integrity",
            "update.unpinned_remote_shell_pipeline_markers",
            "critical",
            "fail" if unsafe_pipelines else "pass",
            "strong",
            "Repository text surfaces were checked for curl-or-wget piped directly into a shell.",
            "Replace remote-code shell pipelines with pinned downloads and local signature verification.",
            [_ev("file_content", "repo:tracked-text", f"unsafe_pipeline_marker_count={len(unsafe_pipelines)}")],
        )
    )
    checks.append(
        _check(
            "update_install_integrity",
            "update.local_wuci_install_files",
            "medium",
            "pass" if install_manifest.get("exists") else "unknown",
            "medium" if install_manifest.get("exists") else "missing",
            "Local Wuci-Ji install files are scored only when present in the repository.",
            "Keep install proof files local, noninteractive, signed, and reproducible.",
            [_ev("file_presence", "repo:install", f"wuci_install_manifest_exists={bool(install_manifest.get('exists'))}")],
        )
    )

    secret_findings = repo.get("secret_findings", [])
    checks.append(
        _check(
            "cryptography_secrets_handling",
            "crypto.exposed_secret_pattern_sweep",
            "critical",
            "fail" if secret_findings else "pass",
            "strong",
            "Tracked text surfaces were swept for high-confidence secret patterns without printing secret values.",
            "Remove exposed secrets, rotate affected credentials, and keep only redacted examples in public files.",
            [_ev("file_content", "repo:tracked-text", f"secret_pattern_count={len(secret_findings)}")],
            {"exposed_secret"} if secret_findings else set(),
        )
    )
    private_keys = repo.get("private_key_markers", [])
    checks.append(
        _check(
            "cryptography_secrets_handling",
            "crypto.private_key_marker_sweep",
            "critical",
            "fail" if private_keys else "pass",
            "strong",
            "Private key block markers were counted without including key material.",
            "Remove private keys from tracked surfaces and rotate any exposed keys.",
            [_ev("file_content", "repo:tracked-text", f"private_key_marker_count={len(private_keys)}")],
            {"exposed_secret"} if private_keys else set(),
        )
    )
    placeholder_crypto = repo.get("placeholder_crypto_markers", [])
    checks.append(
        _check(
            "cryptography_secrets_handling",
            "crypto.placeholder_crypto_wording_sweep",
            "medium",
            "partial" if placeholder_crypto else "pass",
            "medium",
            "Code surfaces were checked for placeholder cryptography wording.",
            "Replace placeholder cryptography with reviewed, pinned implementations or keep it clearly non-production.",
            [_ev("file_content", "repo:code-text", f"placeholder_crypto_marker_count={len(placeholder_crypto)}")],
        )
    )
    invalid_digests = [item for item in repo.get("digest_claims", []) if not item.get("valid")]
    checks.append(
        _check(
            "cryptography_secrets_handling",
            "crypto.digest_format_validation",
            "medium",
            "fail" if invalid_digests else "pass",
            "strong" if repo.get("digest_claims") else "medium",
            "Known digest literals were checked for algorithm-appropriate hex length.",
            "Use complete SHA-256 or SHA3-512 digest literals for public evidence claims.",
            [_ev("file_content", "repo:tracked-text", f"invalid_digest_count={len(invalid_digests)}; digest_claim_count={len(repo.get('digest_claims', []))}")],
        )
    )

    listeners = network.get("listeners", [])
    non_loopback = [item for item in listeners if item.get("bind") in {"wildcard", "non_loopback"}]
    admin_visible = [item for item in non_loopback if item.get("admin_port")]
    checks.append(
        _check(
            "network_exposure",
            "network.local_listening_socket_enumeration",
            "medium",
            "pass",
            "strong",
            "Local listening sockets were enumerated from procfs without packet sending.",
            "Review local listeners and bind services to loopback where remote access is not required.",
            [_ev("command_output", "system:/proc/net/tcp", f"listener_count={len(listeners)}")],
        )
    )
    checks.append(
        _check(
            "network_exposure",
            "network.non_loopback_listener_classification",
            "high",
            "fail" if non_loopback else "pass",
            "strong",
            "Listeners were classified as loopback, wildcard, non-loopback, or unknown without remote probing.",
            "Restrict non-loopback listeners with host firewall rules and service configuration.",
            [_ev("command_output", "system:/proc/net/tcp", f"non_loopback_or_wildcard_listener_count={len(non_loopback)}")],
        )
    )
    checks.append(
        _check(
            "network_exposure",
            "network.remote_admin_port_visible",
            "high",
            "fail" if admin_visible else "pass",
            "strong",
            "Common remote administration ports were checked only for local listening visibility; authentication was not probed.",
            "Disable unnecessary remote administration listeners or restrict them to trusted networks.",
            [_ev("command_output", "system:/proc/net/tcp", f"visible_admin_listener_count={len(admin_visible)}")],
        )
    )
    checks.append(
        _check(
            "network_exposure",
            "network.no_remote_probe_boundary",
            "low",
            "pass",
            "strong",
            "The network collector uses local procfs data and does not send packets.",
            "Keep DaylightSSV network collection local-only by default.",
            [_ev("generated_report", "daylight:ssv:collector-policy", "no remote probing performed")],
        )
    )

    executable_dirs = [name for name, info in paths.items() if name in {"usr_local_bin", "usr_bin", "bin", "sbin"} and info.get("world_writable")]
    checks.append(
        _check(
            "file_process_runtime_integrity",
            "runtime.world_writable_executable_dirs",
            "critical",
            "fail" if executable_dirs else "pass",
            "strong",
            "Common executable directories were checked for world-writable mode bits.",
            "Remove world-writable permissions from executable directories.",
            [_ev("config_value", "system:executable-directory-modes", f"world_writable_executable_dir_count={len(executable_dirs)}")],
        )
    )
    checks.append(
        _check(
            "file_process_runtime_integrity",
            "runtime.suid_sgid_inventory",
            "medium",
            "unknown",
            "missing",
            "SUID/SGID inventory was not collected because v1 avoids broad privileged filesystem traversal by default.",
            "Run a separate approved local hardening inventory if SUID/SGID review is required.",
            [_ev("manual_none", "system:suid-sgid-inventory", "not collected by default")],
        )
    )
    checks.append(
        _check(
            "file_process_runtime_integrity",
            "runtime.process_listing_summary",
            "low",
            "pass" if process.get("process_count") is not None else "unknown",
            "medium" if process.get("process_count") is not None else "missing",
            "Process listing evidence is summarized only as a count, without command lines or usernames.",
            "Use separate local operational review for full process command analysis.",
            [_ev("command_output", "system:/proc", f"process_count={process.get('process_count')}" if process.get("process_count") is not None else "process count unavailable")],
        )
    )
    build_artifact = repo.get("known_files", {}).get("v20_capsule", {})
    checks.append(
        _check(
            "file_process_runtime_integrity",
            "runtime.wuci_build_artifact_integrity",
            "medium",
            "pass" if build_artifact.get("exists") else "unknown",
            "strong" if build_artifact.get("exists") else "missing",
            "Wuci-Ji Daylight v20 build artifact evidence is credited only when a local artifact exists.",
            "Regenerate the Daylight v20 capsule through the documented make target.",
            [_ev("file_presence", "repo:build/daylight/v20-aperture-singularity-capsule.json", f"artifact_exists={bool(build_artifact.get('exists'))}", build_artifact.get("sha256"))],
        )
    )

    debug_markers = repo.get("debug_markers", [])
    env_files = repo.get("env_files", [])
    checks.append(
        _check(
            "configuration_hardening",
            "config.known_insecure_permissions",
            "high",
            "fail" if sensitive_world or executable_dirs else "pass",
            "strong",
            "Known insecure permission markers reuse sensitive-file and executable-directory mode evidence.",
            "Harden file and directory modes before treating posture as controlled.",
            [_ev("config_value", "system:mode-summary", f"insecure_mode_marker_count={len(sensitive_world) + len(executable_dirs)}")],
        )
    )
    checks.append(
        _check(
            "configuration_hardening",
            "config.debug_dev_mode_markers",
            "medium",
            "partial" if debug_markers else "pass",
            "medium",
            "Tracked configuration surfaces were checked for common debug or development mode markers.",
            "Keep debug/dev markers out of release and public deployment configuration.",
            [_ev("file_content", "repo:tracked-config", f"debug_marker_count={len(debug_markers)}")],
        )
    )
    checks.append(
        _check(
            "configuration_hardening",
            "config.unsafe_shell_pipeline_markers",
            "high",
            "fail" if repo.get("unsafe_pipeline_markers") else "pass",
            "strong",
            "Tracked surfaces were checked for remote shell pipeline markers without executing them.",
            "Remove remote-code shell pipelines and use pinned local verification.",
            [_ev("file_content", "repo:tracked-text", f"unsafe_pipeline_marker_count={len(repo.get('unsafe_pipeline_markers', []))}")],
        )
    )
    checks.append(
        _check(
            "configuration_hardening",
            "config.environment_file_exposure_markers",
            "high",
            "partial" if env_files else "pass",
            "medium",
            "Tracked environment-like files were counted without reading or printing variable values.",
            "Keep real environment and secret files untracked; ship only redacted templates.",
            [_ev("file_presence", "repo:tracked-files", f"env_like_file_count={len(env_files)}")],
        )
    )

    npt_report = daylight.get("daylight_npt_report", {})
    score_report = daylight.get("score_integrity_report", {})
    checks.append(
        _check(
            "logging_auditability",
            "logging.logs_directory_presence",
            "low",
            "unknown",
            "missing",
            "A generic logs directory is not required by this repository and was not proven present.",
            "Document where operational logs live if this validator is used as a CI posture input.",
            [_ev("file_presence", "repo:logs", "logs directory evidence not present")],
        )
    )
    checks.append(
        _check(
            "logging_auditability",
            "logging.audit_report_generation_evidence",
            "medium",
            "pass" if npt_report.get("exists") or score_report.get("exists") else "unknown",
            "medium" if npt_report.get("exists") or score_report.get("exists") else "missing",
            "Auditability credit requires generated or tracked audit report evidence.",
            "Generate DaylightNPT or score-integrity reports before relying on this auditability check.",
            [_ev("file_presence", "repo:audit-reports", f"daylight_npt_report={bool(npt_report.get('exists'))}; score_integrity_index={bool(score_report.get('exists'))}")],
        )
    )
    checks.append(
        _check(
            "logging_auditability",
            "logging.daylight_npt_report_exists",
            "medium",
            "pass" if npt_report.get("exists") else "unknown",
            "strong" if npt_report.get("exists") else "missing",
            "DaylightNPT report existence is evidence for numeric-claim auditability.",
            "Run make daylight-npt to generate the DaylightNPT report.",
            [_ev("generated_report", "repo:build/daylight/npt-v1/daylight-npt.report.json", f"exists={bool(npt_report.get('exists'))}", npt_report.get("sha256"))],
        )
    )
    checks.append(
        _check(
            "logging_auditability",
            "logging.score_integrity_report_exists",
            "medium",
            "pass" if score_report.get("exists") else "unknown",
            "strong" if score_report.get("exists") else "missing",
            "Score-integrity report index existence is evidence for score auditability.",
            "Regenerate or update the score-integrity audit index when public score evidence changes.",
            [_ev("generated_report", "repo:audits/daylight/score-integrity/index.json", f"exists={bool(score_report.get('exists'))}", score_report.get("sha256"))],
        )
    )

    recovery_doc_count = sum(
        1
        for key in ("release_runbook", "machine_passoff", "contributor_bootstrap")
        if daylight.get(key, {}).get("exists")
    )
    checks.append(
        _check(
            "backup_recovery_posture",
            "backup.configuration_evidence",
            "medium",
            "unknown",
            "missing",
            "No explicit backup configuration artifact was proven by the v1 collector.",
            "Add a local backup configuration or documented backup evidence artifact if available.",
            [_ev("file_presence", "repo:backup-config", "backup configuration evidence unavailable")],
        )
    )
    checks.append(
        _check(
            "backup_recovery_posture",
            "backup.recovery_docs_evidence",
            "medium",
            "pass" if recovery_doc_count else "unknown",
            "medium" if recovery_doc_count else "missing",
            "Recovery posture uses repository documentation evidence and does not infer operational backups.",
            "Keep recovery and passoff documents current for rebuild and host transition work.",
            [_ev("file_presence", "repo:docs", f"recovery_doc_count={recovery_doc_count}")],
        )
    )
    checks.append(
        _check(
            "backup_recovery_posture",
            "backup.deterministic_rebuild_instructions",
            "medium",
            "pass" if daylight.get("site_validator", {}).get("exists") else "unknown",
            "medium" if daylight.get("site_validator", {}).get("exists") else "missing",
            "Deterministic rebuild credit is limited to local validators and documented build targets.",
            "Maintain build target documentation and deterministic rebuild receipts.",
            [_ev("file_presence", "repo:site/validate.mjs", f"site_validator_exists={bool(daylight.get('site_validator', {}).get('exists'))}")],
        )
    )
    checks.append(
        _check(
            "backup_recovery_posture",
            "backup.no_backup_evidence_unknown",
            "low",
            "unknown",
            "missing",
            "No backup evidence earns no credit; v1 does not assume backups exist.",
            "Provide concrete backup and restore evidence to earn credit for this check.",
            [_ev("manual_none", "repo:backup-evidence", "no backup evidence supplied")],
        )
    )

    checks.append(
        _check(
            "dependency_supply_chain_integrity",
            "supply.lockfile_presence",
            "medium",
            "pass" if repo.get("lockfiles") else "unknown",
            "strong" if repo.get("lockfiles") else "missing",
            "Lockfiles provide supply-chain repeatability evidence.",
            "Commit lockfiles for ecosystems that support deterministic dependency locking.",
            [_ev("file_presence", "repo:lockfiles", f"lockfile_count={len(repo.get('lockfiles', []))}")],
        )
    )
    checks.append(
        _check(
            "dependency_supply_chain_integrity",
            "supply.manifest_lock_consistency_evidence",
            "medium",
            "pass" if repo.get("manifests") and repo.get("lockfiles") else "unknown",
            "medium" if repo.get("manifests") and repo.get("lockfiles") else "missing",
            "Package manifest and lockfile coexistence is treated as consistency evidence, not a full dependency audit.",
            "Run ecosystem-specific lock verification for stronger dependency assurance.",
            [_ev("file_presence", "repo:manifests-lockfiles", f"manifest_count={len(repo.get('manifests', []))}; lockfile_count={len(repo.get('lockfiles', []))}")],
        )
    )
    vendored_binary = repo.get("vendored_binary_markers", [])
    checks.append(
        _check(
            "dependency_supply_chain_integrity",
            "supply.vendored_binary_warning",
            "medium",
            "partial" if vendored_binary else "pass",
            "medium",
            "Tracked binary-like artifacts were counted as a supply-chain review warning.",
            "Document provenance for vendored binaries or remove generated build outputs from source control.",
            [_ev("file_presence", "repo:tracked-files", f"vendored_binary_marker_count={len(vendored_binary)}")],
        )
    )
    checks.append(
        _check(
            "dependency_supply_chain_integrity",
            "supply.ci_workflow_presence",
            "medium",
            "pass" if repo.get("ci_workflows") else "unknown",
            "strong" if repo.get("ci_workflows") else "missing",
            "CI workflow files provide repeatable validation surface evidence.",
            "Keep CI workflows tracked and aligned with local make targets.",
            [_ev("file_presence", "repo:.github/workflows", f"workflow_count={len(repo.get('ci_workflows', []))}")],
        )
    )
    firewall = daylight.get("public_evidence_firewall", {})
    checks.append(
        _check(
            "dependency_supply_chain_integrity",
            "supply.artifact_firewall_presence",
            "medium",
            "pass" if firewall.get("exists") else "unknown",
            "strong" if firewall.get("exists") else "missing",
            "Artifact firewall tooling existence is supply-chain evidence for public artifact boundaries.",
            "Keep public artifact firewall checks in the release and CI lane.",
            [_ev("file_presence", "repo:tools/daylight_public_evidence_firewall.py", f"exists={bool(firewall.get('exists'))}", firewall.get("sha256"))],
        )
    )

    ssv_docs = daylight.get("ssv_docs", {})
    checks.append(
        _check(
            "daylight_evidence_reproducibility",
            "daylight.daylight_npt_report_presence",
            "medium",
            "pass" if npt_report.get("exists") else "unknown",
            "strong" if npt_report.get("exists") else "missing",
            "DaylightNPT report presence is scored as reproducibility evidence.",
            "Run make daylight-npt before publishing numeric-claim posture statements.",
            [_ev("generated_report", "repo:build/daylight/npt-v1/daylight-npt.report.json", f"exists={bool(npt_report.get('exists'))}", npt_report.get("sha256"))],
        )
    )
    checks.append(
        _check(
            "daylight_evidence_reproducibility",
            "daylight.score_integrity_report_presence",
            "medium",
            "pass" if score_report.get("exists") else "unknown",
            "strong" if score_report.get("exists") else "missing",
            "Score-integrity report presence is scored as reproducibility evidence.",
            "Keep score-integrity reports regenerated when public score claims change.",
            [_ev("generated_report", "repo:audits/daylight/score-integrity/index.json", f"exists={bool(score_report.get('exists'))}", score_report.get("sha256"))],
        )
    )
    checks.append(
        _check(
            "daylight_evidence_reproducibility",
            "daylight.site_validation_evidence",
            "medium",
            "pass" if daylight.get("site_validator", {}).get("exists") else "unknown",
            "medium" if daylight.get("site_validator", {}).get("exists") else "missing",
            "Site validation evidence is limited to the presence of the local validator in this audit.",
            "Run make site-validate after changing public Daylight surfaces.",
            [_ev("file_presence", "repo:site/validate.mjs", f"exists={bool(daylight.get('site_validator', {}).get('exists'))}")],
        )
    )
    checks.append(
        _check(
            "daylight_evidence_reproducibility",
            "daylight.v20_gate_evidence",
            "medium",
            "pass" if daylight.get("v20_capsule", {}).get("exists") else "unknown",
            "strong" if daylight.get("v20_capsule", {}).get("exists") else "missing",
            "Daylight v20 gate evidence is credited only when a generated capsule exists.",
            "Run make daylight-v20-aperture-singularity-capsule-demo for local v20 evidence.",
            [_ev("generated_report", "repo:build/daylight/v20-aperture-singularity-capsule.json", f"exists={bool(daylight.get('v20_capsule', {}).get('exists'))}", daylight.get("v20_capsule", {}).get("sha256"))],
        )
    )
    checks.append(
        _check(
            "daylight_evidence_reproducibility",
            "daylight.non_claim_boundary_docs",
            "medium",
            "pass" if ssv_docs.get("exists") or daylight.get("security_boundary", {}).get("exists") else "unknown",
            "strong" if ssv_docs.get("exists") else "medium" if daylight.get("security_boundary", {}).get("exists") else "missing",
            "Non-claim boundary documentation prevents the SSV score from being presented as certification.",
            "Keep DaylightSSV caveats and WUCI security-boundary documentation explicit.",
            [_ev("file_presence", "repo:docs/DAYLIGHT_SSV_V1.md", f"exists={bool(ssv_docs.get('exists'))}", ssv_docs.get("sha256"))],
        )
    )

    return checks
