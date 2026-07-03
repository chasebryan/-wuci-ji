"""Data model and fixed constants for DaylightSSV v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any


DOMAIN_DEFINITIONS: tuple[tuple[str, str, Decimal], ...] = (
    ("identity_privilege_control", "Identity / privilege control", Decimal("12.0")),
    ("update_install_integrity", "Update / install integrity", Decimal("12.0")),
    ("cryptography_secrets_handling", "Cryptography / secrets handling", Decimal("11.0")),
    ("network_exposure", "Network exposure", Decimal("12.0")),
    ("file_process_runtime_integrity", "File / process / runtime integrity", Decimal("11.0")),
    ("configuration_hardening", "Configuration hardening", Decimal("10.0")),
    ("logging_auditability", "Logging / auditability", Decimal("8.0")),
    ("backup_recovery_posture", "Backup / recovery posture", Decimal("7.0")),
    ("dependency_supply_chain_integrity", "Dependency / supply-chain integrity", Decimal("9.0")),
    ("daylight_evidence_reproducibility", "Daylight evidence / reproducibility", Decimal("8.0")),
)

DOMAIN_ORDER = tuple(item[0] for item in DOMAIN_DEFINITIONS)
DOMAIN_NAMES = {item[0]: item[1] for item in DOMAIN_DEFINITIONS}
DOMAIN_WEIGHTS = {item[0]: item[2] for item in DOMAIN_DEFINITIONS}

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 8,
    "high": 5,
    "medium": 3,
    "low": 1,
}

RESULT_VALUES: dict[str, Decimal] = {
    "pass": Decimal("1.0"),
    "partial": Decimal("0.5"),
    "fail": Decimal("0.0"),
    "unknown": Decimal("0.0"),
}

EVIDENCE_QUALITY_VALUES: dict[str, Decimal] = {
    "strong": Decimal("1.0"),
    "medium": Decimal("0.75"),
    "weak": Decimal("0.50"),
    "missing": Decimal("0.0"),
}


@dataclass(frozen=True)
class Evidence:
    """Safe evidence summary. Values must not contain secrets or local identity."""

    type: str
    source: str
    value_summary: str
    sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "value_summary": self.value_summary,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class CheckResult:
    """A single interpreted DaylightSSV check result."""

    id: str
    domain_id: str
    severity: str
    result: str
    evidence_quality: str
    evidence: tuple[Evidence, ...] = ()
    reason: str = ""
    safe_remediation_hint: str = ""
    flags: frozenset[str] = field(default_factory=frozenset)

