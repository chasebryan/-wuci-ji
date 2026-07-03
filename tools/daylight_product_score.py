#!/usr/bin/env python3
"""Generate the Daylight product-standard readiness score."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "daylight" / "product-standard-readiness.json"


def exists(path: str) -> bool:
    return (ROOT / path).exists()


def score_presence(paths: list[str]) -> int:
    if not paths:
        return 0
    present = sum(1 for path in paths if exists(path))
    return present * 100 // len(paths)


def main() -> int:
    categories = {
        "SpecCompleteness": score_presence([
            "docs/DAYLIGHT_EQUATION_STANDARD.md",
            "specs/daylight-equation/v1/README.md"
        ]),
        "SchemaStability": score_presence([
            "specs/daylight-equation/v1/daylight-claim.v1.schema.json",
            "specs/daylight-equation/v1/daylight-evidence.v1.schema.json",
            "specs/daylight-equation/v1/daylight-scorecard.v1.schema.json",
            "specs/daylight-equation/v1/daylight-release-gate.v1.schema.json"
        ]),
        "ConformanceTesting": score_presence([
            "tools/daylight_standard_validate.py",
            "tools/daylight_conformance.py",
            "examples/daylight-standard/unsupported-certification-claim.json"
        ]),
        "CLIUsability": score_presence([
            "tools/daylight_conformance.py",
            "tools/daylight_release_gate.py",
            "tools/daylight_control_map.py",
            "tools/daylight_monitor_signal.py"
        ]),
        "CIIntegration": score_presence([
            ".github/workflows/daylight-standard.yml",
            ".github/actions/daylight-standard/action.yml",
            "examples/integrations/github-action.yml"
        ]),
        "DocumentationCompleteness": score_presence([
            "docs/STANDARDIZATION_ROADMAP.md",
            "docs/WUCI_PRODUCT_STANDARD.md",
            "docs/WUCI_ENTERPRISE_ADOPTION.md",
            "docs/WUCI_SECURITY_PRODUCT_BOUNDARY.md"
        ]),
        "ControlMapping": score_presence([
            "docs/WUCI_CONTROL_PLANE_ARCHITECTURE.md",
            "examples/daylight-standard/control-map-example.json"
        ]),
        "EvidenceInteroperability": score_presence([
            "specs/daylight-equation/v1/daylight-evidence.v1.schema.json",
            "specs/daylight-equation/v1/daylight-attestation.v1.schema.json",
            "examples/daylight-standard/evidence-example.json"
        ]),
        "MonitoringDesign": score_presence([
            "docs/WUCI_MONITORING_DOWNGRADE_MODEL.md",
            "specs/daylight-equation/v1/daylight-monitor-signal.v1.schema.json",
            "examples/daylight-standard/monitor-signal-example.json"
        ]),
        "AdoptionReadiness": score_presence([
            "docs/WUCI_ENTERPRISE_ADOPTION.md",
            "site/enterprise-adoption.html",
            "docs/WUCI_DEFAULT_STANDARD_EXIT_CRITERIA.md"
        ]),
        "NonClaimEnforcement": score_presence([
            "docs/WUCI_SECURITY_PRODUCT_BOUNDARY.md",
            "tools/daylight_market_boundary.py",
            "site/product-boundary.html"
        ]),
        "PackagingReadiness": score_presence([
            "Makefile",
            ".github/workflows/daylight-standard.yml"
        ])
    }
    score = min(categories.values()) if categories else 0
    weakest = min(categories, key=lambda key: categories[key])
    data = {
        "schema": "daylight-product-standard-readiness-v1",
        "generated_at": "1970-01-01T00:00:00Z",
        "score": score,
        "max_score": 100,
        "weakest_category": weakest,
        "categories": categories,
        "blockers": [
            key for key, value in categories.items() if value < 100
        ],
        "non_claim": "Product readiness is not a security score, certification, production authority, or government approval."
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
