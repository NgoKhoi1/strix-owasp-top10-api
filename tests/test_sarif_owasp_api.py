"""OWASP API Top 10 category tagging in the SARIF emitter (strix.report.sarif).

A finding whose CWE maps to an OWASP API Security Top 10 category gets an
``owasp-api:APIn`` tag on its SARIF rule; an ambiguous/unmapped/no-CWE finding
gets none (rather than a wrong label).
"""

from __future__ import annotations

from typing import Any

import pytest

from strix.report.sarif import (
    _CWE_TO_OWASP_API,
    build_sarif_report,
    owasp_api_category_for_cwe,
)


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "Cross-tenant object access",
        "severity": "high",
        "cwe": "CWE-639",
        "description": "Order id is not bound to the caller's tenant.",
    }
    finding.update(overrides)
    return finding


def _rule_tags(doc: dict[str, Any]) -> list[str]:
    return doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        ("CWE-639", "API1"),  # BOLA
        ("CWE-287", "API2"),  # Broken Authentication
        ("CWE-915", "API3"),  # Mass Assignment
        ("CWE-770", "API4"),  # Resource consumption
        ("CWE-862", "API5"),  # Missing Authorization (BFLA)
        ("CWE-918", "API7"),  # SSRF
    ],
)
def test_owasp_api_tag_on_rule_for_known_cwe(cwe: str, category: str) -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe=cwe)]))
    assert f"owasp-api:{category}" in tags
    assert "security" in tags  # existing tags preserved


def test_no_owasp_api_tag_for_unmapped_cwe() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe="CWE-99999")]))
    assert not any(t.startswith("owasp-api:") for t in tags)


def test_no_owasp_api_tag_for_no_cwe() -> None:
    tags = _rule_tags(build_sarif_report([_finding(cwe=None)]))
    assert not any(t.startswith("owasp-api:") for t in tags)


@pytest.mark.parametrize("raw", ["CWE-639", "639", "cwe 639", "CWE639"])
def test_cwe_normalisation_variants(raw: str) -> None:
    assert owasp_api_category_for_cwe(raw) == "API1"


def test_every_category_is_api1_to_api10() -> None:
    valid = {f"API{n}" for n in range(1, 11)}
    assert set(_CWE_TO_OWASP_API.values()) <= valid
