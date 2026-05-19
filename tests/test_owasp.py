from __future__ import annotations

from lemonade_security.owasp import OWASP_RISK_MAPPINGS, risk_ids_for_code


def test_policy_catalog_contains_key_owasp_sources() -> None:
    sources = {risk.source for risk in OWASP_RISK_MAPPINGS}

    assert "GenAI-LLM-Top10/2026" in sources
    assert "GenAI-Agent-Security-Initiative" in sources
    assert "GenAI-Data-Security-Initiative" in sources


def test_finding_codes_map_to_owasp_risks() -> None:
    assert "LLM06:2026" in risk_ids_for_code("cashier_payment_boundary")
    assert "DSGAI09" in risk_ids_for_code("customer_media_boundary")
