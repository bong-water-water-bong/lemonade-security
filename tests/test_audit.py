from __future__ import annotations

from pathlib import Path

from lemonade_security.audit import audit_event_log, finding_events, summary_event

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_event_log_passes() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")

    assert result.checked_events == 2
    assert result.findings == ()
    assert result.passed

    event = summary_event(result)
    assert event.department == "security"
    assert event.type == "security.audit.completed"
    assert event.payload["passed"] is True


def test_bad_event_log_emits_findings() -> None:
    result = audit_event_log(FIXTURES / "bad_events.jsonl", store_id="tie-dye-farms")

    codes = {finding.code for finding in result.findings}
    assert "cashier_payment_boundary" in codes
    assert "customer_media_boundary" in codes
    assert "wrong_store_id" in codes

    events = finding_events(result)
    assert len(events) == len(result.findings)
    assert all(event.type == "security.finding.created" for event in events)
    assert any("DSGAI09" in event.payload["owasp_risks"] for event in events)
