"""Integration tests for the Lemonade SDK security plugin.

Verifies that the plugin can be used to audit store event logs and produce
the correct set of security events for downstream persistence.
"""

from __future__ import annotations

from pathlib import Path

from lemonade_security.sdk_plugin import execute_security_tool

FIXTURES = Path(__file__).parent / "fixtures"


def test_audit_flow_produces_persistent_events() -> None:
    """Verifies that the lemonade_security_audit tool produces the three
    main types of security events: findings, policy checks, and audit summary.
    """
    # Use bad_events.jsonl which is guaranteed to have findings
    text, events = execute_security_tool(
        "lemonade_security_audit",
        {"events_path": str(FIXTURES / "bad_events.jsonl"), "store_id": "tie-dye-farms"},
    )

    # 1. Verify text summary contains the failure state
    assert "FAILED" in text
    assert "finding(s)" in text

    # 2. Verify we got the correct event types
    event_types = {e.type for e in events}
    assert "security.finding.created" in event_types
    assert "security.policy.checked" in event_types
    assert "security.audit.completed" in event_types

    # 3. Verify event structure
    for event in events:
        assert event.department == "security"
        assert event.source == "lemonade-security"
        assert event.store_id == "tie-dye-farms"
        assert event.schema_version == "store.event.v1"
        assert event.actor.id == "security.auditor"

    # 4. Verify specific finding details
    findings = [e for e in events if e.type == "security.finding.created"]
    finding_codes = {f.payload["code"] for f in findings}
    assert "cashier_payment_boundary" in finding_codes
    assert "customer_media_boundary" in finding_codes
    assert "wrong_store_id" in finding_codes


def test_drift_flow_returns_no_events_but_failed_text() -> None:
    """Drift tool currently returns text summary only (no events).
    This test pins that behavior for v0.1.
    """
    text, events = execute_security_tool(
        "lemonade_security_drift",
        {
            "events_path": str(FIXTURES / "drift_namespace_violation.jsonl"),
            "store_id": "tie-dye-farms",
        },
    )

    assert "FAILED" in text
    assert "namespace_violation" in text
    assert events == []
