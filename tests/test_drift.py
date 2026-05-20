"""Tests for the permission-drift scanner (lemonade_security.drift)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from lemonade_security.drift import DriftFinding, DriftResult, scan_permission_drift

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Basic structural tests                                                        #
# --------------------------------------------------------------------------- #


def test_drift_result_passed_when_no_findings() -> None:
    result = DriftResult(store_id="tie-dye-farms", checked_events=2, findings=())
    assert result.passed is True


def test_drift_result_failed_when_findings_present() -> None:
    finding = DriftFinding(
        code="namespace_violation",
        severity="high",
        message="test",
        line_number=1,
        event_id="evt-001",
    )
    result = DriftResult(store_id="tie-dye-farms", checked_events=1, findings=(finding,))
    assert result.passed is False


# --------------------------------------------------------------------------- #
# Clean log                                                                     #
# --------------------------------------------------------------------------- #


def test_clean_log_passes() -> None:
    result = scan_permission_drift(FIXTURES / "drift_clean.jsonl", store_id="tie-dye-farms")

    assert result.passed is True
    assert result.checked_events == 2
    assert result.findings == ()
    assert result.store_id == "tie-dye-farms"


# --------------------------------------------------------------------------- #
# Namespace violation                                                           #
# --------------------------------------------------------------------------- #


def test_namespace_violation_detected() -> None:
    """Cashier emitting store.* (meta namespace, envelope-valid but outside
    cashier's writes contract) must produce a namespace_violation finding."""
    result = scan_permission_drift(
        FIXTURES / "drift_namespace_violation.jsonl", store_id="tie-dye-farms"
    )

    assert not result.passed
    codes = {f.code for f in result.findings}
    assert "namespace_violation" in codes


def test_namespace_violation_severity_is_high() -> None:
    result = scan_permission_drift(
        FIXTURES / "drift_namespace_violation.jsonl", store_id="tie-dye-farms"
    )

    violations = [f for f in result.findings if f.code == "namespace_violation"]
    assert violations, "expected at least one namespace_violation finding"
    assert all(f.severity == "high" for f in violations)


def test_namespace_violation_count_matches_log() -> None:
    """One event in the fixture → exactly one finding."""
    result = scan_permission_drift(
        FIXTURES / "drift_namespace_violation.jsonl", store_id="tie-dye-farms"
    )

    assert len(result.findings) == 1


# --------------------------------------------------------------------------- #
# Approval-gate drift                                                           #
# --------------------------------------------------------------------------- #


def test_approval_gate_drift_detected() -> None:
    """Accounting emitting accounting.export with requires_approval=False
    violates the approval gate contract."""
    result = scan_permission_drift(
        FIXTURES / "drift_approval_gate.jsonl", store_id="tie-dye-farms"
    )

    assert not result.passed
    codes = {f.code for f in result.findings}
    assert "approval_gate_drift" in codes


def test_approval_gate_drift_severity_is_medium() -> None:
    result = scan_permission_drift(
        FIXTURES / "drift_approval_gate.jsonl", store_id="tie-dye-farms"
    )

    gate_findings = [f for f in result.findings if f.code == "approval_gate_drift"]
    assert gate_findings, "expected at least one approval_gate_drift finding"
    assert all(f.severity == "medium" for f in gate_findings)


def test_approval_gate_drift_count_matches_log() -> None:
    """One event in the fixture → exactly one finding."""
    result = scan_permission_drift(
        FIXTURES / "drift_approval_gate.jsonl", store_id="tie-dye-farms"
    )

    assert len(result.findings) == 1


def test_approval_gate_not_triggered_when_approval_set() -> None:
    """An event with requires_approval=True for a gate-required action is fine."""
    # accounting.export with requires_approval=True should not produce a finding.
    result = scan_permission_drift(
        FIXTURES / "drift_with_approval.jsonl", store_id="tie-dye-farms"
    )
    assert result.passed is True
    codes = {f.code for f in result.findings}
    assert "approval_gate_drift" not in codes


# --------------------------------------------------------------------------- #
# Unknown department                                                            #
# --------------------------------------------------------------------------- #


def test_unknown_department_detected() -> None:
    """An event whose department is not present in the registry must produce
    an unknown_department finding.

    The envelope validator rejects departments outside KNOWN_DEPARTMENTS, so
    to exercise the drift scanner's own registry check we temporarily shrink
    the registry by removing 'inventory', then scan a log that contains an
    inventory event that is otherwise envelope-valid.
    """
    from lemonade_store.departments import registry as real_registry

    # Build a registry dict that omits 'inventory'.
    reduced = {k: v for k, v in real_registry().items() if k != "inventory"}

    with patch("lemonade_security.drift.registry", return_value=reduced):
        # Use the clean log — it doesn't contain inventory events, so use
        # a temporary inline fixture instead.
        import json
        import tempfile

        event_line = json.dumps(
            {
                "schema_version": "store.event.v1",
                "event_id": "drift-unk-001",
                "ts": "2026-05-19T18:30:00Z",
                "store_id": "tie-dye-farms",
                "department": "inventory",
                "type": "inventory.created",
                "source": "lemonade-inventory",
                "actor": {"kind": "agent_auto", "id": "inventory.onboarder"},
                "requires_approval": False,
                "approved_by": None,
                "payload": {"sku": "SKU-001"},
            }
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(event_line + "\n")
            tmp_path = tmp.name

        result = scan_permission_drift(tmp_path, store_id="tie-dye-farms")

    codes = {f.code for f in result.findings}
    assert "unknown_department" in codes


def test_unknown_department_severity_is_medium() -> None:
    from lemonade_store.departments import registry as real_registry

    reduced = {k: v for k, v in real_registry().items() if k != "inventory"}

    with patch("lemonade_security.drift.registry", return_value=reduced):
        import json
        import tempfile

        event_line = json.dumps(
            {
                "schema_version": "store.event.v1",
                "event_id": "drift-unk-002",
                "ts": "2026-05-19T18:30:00Z",
                "store_id": "tie-dye-farms",
                "department": "inventory",
                "type": "inventory.created",
                "source": "lemonade-inventory",
                "actor": {"kind": "agent_auto", "id": "inventory.onboarder"},
                "requires_approval": False,
                "approved_by": None,
                "payload": {"sku": "SKU-002"},
            }
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(event_line + "\n")
            tmp_path = tmp.name

        result = scan_permission_drift(tmp_path, store_id="tie-dye-farms")

    unk_findings = [f for f in result.findings if f.code == "unknown_department"]
    assert unk_findings, "expected unknown_department finding"
    assert all(f.severity == "medium" for f in unk_findings)


def test_unknown_department_finding_count_matches_violations() -> None:
    """One unknown-department event → one finding."""
    from lemonade_store.departments import registry as real_registry

    reduced = {k: v for k, v in real_registry().items() if k != "inventory"}

    with patch("lemonade_security.drift.registry", return_value=reduced):
        import json
        import tempfile

        event_line = json.dumps(
            {
                "schema_version": "store.event.v1",
                "event_id": "drift-unk-003",
                "ts": "2026-05-19T18:30:00Z",
                "store_id": "tie-dye-farms",
                "department": "inventory",
                "type": "inventory.created",
                "source": "lemonade-inventory",
                "actor": {"kind": "agent_auto", "id": "inventory.onboarder"},
                "requires_approval": False,
                "approved_by": None,
                "payload": {"sku": "SKU-003"},
            }
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(event_line + "\n")
            tmp_path = tmp.name

        result = scan_permission_drift(tmp_path, store_id="tie-dye-farms")

    assert len(result.findings) == 1


# --------------------------------------------------------------------------- #
# Invalid envelope                                                              #
# --------------------------------------------------------------------------- #


def test_invalid_envelope_produces_finding() -> None:
    """A JSON line that is syntactically valid but fails the envelope contract
    must produce an invalid_envelope finding and not increment checked_events."""
    import json
    import tempfile

    # Missing required field 'type'
    bad_line = json.dumps(
        {
            "schema_version": "store.event.v1",
            "event_id": "bad-001",
            "ts": "2026-05-19T18:30:00Z",
            "store_id": "tie-dye-farms",
            "department": "cashier",
            "source": "lemonade-cashier",
            "actor": {"kind": "attendant", "id": "alice"},
        }
    )
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(bad_line + "\n")
        tmp_path = tmp.name

    result = scan_permission_drift(tmp_path, store_id="tie-dye-farms")

    assert result.checked_events == 0
    codes = {f.code for f in result.findings}
    assert "invalid_envelope" in codes
    envelope_findings = [f for f in result.findings if f.code == "invalid_envelope"]
    assert all(f.severity == "high" for f in envelope_findings)


def test_malformed_json_produces_invalid_envelope_finding() -> None:
    import tempfile, os
    bad_line = '{"schema_version":"store.event.v1",'  # truncated — not valid JSON
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(bad_line + "\n")
        tmp_path = tmp.name
    try:
        result = scan_permission_drift(tmp_path, store_id="tie-dye-farms")
        assert result.checked_events == 0
        invalids = [f for f in result.findings if f.code == "invalid_envelope"]
        assert invalids, "expected an invalid_envelope finding for malformed JSON"
        assert all(f.severity == "high" for f in invalids)
    finally:
        os.unlink(tmp_path)


# --------------------------------------------------------------------------- #
# Finding count accuracy                                                        #
# --------------------------------------------------------------------------- #


def test_finding_count_matches_violations_in_log() -> None:
    """Each fixture with exactly one bad event must produce exactly one finding."""
    for fixture in ("drift_namespace_violation.jsonl", "drift_approval_gate.jsonl"):
        result = scan_permission_drift(FIXTURES / fixture, store_id="tie-dye-farms")
        assert len(result.findings) == 1, (
            f"{fixture}: expected 1 finding, got {len(result.findings)}"
        )
