from __future__ import annotations

from pathlib import Path

from lemonade_security.audit_agent_proposals import audit_agent_proposals

FIXTURES = Path(__file__).parent / "fixtures"

KNOWN_AGENT_IDS = frozenset({"lemonade@http://127.0.0.1:8000#qwen3:4b"})


def _codes(findings: tuple) -> set[str]:
    return {f.code for f in findings}


# ---- rogue agent_id (ASI03) ---------------------------------------------


def test_rogue_agent_id_flags_unknown_agent() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_rogue.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    rogue = [f for f in result.findings if f.code == "ASI03_rogue_agent_id"]
    assert len(rogue) == 1
    assert rogue[0].severity == "high"
    assert "mystery@" in rogue[0].message
    assert rogue[0].event_id == "evt-prop-0011"


def test_rogue_agent_id_clean_when_all_known() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_clean.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI03_rogue_agent_id" not in _codes(result.findings)


def test_rogue_agent_id_legacy_events_do_not_fire() -> None:
    # Legacy events lack agent_id entirely; rogue check must not fire.
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_legacy.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI03_rogue_agent_id" not in _codes(result.findings)


def test_rogue_agent_id_empty_allowlist_flags_everything() -> None:
    # Default-empty allowlist treats every present agent_id as rogue.
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_clean.jsonl",
        store_id="tie-dye-farms",
    )

    rogue = [f for f in result.findings if f.code == "ASI03_rogue_agent_id"]
    assert len(rogue) == 1


# ---- stripped agent_id (ASI03) ------------------------------------------


def test_stripped_agent_id_flagged_when_later_proposal_omits_it() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_stripped.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    stripped = [f for f in result.findings if f.code == "ASI03_stripped_agent_id"]
    assert len(stripped) == 1
    assert stripped[0].severity == "medium"
    assert stripped[0].event_id == "evt-prop-0021"


def test_stripped_agent_id_clean_when_all_proposals_carry_it() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_clean.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI03_stripped_agent_id" not in _codes(result.findings)


def test_stripped_agent_id_silent_on_legacy_log() -> None:
    # No proposal has agent_id anywhere; stripping check must not fire.
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_legacy.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI03_stripped_agent_id" not in _codes(result.findings)


# ---- orphan delegation_id (ASI02) ---------------------------------------


def test_orphan_delegation_id_flagged() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_orphan.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    orphans = [f for f in result.findings if f.code == "ASI02_orphan_delegation"]
    assert len(orphans) == 1
    assert orphans[0].severity == "high"
    assert orphans[0].event_id == "evt-line-0041"
    assert "deadbeef" in orphans[0].message


def test_orphan_delegation_id_clean_when_matched() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_clean.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI02_orphan_delegation" not in _codes(result.findings)


def test_orphan_delegation_id_silent_on_legacy_log() -> None:
    # Legacy log has no delegation_id fields at all.
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_legacy.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert "ASI02_orphan_delegation" not in _codes(result.findings)


# ---- result envelope ----------------------------------------------------


def test_result_carries_store_id_and_checked_event_count() -> None:
    result = audit_agent_proposals(
        FIXTURES / "agent_proposals_clean.jsonl",
        store_id="tie-dye-farms",
        known_agent_ids=KNOWN_AGENT_IDS,
    )

    assert result.store_id == "tie-dye-farms"
    assert result.checked_events == 2
    assert result.passed


def test_owasp_risk_mapping_present_for_new_codes() -> None:
    from lemonade_security.owasp import risk_ids_for_code

    assert "ASI03" in risk_ids_for_code("ASI03_rogue_agent_id")
    assert "ASI03" in risk_ids_for_code("ASI03_stripped_agent_id")
    assert "ASI02" in risk_ids_for_code("ASI02_orphan_delegation")
