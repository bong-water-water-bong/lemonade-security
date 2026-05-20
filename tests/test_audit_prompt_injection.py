from __future__ import annotations

from pathlib import Path

from lemonade_security.audit_prompt_injection import audit_prompt_injection

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(findings: tuple) -> set[str]:
    return {f.code for f in findings}


# ---- system-prompt break (LLM01_system_break) --------------------------


def test_system_break_flags_ignore_previous_instructions() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_system_break.jsonl",
        store_id="tie-dye-farms",
    )

    breaks = [f for f in result.findings if f.code == "LLM01_system_break"]
    assert len(breaks) >= 3  # three positive lines in the fixture
    assert all(f.severity == "high" for f in breaks)
    # event_ids must be populated
    ids = {f.event_id for f in breaks}
    assert {"evt-pi-0010", "evt-pi-0011", "evt-pi-0012"} <= ids
    # message must reference the JSON path of the offending value
    assert any("input" in f.message for f in breaks)


def test_system_break_negative_close_but_legitimate_phrase() -> None:
    # "ignore the bruised apples" must NOT match `ignore previous|above|prior`.
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM01_system_break" not in _codes(result.findings)


# ---- role-confusion (LLM01_role_confusion) -----------------------------


def test_role_confusion_flags_chat_template_markers_and_headers() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_role_confusion.jsonl",
        store_id="tie-dye-farms",
    )

    confusion = [f for f in result.findings if f.code == "LLM01_role_confusion"]
    # three lines: <|system|>, ### Instructions:, new rules:
    assert len(confusion) >= 3
    assert all(f.severity == "high" for f in confusion)


def test_role_confusion_negative_plain_attendant_phrase() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM01_role_confusion" not in _codes(result.findings)


# ---- exfiltration cue (LLM01_exfil_cue) --------------------------------


def test_exfil_cue_flags_reveal_send_and_urls() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_exfil_cue.jsonl",
        store_id="tie-dye-farms",
    )

    exfil = [f for f in result.findings if f.code == "LLM01_exfil_cue"]
    assert len(exfil) >= 3
    assert all(f.severity == "high" for f in exfil)


def test_exfil_cue_negative_on_clean_log() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM01_exfil_cue" not in _codes(result.findings)


# ---- encoded smuggling (LLM01_encoded_smuggling) -----------------------


def test_encoded_smuggling_flags_long_high_entropy_token() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_encoded.jsonl",
        store_id="tie-dye-farms",
    )

    encoded = [f for f in result.findings if f.code == "LLM01_encoded_smuggling"]
    assert len(encoded) >= 1
    assert encoded[0].severity == "medium"


def test_encoded_smuggling_negative_on_normal_english() -> None:
    # Short, low-entropy English tokens like "ignore the bruised apples"
    # must not fire the encoded-smuggling heuristic.
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM01_encoded_smuggling" not in _codes(result.findings)


# ---- nested payload traversal ------------------------------------------


def test_nested_input_payload_is_walked() -> None:
    # input.phrase should be reached and trigger system_break.
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_nested.jsonl",
        store_id="tie-dye-farms",
    )

    breaks = [f for f in result.findings if f.code == "LLM01_system_break"]
    assert len(breaks) == 1
    assert "input.phrase" in breaks[0].message


# ---- empty + non-proposal logs -----------------------------------------


def test_empty_log_emits_no_findings() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_empty.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.findings == ()
    assert result.checked_events == 0
    assert result.passed


def test_log_with_no_agent_proposal_events_emits_no_findings() -> None:
    # The cashier line carries the same injection text in its `note`
    # field — this auditor only inspects `agent.proposal` events, so
    # nothing must fire.
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_no_proposals.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.findings == ()
    # `checked_events` is the count of `agent.proposal` events scanned;
    # the cashier line in this fixture is ignored.
    assert result.checked_events == 0


# ---- truncation contract -----------------------------------------------


def test_long_matched_values_are_truncated_in_messages() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_long_value.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.findings, "expected at least one finding for the long-value fixture"
    for finding in result.findings:
        # Heuristic: messages must never echo a full long blob. Cap at a
        # generous 200 chars (path + category + truncated value).
        assert len(finding.message) <= 200, finding.message


# ---- extra_patterns hook -----------------------------------------------


def test_extra_patterns_hook_fires_finding() -> None:
    # The clean fixture's second line says "ignore the bruised apples";
    # supply a custom regex that should match it.
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
        extra_patterns=(r"\bbruised apples\b",),
    )

    extra = [f for f in result.findings if f.code == "LLM01_extra_pattern"]
    assert len(extra) == 1
    assert extra[0].severity == "high"
    assert extra[0].event_id == "evt-pi-0002"


def test_extra_patterns_default_empty_does_nothing() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM01_extra_pattern" not in _codes(result.findings)


# ---- result envelope ---------------------------------------------------


def test_result_carries_store_id_and_checked_event_count() -> None:
    result = audit_prompt_injection(
        FIXTURES / "proposals_prompt_injection_clean.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.store_id == "tie-dye-farms"
    assert result.checked_events == 2
    assert result.passed


def test_owasp_risk_mapping_present_for_new_codes() -> None:
    from lemonade_security.owasp import risk_ids_for_code

    assert "LLM01:2026" in risk_ids_for_code("LLM01_system_break")
    assert "LLM01:2026" in risk_ids_for_code("LLM01_role_confusion")
    assert "LLM01:2026" in risk_ids_for_code("LLM01_exfil_cue")
    assert "LLM01:2026" in risk_ids_for_code("LLM01_encoded_smuggling")
    assert "LLM01:2026" in risk_ids_for_code("LLM01_extra_pattern")
    # ASI06 — Memory and Context Poisoning — applies because injected
    # proposal payloads could land in persistent agent memory.
    assert "ASI06" in risk_ids_for_code("LLM01_system_break")
