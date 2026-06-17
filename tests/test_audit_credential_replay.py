from __future__ import annotations

from pathlib import Path

from lemonade_security.audit_credential_replay import (
    audit_credential_replay,
    scan_proposal_event,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _codes(findings: tuple) -> set[str]:
    return {f.code for f in findings}


# ---- empty / irrelevant inputs ------------------------------------------


def test_empty_log_emits_no_findings(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    result = audit_credential_replay(empty, store_id="tie-dye-farms")

    assert result.findings == ()
    assert result.checked_events == 0
    assert result.passed


def test_log_without_agent_proposal_emits_no_findings() -> None:
    # Vanilla store_events.jsonl has cashier + accounting events only.
    result = audit_credential_replay(
        FIXTURES / "store_events.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.findings == ()
    assert result.checked_events > 0
    assert result.passed


def test_clean_proposals_do_not_fire() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_clean_credentials.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.findings == ()


# ---- bearer / OAuth tokens ----------------------------------------------


def test_bearer_token_in_header_fires_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_bearer_token.jsonl",
        store_id="tie-dye-farms",
    )

    bearer = [f for f in result.findings if f.code == "LLM02_bearer_token"]
    assert len(bearer) >= 1
    first = bearer[0]
    assert first.severity == "high"
    assert first.event_id == "evt-prop-1001"
    # Path into the payload should be reported.
    assert "headers.Authorization" in first.message
    # Secret must NOT appear verbatim in the message.
    assert "abcdEFGH1234567890ZYXWvuts" not in first.message
    assert "<redacted>" in first.message


def test_prefixed_token_in_freeform_text_fires_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_bearer_token.jsonl",
        store_id="tie-dye-farms",
    )

    # Well-known token prefixes (xoxb-, ghp_, sk_live_, AKIA, ...) must
    # trip the bearer-token finding even when embedded in free-form text.
    prefix_findings = [
        f
        for f in result.findings
        if f.event_id == "evt-prop-1002" and f.code == "LLM02_bearer_token"
    ]
    assert len(prefix_findings) == 1
    msg = prefix_findings[0].message
    assert "notes" in msg
    assert "NOTAREALSLACKTOKEN" not in msg


def test_bearer_token_allowlist_substring_suppresses_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_allowlisted_token.jsonl",
        store_id="tie-dye-farms",
        allow_substrings=frozenset({"DEMO-TOKEN-OK"}),
    )

    assert "LLM02_bearer_token" not in _codes(result.findings)
    assert result.passed


# ---- JWT-shaped strings -------------------------------------------------


def test_jwt_in_context_fires_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_jwt.jsonl",
        store_id="tie-dye-farms",
    )

    jwts = [f for f in result.findings if f.code == "LLM02_jwt"]
    assert len(jwts) == 1
    finding = jwts[0]
    assert finding.severity == "high"
    assert finding.event_id == "evt-prop-1101"
    assert "context.session_jwt" in finding.message
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in finding.message


def test_jwt_pattern_does_not_fire_on_dotted_identifier() -> None:
    # `lemonade@http://127.0.0.1:8000#qwen3:4b` would never look like a JWT
    # because JWT requires three base64url-safe dot-separated segments where
    # the first decodes to JSON with alg/typ. The clean fixture has dotted
    # IP addresses and similar — none should be flagged.
    result = audit_credential_replay(
        FIXTURES / "proposals_clean_credentials.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM02_jwt" not in _codes(result.findings)


# ---- PIN-shaped strings -------------------------------------------------


def test_pin_in_note_fires_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_pin.jsonl",
        store_id="tie-dye-farms",
    )

    pins = [f for f in result.findings if f.code == "LLM02_pin"]
    assert len(pins) == 1
    finding = pins[0]
    assert finding.severity == "high"
    assert finding.event_id == "evt-prop-1201"
    assert "note" in finding.message
    assert "4271" not in finding.message


# ---- secret-named fields ------------------------------------------------


def test_password_field_fires_finding() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_with_secret_field.jsonl",
        store_id="tie-dye-farms",
    )

    secret_findings = [
        f
        for f in result.findings
        if f.code == "LLM02_secret_field" and f.event_id == "evt-prop-1301"
    ]
    assert len(secret_findings) == 1
    finding = secret_findings[0]
    assert finding.severity == "high"
    assert "credentials.password" in finding.message
    assert "hunter2" not in finding.message


def test_empty_api_key_still_fires() -> None:
    # An empty `api_key` field is still leak-shaped — the field shouldn't
    # have existed in the input payload at all.
    result = audit_credential_replay(
        FIXTURES / "proposals_with_secret_field.jsonl",
        store_id="tie-dye-farms",
    )

    secret_findings = [
        f
        for f in result.findings
        if f.code == "LLM02_secret_field" and f.event_id == "evt-prop-1302"
    ]
    assert len(secret_findings) == 1
    assert "api_key" in secret_findings[0].message


# ---- delegation_id is NOT flagged as a 32-hex secret --------------------


def test_delegation_id_is_not_flagged_as_hex_secret() -> None:
    # The clean fixture carries `delegation_id` which is exactly 32 hex
    # chars. The auditor must treat the on-payload `delegation_id` value
    # as a known identifier, not a leaked secret.
    result = audit_credential_replay(
        FIXTURES / "proposals_clean_credentials.jsonl",
        store_id="tie-dye-farms",
    )

    assert "LLM02_credential_leak" not in _codes(result.findings)
    assert result.findings == ()


# ---- secret never echoed in message -------------------------------------


def test_messages_never_echo_the_literal_secret() -> None:
    # Cross-cutting safety check: no matter which pattern fires, the
    # raw secret string must not appear in the finding message.
    forbidden = [
        "abcdEFGH1234567890ZYXWvuts",
        "xoxb-0000-1111-NOTAREALSLACKTOKEN9999",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "hunter2",
        "4271",
    ]

    for fixture in (
        "proposals_with_bearer_token.jsonl",
        "proposals_with_jwt.jsonl",
        "proposals_with_pin.jsonl",
        "proposals_with_secret_field.jsonl",
    ):
        result = audit_credential_replay(
            FIXTURES / fixture,
            store_id="tie-dye-farms",
        )
        for finding in result.findings:
            for secret in forbidden:
                assert secret not in finding.message, (
                    f"finding {finding.code} from {fixture} leaks "
                    f"secret {secret!r} in message: {finding.message!r}"
                )


# ---- OWASP risk mapping -------------------------------------------------


def test_owasp_risk_mapping_present_for_new_codes() -> None:
    from lemonade_security.owasp import risk_ids_for_code

    for code in (
        "LLM02_bearer_token",
        "LLM02_jwt",
        "LLM02_pin",
        "LLM02_secret_field",
    ):
        risks = risk_ids_for_code(code)
        assert "LLM02:2026" in risks, f"{code} should map to LLM02:2026"
        assert "ASI03" in risks, f"{code} should map to ASI03"


# ---- result envelope ----------------------------------------------------


def test_result_carries_store_id_and_checked_event_count() -> None:
    result = audit_credential_replay(
        FIXTURES / "proposals_clean_credentials.jsonl",
        store_id="tie-dye-farms",
    )

    assert result.store_id == "tie-dye-farms"
    assert result.checked_events == 2
    assert result.passed


# ---- scan_proposal_event unit tests -------------------------------------


def test_scan_proposal_event_flags_bearer_token_in_input():
    event = {
        "type": "agent.proposal",
        "payload": {
            "agent": "lemonade",
            "kind": "normalize",
            "input": "please authorize with Bearer abcdef0123456789ABCDEF",
            "output": "2 lemonade",
            "confidence": 0.9,
            "decision": "accepted",
        },
    }
    findings = scan_proposal_event(event)
    assert [f.code for f in findings] == ["LLM02_bearer_token"]


def test_scan_proposal_event_clean_proposal_has_no_findings():
    event = {
        "type": "agent.proposal",
        "payload": {
            "agent": "lemonade",
            "kind": "normalize",
            "input": "2 lemonades",
            "output": "2 lemonade",
            "confidence": 0.9,
            "decision": "accepted",
        },
    }
    assert scan_proposal_event(event) == []


def test_scan_proposal_event_ignores_non_proposal_events():
    assert scan_proposal_event({"type": "cart.add", "payload": {"token": "x"}}) == []


def test_scan_proposal_event_ignores_non_dict_payload():
    assert scan_proposal_event({"type": "agent.proposal", "payload": "nope"}) == []
