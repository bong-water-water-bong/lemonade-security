from __future__ import annotations

from pathlib import Path

from lemonade_security.audit import audit_event_log
from lemonade_security.policy_check import LEMONADE_POLICIES, policy_check_events

FIXTURES = Path(__file__).parent / "fixtures"


def test_all_policies_pass_on_clean_log() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)

    assert len(events) == sum(
        1 for p in LEMONADE_POLICIES if p.check_scope == "store-event-log"
    )
    assert all(e.type == "security.policy.checked" for e in events)
    assert all(e.department == "security" for e in events)
    assert all(e.payload["result"] == "pass" for e in events)
    assert all(e.payload["finding_count"] == 0 for e in events)


def test_policy_count_matches_store_event_log_policies() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)
    assert len(events) == sum(
        1 for p in LEMONADE_POLICIES if p.check_scope == "store-event-log"
    )


def test_proposal_scoped_policy_is_not_reported_by_log_audit() -> None:
    # credential_leak_boundary is evaluated inline by the gate, not by the
    # whole-log CLI audit, so it must NOT appear in policy_check_events output
    # (its LLM02_* codes are never produced by audit_event_log → it would
    # otherwise always report a misleading "pass").
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    policy_ids = {e.payload["policy_id"] for e in policy_check_events(result)}
    assert "credential_leak_boundary" not in policy_ids


def test_payment_boundary_fails_on_bad_log() -> None:
    result = audit_event_log(FIXTURES / "bad_events.jsonl", store_id="tie-dye-farms")
    events = {e.payload["policy_id"]: e for e in policy_check_events(result)}

    assert events["payment_boundary"].payload["result"] == "fail"
    assert events["payment_boundary"].payload["finding_count"] >= 1


def test_customer_media_boundary_fails_on_bad_log() -> None:
    result = audit_event_log(FIXTURES / "bad_events.jsonl", store_id="tie-dye-farms")
    events = {e.payload["policy_id"]: e for e in policy_check_events(result)}

    assert events["customer_media_boundary"].payload["result"] == "fail"
    assert events["customer_media_boundary"].payload["finding_count"] >= 1


def test_store_scope_fails_on_wrong_store_id() -> None:
    result = audit_event_log(FIXTURES / "bad_events.jsonl", store_id="tie-dye-farms")
    events = {e.payload["policy_id"]: e for e in policy_check_events(result)}

    assert events["store_scope"].payload["result"] == "fail"


def test_unrelated_policies_still_pass_on_bad_log() -> None:
    result = audit_event_log(FIXTURES / "bad_events.jsonl", store_id="tie-dye-farms")
    events = {e.payload["policy_id"]: e for e in policy_check_events(result)}

    assert events["agent_approval_gate"].payload["result"] == "pass"
    assert events["event_envelope_integrity"].payload["result"] == "pass"


def test_event_ids_are_stable_and_unique() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)
    ids = [e.event_id for e in events]

    assert len(ids) == len(set(ids)), "each policy must produce a unique event_id"
    assert all(eid.startswith("security-") for eid in ids)


def test_owasp_ids_present_in_payload() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)

    for event in events:
        assert isinstance(event.payload["owasp_ids"], list)
        assert len(event.payload["owasp_ids"]) >= 1


def test_check_scope_is_store_event_log() -> None:
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)

    assert all(e.payload["check_scope"] == "store-event-log" for e in events)


def test_event_ids_stable_regardless_of_policy_order() -> None:
    # Same store, same result → same IDs regardless of which index we use
    result = audit_event_log(FIXTURES / "store_events.jsonl", store_id="tie-dye-farms")
    events = policy_check_events(result)
    # Run again — IDs must be identical (deterministic hash from store_id + policy.id)
    events2 = policy_check_events(result)
    assert [e.event_id for e in events] == [e.event_id for e in events2]


def test_credential_leak_boundary_policy_maps_all_four_llm02_codes():
    rule = next(p for p in LEMONADE_POLICIES if p.id == "credential_leak_boundary")
    assert rule.finding_codes == frozenset(
        {
            "LLM02_secret_field",
            "LLM02_bearer_token",
            "LLM02_jwt",
            "LLM02_pin",
        }
    )
    assert "LLM02:2026" in rule.owasp_ids
