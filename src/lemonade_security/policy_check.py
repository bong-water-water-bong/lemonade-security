"""Named policy checks that emit security.policy.checked events.

One event is emitted per registered policy, recording whether the event
log satisfies that policy. Findings from audit_event_log drive the
pass/fail verdict: a policy fails when any of its associated finding
codes appear in the result.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from lemonade_store.events import Actor, Event

from lemonade_security.audit import AuditResult


@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    owasp_ids: tuple[str, ...]
    finding_codes: frozenset[str]
    # Which scan surface produces this policy's finding codes.
    # ``store-event-log`` policies are evaluated by ``policy_check_events``
    # over an ``audit_event_log`` result; ``proposal-event`` policies are
    # evaluated inline per ``agent.proposal`` by ``gate.evaluate_proposal``
    # and must NOT be reported by the whole-log CLI audit (their codes are
    # never produced by ``audit_event_log``, so they would always "pass").
    check_scope: str = "store-event-log"


LEMONADE_POLICIES: tuple[PolicyRule, ...] = (
    PolicyRule(
        id="payment_boundary",
        description="Cashier events must not contain payment gateway terms.",
        owasp_ids=("LLM06:2026", "DSGAI01"),
        finding_codes=frozenset({"cashier_payment_boundary"}),
    ),
    PolicyRule(
        id="customer_media_boundary",
        description="No event may contain customer audio, images, or biometric keys.",
        owasp_ids=("DSGAI01", "DSGAI09", "LLM02:2026"),
        finding_codes=frozenset({"customer_media_boundary"}),
    ),
    PolicyRule(
        id="event_envelope_integrity",
        description="All events must parse as valid store.event.v1 envelopes.",
        owasp_ids=("DSGAI05", "ASI08"),
        finding_codes=frozenset({"invalid_json", "invalid_envelope"}),
    ),
    PolicyRule(
        id="store_scope",
        description="All events must carry the expected store_id.",
        owasp_ids=("DSGAI11", "DSGAI15"),
        finding_codes=frozenset({"wrong_store_id"}),
    ),
    PolicyRule(
        id="agent_approval_gate",
        description="Draft events must not be pre-approved; owner approval must follow as a separate event.",
        owasp_ids=("LLM06:2026", "ASI09"),
        finding_codes=frozenset({"draft_already_approved"}),
    ),
    PolicyRule(
        id="credential_leak_boundary",
        description=(
            "Agent proposals must not carry bearer tokens, JWTs, PINs, "
            "or secret-named fields."
        ),
        owasp_ids=("LLM02:2026", "ASI03"),
        finding_codes=frozenset(
            {
                "LLM02_secret_field",
                "LLM02_bearer_token",
                "LLM02_jwt",
                "LLM02_pin",
            }
        ),
        check_scope="proposal-event",
    ),
)


def policy_check_events(result: AuditResult) -> list[Event]:
    """Emit one security.policy.checked event per store-event-log policy.

    Only ``store-event-log`` scoped policies are emitted: their finding
    codes are produced by ``audit_event_log``, which feeds this function.
    ``proposal-event`` policies (e.g. ``credential_leak_boundary``) are
    evaluated inline by ``gate.evaluate_proposal`` and are skipped here so
    the CLI audit does not report a meaningless "pass" for codes the
    whole-log scan never generates.
    """
    return [
        _policy_event(result, policy)
        for policy in LEMONADE_POLICIES
        if policy.check_scope == "store-event-log"
    ]


def _policy_event(
    result: AuditResult,
    policy: PolicyRule,
) -> Event:
    active_codes = frozenset(finding.code for finding in result.findings)
    triggered = active_codes & policy.finding_codes
    triggered_count = sum(1 for f in result.findings if f.code in policy.finding_codes)
    return Event(
        schema_version="store.event.v1",
        event_id=_stable_event_id(result.store_id, "policy", policy.id),
        ts=_now_utc(),
        store_id=result.store_id,
        department="security",
        type="security.policy.checked",
        source="lemonade-security",
        actor=Actor(kind="agent_auto", id="security.auditor"),
        requires_approval=False,
        approved_by=None,
        payload=_payload(policy, "fail" if triggered else "pass", triggered_count),
    )


def _payload(policy: PolicyRule, result: str, finding_count: int) -> dict[str, Any]:
    return {
        "policy_id": policy.id,
        "description": policy.description,
        "result": result,
        "owasp_ids": list(policy.owasp_ids),
        "finding_count": finding_count,
        "check_scope": policy.check_scope,
    }


def _stable_event_id(store_id: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join((store_id, *parts)).encode()).hexdigest()[:16]
    return f"security-{digest}"


def _now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
