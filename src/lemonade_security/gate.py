"""Inline credential gate.

Runs the credential-replay scanner against a single in-flight
``agent.proposal`` event and returns an allow/deny :class:`Decision`
*before* the proposal's action executes. This is the preventive
counterpart to the post-hoc, whole-log auditors: same scan logic
(`scan_proposal_event`) and same policy table (`LEMONADE_POLICIES`),
evaluated on one event with a yes/no verdict instead of emitted events.

The function is pure: it performs no I/O and emits no events. Callers
decide what to do on a deny (refuse the action, emit
``security.finding.created``, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lemonade_security.audit import AuditFinding
from lemonade_security.audit_credential_replay import scan_proposal_event
from lemonade_security.policy_check import LEMONADE_POLICIES, PolicyRule


@dataclass(frozen=True)
class Decision:
    """Verdict for one proposal.

    ``allowed`` is True when no policy fired. ``triggered`` lists the
    ``PolicyRule`` ids that fired. ``findings`` are the raw scanner
    findings (useful for logging / emitting a finding event).
    """

    allowed: bool
    triggered: tuple[str, ...]
    findings: tuple[AuditFinding, ...]


def evaluate_proposal(
    event: dict[str, Any],
    *,
    allow_substrings: frozenset[str] = frozenset(),
    policies: tuple[PolicyRule, ...] = LEMONADE_POLICIES,
) -> Decision:
    """Evaluate a single decoded ``agent.proposal`` event.

    Non-proposal events and non-dict payloads produce no findings and
    are allowed (this gate only judges credential leakage in proposals).
    """
    findings = scan_proposal_event(event, allow_substrings=allow_substrings)
    active = frozenset(f.code for f in findings)
    triggered = tuple(p.id for p in policies if active & p.finding_codes)
    return Decision(
        allowed=not triggered,
        triggered=triggered,
        findings=tuple(findings),
    )
