"""Agent-proposal correlation auditor.

This auditor scans a JSONL store event log for `agent.proposal` events
and the cashier line events that follow them, looking for three trust
patterns from IBM's "Agentic Trust" talk (lUQ2NKkCW_Q):

* Rogue agent identity (`ASI03_rogue_agent_id`): a proposal carrying an
  `agent_id` that is not in the caller-supplied allowlist.
* Mid-stream stripping (`ASI03_stripped_agent_id`): a log that has at
  least one proposal with `agent_id` AND a later proposal without it.
  Logs that never carry `agent_id` (pure legacy) are silent on this.
* Orphan delegation (`ASI02_orphan_delegation`): a cashier line event
  whose payload carries a `delegation_id` that no earlier proposal in
  the same log minted.

## Parsing strategy

The shared `store.event.v1` envelope validator
(`lemonade_store.events.load_event`) rejects events whose `type` is
outside its department's namespace, including `agent.proposal` (the
`agent.*` namespace is not registered with any department in v0.1).
Because envelope-validated parsing would silently drop the very events
this auditor must read, we fall back to `json.loads` per-line and treat
each row as a dict. The trade-off is documented in this module's
docstring so the choice is visible at review time — when the v0.1
envelope grows native support for proposals we should switch back to
`load_event` here.

Findings reuse the `AuditFinding` / `AuditResult` types from
`lemonade_security.audit` so downstream consumers (`finding_events`,
`summary_event`) work without changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lemonade_security.audit import AuditFinding, AuditResult

_PROPOSAL_TYPE = "agent.proposal"


def audit_agent_proposals(
    path: str | Path,
    *,
    store_id: str,
    known_agent_ids: frozenset[str] = frozenset(),
) -> AuditResult:
    """Audit a JSONL event log for agent-identity / delegation drift.

    Parameters
    ----------
    path:
        Path to a `store_events.jsonl` log.
    store_id:
        Expected `store_id` — recorded on the returned `AuditResult`
        for traceability; envelope-level store mismatch is the job of
        `audit_event_log`, not this auditor.
    known_agent_ids:
        Allowlist of stable `agent_id` strings
        (`"<agent>@<endpoint>#<model>"`). Any proposal whose `agent_id`
        is not in this set fires `ASI03_rogue_agent_id`. Default empty.
    """
    findings: list[AuditFinding] = []
    checked_events = 0
    known_delegations: set[str] = set()
    proposal_lines_with_agent_id: list[int] = []
    saw_proposal_without_agent_id_after: list[tuple[int, str | None]] = []

    rows: list[tuple[int, dict[str, Any]]] = []

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                # `audit_event_log` is responsible for envelope-level
                # parse failures; we just skip unreadable lines here so
                # this auditor stays focused on its correlation job.
                continue
            if not isinstance(raw, dict):
                continue
            rows.append((line_number, raw))
            checked_events += 1

    # First pass: walk proposals, build the delegation_id set, and
    # detect rogue + stripping patterns.
    for line_number, raw in rows:
        if raw.get("type") != _PROPOSAL_TYPE:
            continue
        payload = raw.get("payload") or {}
        if not isinstance(payload, dict):
            payload = {}

        delegation_id = payload.get("delegation_id")
        if isinstance(delegation_id, str):
            known_delegations.add(delegation_id)

        agent_id = payload.get("agent_id")
        event_id = _event_id_of(raw)

        if isinstance(agent_id, str):
            proposal_lines_with_agent_id.append(line_number)
            if agent_id not in known_agent_ids:
                findings.append(
                    AuditFinding(
                        code="ASI03_rogue_agent_id",
                        severity="high",
                        message=(
                            f"agent.proposal carries agent_id {agent_id!r} "
                            "which is not in the known_agent_ids allowlist"
                        ),
                        line_number=line_number,
                        event_id=event_id,
                    )
                )
        else:
            # Track proposals missing agent_id; we'll only fire the
            # stripping finding if at least one earlier proposal carried
            # one (i.e. mid-stream removal, not pure legacy).
            saw_proposal_without_agent_id_after.append((line_number, event_id))

    # Stripping detection: any proposal-without-agent_id that comes
    # *after* the first proposal-with-agent_id in line order.
    first_with = min(proposal_lines_with_agent_id, default=None)
    if first_with is not None:
        for line_number, event_id in saw_proposal_without_agent_id_after:
            if line_number > first_with:
                findings.append(
                    AuditFinding(
                        code="ASI03_stripped_agent_id",
                        severity="medium",
                        message=(
                            "agent.proposal is missing agent_id after an "
                            "earlier proposal carried one (mid-stream "
                            "stripping)"
                        ),
                        line_number=line_number,
                        event_id=event_id,
                    )
                )

    # Second pass: scan non-proposal events for delegation_id usage.
    for line_number, raw in rows:
        if raw.get("type") == _PROPOSAL_TYPE:
            continue
        payload = raw.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        delegation_id = payload.get("delegation_id")
        if not isinstance(delegation_id, str):
            continue
        if delegation_id not in known_delegations:
            findings.append(
                AuditFinding(
                    code="ASI02_orphan_delegation",
                    severity="high",
                    message=(
                        f"event carries delegation_id {delegation_id!r} "
                        "but no earlier agent.proposal minted it"
                    ),
                    line_number=line_number,
                    event_id=_event_id_of(raw),
                )
            )

    return AuditResult(
        store_id=store_id,
        checked_events=checked_events,
        findings=tuple(findings),
    )


def _event_id_of(raw: dict[str, Any]) -> str | None:
    value = raw.get("event_id")
    if isinstance(value, str):
        return value
    return None
