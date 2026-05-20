"""IAM-for-AI capability maturity scorer.

This module rates a Lemonade Store event log against the four-step
identity-and-access-management maturity model presented in IBM
Technology's *"IAM for AI: 4 Steps to Secure and Futureproof Agentic
Systems"* (video id ``e8ela6puxig``). The model itself was inspired by
the 1986 DoD Capability Maturity Model and steps from "no controls" to
"adaptive, continuously authenticated agents".

The four levels recognised here are:

1. ``ad-hoc``      — no agent identity controls in the log.
2. ``foundation``  — every agent action carries a non-human ``agent_id``
   and lives in an audit log we can read after the fact.
3. ``enhanced``    — additionally, every agent decision is wrapped in an
   ephemeral, per-task ``delegation_id`` that ties the agent's proposal
   to the consequence event (cart add / cart remove).
4. ``adaptive``    — additionally, at least one
   ``security.revocation.created`` event exists in the log, evidencing
   real-time revocation.

The scorer is intentionally **conservative**: it claims a level only
when the evidence in the log proves the level's condition, and degrades
to the strongest level it can prove. A single missing ``agent_id``, a
single orphan model-mediated cart event, or a missing revocation event
is enough to keep the log at the level below.

This module reads logs written by other departments without ever
mutating them, in keeping with ``AGENTS.md`` rule 1 ("Read other
departments; never rewrite their logs"). It maps directly onto the
``ASI03 — Identity and Privilege Abuse`` risk in the local OWASP
GenAI-Agent-Security-Initiative fork at
``/home/bcloud/genai-security-project-forks/GenAI-Agent-Security-Initiative/agentic-top-10/``;
the IBM model is the operational maturity curve that ASI03 controls
move you along.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lemonade_store.events import EventValidationError, load_event

PROPOSAL_TYPE = "agent.proposal"

# Cart event types whose payloads can be model-mediated. We treat any
# ``cart.add`` or ``cart.remove_*`` event as a possible consequence of
# an agent proposal. The set is open (``startswith``) on the remove
# side because the cashier records ``cart.remove_one`` /
# ``cart.remove_all`` / ``cart.remove_line`` variants and the IAM model
# does not distinguish them.
_CART_ADD = "cart.add"
_CART_REMOVE_PREFIX = "cart.remove"

REVOCATION_TYPE = "security.revocation.created"

LEVEL_NAMES: tuple[str, ...] = ("ad-hoc", "foundation", "enhanced", "adaptive")

# Exact phrasings of the "what's missing to reach the next level"
# strings. Tests pin these so they cannot silently drift; keep them
# tight and human-readable.
NEXT_STEP_TO_FOUNDATION = (
    "assign a non-human agent_id to every agent.proposal event "
    "(Foundation: non-human identities + basic delegation + audit log)."
)
NEXT_STEP_TO_ENHANCED = (
    "mint a per-task delegation_id on every agent.proposal and propagate it "
    "to the matching cart.add/cart.remove_* event "
    "(Enhanced: ephemeral, transaction-scoped credentials)."
)
NEXT_STEP_TO_ADAPTIVE = (
    "emit security.revocation.created when anomalies are detected "
    "(Adaptive: real-time revocation)."
)
NEXT_STEP_AT_TOP = "no further IAM maturity step is defined in the IBM 4-step model."


@dataclass(frozen=True)
class MaturityScore:
    """The highest IAM maturity level the writer of a log can prove."""

    level: int  # 1..4
    level_name: str  # "ad-hoc" | "foundation" | "enhanced" | "adaptive"
    evidence: tuple[str, ...]  # one short line per condition met
    next_step: str  # one sentence on the next missing condition


def score_iam_maturity(path: str | Path, *, store_id: str) -> MaturityScore:
    """Score a Lemonade Store JSONL event log against the IBM 4-step model.

    The scorer reads every line, tries ``load_event`` first, then falls
    back to ``json.loads`` for events whose envelope does not validate
    (``agent.proposal`` and ``cart.*`` are written by the cashier under
    its own namespace and do not satisfy the store-wide
    ``department-namespaces-its-own-events`` rule). Lines that are not
    valid JSON at all are silently skipped — the audit log is the
    source of truth, and a corrupted line cannot prove maturity.
    """
    proposals: list[_RawEvent] = []
    cart_events: list[_RawEvent] = []
    revocations: list[_RawEvent] = []

    for raw in _iter_raw_events(path, expected_store_id=store_id):
        event_type = raw.type
        if event_type == PROPOSAL_TYPE:
            proposals.append(raw)
        elif event_type == _CART_ADD or event_type.startswith(_CART_REMOVE_PREFIX):
            cart_events.append(raw)
        elif event_type == REVOCATION_TYPE:
            revocations.append(raw)

    foundation_ok = _check_foundation(proposals)
    enhanced_ok = foundation_ok and _check_enhanced(proposals, cart_events)
    adaptive_ok = enhanced_ok and _check_adaptive(revocations)

    evidence: list[str] = []
    if foundation_ok:
        evidence.append(
            f"Foundation: {len(proposals)} agent.proposal event(s) each carry an agent_id."
        )
    if enhanced_ok:
        evidence.append(
            "Enhanced: every agent.proposal and every model_proposed cart event "
            "shares a per-task delegation_id."
        )
    if adaptive_ok:
        evidence.append(
            f"Adaptive: {len(revocations)} security.revocation.created event(s) present."
        )

    if adaptive_ok:
        level = 4
        next_step = NEXT_STEP_AT_TOP
    elif enhanced_ok:
        level = 3
        next_step = NEXT_STEP_TO_ADAPTIVE
    elif foundation_ok:
        level = 2
        next_step = NEXT_STEP_TO_ENHANCED
    else:
        level = 1
        next_step = NEXT_STEP_TO_FOUNDATION

    return MaturityScore(
        level=level,
        level_name=LEVEL_NAMES[level - 1],
        evidence=tuple(evidence),
        next_step=next_step,
    )


# ---------------------------------------------------------------------------
# Internal: raw event walker. Mirrors the audit.py pattern (envelope
# first, JSON fallback), but never mutates the log and never raises on
# malformed lines.


@dataclass(frozen=True)
class _RawEvent:
    type: str
    payload: Mapping[str, Any]


def _iter_raw_events(path: str | Path, *, expected_store_id: str) -> Iterator[_RawEvent]:
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue

            # Scope to the expected store. Foreign-store events do not
            # prove anything about *this* store's IAM maturity.
            store_id = raw.get("store_id")
            if isinstance(store_id, str) and store_id != expected_store_id:
                continue

            event_type = raw.get("type")
            if not isinstance(event_type, str):
                continue

            # Try the envelope path first to keep the strict-envelope
            # contract honest; fall back to the loose JSON shape for
            # cross-namespace events such as ``agent.proposal`` and
            # ``cart.*`` that the cashier writes under its own log.
            payload: Mapping[str, Any]
            try:
                event = load_event(raw)
                payload = event.payload
            except EventValidationError:
                raw_payload = raw.get("payload", {})
                payload = raw_payload if isinstance(raw_payload, Mapping) else {}

            yield _RawEvent(type=event_type, payload=payload)


# ---------------------------------------------------------------------------
# Internal: per-level evidence checks. Each returns True only when the
# level's condition is unambiguously satisfied by the events seen so
# far.


def _check_foundation(proposals: list[_RawEvent]) -> bool:
    if not proposals:
        return False
    return all(_has_agent_id(proposal.payload) for proposal in proposals)


def _check_enhanced(proposals: list[_RawEvent], cart_events: list[_RawEvent]) -> bool:
    if not proposals:
        return False

    proposal_ids: list[str] = []
    for proposal in proposals:
        delegation_id = _delegation_id(proposal.payload)
        if delegation_id is None:
            return False
        proposal_ids.append(delegation_id)

    # No duplicate delegation ids across distinct decisions. The IBM
    # model calls these "ephemeral, per-task" credentials, so reusing
    # one across two agent.proposal events would be evidence against
    # the level — not for it.
    if len(set(proposal_ids)) != len(proposal_ids):
        return False

    proposal_id_set = set(proposal_ids)

    # Every model-mediated cart event must point at one of those
    # delegation ids. A model_proposed cart event with no delegation,
    # or with a delegation id that does not match any proposal, is an
    # orphan and breaks the one-to-one chain.
    for cart in cart_events:
        if not _is_model_mediated(cart.payload):
            continue
        delegation_id = _delegation_id(cart.payload)
        if delegation_id is None:
            return False
        if delegation_id not in proposal_id_set:
            return False

    return True


def _check_adaptive(revocations: list[_RawEvent]) -> bool:
    # The rubric is intentionally simple: even one
    # ``security.revocation.created`` event is sufficient evidence of
    # real-time revocation capability.
    return bool(revocations)


def _has_agent_id(payload: Mapping[str, Any]) -> bool:
    agent_id = payload.get("agent_id")
    return isinstance(agent_id, str) and bool(agent_id)


def _delegation_id(payload: Mapping[str, Any]) -> str | None:
    delegation_id = payload.get("delegation_id")
    if not isinstance(delegation_id, str):
        return None
    # 32-char hex UUID, lower- or uppercase. We accept hex digits
    # only so a free-form string ("scope=task") cannot accidentally
    # promote the log to Enhanced.
    if len(delegation_id) != 32:
        return None
    try:
        int(delegation_id, 16)
    except ValueError:
        return None
    return delegation_id


def _is_model_mediated(payload: Mapping[str, Any]) -> bool:
    # A cart event counts as model-mediated when it either explicitly
    # marks its source as ``model_proposed`` or carries a
    # ``delegation_id``. Either signal is enough to require the
    # one-to-one chain for Enhanced.
    if payload.get("source") == "model_proposed":
        return True
    return "delegation_id" in payload
