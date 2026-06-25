"""Department permission-drift scanner.

Checks a Lemonade Store JSONL event log against the department registry
contracts defined in ``lemonade_store.departments``.

Three drift rules are enforced:

1. **Namespace drift** — the event ``type`` must start with one of the
   emitting department's ``writes`` prefixes. Emitting into a namespace
   outside those prefixes (e.g. a ``cashier`` agent writing ``store.*``
   events) is a high-severity violation.

2. **Approval-gate drift** — if any meaningful event type token matches
   an entry in the department's ``requires_owner_approval_for`` tuple,
   the event *must* have
   ``requires_approval=True``. An event with ``requires_approval=False``
   for a gate-required action means the approval gate has been bypassed.

3. **Unknown department** — an event whose ``department`` field is not
   present in the registry is a medium-severity violation.

Events that are structurally malformed are recorded as
``invalid_envelope`` findings and skipped for further checks. Note the
scanner uses its own lenient structural parser (``_parse_envelope``)
rather than ``lemonade_store.events.load_event``: contract violations
are exactly what this scanner must classify, and the strict loader would
reject them as ``invalid_envelope`` before the drift rules could run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from lemonade_store.departments import registry
from lemonade_store.events import SCHEMA_VERSION

# --------------------------------------------------------------------------- #
# Public data types                                                             #
# --------------------------------------------------------------------------- #

_SEVERITIES: dict[str, str] = {
    "namespace_violation": "high",
    "approval_gate_drift": "medium",
    "unknown_department": "medium",
    "invalid_envelope": "high",
}


@dataclass(frozen=True)
class DriftFinding:
    code: str
    severity: str
    message: str
    line_number: int | None = None
    event_id: str | None = None


@dataclass(frozen=True)
class DriftResult:
    store_id: str
    checked_events: int
    findings: tuple[DriftFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


@dataclass(frozen=True)
class _Envelope:
    """A leniently-parsed event envelope used only by the drift scanner.

    The drift scanner audits *contract* violations (a department emitting
    outside its namespace, or bypassing an owner-approval gate). Those
    events are, by definition, rejected by the strict ``load_event``
    validator in ``lemonade_store.events``. If the scanner parsed through
    that validator it could never see the very violations it exists to
    report — they would all collapse into ``invalid_envelope``.

    So the scanner does its own *structural* parse here: it confirms the
    envelope is well-formed (required fields present and correctly typed,
    namespaced event type, known schema version) but deliberately does
    NOT enforce registry-coupled rules (namespace match, ``emits``
    membership, approval pairing). Those are the drift rules below.
    """

    event_id: str
    department: str
    type: str
    requires_approval: bool


_REQUIRED_STR_FIELDS: tuple[str, ...] = (
    "schema_version",
    "event_id",
    "ts",
    "store_id",
    "department",
    "type",
    "source",
)


class _EnvelopeStructureError(ValueError):
    """Raised when an envelope is malformed (not merely contract-violating)."""


def _parse_envelope(raw: object) -> _Envelope:
    """Structurally validate a raw event dict for the drift scanner.

    Raises ``_EnvelopeStructureError`` for genuinely malformed envelopes
    (missing/mistyped required fields, non-namespaced type, unknown
    schema). Registry/contract violations are intentionally allowed
    through so the drift rules can classify them.
    """
    if not isinstance(raw, dict):
        raise _EnvelopeStructureError("event must be a JSON object")

    for field_name in _REQUIRED_STR_FIELDS:
        if field_name not in raw:
            raise _EnvelopeStructureError(f"missing required field {field_name!r}")
        if not isinstance(raw[field_name], str):
            raise _EnvelopeStructureError(
                f"{field_name} must be a string, got {type(raw[field_name]).__name__}"
            )

    if raw["schema_version"] != SCHEMA_VERSION:
        raise _EnvelopeStructureError(
            f"unknown schema_version {raw['schema_version']!r}; expected {SCHEMA_VERSION!r}"
        )

    if "." not in raw["type"]:
        raise _EnvelopeStructureError(
            f"event type {raw['type']!r} is not namespaced (expected 'department.foo.bar')"
        )

    actor = raw.get("actor")
    if (
        not isinstance(actor, dict)
        or not isinstance(actor.get("kind"), str)
        or not isinstance(actor.get("id"), str)
    ):
        raise _EnvelopeStructureError("actor must be an object with string 'kind' and 'id'")

    requires_approval = raw.get("requires_approval", False)
    if not isinstance(requires_approval, bool):
        raise _EnvelopeStructureError(
            f"requires_approval must be a boolean, got {type(requires_approval).__name__}"
        )

    return _Envelope(
        event_id=raw["event_id"],
        department=raw["department"],
        type=raw["type"],
        requires_approval=requires_approval,
    )


# --------------------------------------------------------------------------- #
# Public scanner                                                                #
# --------------------------------------------------------------------------- #


def scan_permission_drift(path: str | Path, *, store_id: str) -> DriftResult:
    """Scan a JSONL event log for department permission drift.

    Parameters
    ----------
    path:
        Path to the ``.jsonl`` file to scan.
    store_id:
        Expected store identifier (used only in the result header; this
        scanner does not re-validate store_id match — that belongs to
        ``audit_event_log``).

    Returns
    -------
    DriftResult
        Immutable result object. ``result.passed`` is ``True`` when no
        findings were produced.
    """
    dept_registry = registry()
    findings: list[DriftFinding] = []
    checked_events = 0

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            # ---------------------------------------------------------------- #
            # JSON parse                                                        #
            # ---------------------------------------------------------------- #
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                findings.append(
                    DriftFinding(
                        code="invalid_envelope",
                        severity=_SEVERITIES["invalid_envelope"],
                        message=f"line is not valid JSON: {exc.msg}",
                        line_number=line_number,
                    )
                )
                continue

            # ---------------------------------------------------------------- #
            # Envelope validation (structural only — see _parse_envelope)       #
            # ---------------------------------------------------------------- #
            try:
                event = _parse_envelope(raw)
            except _EnvelopeStructureError as exc:
                findings.append(
                    DriftFinding(
                        code="invalid_envelope",
                        severity=_SEVERITIES["invalid_envelope"],
                        message=str(exc),
                        line_number=line_number,
                        event_id=_raw_event_id(raw),
                    )
                )
                continue

            checked_events += 1

            # ---------------------------------------------------------------- #
            # Rule 3: unknown department                                        #
            # ---------------------------------------------------------------- #
            if event.department not in dept_registry:
                findings.append(
                    DriftFinding(
                        code="unknown_department",
                        severity=_SEVERITIES["unknown_department"],
                        message=(
                            f"department {event.department!r} is not present in the registry"
                        ),
                        line_number=line_number,
                        event_id=event.event_id,
                    )
                )
                # Cannot check write-namespace or approval gate without a
                # registry entry; skip remaining checks for this event.
                continue

            dept = dept_registry[event.department]

            # ---------------------------------------------------------------- #
            # Rule 1: namespace drift                                           #
            # ---------------------------------------------------------------- #
            if not any(event.type.startswith(prefix) for prefix in dept.writes):
                findings.append(
                    DriftFinding(
                        code="namespace_violation",
                        severity=_SEVERITIES["namespace_violation"],
                        message=(
                            f"department {event.department!r} emitted type {event.type!r} "
                            f"which does not start with any allowed write prefix "
                            f"{dept.writes!r}"
                        ),
                        line_number=line_number,
                        event_id=event.event_id,
                    )
                )

            # ---------------------------------------------------------------- #
            # Rule 2: approval-gate drift                                       #
            # ---------------------------------------------------------------- #
            if dept.requires_owner_approval_for:
                action = _approval_gate_action(
                    event.type,
                    dept.requires_owner_approval_for,
                )
                if action is not None and not event.requires_approval:
                    findings.append(
                        DriftFinding(
                            code="approval_gate_drift",
                            severity=_SEVERITIES["approval_gate_drift"],
                            message=(
                                f"department {event.department!r} action {action!r} requires "
                                f"owner approval but event has requires_approval=False"
                            ),
                            line_number=line_number,
                            event_id=event.event_id,
                        )
                    )

    return DriftResult(
        store_id=store_id,
        checked_events=checked_events,
        findings=tuple(findings),
    )


# --------------------------------------------------------------------------- #
# Internal helpers                                                              #
# --------------------------------------------------------------------------- #


def _raw_event_id(raw: object) -> str | None:
    if isinstance(raw, dict):
        event_id = raw.get("event_id")
        if isinstance(event_id, str):
            return event_id
    return None


def _approval_gate_action(event_type: str, required_actions: tuple[str, ...]) -> str | None:
    """Return the owner-gated action named by an event type, if any.

    Event names usually read like ``department.action.state``. Matching every
    token catches ``site.deploy.requested`` and ``accounting.export.created``
    while still requiring an explicit action token from the registry.
    """
    tokens = tuple(part for part in event_type.split(".")[1:] if part)
    for action in required_actions:
        if action in tokens:
            return action
    return None
