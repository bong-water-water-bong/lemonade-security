"""Department permission-drift scanner.

Checks a Lemonade Store JSONL event log against the department registry
contracts defined in ``lemonade_store.departments``.

Three drift rules are enforced:

1. **Namespace drift** — the event ``type`` must start with one of the
   emitting department's ``writes`` prefixes. Emitting into a namespace
   outside those prefixes (e.g. a ``cashier`` agent writing ``store.*``
   events) is a high-severity violation.

2. **Approval-gate drift** — if the event type's *action* suffix (the
   last dot-separated segment) matches an entry in the department's
   ``requires_owner_approval_for`` tuple, the event *must* have
   ``requires_approval=True``. An event with ``requires_approval=False``
   for a gate-required action means the approval gate has been bypassed.

3. **Unknown department** — an event whose ``department`` field is not
   present in the registry is a medium-severity violation.

Events that fail basic envelope validation (``EventValidationError``) are
recorded as ``invalid_envelope`` findings and skipped for further checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from lemonade_store.departments import registry
from lemonade_store.events import EventValidationError, load_event

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
            # Envelope validation                                               #
            # ---------------------------------------------------------------- #
            try:
                event = load_event(raw)
            except EventValidationError as exc:
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
                action = event.type.split(".")[-1]
                if action in dept.requires_owner_approval_for and not event.requires_approval:
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
