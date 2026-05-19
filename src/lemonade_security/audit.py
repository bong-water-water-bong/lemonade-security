"""Local event-log security checks.

The first auditor is intentionally conservative. It validates the shared
event envelope and flags obvious policy drift without trying to infer
business truth from another department's payload.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lemonade_store.events import Actor, Event, EventValidationError, load_event
from lemonade_security.owasp import risk_ids_for_code

SENSITIVE_PAYMENT_TERMS = frozenset(
    {
        "card",
        "credit_card",
        "debit_card",
        "stripe",
        "square",
        "wallet",
        "payment_gateway",
        "tokenized_payment",
    }
)

CUSTOMER_MEDIA_TERMS = frozenset(
    {
        "customer_audio",
        "customer_image",
        "customer_photo",
        "face_image",
        "audio_path",
        "image_path",
    }
)


@dataclass(frozen=True)
class AuditFinding:
    code: str
    severity: str
    message: str
    line_number: int | None = None
    event_id: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "owasp_risks": list(risk_ids_for_code(self.code)),
            "message": self.message,
            "line_number": self.line_number,
            "event_id": self.event_id,
        }


@dataclass(frozen=True)
class AuditResult:
    store_id: str
    checked_events: int
    findings: tuple[AuditFinding, ...]

    @property
    def passed(self) -> bool:
        return not self.findings


def audit_event_log(path: str | Path, *, store_id: str) -> AuditResult:
    """Audit a JSONL store event log and return local findings."""
    findings: list[AuditFinding] = []
    checked_events = 0

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError as exc:
                findings.append(
                    AuditFinding(
                        code="invalid_json",
                        severity="high",
                        message=f"line is not valid JSON: {exc.msg}",
                        line_number=line_number,
                    )
                )
                continue

            try:
                event = load_event(raw)
            except EventValidationError as exc:
                findings.append(
                    AuditFinding(
                        code="invalid_envelope",
                        severity="high",
                        message=str(exc),
                        line_number=line_number,
                        event_id=_raw_event_id(raw),
                    )
                )
                continue

            checked_events += 1
            findings.extend(_check_event(event, line_number=line_number, expected_store_id=store_id))

    return AuditResult(store_id=store_id, checked_events=checked_events, findings=tuple(findings))


def finding_events(result: AuditResult) -> list[Event]:
    """Convert findings into `security.finding.created` envelope events."""
    return [
        Event(
            schema_version="store.event.v1",
            event_id=_stable_event_id(result.store_id, "finding", str(index), finding.code),
            ts=_now_utc(),
            store_id=result.store_id,
            department="security",
            type="security.finding.created",
            source="lemonade-security",
            actor=Actor(kind="agent_auto", id="security.auditor"),
            requires_approval=False,
            approved_by=None,
            payload=finding.to_payload(),
        )
        for index, finding in enumerate(result.findings, start=1)
    ]


def summary_event(result: AuditResult) -> Event:
    """Build the final `security.audit.completed` envelope event."""
    return Event(
        schema_version="store.event.v1",
        event_id=_stable_event_id(
            result.store_id,
            "audit",
            str(result.checked_events),
            str(len(result.findings)),
        ),
        ts=_now_utc(),
        store_id=result.store_id,
        department="security",
        type="security.audit.completed",
        source="lemonade-security",
        actor=Actor(kind="agent_auto", id="security.auditor"),
        requires_approval=False,
        approved_by=None,
        payload={
            "scope": "store-event-log",
            "checked_events": result.checked_events,
            "findings": len(result.findings),
            "passed": result.passed,
        },
    )


def _check_event(event: Event, *, line_number: int, expected_store_id: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []

    if event.store_id != expected_store_id:
        findings.append(
            AuditFinding(
                code="wrong_store_id",
                severity="medium",
                message=f"event store_id {event.store_id!r} does not match expected {expected_store_id!r}",
                line_number=line_number,
                event_id=event.event_id,
            )
        )

    if event.requires_approval and event.approved_by is not None and event.type.endswith(".drafted"):
        findings.append(
            AuditFinding(
                code="draft_already_approved",
                severity="medium",
                message="draft event should remain unapproved until a separate owner approval event",
                line_number=line_number,
                event_id=event.event_id,
            )
        )

    flattened_payload = _flatten_payload_keys(event.payload)
    if event.department == "cashier":
        blocked_payment_terms = sorted(flattened_payload & SENSITIVE_PAYMENT_TERMS)
        if blocked_payment_terms:
            findings.append(
                AuditFinding(
                    code="cashier_payment_boundary",
                    severity="critical",
                    message=f"cashier event contains blocked payment terms: {blocked_payment_terms}",
                    line_number=line_number,
                    event_id=event.event_id,
                )
            )

    blocked_media_terms = sorted(flattened_payload & CUSTOMER_MEDIA_TERMS)
    if blocked_media_terms:
        findings.append(
            AuditFinding(
                code="customer_media_boundary",
                severity="critical",
                message=f"event contains blocked customer media terms: {blocked_media_terms}",
                line_number=line_number,
                event_id=event.event_id,
            )
        )

    return findings


def _flatten_payload_keys(payload: dict[str, Any]) -> set[str]:
    keys: set[str] = set()

    def visit(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = str(key).strip().lower()
                keys.add(normalized)
                if prefix:
                    keys.add(f"{prefix}.{normalized}")
                visit(nested, normalized)
        elif isinstance(value, list):
            for item in value:
                visit(item, prefix)

    visit(payload)
    return keys


def _raw_event_id(raw: object) -> str | None:
    if isinstance(raw, dict):
        event_id = raw.get("event_id")
        if isinstance(event_id, str):
            return event_id
    return None


def _stable_event_id(store_id: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join((store_id, *parts)).encode("utf-8")).hexdigest()[:16]
    return f"security-{digest}"


def _now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
