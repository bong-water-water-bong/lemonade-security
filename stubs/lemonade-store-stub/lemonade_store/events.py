"""Stub for lemonade_store.events — provides minimal types for CI."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = "store.event.v1"


class EventValidationError(ValueError):
    """Raised when an event dict fails structural validation."""


@dataclass(frozen=True)
class Actor:
    kind: str
    id: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Actor:
        return cls(kind=d.get("kind", "unknown"), id=d.get("id", "unknown"))


@dataclass(frozen=True)
class Event:
    schema_version: str = SCHEMA_VERSION
    event_id: str = ""
    ts: str = ""
    store_id: str = ""
    department: str = ""
    type: str = ""
    source: str = ""
    actor: Actor = field(default_factory=lambda: Actor(kind="unknown", id="unknown"))
    requires_approval: bool = False
    approved_by: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


_REQUIRED_STR_FIELDS = (
    "schema_version",
    "event_id",
    "ts",
    "store_id",
    "department",
    "type",
    "source",
)


def load_event(raw: dict[str, Any]) -> Event:
    """Parse a raw event dict into an Event.

    Performs basic structural validation matching the real implementation.
    """
    for field_name in _REQUIRED_STR_FIELDS:
        if field_name not in raw:
            raise EventValidationError(f"missing required field {field_name!r}")
        if not isinstance(raw[field_name], str):
            raise EventValidationError(
                f"{field_name} must be a string, got {type(raw[field_name]).__name__}"
            )
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise EventValidationError(
            f"unknown schema_version {raw.get('schema_version')!r}; "
            f"expected {SCHEMA_VERSION!r}"
        )
    actor_raw = raw.get("actor")
    if not isinstance(actor_raw, dict):
        raise EventValidationError("actor must be an object")
    actor = Actor.from_dict(actor_raw)
    requires_approval = raw.get("requires_approval", False)
    if not isinstance(requires_approval, bool):
        raise EventValidationError(
            f"requires_approval must be a boolean, "
            f"got {type(requires_approval).__name__}"
        )
    payload = {k: v for k, v in raw.items() if k not in _REQUIRED_STR_FIELDS}
    payload.pop("actor", None)
    payload.pop("requires_approval", None)
    payload.pop("approved_by", None)
    return Event(
        schema_version=str(raw["schema_version"]),
        event_id=str(raw["event_id"]),
        ts=str(raw["ts"]),
        store_id=str(raw["store_id"]),
        department=str(raw["department"]),
        type=str(raw["type"]),
        source=str(raw["source"]),
        actor=actor,
        requires_approval=requires_approval,
        approved_by=raw.get("approved_by"),
        payload=payload,
    )


def dump_event(event: Event) -> str:
    """Serialize an Event back to a JSON string."""
    data: dict[str, Any] = {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "ts": event.ts,
        "store_id": event.store_id,
        "department": event.department,
        "type": event.type,
        "source": event.source,
        "actor": {"kind": event.actor.kind, "id": event.actor.id},
        "requires_approval": event.requires_approval,
        "approved_by": event.approved_by,
    }
    data.update(event.payload)
    return json.dumps(data, sort_keys=True)
