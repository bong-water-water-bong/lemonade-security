"""Minimal stub for the lemonade-store package used by lemonade-security CI."""

from lemonade_store.departments import DepartmentInfo, registry
from lemonade_store.events import (
    Actor,
    Event,
    EventValidationError,
    SCHEMA_VERSION,
    dump_event,
    load_event,
)

__all__ = [
    "Actor",
    "DepartmentInfo",
    "Event",
    "EventValidationError",
    "SCHEMA_VERSION",
    "dump_event",
    "load_event",
    "registry",
]
