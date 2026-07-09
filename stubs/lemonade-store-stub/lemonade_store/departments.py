"""Stub for lemonade_store.departments — provides a minimal registry for CI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DepartmentInfo:
    """Information about a department in the registry."""

    writes: tuple[str, ...] = ()
    requires_owner_approval_for: tuple[str, ...] = ()


def registry() -> dict[str, DepartmentInfo]:
    """Return a minimal department registry for CI testing.

    Matches the departments used in test fixtures:
    - cashier: writes "cashier.*", no owner-approval gates
    - inventory: writes "inventory.*", no owner-approval gates
    - accounting: writes "accounting.*", requires approval for "export"
    """
    return {
        "cashier": DepartmentInfo(
            writes=("cashier",),
            requires_owner_approval_for=(),
        ),
        "inventory": DepartmentInfo(
            writes=("inventory",),
            requires_owner_approval_for=(),
        ),
        "accounting": DepartmentInfo(
            writes=("accounting",),
            requires_owner_approval_for=("export",),
        ),
    }
