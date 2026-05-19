"""Local AIBOM manifest support.

This is not a full CycloneDX emitter yet. It captures the Lemonade-local
inventory needed before adapting the forked OWASP AIBOM generator:
models, tools, plugins, datasets, and department repos.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AibomComponent:
    kind: str
    name: str
    version: str | None = None
    supplier: str | None = None
    location: str | None = None
    notes: str | None = None


def local_manifest(*, store_id: str, components: tuple[AibomComponent, ...]) -> dict[str, Any]:
    """Build a small local AIBOM manifest for Lemonade Security."""
    return {
        "schema": "lemonade.security.aibom.v0",
        "store_id": store_id,
        "format_reference": "OWASP AIBOM Generator / CycloneDX AI BOM field mapping",
        "components": [asdict(component) for component in components],
    }
