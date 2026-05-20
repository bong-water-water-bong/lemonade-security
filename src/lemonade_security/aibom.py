"""Local AIBOM manifest support — CycloneDX 1.6-compatible output.

Produces BOM dicts conforming to the CycloneDX 1.6 JSON schema.
Reference: OWASP AIBOM Generator / CycloneDX AI BOM field mapping.
No external dependencies beyond the stdlib.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class AibomComponent:
    kind: str
    name: str
    version: str | None = None
    supplier: str | None = None
    location: str | None = None
    notes: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KIND_TO_CDX_TYPE: dict[str, str] = {
    "model": "machine-learning-model",
    "data": "data",
    "plugin": "library",
    "tool": "library",
    "department": "library",
}


def _cdx_type(kind: str) -> str:
    return _KIND_TO_CDX_TYPE.get(kind, "library")


def _slugify(text: str) -> str:
    """Lower-case, replace non-alphanumeric runs with hyphens."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _deterministic_uuid(store_id: str) -> str:
    """UUID v5 (SHA-1 namespace:URL) seeded from store_id."""
    uid = uuid.uuid5(uuid.NAMESPACE_URL, f"lemonade-security:{store_id}")
    return f"urn:uuid:{uid}"


def _cdx_component(store_id: str, comp: AibomComponent) -> dict[str, Any]:
    bom_ref = f"{_slugify(store_id)}/{_slugify(comp.name)}"
    entry: dict[str, Any] = {
        "type": _cdx_type(comp.kind),
        "bom-ref": bom_ref,
        "name": comp.name,
    }
    if comp.version is not None:
        entry["version"] = comp.version
    if comp.supplier is not None:
        entry["supplier"] = {"name": comp.supplier}
    if comp.notes is not None:
        entry["description"] = comp.notes
    return entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def local_manifest(*, store_id: str, components: tuple[AibomComponent, ...]) -> dict[str, Any]:
    """Build a CycloneDX 1.6-compatible AIBOM manifest for Lemonade Security.

    The returned dict is spec-conformant and also includes the legacy
    ``schema`` and ``store_id`` extension fields so existing consumers
    do not break.
    """
    return {
        # CycloneDX 1.6 required fields
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": _deterministic_uuid(store_id),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {
                "type": "application",
                "bom-ref": "lemonade-security",
                "name": "lemonade-security",
                "description": "Local security policy checks and AIBOM manifests for Lemonade Store.",
            },
        },
        "components": [_cdx_component(store_id, c) for c in components],
        # Legacy extension fields (kept for backward compatibility)
        "schema": "lemonade.security.aibom.v0",
        "store_id": store_id,
    }


def to_cyclonedx_json(manifest: dict[str, Any]) -> str:
    """Serialise a manifest dict to indented JSON."""
    return json.dumps(manifest, indent=2)
