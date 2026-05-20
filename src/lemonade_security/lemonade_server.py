"""Lemonade Server integration.

Probes a local Lemonade Server instance and converts its model inventory
into ``AibomComponent`` entries for the AIBOM manifest.

## Design rules

- No hard dependency on the server being online.  Every function returns
  a safe default (empty list / offline status) if the server is
  unreachable rather than raising.
- stdlib only (``urllib.request`` / ``json``).  No ``requests`` import.
- Never mutates server state.  All calls are ``GET`` requests.
- The default URL matches the Lemonade Server default (``localhost:13305``).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from lemonade_security.aibom import AibomComponent

DEFAULT_URL = "http://localhost:13305"
_MODELS_PATH = "/v1/models"
_TIMEOUT = 2  # seconds — short so offline checks return fast


@dataclass(frozen=True)
class ServerStatus:
    """Result of a lightweight probe against the Lemonade Server."""

    online: bool
    url: str
    downloaded_model_count: int


@dataclass(frozen=True)
class LemonadeModel:
    """A single model entry from ``GET /v1/models``."""

    id: str
    checkpoint: str
    labels: tuple[str, ...]
    size_gb: float | None
    recipe: str
    max_context_window: int | None


def probe_server(url: str = DEFAULT_URL) -> ServerStatus:
    """Check whether a Lemonade Server is reachable at *url*.

    Makes its own direct HTTP call so it is not fooled by
    ``list_downloaded_models``'s broad exception catch.
    Never raises — returns an offline ``ServerStatus`` on any error.
    """
    try:
        with urllib.request.urlopen(f"{url}{_MODELS_PATH}", timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
        count = sum(
            1 for m in raw.get("data", [])
            if isinstance(m, dict) and m.get("downloaded")
        )
        return ServerStatus(online=True, url=url, downloaded_model_count=count)
    except Exception:
        return ServerStatus(online=False, url=url, downloaded_model_count=0)


def list_downloaded_models(url: str = DEFAULT_URL) -> list[LemonadeModel]:
    """Return all downloaded models from the Lemonade Server at *url*.

    Returns an empty list if the server is unreachable or returns an
    unexpected response.
    """
    try:
        with urllib.request.urlopen(f"{url}{_MODELS_PATH}", timeout=_TIMEOUT) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []

    if not isinstance(raw, dict):
        return []

    models: list[LemonadeModel] = []
    for entry in raw.get("data", []):
        if not isinstance(entry, dict):
            continue
        if not entry.get("downloaded"):
            continue
        models.append(_parse_model(entry))
    return models


def models_to_components(models: list[LemonadeModel]) -> tuple[AibomComponent, ...]:
    """Convert a ``LemonadeModel`` list into ``AibomComponent`` entries.

    Each model becomes a ``kind="model"`` component whose ``notes`` field
    captures labels and backend recipe so the AIBOM records capability
    and supply-chain metadata (OWASP LLM03:2026 / ASI04).
    """
    return tuple(
        AibomComponent(
            kind="model",
            name=model.id,
            version=model.checkpoint or None,
            supplier="lemonade-server",
            notes=_model_notes(model),
        )
        for model in models
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_model(entry: dict) -> LemonadeModel:  # type: ignore[type-arg]
    labels_raw = entry.get("labels", [])
    if not isinstance(labels_raw, (list, tuple)):
        labels_raw = []
    labels = tuple(str(lb) for lb in labels_raw if isinstance(lb, str))

    size = entry.get("size")
    size_gb = float(size) if isinstance(size, (int, float)) else None

    ctx = entry.get("max_context_window")
    max_ctx = int(ctx) if isinstance(ctx, int) else None

    return LemonadeModel(
        id=str(entry.get("id", "")),
        checkpoint=str(entry.get("checkpoint", "")),
        labels=labels,
        size_gb=size_gb,
        recipe=str(entry.get("recipe", "")),
        max_context_window=max_ctx,
    )


def _model_notes(model: LemonadeModel) -> str:
    parts = [f"recipe={model.recipe}"]
    if model.labels:
        parts.append(f"labels={','.join(model.labels)}")
    if model.size_gb is not None:
        parts.append(f"size={model.size_gb}GB")
    if model.max_context_window is not None:
        parts.append(f"ctx={model.max_context_window}")
    return " ".join(parts)
