"""Tests for the Lemonade Server integration.

Tests are split into two groups:
- Offline/unit tests that mock the network (always pass).
- Live tests that only run when the server is actually reachable (skipped otherwise).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from lemonade_security.aibom import AibomComponent
from lemonade_security.lemonade_server import (
    DEFAULT_URL,
    LemonadeModel,
    ServerStatus,
    list_downloaded_models,
    models_to_components,
    probe_server,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_MODEL_JSON = {
    "id": "Test-Model-4B-gguf",
    "checkpoint": "test-org/Test-Model-4B-gguf:Q4_K_M",
    "labels": ["tool-calling", "reasoning"],
    "downloaded": True,
    "size": 2.5,
    "recipe": "llamacpp",
    "max_context_window": 32768,
    "object": "model",
    "owned_by": "lemonade",
}

_FAKE_RESPONSE = json.dumps({"object": "list", "data": [_FAKE_MODEL_JSON]}).encode()


def _make_mock_response(body: bytes, status: int = 200):
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = body
    mock.status = status
    return mock


# ---------------------------------------------------------------------------
# list_downloaded_models — unit tests (mocked network)
# ---------------------------------------------------------------------------

def test_returns_empty_list_when_server_unreachable() -> None:
    with patch("urllib.request.urlopen", side_effect=OSError("refused")):
        assert list_downloaded_models("http://localhost:19999") == []


def test_parses_downloaded_model() -> None:
    with patch("urllib.request.urlopen", return_value=_make_mock_response(_FAKE_RESPONSE)):
        models = list_downloaded_models()

    assert len(models) == 1
    m = models[0]
    assert m.id == "Test-Model-4B-gguf"
    assert m.checkpoint == "test-org/Test-Model-4B-gguf:Q4_K_M"
    assert m.labels == ("tool-calling", "reasoning")
    assert m.size_gb == 2.5
    assert m.recipe == "llamacpp"
    assert m.max_context_window == 32768


def test_skips_not_downloaded_models() -> None:
    not_downloaded = {**_FAKE_MODEL_JSON, "downloaded": False}
    body = json.dumps({"data": [not_downloaded]}).encode()
    with patch("urllib.request.urlopen", return_value=_make_mock_response(body)):
        assert list_downloaded_models() == []


def test_handles_malformed_json_gracefully() -> None:
    with patch("urllib.request.urlopen", return_value=_make_mock_response(b"not json")):
        assert list_downloaded_models() == []


def test_handles_missing_data_key() -> None:
    body = json.dumps({"object": "list"}).encode()
    with patch("urllib.request.urlopen", return_value=_make_mock_response(body)):
        assert list_downloaded_models() == []


# ---------------------------------------------------------------------------
# probe_server — unit tests
# ---------------------------------------------------------------------------

def test_probe_returns_online_when_models_returned() -> None:
    with patch("urllib.request.urlopen", return_value=_make_mock_response(_FAKE_RESPONSE)):
        status = probe_server()

    assert isinstance(status, ServerStatus)
    assert status.online is True
    assert status.downloaded_model_count == 1


def test_probe_returns_offline_when_unreachable() -> None:
    with patch("urllib.request.urlopen", side_effect=OSError("refused")):
        status = probe_server("http://localhost:19999")

    assert status.online is False
    assert status.downloaded_model_count == 0
    assert status.url == "http://localhost:19999"


def test_probe_never_raises() -> None:
    with patch("urllib.request.urlopen", side_effect=RuntimeError("unexpected")):
        status = probe_server()
    assert status.online is False


# ---------------------------------------------------------------------------
# models_to_components
# ---------------------------------------------------------------------------

def test_converts_model_to_aibom_component() -> None:
    model = LemonadeModel(
        id="Qwen3-4B-GGUF",
        checkpoint="lemonade/Qwen3-4B-GGUF:Q4_K_M",
        labels=("reasoning",),
        size_gb=2.49,
        recipe="llamacpp",
        max_context_window=32768,
    )
    components = models_to_components([model])

    assert len(components) == 1
    c = components[0]
    assert isinstance(c, AibomComponent)
    assert c.kind == "model"
    assert c.name == "Qwen3-4B-GGUF"
    assert c.version == "lemonade/Qwen3-4B-GGUF:Q4_K_M"
    assert c.supplier == "lemonade-server"
    assert "recipe=llamacpp" in (c.notes or "")
    assert "size=2.49GB" in (c.notes or "")


def test_empty_model_list_returns_empty_tuple() -> None:
    assert models_to_components([]) == ()


def test_notes_include_labels() -> None:
    model = LemonadeModel(
        id="X", checkpoint="x:Q4", labels=("tool-calling", "vision"),
        size_gb=None, recipe="llamacpp", max_context_window=None,
    )
    components = models_to_components([model])
    assert "tool-calling" in (components[0].notes or "")


# ---------------------------------------------------------------------------
# AIBOM tool enrichment — unit test (mocked server)
# ---------------------------------------------------------------------------

def test_aibom_tool_includes_server_models_when_online() -> None:
    from lemonade_security.sdk_plugin import execute_security_tool

    with patch("urllib.request.urlopen", return_value=_make_mock_response(_FAKE_RESPONSE)):
        text, events = execute_security_tool(
            "lemonade_security_aibom", {"store_id": "tie-dye-farms"}
        )

    import json as _json
    # Strip header comment line before parsing JSON
    json_part = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    manifest = _json.loads(json_part)
    model_names = [c["name"] for c in manifest["components"]]
    assert "Test-Model-4B-gguf" in model_names


def test_aibom_tool_works_when_server_offline() -> None:
    from lemonade_security.sdk_plugin import execute_security_tool

    with patch("urllib.request.urlopen", side_effect=OSError("refused")):
        text, events = execute_security_tool(
            "lemonade_security_aibom", {"store_id": "tie-dye-farms"}
        )

    assert "offline" in text
    import json as _json
    json_part = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    manifest = _json.loads(json_part)
    assert manifest["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# Live tests — skipped when server is not reachable
# ---------------------------------------------------------------------------

def _server_live() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen(f"{DEFAULT_URL}/v1/models", timeout=1)
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _server_live(), reason="Lemonade Server not running")
def test_live_probe_returns_online() -> None:
    status = probe_server()
    assert status.online is True
    assert status.downloaded_model_count > 0


@pytest.mark.skipif(not _server_live(), reason="Lemonade Server not running")
def test_live_models_have_expected_fields() -> None:
    models = list_downloaded_models()
    assert len(models) > 0
    for m in models:
        assert isinstance(m.id, str) and m.id
        assert isinstance(m.recipe, str)
        assert isinstance(m.labels, tuple)


@pytest.mark.skipif(not _server_live(), reason="Lemonade Server not running")
def test_live_aibom_tool_includes_real_models() -> None:
    from lemonade_security.sdk_plugin import execute_security_tool
    import json as _json

    text, _ = execute_security_tool("lemonade_security_aibom", {"store_id": "tie-dye-farms"})
    assert "online" in text
    json_part = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    manifest = _json.loads(json_part)
    model_components = [c for c in manifest["components"] if c["type"] == "machine-learning-model"]
    assert len(model_components) > 0
