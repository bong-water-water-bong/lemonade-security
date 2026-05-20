from __future__ import annotations

import json
from pathlib import Path

import pytest

from lemonade_security.sdk_plugin import (
    SECURITY_TOOLS,
    SecurityToolError,
    execute_security_tool,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Tool definition schema
# ---------------------------------------------------------------------------

def test_tool_definitions_are_list_of_dicts() -> None:
    assert isinstance(SECURITY_TOOLS, list)
    assert all(isinstance(t, dict) for t in SECURITY_TOOLS)


def test_all_tools_have_required_fields() -> None:
    for tool in SECURITY_TOOLS:
        assert tool["type"] == "function"
        fn = tool["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn
        params = fn["parameters"]
        assert params["type"] == "object"
        assert "properties" in params
        assert "required" in params


def test_tool_names_are_unique() -> None:
    names = [t["function"]["name"] for t in SECURITY_TOOLS]
    assert len(names) == len(set(names))


def test_tool_definitions_are_valid_json() -> None:
    dumped = json.dumps(SECURITY_TOOLS)
    loaded = json.loads(dumped)
    assert len(loaded) == len(SECURITY_TOOLS)


def test_five_tools_registered() -> None:
    names = {t["function"]["name"] for t in SECURITY_TOOLS}
    assert names == {
        "lemonade_security_audit",
        "lemonade_security_drift",
        "lemonade_security_secrets",
        "lemonade_security_maturity",
        "lemonade_security_aibom",
    }


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------

def test_unknown_tool_raises() -> None:
    with pytest.raises(SecurityToolError):
        execute_security_tool("not_a_real_tool", {})


def test_missing_required_arg_raises() -> None:
    with pytest.raises(SecurityToolError, match="missing required argument"):
        execute_security_tool("lemonade_security_audit", {})  # missing events_path, store_id


def test_nonlocalhost_server_url_raises() -> None:
    with pytest.raises(SecurityToolError, match="localhost"):
        execute_security_tool(
            "lemonade_security_aibom",
            {"store_id": "tie-dye-farms", "server_url": "http://evil.example.com/steal"},
        )


def test_patterns_as_string_raises() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp, pytest.raises(SecurityToolError, match="list"):
        execute_security_tool(
            "lemonade_security_secrets",
            {"scan_root": tmp, "patterns": "*.jsonl"},
        )


# ---------------------------------------------------------------------------
# lemonade_security_audit
# ---------------------------------------------------------------------------

def test_audit_tool_clean_log_passes() -> None:
    text, events = execute_security_tool(
        "lemonade_security_audit",
        {"events_path": str(FIXTURES / "store_events.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert "PASSED" in text
    assert "2 events checked" in text
    assert any(e.type == "security.audit.completed" for e in events)
    assert any(e.type == "security.policy.checked" for e in events)


def test_audit_tool_bad_log_fails() -> None:
    text, events = execute_security_tool(
        "lemonade_security_audit",
        {"events_path": str(FIXTURES / "bad_events.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert "FAILED" in text
    assert any(e.type == "security.finding.created" for e in events)


def test_audit_tool_emits_security_events_only() -> None:
    _, events = execute_security_tool(
        "lemonade_security_audit",
        {"events_path": str(FIXTURES / "store_events.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert all(e.type.startswith("security.") for e in events)
    assert all(e.department == "security" for e in events)


# ---------------------------------------------------------------------------
# lemonade_security_drift
# ---------------------------------------------------------------------------

def test_drift_tool_clean_log_passes() -> None:
    text, events = execute_security_tool(
        "lemonade_security_drift",
        {"events_path": str(FIXTURES / "drift_clean.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert "PASSED" in text
    assert events == []


def test_drift_tool_namespace_violation() -> None:
    text, _ = execute_security_tool(
        "lemonade_security_drift",
        {
            "events_path": str(FIXTURES / "drift_namespace_violation.jsonl"),
            "store_id": "tie-dye-farms",
        },
    )
    assert "FAILED" in text
    assert "namespace_violation" in text


# ---------------------------------------------------------------------------
# lemonade_security_secrets
# ---------------------------------------------------------------------------

def test_secrets_tool_clean_dir_passes(tmp_path) -> None:
    import shutil
    shutil.copy(FIXTURES / "scan_clean.jsonl", tmp_path / "scan_clean.jsonl")

    text, events = execute_security_tool(
        "lemonade_security_secrets",
        {"scan_root": str(tmp_path)},
    )
    assert "PASSED" in text
    assert events == []


def test_secrets_tool_detects_bearer(tmp_path) -> None:
    import shutil
    shutil.copy(FIXTURES / "scan_with_bearer.jsonl", tmp_path / "scan_with_bearer.jsonl")

    text, _ = execute_security_tool(
        "lemonade_security_secrets",
        {"scan_root": str(tmp_path)},
    )
    assert "FAILED" in text
    assert "bearer_token" in text


def test_secrets_tool_output_never_contains_secret_value(tmp_path) -> None:
    import shutil
    shutil.copy(FIXTURES / "scan_with_bearer.jsonl", tmp_path / "scan_with_bearer.jsonl")

    text, _ = execute_security_tool(
        "lemonade_security_secrets",
        {"scan_root": str(tmp_path)},
    )
    # The fixture uses this fake token value — it must not appear in the output
    assert "sk-abc123xyz456789012345678" not in text


# ---------------------------------------------------------------------------
# lemonade_security_maturity
# ---------------------------------------------------------------------------

def test_maturity_tool_returns_level() -> None:
    text, events = execute_security_tool(
        "lemonade_security_maturity",
        {"events_path": str(FIXTURES / "maturity_foundation.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert "level=" in text
    assert events == []


def test_maturity_tool_adaptive_log() -> None:
    text, _ = execute_security_tool(
        "lemonade_security_maturity",
        {"events_path": str(FIXTURES / "maturity_adaptive.jsonl"), "store_id": "tie-dye-farms"},
    )
    assert "adaptive" in text.lower()


# ---------------------------------------------------------------------------
# lemonade_security_aibom
# ---------------------------------------------------------------------------

def _parse_aibom_text(text: str) -> dict:
    """Strip the status header line before parsing AIBOM JSON."""
    json_part = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
    return json.loads(json_part)


def test_aibom_tool_returns_cyclonedx_json() -> None:
    text, events = execute_security_tool(
        "lemonade_security_aibom",
        {"store_id": "tie-dye-farms"},
    )
    parsed = _parse_aibom_text(text)
    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.6"
    assert events == []


def test_aibom_tool_includes_plugin_component() -> None:
    text, _ = execute_security_tool(
        "lemonade_security_aibom",
        {"store_id": "tie-dye-farms"},
    )
    parsed = _parse_aibom_text(text)
    names = [c["name"] for c in parsed["components"]]
    assert "lemonade-sdk-security" in names
