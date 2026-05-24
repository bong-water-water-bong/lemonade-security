"""Tests for the supply chain auditor (lemonade_security.audit_supply_chain)."""

from __future__ import annotations

from lemonade_security.aibom import AibomComponent
from lemonade_security.audit_supply_chain import audit_supply_chain


def test_audit_supply_chain_clean_passes() -> None:
    components = (
        AibomComponent(
            kind="model",
            name="Qwen-7B",
            version="1.0.0",
            supplier="Alibaba",
            location="models/qwen-7b",  # Relative path is ignored in v0.1
        ),
    )
    # Mocking Path.exists for the location check is handled by using a path
    # that doesn't exist but is NOT absolute, or by just accepting it's 
    # not checked for relative paths in v0.1.
    
    findings = audit_supply_chain(components)
    assert findings == []


def test_audit_supply_chain_detects_placeholder_version() -> None:
    components = (
        AibomComponent(
            kind="model",
            name="Placeholder-Model",
            version="0.0.0-placeholder",
            supplier="Unknown",
        ),
    )
    findings = audit_supply_chain(components)
    codes = {f.code for f in findings}
    assert "supply_chain_unversioned" in codes


def test_audit_supply_chain_detects_missing_supplier() -> None:
    components = (
        AibomComponent(
            kind="tool",
            name="Mystery-Tool",
            version="1.2.3",
            supplier=None,
        ),
    )
    findings = audit_supply_chain(components)
    codes = {f.code for f in findings}
    assert "supply_chain_no_supplier" in codes


def test_audit_supply_chain_detects_missing_absolute_location() -> None:
    components = (
        AibomComponent(
            kind="plugin",
            name="Ghost-Plugin",
            version="0.1.0",
            supplier="Ghost",
            location="/tmp/this/path/does/not/exist/ever",
        ),
    )
    findings = audit_supply_chain(components)
    codes = {f.code for f in findings}
    assert "supply_chain_missing_location" in codes
