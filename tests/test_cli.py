from __future__ import annotations

from pathlib import Path

from lemonade_security.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_returns_zero_for_clean_log(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["audit", "--events", str(FIXTURES / "store_events.jsonl"), "--store-id", "tie-dye-farms"])

    assert code == 0
    output = capsys.readouterr().out
    assert "security.audit.completed" in output


def test_cli_returns_one_for_findings(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["audit", "--events", str(FIXTURES / "bad_events.jsonl"), "--store-id", "tie-dye-farms"])

    assert code == 1
    output = capsys.readouterr().out
    assert "security.finding.created" in output


def test_cli_drift_detects_violations(capsys) -> None:  # type: ignore[no-untyped-def]
    # drift_namespace_violation.jsonl has exactly one namespace violation
    code = main(["drift", "--events", str(FIXTURES / "drift_namespace_violation.jsonl"), "--store-id", "tie-dye-farms"])

    assert code == 1
    output = capsys.readouterr().out
    assert "drift: 1 events checked, 1 finding(s)" in output
    assert "[high] namespace_violation" in output


def test_cli_secrets_scan_finds_credentials(capsys) -> None:  # type: ignore[no-untyped-def]
    # fixtures directory contains .jsonl files with secrets
    code = main(["secrets", "--scan-root", str(FIXTURES)])

    assert code == 1
    output = capsys.readouterr().out
    assert "secrets:" in output
    assert "finding(s)" in output
    assert "[critical] jwt" in output or "[critical] bearer_token" in output


def test_cli_aibom_produces_json(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["aibom", "--store-id", "tie-dye-farms"])

    assert code == 0
    output = capsys.readouterr().out
    assert '"bomFormat": "CycloneDX"' in output
    assert '"specVersion": "1.6"' in output
    assert '"name": "lemonade-security"' in output


def test_cli_audit_aibom_passes_for_defaults(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["audit-aibom", "--store-id", "tie-dye-farms"])

    assert code == 0
    output = capsys.readouterr().out
    assert "component(s) checked, 0 finding(s)" in output
