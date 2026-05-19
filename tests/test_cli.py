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
