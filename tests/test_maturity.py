from __future__ import annotations

from pathlib import Path

from lemonade_security.cli import main
from lemonade_security.maturity import (
    MaturityScore,
    score_iam_maturity,
)

FIXTURES = Path(__file__).parent / "fixtures"

# next_step phrasings are asserted exactly so they cannot silently drift.
NEXT_STEP_TO_FOUNDATION = (
    "assign a non-human agent_id to every agent.proposal event "
    "(Foundation: non-human identities + basic delegation + audit log)."
)
NEXT_STEP_TO_ENHANCED = (
    "mint a per-task delegation_id on every agent.proposal and propagate it "
    "to the matching cart.add/cart.remove_* event "
    "(Enhanced: ephemeral, transaction-scoped credentials)."
)
NEXT_STEP_TO_ADAPTIVE = (
    "emit security.revocation.created when anomalies are detected "
    "(Adaptive: real-time revocation)."
)
NEXT_STEP_AT_TOP = "no further IAM maturity step is defined in the IBM 4-step model."


def test_empty_log_is_ad_hoc(tmp_path: Path) -> None:
    log = tmp_path / "empty.jsonl"
    log.write_text("", encoding="utf-8")

    score = score_iam_maturity(log, store_id="tie-dye-farms")

    assert isinstance(score, MaturityScore)
    assert score.level == 1
    assert score.level_name == "ad-hoc"
    assert score.evidence == ()
    assert score.next_step == NEXT_STEP_TO_FOUNDATION


def test_ad_hoc_log_has_no_proposals() -> None:
    score = score_iam_maturity(FIXTURES / "maturity_adhoc.jsonl", store_id="tie-dye-farms")

    assert score.level == 1
    assert score.level_name == "ad-hoc"
    assert score.next_step == NEXT_STEP_TO_FOUNDATION


def test_partial_agent_id_is_still_ad_hoc() -> None:
    # One proposal has agent_id, one doesn't — mixed log stays at level 1.
    score = score_iam_maturity(
        FIXTURES / "maturity_foundation_partial.jsonl", store_id="tie-dye-farms"
    )

    assert score.level == 1
    assert score.next_step == NEXT_STEP_TO_FOUNDATION


def test_foundation_log_just_barely_qualifies() -> None:
    score = score_iam_maturity(
        FIXTURES / "maturity_foundation.jsonl", store_id="tie-dye-farms"
    )

    assert score.level == 2
    assert score.level_name == "foundation"
    assert any("agent.proposal" in line and "agent_id" in line for line in score.evidence)
    assert score.next_step == NEXT_STEP_TO_ENHANCED


def test_enhanced_log_just_barely_qualifies() -> None:
    score = score_iam_maturity(
        FIXTURES / "maturity_enhanced.jsonl", store_id="tie-dye-farms"
    )

    assert score.level == 3
    assert score.level_name == "enhanced"
    assert any("delegation_id" in line for line in score.evidence)
    assert score.next_step == NEXT_STEP_TO_ADAPTIVE


def test_orphan_cart_event_blocks_enhanced() -> None:
    # A model_proposed cart event without a matching delegation_id is the
    # one condition short of enhanced — the log stays at foundation.
    score = score_iam_maturity(
        FIXTURES / "maturity_enhanced_orphan.jsonl", store_id="tie-dye-farms"
    )

    assert score.level == 2
    assert score.next_step == NEXT_STEP_TO_ENHANCED


def test_adaptive_log_just_barely_qualifies() -> None:
    score = score_iam_maturity(
        FIXTURES / "maturity_adaptive.jsonl", store_id="tie-dye-farms"
    )

    assert score.level == 4
    assert score.level_name == "adaptive"
    assert any("security.revocation.created" in line for line in score.evidence)
    assert score.next_step == NEXT_STEP_AT_TOP


def test_evidence_lines_are_short_and_one_per_condition() -> None:
    score = score_iam_maturity(
        FIXTURES / "maturity_adaptive.jsonl", store_id="tie-dye-farms"
    )

    assert len(score.evidence) == 3  # one line per condition met (L2, L3, L4).
    for line in score.evidence:
        assert "\n" not in line
        assert len(line) <= 200


def test_score_is_immutable() -> None:
    score = score_iam_maturity(FIXTURES / "maturity_adhoc.jsonl", store_id="tie-dye-farms")

    # frozen dataclass — assignment must raise.
    try:
        score.level = 4  # type: ignore[misc]
    except Exception:  # noqa: BLE001
        pass
    else:
        raise AssertionError("MaturityScore should be frozen")


def test_cli_maturity_prints_level_and_next_step(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(
        [
            "maturity",
            "--events",
            str(FIXTURES / "maturity_enhanced.jsonl"),
            "--store-id",
            "tie-dye-farms",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "level=3" in output
    assert "enhanced" in output
    assert "next:" in output
    assert NEXT_STEP_TO_ADAPTIVE in output


def test_cli_maturity_ad_hoc(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(
        [
            "maturity",
            "--events",
            str(FIXTURES / "maturity_adhoc.jsonl"),
            "--store-id",
            "tie-dye-farms",
        ]
    )

    assert code == 0
    output = capsys.readouterr().out
    assert "level=1" in output
    assert "ad-hoc" in output
    assert NEXT_STEP_TO_FOUNDATION in output


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    log = tmp_path / "noisy.jsonl"
    log.write_text(
        "not json at all\n"
        '{"schema_version":"store.event.v1","event_id":"evt-x","ts":"2026-05-19T18:30:00Z","store_id":"tie-dye-farms","department":"cashier","type":"agent.proposal","source":"lemonade-cashier","actor":{"kind":"agent_auto","id":"cashier.supervisor"},"requires_approval":false,"approved_by":null,"payload":{"agent":"lemonade","agent_id":"lemonade@http://127.0.0.1:8000#qwen3:4b","kind":"normalize","input":"x","output":"y","confidence":0.5,"decision":"accepted"}}\n',
        encoding="utf-8",
    )

    score = score_iam_maturity(log, store_id="tie-dye-farms")

    # The malformed line is dropped; the one valid agent.proposal carries
    # the log to Foundation.
    assert score.level == 2
