"""Command-line interface for Lemonade Security."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from lemonade_store.events import dump_event

from lemonade_security.audit import audit_event_log, finding_events, summary_event
from lemonade_security.maturity import score_iam_maturity
from lemonade_security.policy_check import policy_check_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lemonade-security")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="audit a local Lemonade Store JSONL event log")
    audit.add_argument("--events", required=True, help="path to store_events.jsonl or cashier events.jsonl")
    audit.add_argument("--store-id", required=True, help="expected store_id")

    maturity = subparsers.add_parser(
        "maturity",
        help="score a JSONL event log against the IBM IAM-for-AI 4-step maturity model",
    )
    maturity.add_argument(
        "--events",
        required=True,
        help="path to store_events.jsonl",
    )
    maturity.add_argument("--store-id", required=True, help="expected store_id")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "audit":
        result = audit_event_log(args.events, store_id=args.store_id)
        for event in finding_events(result):
            print(dump_event(event))
        for event in policy_check_events(result):
            print(dump_event(event))
        print(dump_event(summary_event(result)))
        return 1 if result.findings else 0

    if args.command == "maturity":
        score = score_iam_maturity(args.events, store_id=args.store_id)
        print(f"level={score.level} ({score.level_name})")
        for line in score.evidence:
            print(line)
        print(f"next: {score.next_step}")
        return 0

    return 2
