"""Command-line interface for Lemonade Security."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from lemonade_store.events import dump_event

from lemonade_security.aibom import AibomComponent, local_manifest, to_cyclonedx_json
from lemonade_security.audit import audit_event_log, finding_events, summary_event
from lemonade_security.audit_supply_chain import audit_supply_chain
from lemonade_security.drift import scan_permission_drift
from lemonade_security.lemonade_server import (
    DEFAULT_URL,
    list_downloaded_models,
    models_to_components,
    probe_server,
)
from lemonade_security.maturity import score_iam_maturity
from lemonade_security.policy_check import policy_check_events
from lemonade_security.secret_scan import scan_directory


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

    drift = subparsers.add_parser("drift", help="scan an event log for department permission drift")
    drift.add_argument("--events", required=True, help="path to store_events.jsonl")
    drift.add_argument("--store-id", required=True, help="expected store_id")

    secrets = subparsers.add_parser("secrets", help="scan a directory for credential exposure")
    secrets.add_argument("--scan-root", required=True, help="directory to scan")
    secrets.add_argument("--pattern", action="append", help="glob pattern to include (repeatable)")

    aibom = subparsers.add_parser("aibom", help="generate a CycloneDX 1.6-compatible AIBOM manifest")
    aibom.add_argument("--store-id", required=True, help="store identifier for the manifest")
    aibom.add_argument("--server-url", default=DEFAULT_URL, help=f"Lemonade Server URL (default: {DEFAULT_URL})")

    audit_aibom = subparsers.add_parser("audit-aibom", help="audit the AIBOM for supply-chain risks")
    audit_aibom.add_argument("--store-id", required=True, help="store identifier to audit")
    audit_aibom.add_argument("--server-url", default=DEFAULT_URL, help=f"Lemonade Server URL (default: {DEFAULT_URL})")

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

    if args.command == "drift":
        result = scan_permission_drift(args.events, store_id=args.store_id)
        print(f"drift: {result.checked_events} events checked, {len(result.findings)} finding(s)")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.code} (line {finding.line_number}): {finding.message}")
        return 1 if result.findings else 0

    if args.command == "secrets":
        patterns = tuple(args.pattern) if args.pattern else None
        if patterns:
            result = scan_directory(args.scan_root, patterns=patterns)
        else:
            result = scan_directory(args.scan_root)
        print(f"secrets: {result.paths_checked} files checked, {len(result.findings)} finding(s)")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.code} at {finding.path}:{finding.line_number}")
        if result.unreadable_paths:
            print(f"  unreadable: {', '.join(result.unreadable_paths)}")
        return 1 if result.findings else 0

    if args.command == "aibom":
        components = _get_cli_components(args.server_url)
        manifest = local_manifest(store_id=args.store_id, components=components)
        print(to_cyclonedx_json(manifest))
        return 0

    if args.command == "audit-aibom":
        components = _get_cli_components(args.server_url)
        findings = audit_supply_chain(components)
        print(f"aibom-audit: {len(components)} component(s) checked, {len(findings)} finding(s)")
        for f in findings:
            print(f"  [{f.severity}] {f.code} ({f.component_name}): {f.message}")
        return 1 if findings else 0

    return 2


def _get_cli_components(server_url: str) -> tuple[AibomComponent, ...]:
    static_components = (
        AibomComponent(
            kind="plugin",
            name="lemonade-sdk-security",
            version="0.1.0",
            supplier="lemonade-security",
            location="plugins/lemonade-sdk-security",
        ),
        AibomComponent(
            kind="department",
            name="lemonade-security",
            version="0.1.0",
            supplier="lemonade-security",
            location="src/lemonade_security",
        ),
    )
    status = probe_server(server_url)
    if status.online:
        models = list_downloaded_models(server_url)
        return static_components + models_to_components(models)
    return static_components
