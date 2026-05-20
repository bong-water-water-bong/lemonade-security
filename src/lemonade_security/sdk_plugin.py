"""Lemonade SDK security plugin.

Exposes Lemonade Security capabilities as OpenAI function-calling tool
definitions that any LLM hosted on a Lemonade Server can invoke.

## Design rules

- Read-only by default: no tool mutates another department's data.
- No cloud calls: all checks run against local files and the local
  department registry.
- Thin wrapper: each tool calls an existing ``lemonade_security`` API
  and formats the result as a short text summary for the LLM.
- Side-effect free: ``execute_security_tool`` returns ``security.*``
  events as data; the caller decides whether to persist them.
- Owner-gated: export and sharing actions are not exposed as tools here;
  they require a separate owner-approval event per AGENTS.md rule 5.

## Usage with Lemonade Server

    from lemonade_security.sdk_plugin import SECURITY_TOOLS, execute_security_tool
    from openai import OpenAI

    client = OpenAI(base_url="http://localhost:13305/v1", api_key="not-needed")
    response = client.chat.completions.create(
        model="<any-installed-model>",
        messages=[...],
        tools=SECURITY_TOOLS,
    )
    for tool_call in response.choices[0].message.tool_calls or []:
        import json
        args = json.loads(tool_call.function.arguments)
        text, events = execute_security_tool(tool_call.function.name, args)
        # feed text back to the LLM, optionally persist events
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lemonade_store.events import Event

from lemonade_security.audit import AuditResult, audit_event_log, finding_events, summary_event
from lemonade_security.aibom import AibomComponent, local_manifest, to_cyclonedx_json
from lemonade_security.drift import DriftResult, scan_permission_drift
from lemonade_security.maturity import MaturityScore, score_iam_maturity
from lemonade_security.policy_check import policy_check_events
from lemonade_security.secret_scan import SecretScanResult, scan_directory, scan_files


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling schema)
# ---------------------------------------------------------------------------

SECURITY_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "lemonade_security_audit",
            "description": (
                "Audit a Lemonade Store JSONL event log for security policy violations. "
                "Returns a summary of findings and per-policy pass/fail results. "
                "Read-only. No cloud calls."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "events_path": {
                        "type": "string",
                        "description": "Absolute path to a store_events.jsonl or cashier events.jsonl file.",
                    },
                    "store_id": {
                        "type": "string",
                        "description": "Expected store_id for the event log (e.g. 'tie-dye-farms').",
                    },
                },
                "required": ["events_path", "store_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lemonade_security_drift",
            "description": (
                "Scan a Lemonade Store JSONL event log for department permission drift: "
                "events writing outside their namespace, approval gates bypassed, or "
                "unknown departments. Read-only. No cloud calls."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "events_path": {
                        "type": "string",
                        "description": "Absolute path to a store_events.jsonl file.",
                    },
                    "store_id": {
                        "type": "string",
                        "description": "Expected store_id for the event log.",
                    },
                },
                "required": ["events_path", "store_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lemonade_security_secrets",
            "description": (
                "Scan a local directory for credential exposure in event logs, "
                ".env files, and config files. Reports finding locations and "
                "pattern types only — never the secret values themselves. "
                "Read-only. No cloud calls. Maps to OWASP DSGAI02."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_root": {
                        "type": "string",
                        "description": "Absolute path to the directory to scan.",
                    },
                    "patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Glob patterns to include (default: "
                            "['*.jsonl', '*.env', '*.toml', '*.json'])."
                        ),
                    },
                },
                "required": ["scan_root"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lemonade_security_maturity",
            "description": (
                "Score a Lemonade Store event log against the IBM IAM-for-AI "
                "4-step maturity model. Returns the achieved level (1–4), "
                "evidence from the log, and the next recommended step. "
                "Read-only. No cloud calls."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "events_path": {
                        "type": "string",
                        "description": "Absolute path to a store_events.jsonl file.",
                    },
                    "store_id": {
                        "type": "string",
                        "description": "Expected store_id for the event log.",
                    },
                },
                "required": ["events_path", "store_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lemonade_security_aibom",
            "description": (
                "Generate a CycloneDX 1.6-compatible AI Bill of Materials manifest "
                "for the local Lemonade Security installation. Lists models, tools, "
                "plugins, and department repos. Read-only. No cloud calls. "
                "Maps to OWASP LLM03:2026 (Supply Chain)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "store_id": {
                        "type": "string",
                        "description": "Store identifier to include in the manifest.",
                    },
                },
                "required": ["store_id"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class SecurityToolError(ValueError):
    """Raised when a tool name is unknown or arguments are invalid."""


def execute_security_tool(
    name: str,
    arguments: dict[str, Any],
) -> tuple[str, list[Event]]:
    """Execute a named Lemonade Security tool.

    Parameters
    ----------
    name:
        One of the tool names declared in ``SECURITY_TOOLS``.
    arguments:
        Parsed JSON arguments from the LLM tool call.

    Returns
    -------
    text:
        A short plain-text summary suitable for feeding back to the LLM
        as the tool result.
    events:
        Zero or more ``security.*`` store events emitted by the tool.
        The caller is responsible for persisting these.

    Raises
    ------
    SecurityToolError
        When *name* is not a registered tool.
    """
    dispatch = {
        "lemonade_security_audit": _run_audit,
        "lemonade_security_drift": _run_drift,
        "lemonade_security_secrets": _run_secrets,
        "lemonade_security_maturity": _run_maturity,
        "lemonade_security_aibom": _run_aibom,
    }
    fn = dispatch.get(name)
    if fn is None:
        raise SecurityToolError(f"unknown security tool: {name!r}")
    return fn(arguments)


# ---------------------------------------------------------------------------
# Individual tool runners
# ---------------------------------------------------------------------------

def _run_audit(args: dict[str, Any]) -> tuple[str, list[Event]]:
    events_path = args["events_path"]
    store_id = args["store_id"]

    result: AuditResult = audit_event_log(events_path, store_id=store_id)

    lines = [
        f"audit: {result.checked_events} events checked, "
        f"{len(result.findings)} finding(s), "
        f"{'PASSED' if result.passed else 'FAILED'}",
    ]
    for finding in result.findings:
        lines.append(f"  [{finding.severity}] {finding.code}: {finding.message}")

    emitted: list[Event] = []
    emitted.extend(finding_events(result))
    emitted.extend(policy_check_events(result))
    emitted.append(summary_event(result))

    return "\n".join(lines), emitted


def _run_drift(args: dict[str, Any]) -> tuple[str, list[Event]]:
    events_path = args["events_path"]
    store_id = args["store_id"]

    result: DriftResult = scan_permission_drift(events_path, store_id=store_id)

    lines = [
        f"drift: {result.checked_events} events checked, "
        f"{len(result.findings)} drift finding(s), "
        f"{'PASSED' if result.passed else 'FAILED'}",
    ]
    for finding in result.findings:
        lines.append(f"  [{finding.severity}] {finding.code}: {finding.message}")

    return "\n".join(lines), []


def _run_secrets(args: dict[str, Any]) -> tuple[str, list[Event]]:
    scan_root = args["scan_root"]
    patterns = args.get("patterns")

    if patterns is not None:
        result: SecretScanResult = scan_directory(
            scan_root, patterns=tuple(patterns)
        )
    else:
        result = scan_directory(scan_root)

    lines = [
        f"secret-scan: {result.paths_checked} file(s) checked, "
        f"{len(result.findings)} finding(s), "
        f"{'PASSED' if result.passed else 'FAILED'}",
    ]
    for finding in result.findings:
        # Never include context that could leak a secret value — report
        # path, line, and code only.
        lines.append(
            f"  [{finding.severity}] {finding.code} "
            f"at {finding.path}:{finding.line_number}"
        )
    if result.unreadable_paths:
        lines.append(f"  unreadable: {', '.join(result.unreadable_paths)}")

    return "\n".join(lines), []


def _run_maturity(args: dict[str, Any]) -> tuple[str, list[Event]]:
    events_path = args["events_path"]
    store_id = args["store_id"]

    score: MaturityScore = score_iam_maturity(events_path, store_id=store_id)

    lines = [f"maturity: level={score.level} ({score.level_name})"]
    lines.extend(f"  {e}" for e in score.evidence)
    lines.append(f"  next: {score.next_step}")

    return "\n".join(lines), []


def _run_aibom(args: dict[str, Any]) -> tuple[str, list[Event]]:
    store_id = args["store_id"]

    # Default local inventory — thin, no filesystem discovery in v0.1.
    components = (
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

    manifest = local_manifest(store_id=store_id, components=components)
    text = to_cyclonedx_json(manifest)

    return text, []
