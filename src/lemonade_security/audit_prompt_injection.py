"""Prompt-injection auditor for `agent.proposal` inputs.

OWASP GenAI Security Project's **LLM01:2026 Prompt Injection** names the
input boundary as the canonical AI-application attack surface: attacker
text persuades the model to ignore its system prompt, exfiltrate
context, escalate privilege, or invoke tools it shouldn't. This auditor
scans the *input* side of every `agent.proposal` event for known LLM01
signatures so the operator gets an upstream signal even when the
downstream supervisor handled containment correctly.

## Why per-pattern finding codes

We emit a distinct finding code per pattern category
(`LLM01_system_break`, `LLM01_role_confusion`, `LLM01_exfil_cue`,
`LLM01_encoded_smuggling`, `LLM01_extra_pattern`) rather than a single
umbrella `LLM01_prompt_injection` code. The operator's response to each
is materially different:

* `LLM01_system_break` — an attendant (or whoever supplied the input)
  tried to override the cashier supervisor's system prompt. Possible
  social-engineering or coached customer; investigate the attendant
  session, not the model.
* `LLM01_role_confusion` — chat-template markers or instruction headers
  leaked in. Often indirect: scanned barcode label, OCR output, or a
  copy-pasted ticket. Audit the upstream ingest path.
* `LLM01_exfil_cue` — explicit "send/reveal/exfil" verbs or
  exfiltration URLs. Treat as a high-confidence direct attack.
* `LLM01_encoded_smuggling` — long high-entropy token (base64, hex,
  or similar). Often used to hide a payload from a text-only filter.
* `LLM01_extra_pattern` — operator-supplied regex matched. Up to the
  operator to interpret.

Severity is `high` for the four signature codes that map to direct
attacks; `medium` for the entropy heuristic, which is the most
false-positive-prone.

## Parsing strategy

Mirrors `audit_agent_proposals`: the shared `store.event.v1` envelope
validator (`lemonade_store.events.load_event`) rejects `agent.proposal`
events because the `agent.*` namespace is not registered with any
department in v0.1. Envelope-validated parsing would silently drop the
very events this auditor must read, so we fall back to `json.loads`
per-line and treat each row as a dict. The trade-off is documented
here so the choice is visible at review time — when the v0.1 envelope
grows native support for proposals we should switch back to
`load_event` here.

## Sources

* `GenAI-LLM-Top10/2026/LLM01_PromptInjection.md` — risk anatomy,
  scenarios (Scenario #1 direct injection; Scenario #5 payload
  splitting; Scenario #8 encoded payloads), and the explicit
  invisible-Unicode / encoded-smuggling subclass.
* `GenAI-Agent-Security-Initiative/.../ASI06_Memory_and_Context_Poisoning`
  — cross-references the case where a successful injection lands in
  persistent agent memory.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from lemonade_security.audit import AuditFinding, AuditResult

_PROPOSAL_TYPE = "agent.proposal"

# Maximum number of characters of a matched value that may appear in a
# finding's `message` field. Long matches are replaced by a placeholder
# so we never echo a multi-kilobyte base64 blob into a finding event.
_MAX_VALUE_ECHO = 80

# Minimum length and entropy that together count a token as a
# candidate for encoded smuggling.
_SMUGGLE_MIN_LEN = 40
_SMUGGLE_MIN_ENTROPY = 3.5

# Tokens we split on for the entropy heuristic. We deliberately split on
# whitespace only so a long base64 blob stays as one contiguous token.
_TOKEN_SPLIT_RE = re.compile(r"\s+")


# Pattern categories. Each tuple is (code, severity, label, regex).
_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    # 1. System-prompt break attempts.
    (
        "LLM01_system_break",
        "high",
        "system-prompt break attempt",
        re.compile(
            r"\bignore\s+(the\s+)?(previous|above|prior)\s+(instructions?|rules?|prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LLM01_system_break",
        "high",
        "system-prompt break attempt",
        re.compile(
            r"\b(disregard|forget|override)\s+(all\s+)?(previous|prior|system)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LLM01_system_break",
        "high",
        "system-prompt break attempt",
        re.compile(
            r"\b(you are now|act as|pretend to be)\s+(an?\s+)?"
            r"(unrestricted|jailbroken|admin|root|developer|DAN)\b",
            re.IGNORECASE,
        ),
    ),
    # 2. Role-confusion attacks.
    (
        "LLM01_role_confusion",
        "high",
        "role-confusion marker",
        re.compile(r"<\|?(system|assistant|im_start|im_end)\|?>", re.IGNORECASE),
    ),
    (
        "LLM01_role_confusion",
        "high",
        "role-confusion header",
        re.compile(r"(?:###\s+Instructions|System:)\s*", re.IGNORECASE),
    ),
    (
        "LLM01_role_confusion",
        "high",
        "role-confusion header",
        re.compile(r"\bnew\s+(rules?|instructions?)\s*:", re.IGNORECASE),
    ),
    # 3. Tool / exfiltration cues.
    (
        "LLM01_exfil_cue",
        "high",
        "exfiltration cue",
        re.compile(
            r"\b(print|echo|reveal|show|tell me)\s+(your\s+)?"
            r"(system\s+)?(prompt|instructions|rules)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LLM01_exfil_cue",
        "high",
        "exfiltration cue",
        re.compile(
            r"\bsend\s+(the|your|all)\s+(data|history|context|tokens?)\s+to\b",
            re.IGNORECASE,
        ),
    ),
    (
        "LLM01_exfil_cue",
        "high",
        "exfiltration URL",
        re.compile(
            r"\b(?:curl|wget|http://\S+|https://\S+/exfil\S*)",
            re.IGNORECASE,
        ),
    ),
)


def audit_prompt_injection(
    path: str | Path,
    *,
    store_id: str,
    extra_patterns: tuple[str, ...] = (),
) -> AuditResult:
    """Audit a JSONL event log for OWASP LLM01 prompt-injection signatures.

    Parameters
    ----------
    path:
        Path to a `store_events.jsonl` log.
    store_id:
        Expected `store_id` — recorded on the returned `AuditResult` for
        traceability; envelope-level store mismatch is the job of
        `audit_event_log`, not this auditor.
    extra_patterns:
        Optional tuple of regex strings the operator can supply to flag
        site-specific injection signatures without modifying this
        module. Each match fires a `LLM01_extra_pattern` finding at
        `high` severity. Compiled with `re.IGNORECASE`.

    Returns
    -------
    AuditResult
        `checked_events` counts `agent.proposal` events scanned.
        Findings are emitted at most once per (event, code, JSON path,
        pattern) tuple to avoid duplicate signals when the same value
        matches more than one regex in the same category.
    """
    findings: list[AuditFinding] = []
    checked_events = 0

    compiled_extras = tuple(re.compile(pat, re.IGNORECASE) for pat in extra_patterns)

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                # `audit_event_log` owns envelope-level parse failures;
                # this auditor stays focused on its detection job.
                continue
            if not isinstance(raw, dict):
                continue
            if raw.get("type") != _PROPOSAL_TYPE:
                continue

            checked_events += 1
            payload = raw.get("payload") or {}
            if not isinstance(payload, dict):
                continue

            event_id = _event_id_of(raw)
            findings.extend(
                _scan_payload(
                    payload,
                    line_number=line_number,
                    event_id=event_id,
                    extra_patterns=compiled_extras,
                )
            )

    return AuditResult(
        store_id=store_id,
        checked_events=checked_events,
        findings=tuple(findings),
    )


def _scan_payload(
    payload: dict[str, Any],
    *,
    line_number: int,
    event_id: str | None,
    extra_patterns: tuple[re.Pattern[str], ...],
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    seen: set[tuple[str, str, str]] = set()

    for path_str, value in _walk_strings(payload, prefix=""):
        for code, severity, label, pattern in _PATTERNS:
            if pattern.search(value):
                key = (code, path_str, label)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    AuditFinding(
                        code=code,
                        severity=severity,
                        message=_format_message(label, path_str, value),
                        line_number=line_number,
                        event_id=event_id,
                    )
                )

        for pattern in extra_patterns:
            if pattern.search(value):
                key = ("LLM01_extra_pattern", path_str, pattern.pattern)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    AuditFinding(
                        code="LLM01_extra_pattern",
                        severity="high",
                        message=_format_message(
                            f"operator pattern {pattern.pattern!r}",
                            path_str,
                            value,
                        ),
                        line_number=line_number,
                        event_id=event_id,
                    )
                )

        if _looks_encoded(value):
            key = ("LLM01_encoded_smuggling", path_str, "entropy")
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                AuditFinding(
                    code="LLM01_encoded_smuggling",
                    severity="medium",
                    message=_format_message(
                        "encoded-smuggling candidate",
                        path_str,
                        value,
                    ),
                    line_number=line_number,
                    event_id=event_id,
                )
            )

    return findings


def _walk_strings(value: Any, *, prefix: str) -> Iterable[tuple[str, str]]:
    """Yield `(json_path, string_value)` tuples for every string in a payload."""
    if isinstance(value, str):
        yield prefix or "<root>", value
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            new_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_strings(nested, prefix=new_prefix)
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            new_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from _walk_strings(nested, prefix=new_prefix)
        return
    # numbers, bools, None — nothing to scan.


def _format_message(label: str, path_str: str, value: str) -> str:
    safe = _truncated(value)
    return f"{label} at {path_str}: {safe}"


def _truncated(value: str) -> str:
    if len(value) <= _MAX_VALUE_ECHO:
        return repr(value)
    return f"<truncated, {len(value)} chars>"


def _looks_encoded(value: str) -> bool:
    """Heuristic: is there a long high-entropy contiguous token in `value`?"""
    for token in _TOKEN_SPLIT_RE.split(value):
        if len(token) < _SMUGGLE_MIN_LEN:
            continue
        if _shannon_entropy(token) >= _SMUGGLE_MIN_ENTROPY:
            return True
    return False


def _shannon_entropy(token: str) -> float:
    counts = Counter(token)
    length = len(token)
    if length == 0:
        return 0.0
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _event_id_of(raw: dict[str, Any]) -> str | None:
    value = raw.get("event_id")
    if isinstance(value, str):
        return value
    return None
