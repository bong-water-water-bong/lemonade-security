"""Credential-replay auditor.

This auditor scans a JSONL store event log for `agent.proposal` events
whose `payload.input` (or any nested value inside the payload) carries
credential-shaped strings — bearer tokens, JWTs, PINs, or values keyed
by secret-shaped names like ``password`` / ``api_key``. The threat
model comes from IBM's "Agentic Trust" talk (lUQ2NKkCW_Q): a bad actor
extracts an identity token from the model's memory or input and
**replays** it elsewhere.

The cashier already mitigates this at *write* time
(`lemonade_client.py` never serializes identifiers or PINs). This
auditor verifies it at *read* time — every `agent.proposal` payload is
walked and any value matching a credential shape is flagged with the
JSON path that contained it. The secret value itself is never copied
into the finding message; the substring `<redacted>` stands in.

## Finding codes

Each pattern produces a distinct code so downstream policy hooks can
react with different severities or routing:

* ``LLM02_bearer_token`` — RFC 6750 `Bearer` headers, OAuth tokens,
  and well-known secret prefixes (Stripe, GitHub, Slack, AWS, Google,
  generic ``sk-``).
* ``LLM02_jwt`` — three-segment base64url strings whose first segment
  decodes to a JSON object with ``alg`` or ``typ`` keys.
* ``LLM02_pin`` — ``pin=NNNN``-shaped substrings (PINs are short
  numeric secrets, too small for entropy heuristics).
* ``LLM02_secret_field`` — values nested under keys named
  ``password``, ``passwd``, ``secret``, ``api_key``, ``apikey``, or
  ``token`` (case-insensitive). Even an empty value on such a field is
  leak-shaped: the field should not have existed in the input.

All four codes map to LLM02:2026 (Sensitive Information Disclosure)
and ASI03 (Identity and Privilege Abuse) in
`lemonade_security.owasp`.

The umbrella code ``LLM02_credential_leak`` is reserved for future
generic matches (e.g. high-entropy hex strings) but is *not* used by
the default ruleset because `delegation_id` values are also 32 hex
chars and the per-pattern codes give cleaner signal.

## Parsing strategy

Like `audit_agent_proposals`, this auditor falls back to `json.loads`
per line: the shared `store.event.v1` envelope validator rejects
events with a `type` outside its department's namespace (including
`agent.proposal`), so envelope-validated parsing would silently drop
the very events we need to read.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from lemonade_security.audit import AuditFinding, AuditResult

_PROPOSAL_TYPE = "agent.proposal"

# Well-known secret-token prefixes treated as bearer/OAuth-class credentials.
# The list is duplicated in `_TOKEN_PREFIX_RE` below; keep them aligned.
_TOKEN_PREFIXES: tuple[str, ...] = (
    "sk-",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "AIza",
    "AGNT",
)

# RFC 6750-style `Bearer <token>` / `Token <token>` / `Basic <token>`.
_BEARER_RE = re.compile(r"\b(?:Bearer|Token|Basic)\s+[A-Za-z0-9._\-+/=]{16,}")

# Well-known secret-token prefixes detected anywhere in a string (not just
# at offset 0): a leaked Stripe key embedded in a "customer paid with ..."
# note is still a leak. Built from `_TOKEN_PREFIXES` at import time.
_TOKEN_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    + "|".join(re.escape(prefix) for prefix in _TOKEN_PREFIXES)
    + r")[A-Za-z0-9_\-]{8,}"
)

# JWT shape pre-filter: three base64url-safe segments separated by dots.
# Each segment must be at least 2 chars to weed out trivial dotted names.
_JWT_SHAPE_RE = re.compile(r"\b[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\b")

# `pin = 1234` / `pin: 1234` / `PIN=1234567`, etc.
_PIN_RE = re.compile(r"\bpin\s*[:=]\s*\d{4,8}\b", re.IGNORECASE)

# Key names whose *value* is leak-shaped regardless of content.
_SECRET_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
    }
)


def audit_credential_replay(
    path: str | Path,
    *,
    store_id: str,
    allow_substrings: frozenset[str] = frozenset(),
) -> AuditResult:
    """Audit a JSONL event log for credential / identity token leakage.

    Parameters
    ----------
    path:
        Path to a `store_events.jsonl` log.
    store_id:
        Expected ``store_id`` — recorded on the returned `AuditResult`
        for traceability; envelope-level store mismatch is the job of
        `audit_event_log`, not this auditor.
    allow_substrings:
        Set of substrings that mark a value as cleared. Any matched
        value containing any of these substrings is treated as a test
        placeholder and no finding is emitted. Default: empty.
    """
    findings: list[AuditFinding] = []
    checked_events = 0

    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                # `audit_event_log` owns envelope-level parse failures;
                # we just skip unreadable lines so this auditor stays
                # focused on the credential-shape job.
                continue
            if not isinstance(raw, dict):
                continue
            checked_events += 1
            if raw.get("type") != _PROPOSAL_TYPE:
                continue

            payload = raw.get("payload")
            if not isinstance(payload, dict):
                continue

            event_id = _event_id_of(raw)
            known_delegation = payload.get("delegation_id")
            known_delegation_str = (
                known_delegation if isinstance(known_delegation, str) else None
            )

            findings.extend(
                _scan_payload(
                    payload,
                    event_id=event_id,
                    line_number=line_number,
                    allow_substrings=allow_substrings,
                    known_delegation=known_delegation_str,
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
    event_id: str | None,
    line_number: int,
    allow_substrings: frozenset[str],
    known_delegation: str | None,
) -> Iterator[AuditFinding]:
    for path_parts, key, value in _walk(payload):
        # Secret-named field check fires on the *key*, even for empty
        # / non-string values.
        if (
            key is not None
            and key.lower() in _SECRET_FIELD_NAMES
            and not _is_allowlisted(value, allow_substrings)
        ):
            yield AuditFinding(
                code="LLM02_secret_field",
                severity="high",
                message=(
                    f"secret-named field {key!r} present in agent.proposal "
                    f"payload at {_join_path(path_parts)} "
                    "(value <redacted>)"
                ),
                line_number=line_number,
                event_id=event_id,
            )
            # Don't double-fire pattern checks on the same value when
            # the field name already condemned it.
            continue

        if not isinstance(value, str):
            continue
        if _is_allowlisted(value, allow_substrings):
            continue
        # `delegation_id` is the same payload's own identifier — not a
        # leaked secret. Allowlist it explicitly when scanning siblings.
        if known_delegation is not None and value == known_delegation:
            continue

        # Bearer / OAuth token shape.
        if _BEARER_RE.search(value) or _TOKEN_PREFIX_RE.search(value):
            yield AuditFinding(
                code="LLM02_bearer_token",
                severity="high",
                message=(
                    f"bearer or OAuth token shape at {_join_path(path_parts)} "
                    "(value <redacted>)"
                ),
                line_number=line_number,
                event_id=event_id,
            )
            continue

        # JWT shape — only attempt base64url decode when the regex
        # pre-filter matches, to keep the scan O(n).
        if _JWT_SHAPE_RE.search(value) and _looks_like_jwt(value):
            yield AuditFinding(
                code="LLM02_jwt",
                severity="high",
                message=(
                    f"JWT-shaped token at {_join_path(path_parts)} "
                    "(value <redacted>)"
                ),
                line_number=line_number,
                event_id=event_id,
            )
            continue

        # PIN substring.
        if _PIN_RE.search(value):
            yield AuditFinding(
                code="LLM02_pin",
                severity="high",
                message=(
                    f"PIN-shaped substring at {_join_path(path_parts)} "
                    "(value <redacted>)"
                ),
                line_number=line_number,
                event_id=event_id,
            )
            continue


def _walk(
    value: Any,
    parts: tuple[str, ...] = ("input",),
) -> Iterator[tuple[tuple[str, ...], str | None, Any]]:
    """Yield ``(path_parts, key, value)`` for every value in *value*.

    The leading path part is ``"input"`` so finding messages read
    naturally: ``input.headers.Authorization``. ``key`` is the dict
    key that produced *value* (None for list elements and the root).
    """
    if isinstance(value, dict):
        for key, nested in value.items():
            key_str = str(key)
            child_parts = (*parts, key_str)
            yield child_parts, key_str, nested
            yield from _walk(nested, child_parts)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            child_parts = (*parts, f"[{index}]")
            yield child_parts, None, nested
            yield from _walk(nested, child_parts)


def _join_path(parts: tuple[str, ...]) -> str:
    out: list[str] = []
    for part in parts:
        if part.startswith("["):
            out.append(part)
        else:
            out.append(("." if out else "") + part)
    return "".join(out)


def _looks_like_jwt(value: str) -> bool:
    """Return True if *value* contains a JWT-shaped substring whose first
    base64url segment decodes to a JSON object with ``alg`` or ``typ``.
    """
    match = _JWT_SHAPE_RE.search(value)
    if match is None:
        return False
    candidate = match.group(0)
    header_segment = candidate.split(".", 1)[0]
    # base64url padding: pad to a multiple of 4.
    padded = header_segment + "=" * (-len(header_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError):
        return False
    try:
        header = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(header, dict):
        return False
    return "alg" in header or "typ" in header


def _is_allowlisted(value: Any, allow_substrings: frozenset[str]) -> bool:
    if not allow_substrings:
        return False
    if not isinstance(value, str):
        return False
    return any(needle in value for needle in allow_substrings)


def _event_id_of(raw: dict[str, Any]) -> str | None:
    value = raw.get("event_id")
    if isinstance(value, str):
        return value
    return None
