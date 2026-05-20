"""Filesystem-level secret scanner.

Scans arbitrary files (event logs, ``.env``, config files) for credential
exposure patterns, mapped to OWASP DSGAI02 (Agent Identity and Credential
Exposure).

## OWASP mapping

* ``DSGAI02`` — Do not place credentials or broad tokens in agent payloads,
  logs, or tool metadata.
* ``LLM02:2026`` — Sensitive Information Disclosure.
* ``ASI03`` — Identity and Privilege Abuse.

## Finding codes

* ``bearer_token`` (critical) — RFC 6750 ``Bearer`` header value detected in a
  log line; minimum 20-char token.
* ``jwt`` (critical) — Three base64url segments joined by dots whose first
  segment starts with ``eyJ`` (encoded ``{"``).
* ``env_secret`` (high) — ``.env``-style ``KEY=value`` assignment where the
  key name suggests a secret (``SECRET``, ``PASSWORD``, ``TOKEN``,
  ``API_KEY``, ``PRIVATE_KEY``).
* ``secret_field_name`` (high) — A JSON / JSONL object field whose key name
  (lowercased) is exactly one of ``password``, ``secret``, ``token``,
  ``api_key``, ``private_key``, ``credential`` and whose value is a non-empty
  string.
* ``high_entropy_key`` (high) — A quoted or bare string value of at least
  40 hex characters (potential API key or hash).

## Safety contract

Matched secret values are NEVER stored or returned.  Findings carry only:
``path``, ``line_number``, ``code``, ``severity``, and ``context`` (a key name
or surrounding label, not the secret itself).
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretFinding:
    """A single credential-exposure finding from the filesystem scanner."""

    code: str
    """Pattern type: ``bearer_token``, ``jwt``, ``env_secret``,
    ``secret_field_name``, or ``high_entropy_key``."""

    severity: str
    """``"critical"`` or ``"high"``."""

    path: str
    """Absolute (or caller-supplied) file path.  Never contains the secret."""

    line_number: int
    """1-based line number within *path*."""

    context: str
    """Key name, surrounding label, or brief description.
    MUST NOT contain the matched secret value."""


@dataclass(frozen=True)
class SecretScanResult:
    """Aggregate result from scanning one or more files."""

    paths_checked: int
    findings: tuple[SecretFinding, ...]
    unreadable_paths: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        """Return ``True`` when no findings were emitted and all files were readable."""
        return not self.findings and not self.unreadable_paths


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Bearer token: the header value itself (≥20 chars after "Bearer ")
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9+/=_\-]{20,}")

# JWT shape: three base64url segments; first must start with "eyJ"
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]+"
    r"\.[A-Za-z0-9_\-]+"
    r"\.[A-Za-z0-9_\-]*"
)

# .env-style assignment: SECRET_KEY=... PASSWORD=... TOKEN=... API_KEY=... PRIVATE_KEY=...
# The value must be non-empty (at least one non-whitespace character).
_ENV_SECRET_RE = re.compile(
    r"^(?:export\s+)?"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*=\s*"
    r"(?P<value>\S.*)",
    re.MULTILINE,
)
_ENV_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)(?:_|$)",
    re.IGNORECASE,
)

# High-entropy hex key: ≥40 consecutive hex digits (e.g. API keys / hashes)
_HEX_KEY_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")

# Field names that are always secret-shaped in JSON/JSONL
_SECRET_JSON_KEYS: frozenset[str] = frozenset(
    {"password", "secret", "token", "api_key", "private_key", "credential"}
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_files(paths: list[str | Path]) -> SecretScanResult:
    """Scan *paths* for credential-exposure patterns.

    Each file is scanned line-by-line.  Secret values are never stored;
    findings record only the file path, line number, pattern code, severity,
    and a context label (key name or descriptor).

    Parameters
    ----------
    paths:
        List of file paths to scan (any mix of ``str`` and ``Path``).
    """
    findings: list[SecretFinding] = []
    unreadable: list[str] = []
    paths_checked = 0

    for raw_path in paths:
        p = Path(raw_path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Unreadable file — record path so callers know it was not scanned.
            unreadable.append(str(p))
            continue

        paths_checked += 1
        findings.extend(_scan_text(text, str(p)))

    return SecretScanResult(
        paths_checked=paths_checked,
        findings=tuple(findings),
        unreadable_paths=tuple(unreadable),
    )


def scan_directory(
    root: str | Path,
    *,
    patterns: tuple[str, ...] = ("*.jsonl", "*.env", "*.toml", "*.json"),
) -> SecretScanResult:
    """Recursively scan *root* for files matching *patterns*.

    Parameters
    ----------
    root:
        Directory to scan recursively.
    patterns:
        Glob patterns (``fnmatch``-style) for file names to include.
        Defaults to ``("*.jsonl", "*.env", "*.toml", "*.json")``.
    """
    root_path = Path(root)
    matched: list[Path] = []

    for candidate in root_path.rglob("*"):
        if not candidate.is_file():
            continue
        name = candidate.name
        if any(fnmatch.fnmatch(name, pat) for pat in patterns):
            matched.append(candidate)

    return scan_files([str(p) for p in sorted(matched)])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _scan_text(text: str, path: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    # For .json files, attempt a whole-file parse to catch pretty-printed secrets.
    # Findings from the whole-file parse replace the per-line secret_field_name
    # check so that there is no double-counting.
    whole_file_json_finding: SecretFinding | None = None
    skip_per_line_secret_field = False
    if path.endswith(".json"):
        try:
            obj: Any = json.loads(text)
            key_found = _find_secret_key(obj)
            if key_found is not None:
                whole_file_json_finding = SecretFinding(
                    code="secret_field_name",
                    severity="high",
                    path=path,
                    line_number=1,
                    context=key_found,
                )
            # Whether or not a secret was found, suppress per-line parsing of
            # secret_field_name to avoid double-counting.
            skip_per_line_secret_field = True
        except json.JSONDecodeError:
            pass  # Fall through to line-by-line scanning below

    if whole_file_json_finding is not None:
        findings.append(whole_file_json_finding)

    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(_scan_line(line, path, line_number, skip_secret_field=skip_per_line_secret_field))
    return findings


def _scan_line(
    line: str,
    path: str,
    line_number: int,
    *,
    skip_secret_field: bool = False,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    seen_codes: set[str] = set()  # one finding per code per line is enough
    if skip_secret_field:
        seen_codes.add("secret_field_name")

    # --- 1. Bearer token (critical) ----------------------------------------
    if "bearer_token" not in seen_codes and _BEARER_RE.search(line):
        findings.append(
            SecretFinding(
                code="bearer_token",
                severity="critical",
                path=path,
                line_number=line_number,
                context="Bearer authorization header",
            )
        )
        seen_codes.add("bearer_token")

    # --- 2. JWT (critical) --------------------------------------------------
    if "jwt" not in seen_codes and _JWT_RE.search(line):
        findings.append(
            SecretFinding(
                code="jwt",
                severity="critical",
                path=path,
                line_number=line_number,
                context="JWT token",
            )
        )
        seen_codes.add("jwt")

    # --- 3. .env secret assignment (high) -----------------------------------
    if "env_secret" not in seen_codes:
        env_match = _ENV_SECRET_RE.match(line.strip())
        if env_match:
            key = env_match.group("key")
            if _ENV_SECRET_KEY_RE.search(key):
                findings.append(
                    SecretFinding(
                        code="env_secret",
                        severity="high",
                        path=path,
                        line_number=line_number,
                        context=key,
                    )
                )
                seen_codes.add("env_secret")

    # --- 4. Secret-named JSON field (high) ----------------------------------
    if "secret_field_name" not in seen_codes:
        json_finding = _check_json_secret_fields(line, path, line_number)
        if json_finding is not None:
            findings.append(json_finding)
            seen_codes.add("secret_field_name")

    # --- 5. High-entropy hex key (high) -------------------------------------
    if "high_entropy_key" not in seen_codes and _HEX_KEY_RE.search(line):
        findings.append(
            SecretFinding(
                code="high_entropy_key",
                severity="high",
                path=path,
                line_number=line_number,
                context="high-entropy hex value",
            )
        )
        seen_codes.add("high_entropy_key")

    return findings


def _check_json_secret_fields(
    line: str, path: str, line_number: int
) -> SecretFinding | None:
    """Return a finding if the line is valid JSON containing a secret-named field."""
    stripped = line.strip()
    if not stripped or stripped[0] not in ("{", "["):
        return None
    try:
        obj: Any = json.loads(stripped)
    except json.JSONDecodeError:
        return None

    key_found = _find_secret_key(obj)
    if key_found is None:
        return None

    return SecretFinding(
        code="secret_field_name",
        severity="high",
        path=path,
        line_number=line_number,
        context=key_found,
    )


def _find_secret_key(obj: Any) -> str | None:
    """Return the first secret-named key with a non-empty string value, or None."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _SECRET_JSON_KEYS and isinstance(value, str) and value:
                return key
            # Recurse into nested structures
            nested = _find_secret_key(value)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            nested = _find_secret_key(item)
            if nested is not None:
                return nested
    return None
