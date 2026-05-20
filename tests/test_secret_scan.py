"""Tests for the filesystem-level secret scanner (DSGAI02).

Safety contract: secret values must never appear in finding fields.
All fixtures use fake / placeholder credentials only.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from lemonade_security.secret_scan import (
    SecretFinding,
    SecretScanResult,
    scan_directory,
    scan_files,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _codes(result: SecretScanResult) -> set[str]:
    return {f.code for f in result.findings}


# ---------------------------------------------------------------------------
# scan_files: clean log → no findings
# ---------------------------------------------------------------------------


def test_clean_log_passes(tmp_path: Path) -> None:
    """A log with no secrets produces no findings and passes."""
    result = scan_files([FIXTURES / "scan_clean.jsonl"])

    assert result.passed
    assert result.findings == ()
    assert result.paths_checked == 1


# ---------------------------------------------------------------------------
# scan_files: bearer token
# ---------------------------------------------------------------------------


def test_bearer_token_detected() -> None:
    result = scan_files([FIXTURES / "scan_with_bearer.jsonl"])

    assert "bearer_token" in _codes(result)


def test_bearer_token_severity_is_critical() -> None:
    result = scan_files([FIXTURES / "scan_with_bearer.jsonl"])

    bearer = [f for f in result.findings if f.code == "bearer_token"]
    assert len(bearer) >= 1
    assert all(f.severity == "critical" for f in bearer)


def test_bearer_token_finding_has_path_and_line() -> None:
    result = scan_files([FIXTURES / "scan_with_bearer.jsonl"])

    bearer = [f for f in result.findings if f.code == "bearer_token"]
    assert len(bearer) >= 1
    finding = bearer[0]
    assert finding.path.endswith("scan_with_bearer.jsonl")
    assert finding.line_number == 2  # second line carries the token


# ---------------------------------------------------------------------------
# scan_files: JWT
# ---------------------------------------------------------------------------


def test_jwt_detected() -> None:
    result = scan_files([FIXTURES / "scan_with_jwt.jsonl"])

    assert "jwt" in _codes(result)


def test_jwt_severity_is_critical() -> None:
    result = scan_files([FIXTURES / "scan_with_jwt.jsonl"])

    jwts = [f for f in result.findings if f.code == "jwt"]
    assert len(jwts) >= 1
    assert all(f.severity == "critical" for f in jwts)


def test_jwt_finding_line_number() -> None:
    result = scan_files([FIXTURES / "scan_with_jwt.jsonl"])

    jwts = [f for f in result.findings if f.code == "jwt"]
    assert any(f.line_number == 2 for f in jwts)


# ---------------------------------------------------------------------------
# scan_files: .env secret assignment
# ---------------------------------------------------------------------------


def test_env_secret_detected() -> None:
    result = scan_files([FIXTURES / "scan_with_env_secret.env"])

    assert "env_secret" in _codes(result)


def test_env_secret_count_is_two() -> None:
    """Both SECRET_KEY and DB_PASSWORD must trigger env_secret findings."""
    result = scan_files([FIXTURES / "scan_with_env_secret.env"])

    env_findings = [f for f in result.findings if f.code == "env_secret"]
    assert len(env_findings) == 2


def test_env_secret_context_is_key_name_not_value() -> None:
    result = scan_files([FIXTURES / "scan_with_env_secret.env"])

    env_findings = [f for f in result.findings if f.code == "env_secret"]
    contexts = {f.context for f in env_findings}
    # Contexts should be key names, not secret values
    assert "SECRET_KEY" in contexts or "DB_PASSWORD" in contexts
    assert "fakesecretvalue12345" not in contexts
    assert "notarealpassword99" not in contexts


# ---------------------------------------------------------------------------
# Safety contract: context field must NEVER contain the secret value
# ---------------------------------------------------------------------------


def test_bearer_context_does_not_contain_secret() -> None:
    result = scan_files([FIXTURES / "scan_with_bearer.jsonl"])

    bearer = [f for f in result.findings if f.code == "bearer_token"]
    assert bearer
    for f in bearer:
        assert "sk-abc123xyz456789012345678" not in f.context


def test_jwt_context_does_not_contain_secret() -> None:
    result = scan_files([FIXTURES / "scan_with_jwt.jsonl"])

    jwts = [f for f in result.findings if f.code == "jwt"]
    assert jwts
    for f in jwts:
        # The JWT header, payload, and signature segments must not appear in context
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in f.context
        assert "eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNzE2MjAwMDAwfQ" not in f.context
        assert "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" not in f.context


def test_env_secret_context_does_not_contain_value() -> None:
    result = scan_files([FIXTURES / "scan_with_env_secret.env"])

    env_findings = [f for f in result.findings if f.code == "env_secret"]
    assert env_findings
    for f in env_findings:
        assert "fakesecretvalue12345" not in f.context
        assert "notarealpassword99" not in f.context


def test_no_finding_path_contains_secret_values() -> None:
    """Cross-cutting check: no finding path field contains a secret string."""
    all_secrets = [
        "sk-abc123xyz456789012345678",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "fakesecretvalue12345",
        "notarealpassword99",
    ]
    results = [
        scan_files([FIXTURES / "scan_with_bearer.jsonl"]),
        scan_files([FIXTURES / "scan_with_jwt.jsonl"]),
        scan_files([FIXTURES / "scan_with_env_secret.env"]),
    ]
    for result in results:
        for finding in result.findings:
            for secret in all_secrets:
                assert secret not in finding.path, (
                    f"finding.path leaks secret {secret!r}"
                )
                assert secret not in finding.context, (
                    f"finding.context leaks secret {secret!r} in {finding!r}"
                )


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


def test_scan_directory_clean_only(tmp_path: Path) -> None:
    """Directory with only the clean fixture → no findings."""
    shutil.copy(FIXTURES / "scan_clean.jsonl", tmp_path / "scan_clean.jsonl")

    result = scan_directory(tmp_path, patterns=("*.jsonl",))

    assert result.passed
    assert result.findings == ()
    assert result.paths_checked == 1


def test_scan_directory_clean_and_bearer(tmp_path: Path) -> None:
    """Directory with clean + bearer fixtures → bearer finding present."""
    shutil.copy(FIXTURES / "scan_clean.jsonl", tmp_path / "scan_clean.jsonl")
    shutil.copy(FIXTURES / "scan_with_bearer.jsonl", tmp_path / "scan_with_bearer.jsonl")

    result = scan_directory(tmp_path, patterns=("*.jsonl",))

    assert result.paths_checked == 2
    assert "bearer_token" in _codes(result)
    # Clean file must not inflate the finding count
    bearer_findings = [f for f in result.findings if f.code == "bearer_token"]
    assert len(bearer_findings) >= 1


def test_scan_directory_respects_pattern_filter(tmp_path: Path) -> None:
    """Patterns filter correctly — .env file is excluded when only *.jsonl given."""
    shutil.copy(FIXTURES / "scan_with_env_secret.env", tmp_path / "scan_with_env_secret.env")
    shutil.copy(FIXTURES / "scan_clean.jsonl", tmp_path / "scan_clean.jsonl")

    result = scan_directory(tmp_path, patterns=("*.jsonl",))

    # Only the jsonl file should have been checked; no env_secret findings
    assert result.paths_checked == 1
    assert "env_secret" not in _codes(result)


def test_scan_directory_includes_env_when_pattern_set(tmp_path: Path) -> None:
    """When *.env is in patterns, env secrets are detected."""
    shutil.copy(FIXTURES / "scan_with_env_secret.env", tmp_path / "scan_with_env_secret.env")

    result = scan_directory(tmp_path, patterns=("*.env",))

    assert result.paths_checked == 1
    assert "env_secret" in _codes(result)


# ---------------------------------------------------------------------------
# SecretScanResult.passed property
# ---------------------------------------------------------------------------


def test_result_passed_true_with_no_findings() -> None:
    result = SecretScanResult(paths_checked=3, findings=())
    assert result.passed is True


def test_result_passed_false_with_findings() -> None:
    finding = SecretFinding(
        code="bearer_token",
        severity="critical",
        path="/tmp/fake.jsonl",
        line_number=1,
        context="Bearer authorization header",
    )
    result = SecretScanResult(paths_checked=1, findings=(finding,))
    assert result.passed is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_empty_file_produces_no_findings(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    result = scan_files([empty])

    assert result.passed
    assert result.paths_checked == 1


def test_unreadable_path_is_skipped_gracefully(tmp_path: Path) -> None:
    """A non-existent path is skipped; paths_checked stays 0 and path is recorded."""
    result = scan_files([tmp_path / "does_not_exist.jsonl"])

    assert result.paths_checked == 0
    assert len(result.unreadable_paths) == 1


def test_clean_log_does_not_trigger_on_event_ids(tmp_path: Path) -> None:
    """Normal event-id hex strings shorter than 40 chars do not trigger high_entropy_key."""
    result = scan_files([FIXTURES / "scan_clean.jsonl"])

    assert "high_entropy_key" not in _codes(result)


# ---------------------------------------------------------------------------
# Fix 2: OSError tracking
# ---------------------------------------------------------------------------


def test_unreadable_file_marks_result_as_not_passed() -> None:
    result = scan_files([Path("/nonexistent/path/that/does/not/exist.jsonl")])
    assert not result.passed
    assert len(result.unreadable_paths) == 1


# ---------------------------------------------------------------------------
# Fix 3: Pretty-printed JSON scanning
# ---------------------------------------------------------------------------


def test_pretty_printed_json_file_detects_secret_field() -> None:
    import json
    import os
    import tempfile

    data = {"user": "alice", "password": "supersecret123", "role": "admin"}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = tmp.name
    try:
        result = scan_files([Path(tmp_path)])
        codes = {f.code for f in result.findings}
        assert "secret_field_name" in codes
        # context must not contain the password value
        for f in result.findings:
            assert "supersecret123" not in f.context
    finally:
        os.unlink(tmp_path)
