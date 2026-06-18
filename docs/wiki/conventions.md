# Conventions: Lemonade Security

All development in this repository follows strict standards to keep the security auditing suite simple, robust, deterministic, and local-first.

## Code Style & Formatting

We use **Ruff** for linting and formatting.
- **Line Length**: Capped at 100 characters.
- **Lint Target**: Python 3.11+.
- **Selected Rules**: `E`, `F`, `I` (isort imports), `UP` (pyupgrade), `B` (flake8-bugbear), `SIM` (flake8-simplify).
- **Ignored Rules**: `E501` (Ruff formatting takes priority).

Verify code cleanliness or format files by running:
```bash
make lint
make fmt
```

## Strict Type Safety

We use **mypy** in strict mode to ensure robustness across all audit code.
- **Configuration**: `strict = true` in `pyproject.toml`.
- **Imports**: `from __future__ import annotations` must be present at the top of every file to leverage postponed evaluation of type annotations.
- **Requirements**: Every function/method must be fully typed.

Verify type safety by running:
```bash
make type
```

## Import Policies & Local-First Isolation

To enforce the local-first security default and maintain department boundaries:
- **No Cloud Dependencies**: Never import third-party packages or write code that makes external cloud calls.
- **SSRF Prevention**: The SDK plugin enforces local-only routing via `_assert_localhost` checks. Probing `localhost:13305` in `lemonade_server.py` is the only external probe allowed, and it is strictly constrained to localhost.
- **Zero-Mutation Registry Consumers**: The security department behaves strictly as a read-only consumer of other departments' event logs. It must never rewrite, modify, or mutate input logs.

## Audit Output Conventions

To ensure findings are useful and safe:
- **Redaction of Secrets**: Secrets matched by `audit_credential_replay.py` and `secret_scan.py` must never be stored in finding outputs. Match occurrences are replaced with `<redacted>` or omitted to prevent findings from becoming an exfiltration channel.
- **Deterministic ID Generation**: Finding `event_id` values must be deterministic SHA-256 hashes generated from the `store_id` and finding index, so that re-runs are reproducible and consistent.
- **Dedicated Finding Codes**: Map finding codes to specific OWASP LLM and ASI risk IDs in `owasp.py` instead of generic umbrella codes, enabling granular operator responses.

## Related

- [[README]] — mission and agent handoff
- [[architecture]] — overall system design
- [[runbook]] — command execution and setup
- [[agents]] — agent perimeters and safety rules

