# Runbook: Lemonade Security

This runbook covers how to run, test, verify, and operate the `lemonade-security` package and its command-line interface.

## Local Verification Commands

To perform quality checks, run:

- **All Quality Checks**: Runs linting, typechecking, and tests in one step:
  ```bash
  make all
  ```
- **Linter & Formatter**: Run Ruff check/format:
  ```bash
  make lint
  make fmt
  ```
- **Type Checking**: Run Mypy:
  ```bash
  make type
  ```
- **Unit Tests**: Run tests:
  ```bash
  make test
  ```

## CLI Usage

The primary interface is the `lemonade-security` command-line tool.

### 1. Store Event Log Auditing (`audit`)
Audits a local Lemonade Store JSONL event log for policy boundaries, malformed envelopes, and cashier payment bypasses.
```bash
lemonade-security audit --events tests/fixtures/store_events.jsonl --store-id tie-dye-farms
```

### 2. IAM Maturity Scoring (`maturity`)
Scores an event log against the IBM IAM-for-AI 4-step maturity model (evidence of agent identities, delegation IDs, and revocation events).
```bash
lemonade-security maturity --events tests/fixtures/store_events.jsonl --store-id tie-dye-farms
```

### 3. Department Permission Drift Scanner (`drift`)
Scans event logs for department registry drift, such as unauthorized event namespaces or unapproved actions.
```bash
lemonade-security drift --events tests/fixtures/store_events.jsonl --store-id tie-dye-farms
```

### 4. Filesystem Secret Scanner (`secrets`)
Scans directories for credential exposures, including bearer tokens, JWTs, and PINs.
```bash
lemonade-security secrets --scan-root src/ [--pattern "*.py"]
```

### 5. AI Bill of Materials Generation (`aibom`)
Generates a CycloneDX 1.6-compatible AIBOM manifest. Probes the Lemonade Server for local model details.
```bash
lemonade-security aibom --store-id tie-dye-farms [--server-url http://localhost:13305]
```

### 6. AIBOM Supply-Chain Auditor (`audit-aibom`)
Audits generated components in the AIBOM manifest for supply-chain risks.
```bash
lemonade-security audit-aibom --store-id tie-dye-farms [--server-url http://localhost:13305]
```

## Network Port Configurations

- **Lemonade Server Port (`13305`)**: When generating AIBOMs (`aibom` or `audit-aibom`), the CLI tool will attempt to query a local Lemonade Server at `http://localhost:13305` via `GET /v1/models` to discover model metadata.
- **No Inbound Port Binding**: The `lemonade-security` package behaves as a library and CLI runner. It **does not** run a daemon or bind any local TCP ports.

## Environment Variables

The package runs locally and does not require complex environment setup. The following standard variables are used when integrating with the Multica platform:

- `MULTICA_WORKSPACE_ID`: Identifies the target Multica workspace during deployment.
- `MULTICA_SERVER_URL`: Overrides the default platform endpoint.

## Related

- [[README]] — mission and agent handoff
- [[architecture]] — overall system design
- [[conventions]] — coding style and type safety
- [[agents]] — agent perimeters and safety rules

