# Architecture

> Lemonade Security is a local-first security audit suite that reads Lemonade Store event logs and emits `security.*` findings without ever mutating another department's data.

## Overview

Lemonade Security is the `security` department of the Lemonade Store umbrella. It consumes `store_events.jsonl` JSONL logs written by other departments (cashier, inventory, etc.) and produces structured `security.finding.created` and `security.audit.completed` events in the shared `store.event.v1` envelope format. All checks run locally — no cloud calls, no customer PII, no payment data.

The project is a Python 3.11+ package at `src/lemonade_security/`. It also ships a Lemonade SDK plugin at `plugins/lemonade-sdk-security/` that exposes the same capabilities as OpenAI function-calling tool definitions for use with a local Lemonade Server.

OWASP risk coverage is grounded in three forked reference repositories at `/home/bcloud/genai-security-project-forks/`: `GenAI-LLM-Top10`, `GenAI-Agent-Security-Initiative`, and `GenAI-Data-Security-Initiative`.

## How It Works

### Invocation

```sh
# Envelope + policy audit
lemonade-security audit --events tests/fixtures/store_events.jsonl --store-id tie-dye-farms

# IAM maturity scoring
lemonade-security maturity --events tests/fixtures/store_events.jsonl --store-id tie-dye-farms
```

The CLI writes one JSON event per line to stdout. Findings use `security.finding.created`; the final summary uses `security.audit.completed`. Exit code is 1 when any findings are present, 0 on a clean pass.

### The four audit surfaces

**1. Event-log auditor (`audit.py` + `drift.py`)**

The primary auditor. Reads every JSONL line through `lemonade_store.events.load_event` (the shared `store.event.v1` envelope validator) and flags:

- Invalid JSON or malformed envelopes (`invalid_json`, `invalid_envelope`)
- Mismatched `store_id` (`wrong_store_id`)
- Draft events that arrive pre-approved (`draft_already_approved`) — the approval-gate bypass pattern
- Cashier events containing payment terms (`card`, `stripe`, `wallet`, etc.) in their payload keys (`cashier_payment_boundary`, critical)
- Any event with customer media keys (`customer_audio`, `face_image`, etc.) in its payload (`customer_media_boundary`, critical)

The drift scanner (`drift.py`) extends this with registry-aware checks: namespace violations (a department writing event types outside its declared `writes` prefixes) and approval-gate drift (a gate-required action arriving with `requires_approval=False`).

**2. IAM maturity scorer (`maturity.py`)**

Scores an event log against the IBM IAM-for-AI 4-step model (sourced from IBM video `e8ela6puxig`), which maps onto OWASP ASI03 (Identity and Privilege Abuse):

| Level | Name | Evidence required |
|-------|------|-------------------|
| 1 | ad-hoc | No agent identity controls found |
| 2 | foundation | Every `agent.proposal` carries a non-empty `agent_id` |
| 3 | enhanced | Every `agent.proposal` carries a unique 32-hex-char `delegation_id`, and every model-mediated `cart.*` event links back to one of those delegation IDs |
| 4 | adaptive | At least one `security.revocation.created` event is present |

The scorer is conservative: it degrades to the highest level it can prove. A single orphan `cart.*` event or a single missing `agent_id` holds the log below Enhanced.

**3. Credential-replay auditor (`audit_credential_replay.py`)**

Scans `agent.proposal` payloads for credential-shaped values that could be replayed elsewhere (OWASP LLM02:2026 / DSGAI02). Four pattern codes:

- `LLM02_bearer_token` — RFC 6750 `Bearer`/`Token`/`Basic` headers and well-known secret prefixes (`sk-`, `ghp_`, `AKIA`, `AIza`, etc.)
- `LLM02_jwt` — three-segment base64url strings whose first segment decodes to a JSON object with `alg` or `typ`
- `LLM02_pin` — `pin=NNNN`-shaped substrings (4–8 digits)
- `LLM02_secret_field` — any payload key named `password`, `passwd`, `secret`, `api_key`, `apikey`, or `token`

Secret values are never copied into findings; the placeholder `<redacted>` is used instead. The auditor knows the event's own `delegation_id` and allowlists it so 32-hex delegation IDs do not trigger `LLM02_bearer_token`.

**4. Prompt-injection auditor (`audit_prompt_injection.py`)**

Scans `agent.proposal` `payload.input` strings for OWASP LLM01:2026 signatures (Prompt Injection / ASI06 Memory and Context Poisoning). Five finding codes:

- `LLM01_system_break` (high) — "ignore previous instructions", "you are now DAN", etc.
- `LLM01_role_confusion` (high) — chat-template markers (`<|system|>`, `### Instructions:`)
- `LLM01_exfil_cue` (high) — explicit exfiltration verbs or URLs (`curl`, `wget`, `https://*/exfil*`)
- `LLM01_encoded_smuggling` (medium) — token ≥40 chars with Shannon entropy ≥3.5 bits/char
- `LLM01_extra_pattern` (high) — operator-supplied regex, passed in via `extra_patterns`

### Supporting modules

- **`owasp.py`** — compact local catalog mapping finding codes to OWASP risk IDs (LLM01–LLM08:2026, ASI02/03/04/06/09, DSGAI01/02/06/09/14/15). Every `AuditFinding.to_payload()` call pulls from this table.
- **`aibom.py`** — builds CycloneDX 1.6-compatible AIBOM manifests (`bomFormat: CycloneDX`, `specVersion: 1.6`). Covers models, tools, plugins, and department repos.
- **`lemonade_server.py`** — probes `localhost:13305/v1/models` (GET only, 2-second timeout) and converts downloaded model entries to `AibomComponent` objects for AIBOM enrichment. Never raises on a missing server.
- **`secret_scan.py`** — filesystem scanner for `.jsonl`, `.env`, `.toml`, `.json` files; finds bearer tokens, JWTs, `.env`-style secret assignments, secret-named JSON fields, and 40-char hex keys. Values are never stored in findings.
- **`sdk_plugin.py`** — exposes five OpenAI function-calling tools (`SECURITY_TOOLS`) callable by any LLM on a local Lemonade Server. The `_assert_localhost` guard prevents SSRF by rejecting non-localhost `server_url` values.
- **`policy_check.py`** — produces `security.policy.checked` events from an `AuditResult`.

### Output format

All findings arrive as `store.event.v1` envelope events with `department="security"`, `actor.kind="agent_auto"`, and `actor.id="security.auditor"`. `event_id` values are deterministic SHA-256 hashes seeded from `store_id` and the finding index, so re-running the same log produces the same IDs.

## Key Decisions

- **`agent.proposal` events bypass envelope validation**: The shared `store.event.v1` validator rejects events whose `type` is outside its department's namespace, and `agent.*` is not registered in v0.1. The credential-replay, prompt-injection, and agent-proposal auditors therefore fall back to raw `json.loads` per line. This is explicitly documented in each module so the workaround is visible at review time and can be removed when the envelope grows native proposal support.

- **One finding code per pattern, not one umbrella code**: Both the credential-replay and prompt-injection auditors emit distinct codes (`LLM02_bearer_token` vs `LLM02_jwt`; `LLM01_system_break` vs `LLM01_role_confusion`) because the operator response to each differs: a system-break finding implicates the attendant session, a JWT finding implicates the token issuance path, and an encoded-smuggling finding implicates the OCR/barcode ingest path.

- **IAM maturity is conservative by design**: The scorer claims a level only when the log proves every condition for that level. A single orphan cart event, a single missing `agent_id`, or a missing revocation event holds the score at the level below. This matches the IBM model's intent: operators should earn the level, not receive it for partial evidence.

- **No cloud calls, ever**: All network access is blocked by policy (AGENTS.md rule 3). The Lemonade Server probe in `lemonade_server.py` is the only outbound connection, and it is scoped to `localhost:13305` with a 2-second timeout. The SDK plugin enforces this with `_assert_localhost` at the tool-dispatch boundary to prevent an LLM-controlled `server_url` from reaching external hosts.

- **Secret values never appear in findings**: Both `audit_credential_replay.py` and `secret_scan.py` emit only path, line number, and code when a secret matches. The matched value is replaced by `<redacted>` or omitted entirely. This ensures that security findings themselves cannot become a secondary exfiltration channel.

## Gotchas

- **`agent.proposal` events are not in the store.event.v1 namespace**: Because the `agent.*` type is unregistered, `audit_event_log` (the primary auditor) will emit an `invalid_envelope` finding for every `agent.proposal` line in a mixed log. This is correct behavior — the proposal events are intentionally outside the shared envelope — but it means a combined log will always have findings unless you filter by event type before auditing.

- **Delegation IDs must be exactly 32 lowercase hex characters**: The maturity scorer's `_delegation_id` helper validates the value with `int(delegation_id, 16)` and a length check of exactly 32 chars. A UUID with hyphens (36 chars) or a free-form string will not satisfy the Enhanced level check, even if the intent was correct. Callers must mint 32-char lowercase hex strings, not UUIDs.

- **The `audit` CLI subcommand does not invoke the agent-proposal, credential-replay, or prompt-injection auditors**: `cli.py` calls only `audit_event_log`, `policy_check_events`, and `summary_event`. The other four auditors (`audit_agent_proposals`, `audit_credential_replay`, `audit_prompt_injection`, `scan_permission_drift`) are available in the SDK plugin (`sdk_plugin.py`) and as standalone library calls, but have no dedicated CLI subcommands yet.

## Related

- [[README]] — current state, open threads, and article index for this wiki
