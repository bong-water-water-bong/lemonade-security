# lemonade-security — Wiki

> Local policy checks, agent audits, AIBOM manifests, and privacy findings for Lemonade Store.

## Current State

v0.1 is fully scaffolded and passing tests. Five audit surfaces are implemented: envelope/policy audit, department permission-drift scanner, IAM maturity scorer (IBM 4-step model), credential-replay auditor (LLM02), and prompt-injection auditor (LLM01). The Lemonade SDK plugin exposes all five as OpenAI function-calling tools for use with a local Lemonade Server. The CycloneDX 1.6 AIBOM manifest builder is in place and can enrich itself from `localhost:13305` when the server is online. Active development: no CLI subcommands yet for the agent-proposal, credential-replay, or prompt-injection auditors — those are library/SDK-only for now. The `maturity` subcommand is wired but the `audit` subcommand does not call the agent-specific auditors.

## Start Here

- [[architecture]] — 4-agent structure (envelope auditor, IAM maturity, credential-replay, prompt-injection), what each audit surface covers, how to invoke audits, gotchas about `agent.proposal` envelope handling

## Open Threads

- **CLI coverage gap**: `lemonade-security audit` runs only `audit_event_log` + `policy_check_events`. The `audit_agent_proposals`, `audit_credential_replay`, `audit_prompt_injection`, and `scan_permission_drift` auditors have no CLI entry points — they are reachable only through `sdk_plugin.execute_security_tool` or direct Python calls.
- **`agent.proposal` namespace registration**: All three proposal-targeting auditors fall back to raw `json.loads` because `store.event.v1` rejects unregistered type namespaces. When the shared envelope in `lemonade-store` gains native `agent.*` support, these auditors should switch back to `load_event`.
- **AIBOM export gate**: `aibom.py` and `lemonade_server.py` are complete, but emitting an AIBOM to disk or sharing it outside the workstation requires an owner-approval event that is not yet wired (AGENTS.md rule 5).

## Article Index

| Article | What it covers |
|---------|----------------|
| [[architecture]] | 4-audit-surface structure, agent roles, invocation, key design decisions, and operational gotchas |
