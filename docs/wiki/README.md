# Project Wiki: Lemonade Security

## Mission
Build a local-first security auditor for Lemonade Store and a plugin surface for Lemonade SDK. It provides policy checks, agent audits, and AIBOM manifests.

## Architecture
- **Auditor Pattern**: Reads store event logs (`jsonl`) and emits `security.*` findings in the shared envelope.
- **OWASP-Aligned**: Uses forked material from the GenAI Security Project (LLM Top 10, Agentic Security Initiative) as the baseline for risk IDs.
- **Department Boundary**: Acts as a read-only consumer of other departments' logs.
- **Plugin Surface**: Includes a dedicated `plugins/` directory for exposing security capabilities to Lemonade SDK hosts.

## Agent Handoff
- **How to Test**: Run `make test`. Sample event logs are available in `tests/fixtures/`.
- **Hot Paths**:
    - `src/lemonade_security/`: The main auditor logic and policy engine.
    - `plugins/lemonade-sdk-security/`: The SDK plugin wrapper.
- **Current Priorities**: 
    - v0.1: Refining the local event-log auditor for policy drift (e.g., unknown departments, invalid envelopes).
    - Next Milestone: Implementing CycloneDX-compatible AIBOM export for local models and datasets.

## Decisions & Gotchas
- **Read-Only Enforcement**: Never attempt to rewrite or mutate the event logs of other departments.
- **Local-First Default**: Cloud calls are strictly forbidden by default.
- **Owner Approval Required**: Sharing findings or exporting reports outside the local workstation requires explicit owner approval.
- **Reference Forks**: Reference material is located at `/home/bcloud/genai-security-project-forks/`; do not vendor samples into the store apps.
- **Privacy Core**: Specifically checks for prohibited data types (card data, customer audio/images) in the event log.

## OpenSpec Workflow

Use `openspec/` as the working standard for department changes:

- `openspec/project.md` defines this repo's department workflow.
- `openspec/specs/security/spec.md` records the active contract for this department.
- `openspec/changes/<change-id>/` holds proposal, design, and task files for active work.
- GitHub issues and PRs must name affected event types and approval gates.

Keep this repo aligned with `lemonade-store` when event contracts, owner approval gates, or department boundaries change.

## LLM Wiki Standard

This repo treats Andrej Karpathy's LLM Wiki pattern as the governing source for agent knowledge management: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

For this project, that means:

- `docs/wiki/` is the maintained project memory for architecture, decisions, gotchas, and onboarding.
- `AGENTS.md` is the agent instruction schema.
- `openspec/` is the structured change/spec layer.
- Raw source material stays in docs, examples, tests, issue/PR discussions, and committed specs.
- Agents must update the wiki when they learn durable repo knowledge that future agents need.

Keep wiki entries concise, factual, and linked back to concrete files, specs, or test evidence.
