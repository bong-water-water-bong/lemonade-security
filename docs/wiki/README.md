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
