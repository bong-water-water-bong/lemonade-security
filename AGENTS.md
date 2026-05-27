> **Start here:** Read `docs/wiki/README.md` before any work on this project.

# AGENTS.md — Lemonade Security

This repo is the `security` department for Lemonade Store.

## Mission

Build a local-first security auditor for Lemonade Store and a plugin
surface for Lemonade SDK.

## Hard rules

1. Read other departments; never rewrite their logs.
2. Emit only `security.*` events.
3. No cloud calls by default.
4. No customer card data, audio, or images.
5. Owner approval is required before exporting reports or sharing
   findings outside the workstation.
6. Keep the first version simple: local event logs, local configs,
   JSON output, and tests.

## First build order

```text
event-log auditor
   ↓
policy findings
   ↓
AIBOM manifest
   ↓
Lemonade SDK plugin wrapper
```


- Treat Karpathy's LLM Wiki pattern as governing law for durable agent memory: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f. Update `docs/wiki/` whenever work reveals durable architecture, workflow, gotcha, or onboarding knowledge.

## OpenSpec Department Standard

Use `openspec/` for every department-level change before implementation:

1. Create or update a change folder under `openspec/changes/<change-id>/`.
2. Record the department, affected event types, approval gates, and repo boundaries.
3. Keep `openspec/specs/security/spec.md` aligned with this repo, `lemonade-store`, and the shared department registry.
4. Implementation work must reference the change `tasks.md` and update it as tasks complete.
5. Archive completed changes only after checks and owner/review approval are recorded.

This repo owns the `security` implementation. `lemonade-store` remains the suite-level source for the shared registry and cross-department contract.

## Definition of done

- `make test` passes.
- `make lint` and `make type` pass when dev tools are installed.
- Any new event type is declared in Lemonade Store's department
  registry before this repo emits it.

## GitHub / OpenSpec / LLM Wiki Standard

Treat Karpathy's LLM Wiki pattern as governing law for durable agent memory: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

- `docs/wiki/` is the durable project memory for architecture, decisions, gotchas, and onboarding.
- `AGENTS.md` is the agent instruction schema.
- `openspec/` is the structured change/spec layer.
- Start non-trivial work with `openspec/changes/<change-id>/proposal.md`.
- Track implementation in `openspec/changes/<change-id>/tasks.md`.
- Update `docs/wiki/` whenever work reveals durable repo knowledge future agents need.
- Keep changes surgical, simple, and verified by repo-native checks.
