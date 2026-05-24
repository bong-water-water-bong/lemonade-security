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

## Definition of done

- `make test` passes.
- `make lint` and `make type` pass when dev tools are installed.
- Any new event type is declared in Lemonade Store's department
  registry before this repo emits it.
