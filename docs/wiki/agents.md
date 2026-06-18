# Agent Handoff & Safety: Lemonade Security

This file details the safety policies, boundaries, and safe zones that all automation agents (human or AI) must respect when working in this repository.

## Safe Zones vs. Human-Review-Only Zones

To protect project boundaries, we partition the repository into areas where agents can operate autonomously and areas requiring strict oversight:

| Directory/File | Classification | Allowed Agent Action |
|:---|:---|:---|
| `docs/wiki/` | **Safe Zone** | Fully autonomous. Agents may add or update documentation pages. |
| `openspec/changes/` | **Safe Zone** | Autonomous. Agents may create change folders, proposals, and task lists. |
| `tests/` | **Safe Zone** | Autonomous. Agents may write new test cases or expand verification files. |
| `src/` | **Human-Review-Only** | Strictly gated. Code changes must be surgical and require human review. |
| `Makefile` | **Human-Review-Only** | Human approval required for target modifications. |
| `pyproject.toml` | **Human-Review-Only** | Human approval required for adding/updating dependencies. |
| `openspec/specs/` | **Human-Review-Only** | Gated. Changing spec contracts requires suite-wide coordinator approval. |

## Hard Safety Rules for Agents

All automation agents must strictly adhere to the following hard rules defined for `lemonade-security`:

1. **Read-Only Department Boundary**: Read other departments' event logs; never rewrite or modify them.
2. **Namespace Restriction**: Emit only `security.*` events.
3. **No Cloud Calls**: Operate entirely local-first. No external cloud calls are allowed.
4. **Data Privacy Core**: Never process or persist customer card data, audio, or images.
5. **Owner Approval Gates**: Explicit owner approval is required before exporting reports or sharing security findings outside the workstation.
6. **Simplicity First**: Keep changes simple and focused on local event logs, local configs, JSON output, and tests.

## Verification Loop

Before submitting a change for review:
1. Ensure all tests, lint checks, and typechecks pass by running `make all`.
2. Ensure you have documented any durable knowledge gained during implementation in `docs/wiki/`.
3. Track and update implementation steps in the relevant `openspec/changes/<change-id>/tasks.md`.

## Related

- [[README]] — mission and agent handoff
- [[architecture]] — overall system design
- [[conventions]] — coding style and type safety
- [[runbook]] — command execution and setup

