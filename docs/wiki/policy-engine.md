# Policy Engine

> How lemonade-security evaluates events against security policies and emits findings.

## Overview
The policy engine reads `lemonade-cashier` (and other department) JSONL event logs and evaluates each event against a ruleset derived from OWASP LLM Top 10 and the Agentic Security Initiative.

## Policy Evaluation Pipeline
```
store.event.v1 JSONL
        ↓
EventReader (parses, validates envelope schema)
        ↓
PolicyEngine.evaluate(event)
  ├── RuleRegistry.match(event.type)  → list of applicable rules
  ├── Rule.evaluate(event)            → Finding | None
  └── FindingAggregator               → dedup, severity sort
        ↓
security.finding.v1 events
security.aibom.v1 events (on session close)
```

## Rule Categories
| Category | Example rules |
|----------|--------------|
| Agent Identity | agent claimed `supervisor` role without PIN verification |
| Price Authority | agent set SKU price directly (bypasses cashier parser) |
| Audit Integrity | event hash chain broken |
| Data Retention | customer audio/image persisted beyond session |
| LLM Top 10 | prompt injection patterns in agent inputs |

## Adding a New Rule
1. Create `src/lemonade_security/rules/<category>/<rule_name>.py`
2. Implement `class MyRule(BaseRule)` with `matches(event)` and `evaluate(event) -> Finding | None`
3. Register in `src/lemonade_security/rules/__init__.py`
4. Write test in `tests/rules/test_<rule_name>.py` with a fixture that triggers the rule

## AIBOM (AI Bill of Materials)
On session close, the engine emits a `security.aibom.v1` event listing all AI models, agent identities, and tool calls used in the session. Format follows the CycloneDX AI BOM draft spec.

## Related
- [[README]] — mission and agent handoff
- [[architecture]] — overall system design
