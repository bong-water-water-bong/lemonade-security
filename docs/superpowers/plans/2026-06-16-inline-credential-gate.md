# Inline Credential Gate (Option 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure, in-process gate that runs the existing credential-replay scanner against a single in-flight `agent.proposal` event and returns an allow/deny `Decision` *before* the proposal's action executes.

**Architecture:** Invert `lemonade-security`'s post-hoc, whole-log auditing into a single-event check. Extract the per-event scan atom already latent in `audit_credential_replay.py` (`_scan_payload`) into a public `scan_proposal_event(raw)` entry point. Add one `PolicyRule` mapping the four `LLM02_*` credential codes to a named policy. A new `gate.py` composes them into `evaluate_proposal(event) -> Decision`. No new dependencies; all logic is stdlib + existing modules.

**Tech Stack:** Python 3.11+, pytest, existing `lemonade_security` package.

**Scope boundary (YAGNI):** This plan delivers the reusable gate primitive *inside `lemonade-security` only*. Wiring a caller (e.g. the cashier supervisor) to refuse on deny and emit `security.finding.created` is deliberately **out of scope** — it touches `lemonade-cashier` (separate repo, separate rules) and is a follow-up. Chain-authorization (Option 2) is also out of scope: the data check confirmed no delegation chain exists in proposal events.

**Commit note:** Per `lemonade-security/CLAUDE.md` rule #2078, do **NOT** add a `Co-Authored-By` trailer unless `.claude/settings.json` sets `attribution.commit`. Plain Conventional Commit messages only.

---

## File Structure

- **Modify** `src/lemonade_security/audit_credential_replay.py` — extract `scan_proposal_event(raw)` (single-event public entry point); refactor the file loop to call it (DRY: one source of truth for "scan one proposal").
- **Modify** `src/lemonade_security/policy_check.py` — add a `credential_leak_boundary` `PolicyRule` to `LEMONADE_POLICIES` so the four credential codes have a named policy.
- **Create** `src/lemonade_security/gate.py` — `Decision` dataclass + pure `evaluate_proposal(event)`.
- **Create** `tests/test_gate.py` — gate unit tests.
- **Modify** `tests/test_audit_credential_replay.py` — add `scan_proposal_event` direct-contract tests (file may be appended to; keep existing tests untouched).

---

### Task 1: Extract `scan_proposal_event` from the file loop

**Files:**
- Modify: `src/lemonade_security/audit_credential_replay.py` (function `audit_credential_replay`, lines ~136–181)
- Test: `tests/test_audit_credential_replay.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_audit_credential_replay.py`:

```python
from lemonade_security.audit_credential_replay import scan_proposal_event


def test_scan_proposal_event_flags_bearer_token_in_input():
    event = {
        "type": "agent.proposal",
        "payload": {
            "agent": "lemonade",
            "kind": "normalize",
            "input": "please authorize with Bearer abcdef0123456789ABCDEF",
            "output": "2 lemonade",
            "confidence": 0.9,
            "decision": "accepted",
        },
    }
    findings = scan_proposal_event(event)
    assert [f.code for f in findings] == ["LLM02_bearer_token"]


def test_scan_proposal_event_clean_proposal_has_no_findings():
    event = {
        "type": "agent.proposal",
        "payload": {
            "agent": "lemonade",
            "kind": "normalize",
            "input": "2 lemonades",
            "output": "2 lemonade",
            "confidence": 0.9,
            "decision": "accepted",
        },
    }
    assert scan_proposal_event(event) == []


def test_scan_proposal_event_ignores_non_proposal_events():
    assert scan_proposal_event({"type": "cart.add", "payload": {"token": "x"}}) == []


def test_scan_proposal_event_ignores_non_dict_payload():
    assert scan_proposal_event({"type": "agent.proposal", "payload": "nope"}) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_audit_credential_replay.py::test_scan_proposal_event_flags_bearer_token_in_input -v`
Expected: FAIL — `ImportError: cannot import name 'scan_proposal_event'`

- [ ] **Step 3: Add `scan_proposal_event` and refactor the loop to use it**

In `src/lemonade_security/audit_credential_replay.py`, add this function immediately **above** `def audit_credential_replay(`:

```python
def scan_proposal_event(
    raw: dict[str, Any],
    *,
    line_number: int = 1,
    allow_substrings: frozenset[str] = frozenset(),
) -> list[AuditFinding]:
    """Scan a single decoded event dict for credential-shaped leaks.

    Returns an empty list for events that are not ``agent.proposal`` or
    whose ``payload`` is not a dict. This is the per-event atom shared by
    the file-based :func:`audit_credential_replay` and the inline gate.
    """
    if raw.get("type") != _PROPOSAL_TYPE:
        return []
    payload = raw.get("payload")
    if not isinstance(payload, dict):
        return []
    event_id = _event_id_of(raw)
    known_delegation = payload.get("delegation_id")
    known_delegation_str = (
        known_delegation if isinstance(known_delegation, str) else None
    )
    return list(
        _scan_payload(
            payload,
            event_id=event_id,
            line_number=line_number,
            allow_substrings=allow_substrings,
            known_delegation=known_delegation_str,
        )
    )
```

Then replace the body of the `with` loop in `audit_credential_replay` (the block from `if raw.get("type") != _PROPOSAL_TYPE:` through the `findings.extend(...)` call) with a single call. The loop becomes:

```python
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            checked_events += 1
            findings.extend(
                scan_proposal_event(
                    raw,
                    line_number=line_number,
                    allow_substrings=allow_substrings,
                )
            )
```

Note: `checked_events` still counts every dict line (parity with prior behaviour, which incremented before the type filter).

- [ ] **Step 4: Run the new tests AND the existing suite to verify parity**

Run: `pytest tests/test_audit_credential_replay.py -v`
Expected: PASS — all four new tests pass AND every pre-existing test in the file still passes (the refactor must not change file-scan results).

- [ ] **Step 5: Commit**

```bash
git add src/lemonade_security/audit_credential_replay.py tests/test_audit_credential_replay.py
git commit -m "refactor: extract scan_proposal_event from credential-replay loop"
```

---

### Task 2: Add the `credential_leak_boundary` policy rule

**Files:**
- Modify: `src/lemonade_security/policy_check.py` (`LEMONADE_POLICIES`, lines ~29–60)
- Test: `tests/test_policy_check.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_policy_check.py`:

```python
from lemonade_security.policy_check import LEMONADE_POLICIES


def test_credential_leak_boundary_policy_maps_all_four_llm02_codes():
    rule = next(p for p in LEMONADE_POLICIES if p.id == "credential_leak_boundary")
    assert rule.finding_codes == frozenset(
        {
            "LLM02_secret_field",
            "LLM02_bearer_token",
            "LLM02_jwt",
            "LLM02_pin",
        }
    )
    assert "LLM02:2026" in rule.owasp_ids
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_policy_check.py::test_credential_leak_boundary_policy_maps_all_four_llm02_codes -v`
Expected: FAIL — `StopIteration` (no rule with that id).

- [ ] **Step 3: Add the rule**

In `src/lemonade_security/policy_check.py`, add this entry as the last element inside the `LEMONADE_POLICIES` tuple (before the closing `)`):

```python
    PolicyRule(
        id="credential_leak_boundary",
        description=(
            "Agent proposals must not carry bearer tokens, JWTs, PINs, "
            "or secret-named fields."
        ),
        owasp_ids=("LLM02:2026", "ASI03"),
        finding_codes=frozenset(
            {
                "LLM02_secret_field",
                "LLM02_bearer_token",
                "LLM02_jwt",
                "LLM02_pin",
            }
        ),
    ),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_policy_check.py -v`
Expected: PASS — new test passes; existing policy tests still pass (the addition is additive; whole-log `audit_event_log` results never carry these codes, so existing `policy_check_events` behaviour is unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/lemonade_security/policy_check.py tests/test_policy_check.py
git commit -m "feat: add credential_leak_boundary policy rule"
```

---

### Task 3: Create the gate (`Decision` + `evaluate_proposal`)

**Files:**
- Create: `src/lemonade_security/gate.py`
- Create: `tests/test_gate.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_gate.py`:

```python
from lemonade_security.gate import Decision, evaluate_proposal


def _proposal(payload: dict) -> dict:
    base = {
        "agent": "lemonade",
        "kind": "normalize",
        "input": "2 lemonades",
        "output": "2 lemonade",
        "confidence": 0.9,
        "decision": "accepted",
    }
    base.update(payload)
    return {"type": "agent.proposal", "payload": base}


def test_clean_proposal_is_allowed():
    decision = evaluate_proposal(_proposal({}))
    assert isinstance(decision, Decision)
    assert decision.allowed is True
    assert decision.triggered == ()
    assert decision.findings == ()


def test_bearer_token_in_input_is_denied():
    decision = evaluate_proposal(
        _proposal({"input": "use Bearer abcdef0123456789ABCDEF now"})
    )
    assert decision.allowed is False
    assert "credential_leak_boundary" in decision.triggered
    assert [f.code for f in decision.findings] == ["LLM02_bearer_token"]


def test_secret_named_field_is_denied():
    decision = evaluate_proposal(_proposal({"input": {"api_key": "whatever"}}))
    assert decision.allowed is False
    assert "credential_leak_boundary" in decision.triggered
    assert "LLM02_secret_field" in [f.code for f in decision.findings]


def test_non_proposal_event_is_allowed_with_no_findings():
    decision = evaluate_proposal({"type": "cart.add", "payload": {"token": "x"}})
    assert decision.allowed is True
    assert decision.findings == ()


def test_allow_substrings_clears_a_placeholder():
    decision = evaluate_proposal(
        _proposal({"input": {"api_key": "TEST_PLACEHOLDER"}}),
        allow_substrings=frozenset({"TEST_PLACEHOLDER"}),
    )
    assert decision.allowed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_gate.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'lemonade_security.gate'`

- [ ] **Step 3: Create `gate.py`**

Create `src/lemonade_security/gate.py`:

```python
"""Inline credential gate.

Runs the credential-replay scanner against a single in-flight
``agent.proposal`` event and returns an allow/deny :class:`Decision`
*before* the proposal's action executes. This is the preventive
counterpart to the post-hoc, whole-log auditors: same scan logic
(`scan_proposal_event`) and same policy table (`LEMONADE_POLICIES`),
evaluated on one event with a yes/no verdict instead of emitted events.

The function is pure: it performs no I/O and emits no events. Callers
decide what to do on a deny (refuse the action, emit
``security.finding.created``, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from lemonade_security.audit import AuditFinding
from lemonade_security.audit_credential_replay import scan_proposal_event
from lemonade_security.policy_check import LEMONADE_POLICIES, PolicyRule


@dataclass(frozen=True)
class Decision:
    """Verdict for one proposal.

    ``allowed`` is True when no policy fired. ``triggered`` lists the
    ``PolicyRule`` ids that fired. ``findings`` are the raw scanner
    findings (useful for logging / emitting a finding event).
    """

    allowed: bool
    triggered: tuple[str, ...]
    findings: tuple[AuditFinding, ...]


def evaluate_proposal(
    event: dict[str, Any],
    *,
    allow_substrings: frozenset[str] = frozenset(),
    policies: tuple[PolicyRule, ...] = LEMONADE_POLICIES,
) -> Decision:
    """Evaluate a single decoded ``agent.proposal`` event.

    Non-proposal events and non-dict payloads produce no findings and
    are allowed (this gate only judges credential leakage in proposals).
    """
    findings = scan_proposal_event(event, allow_substrings=allow_substrings)
    active = frozenset(f.code for f in findings)
    triggered = tuple(p.id for p in policies if active & p.finding_codes)
    return Decision(
        allowed=not triggered,
        triggered=triggered,
        findings=tuple(findings),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_gate.py -v`
Expected: PASS — all five tests pass.

- [ ] **Step 5: Run the full suite + lint + types**

Run: `pytest tests/ -q && ruff check src/lemonade_security/gate.py && mypy src/lemonade_security/gate.py`
Expected: all green. (If `make` targets exist, `make all` is equivalent.)

- [ ] **Step 6: Commit**

```bash
git add src/lemonade_security/gate.py tests/test_gate.py
git commit -m "feat: add inline credential gate (evaluate_proposal)"
```

---

## Self-Review

**1. Spec coverage:**
- "Invert post-hoc auditor to single-event" → Task 1 (`scan_proposal_event`). ✅
- "Reuse `LEMONADE_POLICIES` finding-code mapping" → Task 2 adds the missing credential policy so the reuse actually denies. ✅
- "Pure `evaluate(proposal) -> Decision`, no I/O" → Task 3. ✅
- Out-of-scope items (caller wiring, chain-authorization) explicitly excluded. ✅

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code. ✅

**3. Type consistency:** `scan_proposal_event(raw, *, line_number, allow_substrings) -> list[AuditFinding]` defined in Task 1, called identically in Tasks 1 & 3. `Decision(allowed, triggered, findings)` defined and asserted consistently. `PolicyRule` fields (`id`, `description`, `owasp_ids`, `finding_codes`) match the existing dataclass in `policy_check.py`. Finding codes (`LLM02_secret_field/bearer_token/jwt/pin`) identical across Tasks 2 & 3. ✅

**4. Known behavioural notes:** Task 2's new policy is additive — `audit_event_log` never produces `LLM02_*` codes, so existing `policy_check_events` output is unchanged; the credential policy will simply always report `pass` on a normal whole-log audit. This is intended.
