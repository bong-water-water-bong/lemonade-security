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
