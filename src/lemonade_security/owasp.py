"""OWASP GenAI Security mappings used by Lemonade Security.

This module keeps a compact local catalog derived from the forked OWASP
GenAI Security Project repos. It is intentionally small: the full source
material stays in the forks, while Lemonade Security records the risk IDs
it needs for local policy checks.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskMapping:
    id: str
    name: str
    source: str
    lemonade_policy: str


OWASP_RISK_MAPPINGS: tuple[RiskMapping, ...] = (
    RiskMapping(
        id="LLM01:2026",
        name="Prompt Injection",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Scan agent input boundaries for system-prompt break, role confusion, exfiltration cues, and encoded smuggling.",
    ),
    RiskMapping(
        id="LLM02:2026",
        name="Sensitive Information Disclosure",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Do not expose customer, store, prompt, credential, or private transaction data.",
    ),
    RiskMapping(
        id="LLM03:2026",
        name="Supply Chain",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Track local models, tools, datasets, and plugin surfaces with an AIBOM.",
    ),
    RiskMapping(
        id="LLM06:2026",
        name="Excessive Agency",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Agents draft or audit; high-impact actions require deterministic gates and owner approval.",
    ),
    RiskMapping(
        id="LLM07:2026",
        name="Hidden Context Exposure",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Keep system prompts, tool outputs, retrieved context, and event logs scoped to the task.",
    ),
    RiskMapping(
        id="LLM08:2026",
        name="Vector and Embedding Weaknesses",
        source="GenAI-LLM-Top10/2026",
        lemonade_policy="Any future RAG or vector store must enforce local access boundaries and audit retrieval.",
    ),
    RiskMapping(
        id="ASI02",
        name="Tool Misuse and Exploitation",
        source="GenAI-Agent-Security-Initiative",
        lemonade_policy="Tools must be narrow, schema-checked, and unable to mutate other departments directly.",
    ),
    RiskMapping(
        id="ASI03",
        name="Identity and Privilege Abuse",
        source="GenAI-Agent-Security-Initiative",
        lemonade_policy="Agents must run with department-scoped identities and minimum permissions.",
    ),
    RiskMapping(
        id="ASI04",
        name="Agentic Supply Chain Vulnerabilities",
        source="GenAI-Agent-Security-Initiative",
        lemonade_policy="Model, tool, plugin, and dataset provenance must be locally inspectable.",
    ),
    RiskMapping(
        id="ASI06",
        name="Memory and Context Poisoning",
        source="GenAI-Agent-Security-Initiative",
        lemonade_policy="Persistent agent memory is off by default and must be bounded by store/event scope.",
    ),
    RiskMapping(
        id="ASI09",
        name="Human-Agent Trust Exploitation",
        source="GenAI-Agent-Security-Initiative",
        lemonade_policy="Approval prompts must be concise, auditable, and resistant to review fatigue.",
    ),
    RiskMapping(
        id="DSGAI01",
        name="Sensitive Data Leakage",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="No customer PII, card data, audio, or images at rest in the first security path.",
    ),
    RiskMapping(
        id="DSGAI02",
        name="Agent Identity and Credential Exposure",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="Do not place credentials or broad tokens in agent payloads, logs, or tool metadata.",
    ),
    RiskMapping(
        id="DSGAI06",
        name="Tool, Plugin and Agent Data Exchange Risks",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="Lemonade SDK plugins must be thin wrappers over local policy APIs.",
    ),
    RiskMapping(
        id="DSGAI09",
        name="Multimodal Capture and Cross-Channel Data Leakage",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="Camera and speech layers must not persist customer media by default.",
    ),
    RiskMapping(
        id="DSGAI14",
        name="Excessive Telemetry and Monitoring Leakage",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="Reports and logs must avoid prompt, response, media, and secret leakage.",
    ),
    RiskMapping(
        id="DSGAI15",
        name="Over-Broad Context Windows and Prompt Over-Sharing",
        source="GenAI-Data-Security-Initiative",
        lemonade_policy="Agents receive the smallest event/context slice needed for the task.",
    ),
)


def risk_ids_for_code(code: str) -> tuple[str, ...]:
    """Return OWASP risk IDs that explain a Lemonade finding code."""
    mapping = {
        "cashier_payment_boundary": ("LLM06:2026", "DSGAI01", "DSGAI08"),
        "customer_media_boundary": ("DSGAI01", "DSGAI09", "LLM02:2026"),
        "wrong_store_id": ("DSGAI11", "DSGAI15"),
        "invalid_envelope": ("DSGAI05", "ASI08"),
        "invalid_json": ("DSGAI05",),
        "draft_already_approved": ("LLM06:2026", "ASI09"),
        "ASI03_rogue_agent_id": ("ASI03", "LLM06:2026"),
        "ASI03_stripped_agent_id": ("ASI03",),
        "ASI02_orphan_delegation": ("ASI02", "LLM06:2026"),
        "LLM02_bearer_token": ("LLM02:2026", "ASI03", "DSGAI02"),
        "LLM02_jwt": ("LLM02:2026", "ASI03", "DSGAI02"),
        "LLM02_pin": ("LLM02:2026", "ASI03", "DSGAI02"),
        "LLM02_secret_field": ("LLM02:2026", "ASI03", "DSGAI02"),
        "LLM02_credential_leak": ("LLM02:2026", "ASI03", "DSGAI02"),
        "LLM01_system_break": ("LLM01:2026", "ASI06"),
        "LLM01_role_confusion": ("LLM01:2026", "ASI06"),
        "LLM01_exfil_cue": ("LLM01:2026", "LLM02:2026"),
        "LLM01_encoded_smuggling": ("LLM01:2026", "ASI06"),
        "LLM01_extra_pattern": ("LLM01:2026",),
    }
    return mapping.get(code, ())
