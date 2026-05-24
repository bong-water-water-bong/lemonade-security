"""Supply Chain security auditor (OWASP LLM03:2026).

Checks the AIBOM manifest for common supply-chain risks:
- Placeholder or missing versions for critical components.
- Missing supplier information.
- Non-existent component locations.
- Components using known-vulnerable base names (placeholder for v0.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from lemonade_security.aibom import AibomComponent


@dataclass(frozen=True)
class SupplyChainFinding:
    code: str
    severity: str
    message: str
    component_name: str


def audit_supply_chain(components: tuple[AibomComponent, ...]) -> list[SupplyChainFinding]:
    """Audit a list of AIBOM components for supply-chain risks."""
    findings: list[SupplyChainFinding] = []

    for comp in components:
        # 1. Missing or placeholder versions
        if not comp.version or "placeholder" in comp.version.lower() or comp.version == "0.0.0":
            findings.append(
                SupplyChainFinding(
                    code="supply_chain_unversioned",
                    severity="medium",
                    message=f"Component {comp.name!r} has a missing or placeholder version: {comp.version!r}",
                    component_name=comp.name,
                )
            )

        # 2. Missing supplier
        if not comp.supplier:
            findings.append(
                SupplyChainFinding(
                    code="supply_chain_no_supplier",
                    severity="low",
                    message=f"Component {comp.name!r} is missing supplier information",
                    component_name=comp.name,
                )
            )

        # 3. Location check
        if comp.location:
            # If location is relative, we'd need a base path.
            # For v0.1 we just check if it's an absolute path and if it exists.
            p = Path(comp.location)
            if p.is_absolute() and not p.exists():
                findings.append(
                    SupplyChainFinding(
                        code="supply_chain_missing_location",
                        severity="high",
                        message=f"Component {comp.name!r} specifies a location that does not exist: {comp.location}",
                        component_name=comp.name,
                    )
                )

    return findings
