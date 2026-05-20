# Lemonade SDK Security Plugin

Exposes Lemonade Security capabilities as OpenAI function-calling tool
definitions for use with a local Lemonade Server.

## Implementation

The plugin lives at `src/lemonade_security/sdk_plugin.py` in the main
package. This folder is the integration boundary — a thin entry point
that wires the installed package into a Lemonade Server context.

## Available tools

| Tool name | What it does |
|---|---|
| `lemonade_security_audit` | Audit a store event log for policy violations |
| `lemonade_security_drift` | Scan for department permission drift |
| `lemonade_security_secrets` | Scan files for credential exposure (DSGAI02) |
| `lemonade_security_maturity` | Score IAM maturity (IBM 4-step model) |
| `lemonade_security_aibom` | Generate a CycloneDX 1.6 AIBOM manifest |

## Usage

```python
from lemonade_security.sdk_plugin import SECURITY_TOOLS, execute_security_tool
from openai import OpenAI

client = OpenAI(base_url="http://localhost:13305/v1", api_key="not-needed")
response = client.chat.completions.create(
    model="<any-installed-model>",
    messages=[{"role": "user", "content": "Audit the store event log at /path/to/events.jsonl"}],
    tools=SECURITY_TOOLS,
)

for tool_call in response.choices[0].message.tool_calls or []:
    import json
    args = json.loads(tool_call.function.arguments)
    text, events = execute_security_tool(tool_call.function.name, args)
    # text → feed back to LLM as tool result
    # events → security.* events to persist in your event log
```

## Design rules

- Read-only: no tool mutates another department's data.
- No cloud: all checks run against local files and the local registry.
- Side-effect free: `execute_security_tool` returns events as data;
  the caller persists them.
- Owner-gated: export and sharing require a separate approval event.
