# Lemonade Security

Lemonade Security is the local-first security department for Lemonade
Store.

It reads local event logs and config, checks policy drift, and emits
`security.*` events. It does not mutate other department logs and does
not call cloud services by default.

Its policy catalog is aligned to the forked OWASP GenAI Security Project
repos under `/home/bcloud/genai-security-project-forks`.

## First surfaces

- `security.audit.completed` for local audit summaries.
- `security.finding.created` for policy and privacy findings.
- `security.aibom.generated` for future AI bill-of-materials output.
- `plugins/lemonade-sdk-security/` for the Lemonade SDK plugin wrapper.

## Run

```sh
PYTHONPATH=src:../lemonade-store/src python3 -m lemonade_security audit \
  --events /home/bcloud/lemonade-data/tie-dye-farms/store_events.jsonl \
  --store-id tie-dye-farms
```
