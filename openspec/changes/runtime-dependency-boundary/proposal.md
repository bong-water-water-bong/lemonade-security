# Change Proposal: runtime-dependency-boundary

## Department

- Department: security
- Repo: lemonade-security
- Namespace: security.*

## Why

Security audits local event logs and policy metadata by default. The
base package should stay local and lightweight; the GAIA-backed external
agent bridge is only needed for agent-hosted checks.

## What Changes

- Move `lemonade-agents` from required dependencies to the optional
  `agents` extra.
- Keep `lemonade-store@main` as the shared contract dependency.
- Teach the Makefile to create and prefer `.venv` for local development.
- Document the base install versus optional external agent bridge install.

## Affected Events

- Consumes: store event logs
- Emits: security.audit.completed, security.finding.created

## Approval Gates

- Owner approval required: no
- Approval type: packaging/docs cleanup; no event contract change

## Verification

- [x] `make install`
- [x] `make all`
