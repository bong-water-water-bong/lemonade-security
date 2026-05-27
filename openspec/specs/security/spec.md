# Security Department Spec

Status: active
Department repo: `lemonade-security`
Suite registry: `lemonade-store/src/lemonade_store/departments.py`

## Namespace

`security.*`

## Owns

policy checks, agent audits, AIBOM manifests, model/tool inventory, privacy checks, and offline security reports.

## Consumes

cashier.transaction.closed, cashier.cit.bag.received, accounting.daily_close, inventory.created, marketing.post.approved, supplier.order.received, reports.exception, site.deploy.completed.

## Emits

security.finding.created, security.policy.checked, security.aibom.generated, security.audit.completed.

## Owner Approval

export_report and share_finding require owner approval.

## Must Not

mutate other department events or export findings without approval.

## Change Rules

- Changes to consumed/emitted events must be reflected in `lemonade-store`.
- Event-shape changes must include examples and tests in this repo.
- Public, financial, deployment, export, publish, and purchase-order side effects must remain owner-gated.
