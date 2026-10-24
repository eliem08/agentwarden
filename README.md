# agent-okta

> **Okta for agents** — who each agent is and what it's allowed to touch.

Every company is about to have more agents than employees. Today those
agents share one API key with god-mode access. `agent-okta` gives each agent
an identity, short-lived signed credentials and least-privilege policies —
with a full audit trail.

## What the MVP does

- **Agent registry** — register agents with an owner, description and roles
- **Policies** — roles grant `action:resource` scopes with glob patterns
  (`read:crm/*`, `write:email/drafts`, `spend:stripe` with `max_amount`),
  plus explicit **deny** rules that always win
- **Tokens** — HMAC-SHA256 signed, expiring, scoped JWT-style tokens
  (no external deps); revocation list
- **Authorization** — `authorize(token, action, resource, context)` → allow/deny + reason
- **Audit log** — every decision appended as JSONL
- File-backed store (`agent-okta.json`) so the CLI is stateful

## Quickstart

```bash
pip install -e .
export AGENT_OKTA_SECRET=change-me
agent-okta role add support-bot --allow "read:crm/*" --allow "write:email/drafts" --deny "read:crm/payroll*"
agent-okta agent add helpdesk-1 --owner alice@acme.com --role support-bot
TOKEN=$(agent-okta token issue helpdesk-1 --ttl 900)
agent-okta check "$TOKEN" read crm/tickets/42      # ALLOW
agent-okta check "$TOKEN" read crm/payroll/2026    # DENY (explicit deny)
agent-okta check "$TOKEN" send email/outbox        # DENY (no matching grant)
```

## Roadmap

- OAuth 2.0 token exchange / MCP authorization server mode
- Human-in-the-loop step-up approval for risky scopes
- SCIM-style sync with your IdP (agent owners = employees)
- Anomaly detection on the audit stream (see agent-alarm)
