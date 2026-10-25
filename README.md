<!-- sell-kit:start -->
# AgentWarden

[![CI](https://github.com/eliem08/agentwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/eliem08/agentwarden/actions/workflows/ci.yml)

> **Give every AI agent an identity, a scoped role and spend limits, with an audit trail.**

**Who it's for:** Engineering and security teams putting agents into production.

**The problem:** Agents run on shared API keys with no identity, so nobody can say which agent did what or stop one from overreaching.

**What you get:** Signed, expiring agent tokens; role policies where an explicit deny always wins; per-scope spend caps; and an append-only audit log.

## Quickstart

Customers receive a release archive with the wheel and the examples. Python 3.10+ and no other dependencies.

```bash
pip install agentwarden-0.1.0-py3-none-any.whl
agentwarden --store okta.json role add support --allow read:crm/* --deny read:crm/payroll*
agentwarden --store okta.json agent add bot1 --owner a@x.com --role support
agentwarden --store okta.json agent list
```

## Web app and API

Every command is also a JSON API endpoint and a browser form, served by the built-in web app.

```bash
agentwarden-web --port 8000          # then open http://127.0.0.1:8000
agentwarden-web keys create --label "first customer"   # prints an API key (stored hashed)
docker build -t agentwarden . && docker run -p 8000:8000 -e API_KEYS=sk_... -v agentwarden-data:/data agentwarden
```

Every API call needs `Authorization: Bearer <key>` once any key exists; a server on a public address refuses to start without one. Calls are rate-limited per key (60/min, `--rate`) and metered: `agentwarden-web usage` prints calls per key for billing.

Endpoints: `POST /api/role-add`, `POST /api/role-list`, `POST /api/agent-add`, `POST /api/agent-disable`, `POST /api/agent-list`, `POST /api/token-issue`, `POST /api/token-revoke`, `POST /api/check`, plus `GET /healthz` and `GET /api/spec` (machine-readable field list).
Files are sent as `{"name": ..., "content": ...}`, folders as `{"files": [...]}` or a base64 zip.

## Pricing

Every plan starts with a 14-day free trial. Prices in USD, billed monthly unless noted.

| Plan | Price | Includes |
|---|---|---|
| **Team** | $99 per month | Up to 25 agents; Roles, deny rules and spend limits; Audit log |
| **Business** | $499 per month | Up to 250 agents; Key rotation tooling; Audit export for compliance |
| **Enterprise** | $2,000 per month | Unlimited agents; SSO and on-prem deployment; Security review support |

To start a trial or buy a plan, [request access](https://github.com/eliem08/agentwarden/issues/new?title=AgentWarden%20trial&labels=sales).

## Licence

Proprietary. Copyright (c) 2026 eliem08. All rights reserved. Use requires a paid plan or an active trial; see [LICENSE](LICENSE).
<!-- sell-kit:end -->

## What it does

- **Agent registry** — register agents with an owner, description and roles
- **Policies** — roles grant `action:resource` scopes with glob patterns
  (`read:crm/*`, `write:email/drafts`, `spend:stripe` with `max_amount`),
  plus explicit **deny** rules that always win
- **Tokens** — HMAC-SHA256 signed, expiring, scoped JWT-style tokens
  (no external deps); revocation list
- **Authorization** — `authorize(token, action, resource, context)` → allow/deny + reason
- **Audit log** — every decision appended as JSONL
- File-backed store (`agentwarden.json`) so the CLI is stateful
- No guessable default key: tokens are signed with `AGENTWARDEN_SECRET` or a random per-store key
- Spend checks reject `nan`, `inf` and negative amounts, so a limit cannot be slipped

## Quickstart

```bash
pip install -e .
# optional: without it, a random signing key is created once at agentwarden.json.secret (keep that file private)
export AGENTWARDEN_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
agentwarden role add support-bot --allow "read:crm/*" --allow "write:email/drafts" --deny "read:crm/payroll*"
agentwarden agent add helpdesk-1 --owner alice@acme.com --role support-bot
TOKEN=$(agentwarden token issue helpdesk-1 --ttl 900)
agentwarden check "$TOKEN" read crm/tickets/42      # ALLOW
agentwarden check "$TOKEN" read crm/payroll/2026    # DENY (explicit deny)
agentwarden check "$TOKEN" send email/outbox        # DENY (no matching grant)
```

## Roadmap

- OAuth 2.0 token exchange / MCP authorization server mode
- Human-in-the-loop step-up approval for risky scopes
- SCIM-style sync with your IdP (agent owners = employees)
- Anomaly detection on the audit stream (see agent-alarm)

## Development

Zero runtime dependencies; Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m unittest discover -s tests -t .           # unit + CLI smoke tests
ruff check . && ruff format --check .               # lint + format
```

```
agentwarden/core.py       domain logic (pure, importable, fully tested)
agentwarden/__main__.py   CLI (`agentwarden ...` / `python -m agentwarden ...`)
tests/                unit tests + generated CLI smoke tests
```

CI runs lint and tests on Ubuntu and Windows across Python 3.10, 3.12 and 3.13.
Design, data model, trade-offs and production path: **[ARCHITECTURE.md](ARCHITECTURE.md)**.

Part of the [agent-economy](https://github.com/eliem08/agent-economy) portfolio (idea #4).
