# Architecture — agentwarden

## 1. Scope
Identity, credentials and least-privilege authorization for AI agents, with an audit trail.
**MVP:** file-backed directory (agents, roles, rules), HS256 JWT-style tokens with expiry and
revocation, allow/deny glob policies with spend caps, JSONL audit log, CLI.
**Product:** hosted authorization server (OAuth 2.0 token exchange, MCP auth), policy decision
point SDKs, step-up human approval, IdP sync.

## 2. System context
```mermaid
flowchart LR
  Owner[Human owner / admin] -->|registers agents, roles| Dir[(Directory)]
  Agent -->|1. request token| AS[Token service]
  AS --> Dir
  Agent -->|2. call with token| Tool[Tool / API / MCP server]
  Tool -->|3. authorize(token, action, resource)| PDP[Policy decision point]
  PDP --> Dir
  PDP --> Audit[(Audit log)]
  Audit --> Alarm[agent-alarm]
```

## 3. Components
| Module | Responsibility | Status |
|---|---|---|
| `Directory` | Roles, agents, revocation list, JSON persistence | MVP |
| `issue_token / verify_token` | HMAC-SHA256 signed claims `{sub, roles, iat, exp, jti}` | MVP |
| `Rule.matches` | `action:resource` glob matching (`fnmatchcase`) | MVP |
| `authorize` | Deny-overrides → allow with optional `max_amount` → default deny; audited | MVP |
| Token exchange | RFC 8693 for delegating a user's authority to an agent | Roadmap |
| Step-up | Push approval for risky scopes; short-lived elevated token | Roadmap |

## 4. Policy semantics
1. Verify signature, expiry, revocation and agent status. Any failure is a deny, and it's audited.
2. Collect rules from all roles in the token.
3. **Any matching deny wins**, then the first matching allow. A spend scope also requires
   `amount ≤ max_amount`.
4. No match means **default deny**.

Roles are re-read at decision time (the token carries role *names*), so revoking a grant from a role
takes effect immediately, without waiting for token expiry.

## 5. Design decisions
- **Deny-overrides + default-deny.** This is the only safe combination for autonomous callers.
- **Short TTL (900 s) + jti revocation list.** It bounds the blast radius, and the revocation list
  stays small because entries can be dropped after `exp`.
- **HS256 in the MVP.** It needs zero dependencies and works for a single trust domain.
  *Trade-off:* verifiers need the shared secret. The product moves to EdDSA with JWKS so
  third-party tools can verify without a secret.
- **Glob scopes over a full policy language (Rego/Cedar).** They're readable by non-engineers.
  Cedar is the planned upgrade once conditions (time, IP, amount ranges) grow.

## 6. Production architecture
- Token service + PDP as a stateless Go/Rust service. Directory in Postgres. Revocations in Redis
  with TTL = token exp.
- PDP SDKs (Python/TS) cache role definitions with a 30 s TTL and pub/sub invalidation.
- Audit: append-only, with events shipped to object storage (WORM) and to agent-alarm in real time.

## 7. Security
- Constant-time signature comparison (`hmac.compare_digest`), already in place.
- Secrets come from the environment or KMS, never from the store file.
- Threats and mitigations: token theft (short TTL, audience binding planned); privilege creep
  (quarterly access review report); confused deputy (the agent identity is always the token
  subject, never a parameter).

## 8. Scaling & reliability
Authorization is CPU-bound, with HMAC verification costing microseconds. Target p99 PDP latency
is under 5 ms with local caching. If the PDP is unreachable, the SDKs **fail closed**.

## 9. Risks
- Adoption depends on tools calling the PDP. An MCP gateway mode (a proxy that enforces policy
  in front of any MCP server) removes that dependency.
