"""Agent identities, role policies, signed tokens and authorization decisions."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field

__all__ = ["Rule", "Role", "Agent", "Directory", "TokenError"]


class TokenError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Rule:
    """`effect` is allow/deny; `scope` is `action:resource-glob`; optional `max_amount` for spend scopes."""

    effect: str
    scope: str
    max_amount: float | None = None

    def matches(self, action: str, resource: str) -> bool:
        act, _, res = self.scope.partition(":")
        return fnmatch.fnmatchcase(action, act) and fnmatch.fnmatchcase(resource, res or "*")


@dataclass
class Role:
    name: str
    rules: list[Rule] = field(default_factory=list)


@dataclass
class Agent:
    agent_id: str
    owner: str
    roles: list[str]
    description: str = ""
    disabled: bool = False
    created_at: float = field(default_factory=time.time)


class Directory:
    def __init__(self, path: str | None = None, secret: str | None = None):
        self.path = path
        self.secret = (secret or os.environ.get("AGENT_OKTA_SECRET") or "dev-secret").encode()
        self.roles: dict[str, Role] = {}
        self.agents: dict[str, Agent] = {}
        self.revoked: set[str] = set()
        self.audit_path = (path + ".audit.jsonl") if path else None
        self.audit: list[dict] = []
        if path and os.path.exists(path):
            self._load()

    # persistence -------------------------------------------------------
    def _load(self):
        with open(self.path, encoding="utf-8") as fh:
            d = json.load(fh)
        self.roles = {n: Role(n, [Rule(**r) for r in rules]) for n, rules in d.get("roles", {}).items()}
        self.agents = {a["agent_id"]: Agent(**a) for a in d.get("agents", [])}
        self.revoked = set(d.get("revoked", []))

    def save(self):
        if not self.path:
            return
        d = {
            "roles": {n: [asdict(r) for r in role.rules] for n, role in self.roles.items()},
            "agents": [asdict(a) for a in self.agents.values()],
            "revoked": sorted(self.revoked),
        }
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(d, fh, indent=2)

    # admin -------------------------------------------------------------
    def add_role(self, name: str, allow=(), deny=(), spend_limits: dict | None = None) -> Role:
        spend_limits = spend_limits or {}
        rules = [Rule("allow", s, spend_limits.get(s)) for s in allow] + [Rule("deny", s) for s in deny]
        self.roles[name] = Role(name, rules)
        return self.roles[name]

    def add_agent(self, agent_id: str, owner: str, roles: list[str], description: str = "") -> Agent:
        missing = [r for r in roles if r not in self.roles]
        if missing:
            raise KeyError(f"unknown roles: {missing}")
        self.agents[agent_id] = Agent(agent_id, owner, list(roles), description)
        return self.agents[agent_id]

    def disable_agent(self, agent_id: str):
        self.agents[agent_id].disabled = True

    # tokens ------------------------------------------------------------
    def issue_token(self, agent_id: str, ttl: int = 900, now: float | None = None) -> str:
        agent = self.agents[agent_id]
        if agent.disabled:
            raise TokenError("agent disabled")
        now = now or time.time()
        claims = {
            "sub": agent_id,
            "roles": agent.roles,
            "iat": int(now),
            "exp": int(now + ttl),
            "jti": secrets.token_hex(8),
        }
        header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = _b64(json.dumps(claims, separators=(",", ":")).encode())
        sig = _b64(hmac.new(self.secret, f"{header}.{body}".encode(), hashlib.sha256).digest())
        return f"{header}.{body}.{sig}"

    def verify_token(self, token: str, now: float | None = None) -> dict:
        try:
            header, body, sig = token.split(".")
        except ValueError:
            raise TokenError("malformed token") from None
        expected = _b64(hmac.new(self.secret, f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            raise TokenError("bad signature")
        claims = json.loads(_unb64(body))
        if (now or time.time()) >= claims["exp"]:
            raise TokenError("token expired")
        if claims["jti"] in self.revoked:
            raise TokenError("token revoked")
        agent = self.agents.get(claims["sub"])
        if not agent or agent.disabled:
            raise TokenError("agent unknown or disabled")
        return claims

    def revoke(self, token: str):
        _, body, _ = token.split(".")
        self.revoked.add(json.loads(_unb64(body))["jti"])

    # authorization -----------------------------------------------------
    def authorize(
        self, token: str, action: str, resource: str, amount: float | None = None, now: float | None = None
    ) -> tuple[bool, str]:
        try:
            claims = self.verify_token(token, now)
        except TokenError as e:
            return self._log(None, action, resource, False, str(e))
        rules = [r for name in claims["roles"] if name in self.roles for r in self.roles[name].rules]
        for r in rules:
            if r.effect == "deny" and r.matches(action, resource):
                return self._log(claims["sub"], action, resource, False, f"explicit deny {r.scope}")
        for r in rules:
            if r.effect == "allow" and r.matches(action, resource):
                if r.max_amount is not None and (amount is None or amount > r.max_amount):
                    return self._log(claims["sub"], action, resource, False, f"amount exceeds limit {r.max_amount}")
                return self._log(claims["sub"], action, resource, True, f"allowed by {r.scope}")
        return self._log(claims["sub"], action, resource, False, "no matching grant")

    def _log(self, agent, action, resource, allowed, reason):
        entry = {
            "ts": time.time(),
            "agent": agent,
            "action": action,
            "resource": resource,
            "allowed": allowed,
            "reason": reason,
        }
        self.audit.append(entry)
        if self.audit_path:
            with open(self.audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return allowed, reason
