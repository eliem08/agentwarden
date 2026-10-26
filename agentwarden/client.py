"""Zero-dependency client for a hosted AgentWarden server: gate every agent action in one line.

from agentwarden.client import AgentWarden
warden = AgentWarden("https://warden.example.com", api_key="sk_...")
warden.require(token, "spend", "stripe/charges", amount=40)   # raises Denied if not allowed
"""

import json
import urllib.error
import urllib.request


class Denied(PermissionError):
    """The agent is not allowed to do this; `reason` says which rule decided."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class AgentWardenError(RuntimeError):
    """The server could not answer (network, auth, bad request). Treat as a deny: fail closed."""


class AgentWarden:
    def __init__(self, base_url: str, api_key: str = "", timeout: float = 10.0):
        self.base = base_url.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _call(self, op: str, payload: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        body = json.dumps({k: v for k, v in payload.items() if v is not None}).encode()
        req = urllib.request.Request(f"{self.base}/api/{op}", data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            with e:
                detail = e.read()[:500].decode("utf-8", "replace")
            raise AgentWardenError(f"HTTP {e.code}: {detail}") from None
        except (OSError, ValueError) as e:
            raise AgentWardenError(str(e)) from None

    def check(self, token: str, action: str, resource: str, amount: float | None = None) -> tuple[bool, str]:
        """Return (allowed, reason). Anything other than a clear ALLOW is a deny."""
        res = self._call("check", {"token": token, "action": action, "resource": resource, "amount": amount})
        line = (res.get("stdout") or "").strip()
        verdict, _, reason = line.partition(" ")
        if verdict == "ALLOW" and res.get("exit_code") == 0:
            return True, reason.strip()
        if verdict == "DENY":
            return False, reason.strip()
        raise AgentWardenError(res.get("error") or f"unexpected answer: {line[:200]!r}")

    def require(self, token: str, action: str, resource: str, amount: float | None = None) -> str:
        allowed, reason = self.check(token, action, resource, amount)
        if not allowed:
            raise Denied(reason)
        return reason

    def issue_token(self, agent_id: str, ttl: int = 900) -> str:
        res = self._call("token-issue", {"agent_id": agent_id, "ttl": ttl})
        out = (res.get("stdout") or "").strip()
        if not res.get("ok") or not out:
            raise AgentWardenError(res.get("error") or "no token returned")
        return out.split()[-1]
