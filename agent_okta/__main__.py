import argparse
import csv
import math
import os
import sys

from .core import Directory, TokenError


def _finite_float(s: str) -> float:
    """argparse type: a float that is not nan/inf, so limits and prices cannot be bypassed."""
    v = float(s)
    if not math.isfinite(v):
        raise argparse.ArgumentTypeError(f"must be a finite number, got {s!r}")
    return v


def _run(argv=None):
    ap = argparse.ArgumentParser(prog="agent-okta", description="Identity and access for AI agents.")
    ap.add_argument("--store", default=os.environ.get("AGENT_OKTA_STORE", "agent-okta.json"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    role = sub.add_parser("role").add_subparsers(dest="sub", required=True)
    ra = role.add_parser("add")
    ra.add_argument("name")
    ra.add_argument("--allow", action="append", default=[])
    ra.add_argument("--deny", action="append", default=[])
    ra.add_argument("--limit", action="append", default=[], help="scope=max_amount for spend scopes")
    role.add_parser("list")

    agent = sub.add_parser("agent").add_subparsers(dest="sub", required=True)
    aa = agent.add_parser("add")
    aa.add_argument("agent_id")
    aa.add_argument("--owner", required=True)
    aa.add_argument("--role", action="append", required=True)
    ad = agent.add_parser("disable")
    ad.add_argument("agent_id")
    agent.add_parser("list")

    tok = sub.add_parser("token").add_subparsers(dest="sub", required=True)
    ti = tok.add_parser("issue")
    ti.add_argument("agent_id")
    ti.add_argument("--ttl", type=int, default=900)
    tr = tok.add_parser("revoke")
    tr.add_argument("token")

    ck = sub.add_parser("check")
    ck.add_argument("token")
    ck.add_argument("action")
    ck.add_argument("resource")
    ck.add_argument("--amount", type=_finite_float)

    a = ap.parse_args(argv)
    d = Directory(a.store)

    if a.cmd == "role" and a.sub == "add":
        limits = {k: float(v) for k, v in (x.split("=", 1) for x in a.limit)}
        role = d.add_role(a.name, a.allow, a.deny, limits)
        print(f"role {role.name} saved ({len(role.rules)} rules)")
    elif a.cmd == "role":
        for r in d.roles.values():
            print(r.name, ", ".join(f"{x.effect}:{x.scope}" for x in r.rules))
    elif a.cmd == "agent" and a.sub == "add":
        ag = d.add_agent(a.agent_id, a.owner, a.role)
        print(f"agent {ag.agent_id} registered (owner {ag.owner}, roles {', '.join(ag.roles)})")
    elif a.cmd == "agent" and a.sub == "disable":
        d.disable_agent(a.agent_id)
        print(f"agent {a.agent_id} disabled; existing tokens now fail verification")
    elif a.cmd == "agent":
        for ag in d.agents.values():
            print(f"{ag.agent_id:<20} owner={ag.owner} roles={','.join(ag.roles)}{' DISABLED' if ag.disabled else ''}")
    elif a.cmd == "token" and a.sub == "issue":
        try:
            print(d.issue_token(a.agent_id, a.ttl))
        except TokenError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    elif a.cmd == "token":
        try:
            d.revoke(a.token)
        except TokenError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print("token revoked")
    elif a.cmd == "check":
        ok, reason = d.authorize(a.token, a.action, a.resource, a.amount)
        print(f"{'ALLOW' if ok else 'DENY'}  {reason}")
        d.save()
        return 0 if ok else 2
    d.save()
    return 0


def main(argv=None):
    """Run the CLI; a bad input file or argument exits 2 with a one-line error instead of a traceback.

    Set AGENT_ECONOMY_DEBUG=1 to see the full traceback.
    """
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        return _run(argv)
    except (OSError, ValueError, KeyError, csv.Error) as e:
        if os.environ.get("AGENT_ECONOMY_DEBUG"):
            raise
        msg = e.args[0] if isinstance(e, KeyError) and e.args else e
        print(f"error: {msg}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
