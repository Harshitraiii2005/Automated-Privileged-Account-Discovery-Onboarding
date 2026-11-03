"""Lab-only failure scenarios for the CPM, plus a safe-membership access check.

These use powers the pipeline deliberately does not have (the LDAP root DN, `docker compose exec`),
because they play the part of a rogue or careless administrator acting outside the vault.
"""

from __future__ import annotations

import json
import logging
import secrets
import subprocess
from typing import Any

import hvac
import ldap3
from hvac.exceptions import Forbidden

from autoonboard import config as cfg
from autoonboard.cpm import Managed, managed_accounts, record

log = logging.getLogger(__name__)


def compose_exec(host: str, *argv: str, stdin: str | None = None) -> None:
    subprocess.run(["docker", "compose", "exec", "-T", host, *argv], input=stdin, text=True, check=True, cwd=cfg.REPO_ROOT, capture_output=True)


def admin_set_ldap_password(dn: str, password: str) -> None:
    with ldap3.Connection(cfg.ldap_server(), cfg.ADMIN_DN, cfg.secret("LDAP_ADMIN_PASSWORD"), auto_bind=True) as conn:
        if not conn.modify(dn, {"userPassword": [(ldap3.MODIFY_REPLACE, [password])]}):
            raise RuntimeError(f"could not reset {dn}: {conn.result}")


def targets() -> dict[str, Managed]:
    """Deterministic picks among onboarded accounts: one LDAP drift, one Linux drift, one Linux expiry."""
    managed = sorted(managed_accounts(cfg.vault_client("auditor")), key=lambda m: m.path)
    ldap = [m for m in managed if m.meta["platform"] == "LDAP-SVC"]
    unix = [m for m in managed if m.meta["platform"] == "UNIX-SHARED"] + [m for m in managed if m.meta["platform"] == "UNIX-ROOT"]
    if not ldap or len(unix) < 2:
        raise SystemExit("need at least one onboarded LDAP-SVC and two Linux accounts; run onboarding first")
    return {"ldap_drift": ldap[0], "linux_drift": unix[0], "linux_expired": unix[1]}


def failures() -> dict[str, Any]:
    """Change two passwords behind the vault's back and expire a third account (reconcile cannot fix that)."""
    picked = targets()
    admin_set_ldap_password(picked["ldap_drift"].meta["dn"], secrets.token_urlsafe(18))
    drift = picked["linux_drift"]
    compose_exec(drift.meta["host"], "chpasswd", stdin=f"{drift.meta['account']}:{secrets.token_urlsafe(18)}\n")
    expired = picked["linux_expired"]
    compose_exec(expired.meta["host"], "chage", "-E", "0", expired.meta["account"])
    state = {k: {"path": m.path, "host": m.meta.get("host", ""), "account": m.meta["account"]} for k, m in picked.items()}
    cfg.SCENARIOS.parent.mkdir(parents=True, exist_ok=True)
    cfg.SCENARIOS.write_text(json.dumps(state, indent=1))
    for k, m in picked.items():
        record("simulate", m.path, k, "info", detail="lab scenario: out-of-band change" if "drift" in k else "lab scenario: account expired")
    return state


def restore() -> None:
    """Undo the expiry so the CPM can verify again (the drifted passwords were already reconciled)."""
    state = json.loads(cfg.SCENARIOS.read_text())
    expired = state["linux_expired"]
    compose_exec(expired["host"], "chage", "-E", "-1", expired["account"])
    record("simulate", expired["path"], "restored", "info", detail="lab scenario: expiry removed")


def access_check() -> list[tuple[str, bool, str]]:
    """Log in to Vault as a directory user and show safe membership working in both directions."""
    managed = managed_accounts(cfg.vault_client("auditor"))
    by_safe: dict[str, list[Managed]] = {}
    for m in managed:
        if m.meta["platform"].startswith("LDAP"):
            by_safe.setdefault(m.safe, []).append(m)
    if "LDAP-DBA" not in by_safe or len(by_safe) < 2:
        raise SystemExit("need onboarded accounts in LDAP-DBA and one other LDAP safe")
    own = min(by_safe["LDAP-DBA"], key=lambda m: m.path)
    other = min((m for safe, ms in by_safe.items() if safe != "LDAP-DBA" for m in ms), key=lambda m: m.path)

    # A member of the "Database Team" group with a daily (non-privileged) account.
    inventory = json.loads(cfg.INVENTORY.read_text())["accounts"]
    member = next(a for a in inventory if a["source"] == "ldap" and "Database Team" in a["groups"] and not a["privileged"] and a["activity"] == "active")
    password = secrets.token_urlsafe(24)
    admin_set_ldap_password(member["dn"], password)  # lab only: nobody knows seeded passwords

    user = hvac.Client(url=cfg.VAULT_ADDR, verify=str(cfg.CA_CERT))
    user.auth.ldap.login(username=member["name"], password=password)
    results = []
    for m, expect in ((own, True), (other, False)):
        try:
            user.read(f"ldap/static-cred/{m.path}")
            allowed = True
        except Forbidden:
            allowed = False
        detail = f"{member['name']} (Database Team) reading {m.path}: {'allowed' if allowed else 'denied'}"
        results.append((m.path, allowed == expect, detail))
        record("access-check", m.path, "allowed" if allowed else "denied", "info" if allowed == expect else "critical", detail=detail)
    return results
