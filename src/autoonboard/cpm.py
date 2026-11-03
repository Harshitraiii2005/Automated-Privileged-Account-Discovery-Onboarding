"""Phase 5 - CPM: verify, rotate and reconcile onboarded credentials, and alert on failures.

CyberArk CPM mapping:
- platform  = rotation period + password policy + verify/reconcile method (PLATFORMS below).
- change    = LDAP: Vault static-role rotation (Vault is the CPM for directory accounts).
              Linux: generate (Vault password policy) -> store as *pending* -> set through the
              reconcile account -> verify -> mark active. Storing first means a crash mid-change can
              never lose the only copy of the new password.
- verify    = a real login with the vaulted password: LDAP bind, or `su` on a PTY via the logon account.
- reconcile = when verify fails (password changed out of band), reset it with the privileged
              reconcile identity (Vault's rotator for LDAP, svc_aorecon for Linux) and verify again.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import logging
import shlex
from collections import Counter
from dataclasses import dataclass
from typing import Any

import hvac
import paramiko
from hvac.exceptions import InvalidPath

from autoonboard import config as cfg

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Platform:
    kind: str  # ldap | unix
    rotation_days: int
    description: str


PLATFORMS = {
    "LDAP-SVC": Platform("ldap", 30, "Directory service account; Vault static role rotates it"),
    "LDAP-SHARED": Platform("ldap", 7, "Shared directory account; Vault static role rotates it"),
    "LDAP-ADM": Platform("ldap", 1, "Personal tiered admin account; rotated daily"),
    "UNIX-ROOT": Platform("unix", 7, "Linux root; CPM changes it via the reconcile account, verifies with su"),
    "UNIX-SHARED": Platform("unix", 7, "Linux shared login; CPM changes it via the reconcile account, verifies with su"),
}
# CyberArk Master Policy analogue: rules every platform and onboarding must satisfy (checked in report.py).
MASTER_POLICY = {
    "max_rotation_days": 90,
    "approval_required": True,
    "self_approval_allowed": False,
    "verify_after_change": True,
}
assert all(p.rotation_days <= MASTER_POLICY["max_rotation_days"] for p in PLATFORMS.values())

PASSWORD_POLICY = "sys/policies/password/autoonboard-unix/generate"
VERIFY_MARK = "AUTOONBOARD-VERIFY-OK"


def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def record(event: str, account: str, result: str, severity: str = "info", **detail: Any) -> dict[str, Any]:
    """Append to the CPM activity log (events.jsonl); warning/critical entries are the alerts."""
    entry = {"ts": now().isoformat(timespec="seconds"), "event": event, "account": account, "result": result, "severity": severity, **detail}
    cfg.EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with cfg.EVENTS.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    (log.warning if severity != "info" else log.debug)("%s %s %s %s", event, account, result, detail.get("detail", ""))
    return entry


def read_events() -> list[dict[str, Any]]:
    return [json.loads(line) for line in cfg.EVENTS.read_text().splitlines()] if cfg.EVENTS.exists() else []


@dataclass
class Managed:
    """An onboarded account, as recorded in its safe's KV metadata (Vault is the source of truth)."""

    safe: str
    obj: str
    meta: dict[str, str]

    @property
    def path(self) -> str:
        return f"{self.safe}/{self.obj}"

    @property
    def platform(self) -> Platform:
        return PLATFORMS[self.meta["platform"]]


def managed_accounts(vault: hvac.Client) -> list[Managed]:
    kv = vault.secrets.kv.v2
    try:
        safes = [s.rstrip("/") for s in kv.list_secrets("", mount_point="safes")["data"]["keys"]]
    except InvalidPath:
        return []
    found = []
    for safe in safes:
        if safe == cfg.RECON_SECRET.split("/")[0]:
            continue
        for obj in kv.list_secrets(safe, mount_point="safes")["data"]["keys"]:
            meta = kv.read_secret_metadata(f"{safe}/{obj}", mount_point="safes")["data"].get("custom_metadata") or {}
            if meta.get("platform") in PLATFORMS:
                found.append(Managed(safe, obj, meta))
    return found


# --- LDAP: Vault rotates, we verify ---------------------------------------------------------------


def verify_ldap(vault: hvac.Client, m: Managed) -> bool:
    cred = vault.read(f"ldap/static-cred/{m.path}")["data"]
    return cfg.ldap_binds(cred["dn"], cred["password"])


def rotate_ldap(vault: hvac.Client, m: Managed) -> None:
    vault.write_data(f"ldap/rotate-role/{m.path}", data={})


# --- Linux: we are the CPM ------------------------------------------------------------------------


def reconcile_key(vault: hvac.Client) -> paramiko.PKey:
    secret = vault.secrets.kv.v2.read_secret_version(cfg.RECON_SECRET, mount_point="safes", raise_on_deleted_version=True)
    return paramiko.Ed25519Key.from_private_key(io.StringIO(secret["data"]["data"]["private_key"]))


def _read_until(chan: paramiko.Channel, token: bytes | None) -> bytes:
    buf = b""
    while token is None or token not in buf:
        chunk = chan.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def su_ok(ssh: paramiko.SSHClient, user: str, password: str) -> bool:
    """Verify by actually logging in: `su - user` on a PTY, answering the prompt with the vaulted password."""
    transport = ssh.get_transport()
    assert transport is not None
    chan = transport.open_session(timeout=10)
    try:
        chan.settimeout(20)
        chan.get_pty()
        chan.exec_command(f"LC_ALL=C su - {shlex.quote(user)} -c 'echo {VERIFY_MARK}'")
        if b"assword" not in _read_until(chan, b"assword"):
            return False
        chan.sendall(password.encode() + b"\n")
        return VERIFY_MARK.encode() in _read_until(chan, None) and chan.recv_exit_status() == 0
    except TimeoutError:
        return False
    finally:
        chan.close()


def set_password(ssh: paramiko.SSHClient, user: str, password: str) -> tuple[bool, str]:
    """Set via the root-owned setpw wrapper; the password travels on stdin, never in a command line."""
    stdin, stdout, stderr = ssh.exec_command(f"sudo -n {cfg.SETPW} {shlex.quote(user)}", timeout=30)
    stdin.write(password + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    status = stdout.channel.recv_exit_status()
    return status == 0, stderr.read().decode().strip()


def unix_secret(vault: hvac.Client, m: Managed) -> dict[str, str] | None:
    try:
        data = vault.secrets.kv.v2.read_secret_version(m.path, mount_point="safes", raise_on_deleted_version=True)
    except InvalidPath:
        return None
    return dict(data["data"]["data"])


def store(vault: hvac.Client, m: Managed, secret: dict[str, str]) -> None:
    vault.secrets.kv.v2.create_or_update_secret(m.path, secret=secret, mount_point="safes")


def change_unix(vault: hvac.Client, m: Managed, key: paramiko.PKey) -> tuple[bool, str]:
    """Pending -> set -> verify -> active. Returns (verified, detail)."""
    host, user = m.meta["host"], m.meta["account"]
    previous = unix_secret(vault, m)
    new = vault.read(PASSWORD_POLICY)["data"]["password"]
    stamp = now().isoformat(timespec="seconds")
    store(vault, m, {"password": new, "status": "pending", "changed_at": stamp})
    with cfg.ssh_connect(host, cfg.RECON_USER, key) as ssh:
        changed, err = set_password(ssh, user, new)
        if not changed:
            # The host still has the previous password, so the vault must too.
            store(vault, m, previous or {"password": "", "status": "change_failed", "changed_at": stamp})
            return False, f"set password failed: {err}"
        verified = su_ok(ssh, user, new)
    store(vault, m, {"password": new, "status": "active" if verified else "verify_failed", "changed_at": stamp,
                     "verified_at": stamp if verified else ""})  # fmt: skip
    return verified, "changed and verified" if verified else "changed, but login with the new password failed"


def verify_unix(vault: hvac.Client, m: Managed, key: paramiko.PKey) -> bool:
    secret = unix_secret(vault, m)
    if not secret or not secret.get("password"):
        return False
    with cfg.ssh_connect(m.meta["host"], cfg.RECON_USER, key) as ssh:
        ok = su_ok(ssh, m.meta["account"], secret["password"])
    if ok and secret.get("status") != "active":
        store(vault, m, secret | {"status": "active", "verified_at": now().isoformat(timespec="seconds")})
    return ok


def due(secret: dict[str, str] | None, platform: Platform) -> bool:
    if not secret or not secret.get("changed_at"):
        return True
    return now() - dt.datetime.fromisoformat(secret["changed_at"]) >= dt.timedelta(days=platform.rotation_days)


# --- one CPM cycle --------------------------------------------------------------------------------


def run(force: bool = False) -> Counter[str]:
    """Verify every managed account; change Linux ones that are due (or all, with force); reconcile drift."""
    vault = cfg.vault_client("cpm")
    key: paramiko.PKey | None = None
    outcome: Counter[str] = Counter()
    for m in managed_accounts(vault):
        name, platform = m.path, m.meta["platform"]
        try:
            if m.platform.kind == "ldap":
                if force:
                    rotate_ldap(vault, m)
                    record("change", name, "success", platform=platform, detail="rotated by Vault (rotate-role)")
                if verify_ldap(vault, m):
                    record("verify", name, "success", platform=platform)
                    outcome["verified"] += 1
                    continue
                record("verify", name, "failure", "warning", platform=platform, detail="vaulted password rejected (changed out of band?)")
                rotate_ldap(vault, m)  # reconcile: the rotator resets it without knowing the old one
                ok = verify_ldap(vault, m)
            else:
                key = key or reconcile_key(vault)
                secret = unix_secret(vault, m)
                if force or due(secret, m.platform):
                    ok, detail = change_unix(vault, m, key)
                    record("change", name, "success" if ok else "failure", "info" if ok else "critical", platform=platform, detail=detail)
                    outcome["changed" if ok else "failed"] += 1
                    continue
                if verify_unix(vault, m, key):
                    recovered = secret is not None and secret.get("status") != "active"
                    record("verify", name, "success", platform=platform, detail="recovered" if recovered else "")
                    outcome["verified"] += 1
                    continue
                record("verify", name, "failure", "warning", platform=platform, detail="vaulted password rejected (changed out of band?)")
                ok, detail = change_unix(vault, m, key)
            if ok:
                record("reconcile", name, "success", "warning", platform=platform, detail="drift detected and reset by the reconcile account")
                outcome["reconciled"] += 1
            else:
                record("reconcile", name, "failure", "critical", platform=platform, detail="reconcile failed: manual intervention required")
                outcome["failed"] += 1
        except Exception as e:  # noqa: BLE001 - one broken account must not stop the cycle
            record("error", name, "failure", "critical", platform=platform, detail=f"{type(e).__name__}: {e}")
            outcome["failed"] += 1
    return outcome
