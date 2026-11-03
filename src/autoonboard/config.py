"""Lab endpoints, paths, secrets and connection factories shared by every AutoOnboard module.

Endpoints are constants because the lab is fixed by compose.yaml; secrets come only from the
environment or the git-ignored `.env` (created from `.env.example` by `make lab-gen`).
"""

from __future__ import annotations

import json
import os
import ssl
from pathlib import Path
from typing import NamedTuple

import hvac
import ldap3
import paramiko
from ldap3.core.exceptions import LDAPBindError

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

GENERATED = REPO_ROOT / "lab" / ".generated"
MANIFEST = GENERATED / "manifest.json"
GROUND_TRUTH = GENERATED / "ground_truth.csv"
CA_CERT = GENERATED / "certs" / "ca.crt"
SCANNER_KEY = GENERATED / "ssh" / "scanner_ed25519"
RECON_KEY = GENERATED / "ssh" / "recon_ed25519"  # uploaded into Vault by bootstrap, then deleted
KNOWN_HOSTS = GENERATED / "ssh" / "known_hosts"
VAULT_INIT = GENERATED / "vault" / "init.json"
VAULT_APPROLES = GENERATED / "vault" / "approles.json"

# Pipeline outputs (git-ignored). Override with AUTOONBOARD_OUT, e.g. in tests.
OUT = Path(os.environ.get("AUTOONBOARD_OUT", REPO_ROOT / "out"))
INVENTORY = OUT / "inventory.json"
CLASSIFICATION = OUT / "classification.json"
METRICS = OUT / "classification_metrics.json"
PLAN = OUT / "onboarding_plan.json"
APPROVAL = OUT / "approval.json"
EVENTS = OUT / "events.jsonl"
SCENARIOS = OUT / "scenarios.json"
REPORT_DIR = OUT / "report"
EVIDENCE_DIR = OUT / "evidence"

BASE_DN = "dc=autoonboard,dc=lab"
ADMIN_DN = f"cn=admin,{BASE_DN}"
SCANNER_DN = f"cn=discovery-scanner,ou=System,{BASE_DN}"
ROTATOR_DN = f"cn=vault-rotator,ou=System,{BASE_DN}"

# Everything is published on loopback only (see compose.yaml). Vault is addressed by IP (cert has an
# IP SAN); LDAP by name, because ldap3's hostname check cannot match IP SANs (see ldap_server()).
LDAP_HOST, LDAP_PORT = "localhost", 1636
VAULT_ADDR = "https://127.0.0.1:8200"
VAULT_LDAP_URL = "ldaps://ldap:636"  # as seen from inside the compose network

SCANNER_USER = "svc_aoscan"  # discovery: may sudo exactly COLLECTOR, nothing else
RECON_USER = "svc_aorecon"  # CPM reconcile/logon account: may sudo exactly SETPW
COLLECTOR = "/usr/local/sbin/autoonboard-collect"
SETPW = "/usr/local/sbin/autoonboard-setpw"
RECON_SECRET = "PAM-INTERNAL/unix-reconcile"  # path in the safes/ KV mount


class Host(NamedTuple):
    port: int  # published SSH port on 127.0.0.1
    sudo_group: str
    team: str  # owning team; picks the safe for host-level accounts such as root


HOSTS: dict[str, Host] = {
    "web01": Host(2201, "sudo", "infra"),
    "db01": Host(2202, "wheel", "dba"),
    "app01": Host(2203, "sudo", "engineering"),
}

PRIVILEGED_GROUPS = ("Domain Admins", "DB Admins", "Linux Sudo", "Backup Operators", "Network Admins", "Helpdesk")
STALE_AFTER_DAYS = 90


def ldap_server() -> ldap3.Server:
    """LDAPS with full certificate and hostname verification against the lab CA; IPv4 only (no ::1 attempt)."""
    tls = ldap3.Tls(ca_certs_file=str(CA_CERT), validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
    return ldap3.Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, tls=tls, mode=ldap3.IP_V4_ONLY, get_info=ldap3.NONE, connect_timeout=5)


def ldap_binds(dn: str | None, password: str | None) -> bool:
    """True if a simple bind succeeds: the LDAP 'verify' (and how the health check proves denials)."""
    try:
        ldap3.Connection(ldap_server(), dn, password, auto_bind=True).unbind()
        return True
    except LDAPBindError:
        return False


def vault_client(role: str | None = None) -> hvac.Client:
    """Vault client over verified TLS; with `role`, logged in via that AppRole (onboarder, cpm, auditor)."""
    client = hvac.Client(url=VAULT_ADDR, verify=str(CA_CERT))
    if role:
        creds = json.loads(VAULT_APPROLES.read_text())[role]
        client.auth.approle.login(role_id=creds["role_id"], secret_id=creds["secret_id"])
    return client


def ssh_connect(host: str, user: str, key: paramiko.PKey) -> paramiko.SSHClient:
    """SSH to a lab host with key auth and a pinned host key (unknown or changed keys are rejected)."""
    ssh = paramiko.SSHClient()
    ssh.load_host_keys(str(KNOWN_HOSTS))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())  # never trust on first use
    ssh.connect("127.0.0.1", port=HOSTS[host].port, username=user, pkey=key, look_for_keys=False,
                allow_agent=False, timeout=10, banner_timeout=10, auth_timeout=10)  # fmt: skip
    return ssh


def read_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines. No quoting/escaping support; generated values never need it."""
    if not path.exists():
        return {}
    pairs = (line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.lstrip().startswith("#"))
    return {k.strip(): v.strip() for k, v in pairs}


def secret(name: str) -> str:
    """Return a lab secret from the process environment, falling back to .env."""
    value = os.environ.get(name) or read_env_file(ENV_FILE).get(name)
    if not value:
        raise RuntimeError(f"{name} is not set; run `make lab-gen` to create .env")
    return value
