"""Lab health check: proves each component is up *and* enforcing the intended controls. Exit 1 on any failure."""

from __future__ import annotations

import csv
import json
import logging
import sys
from collections import Counter
from collections.abc import Callable, Iterator

import ldap3
import paramiko

from autoonboard import config as cfg

Result = tuple[str, bool, str]


def ground_truth() -> list[dict[str, str]]:
    with cfg.GROUND_TRUTH.open() as f:
        return list(csv.DictReader(f))


def check_seed() -> Iterator[Result]:
    rows = ground_truth()
    manifest = json.loads(cfg.MANIFEST.read_text())
    labels = Counter(r["label"] for r in rows)
    yield "seed: ground truth", bool(rows), f"{len(rows)} accounts, generated {manifest['generated_at']}: {dict(labels)}"


def check_ldap() -> Iterator[Result]:
    server = cfg.ldap_server()
    with ldap3.Connection(server, cfg.SCANNER_DN, cfg.secret("LDAP_SCANNER_PASSWORD"), auto_bind=True) as conn:
        yield "ldap: LDAPS bind as discovery-scanner (CA + hostname verified)", True, f"{cfg.LDAP_HOST}:{cfg.LDAP_PORT}"

        conn.search(cfg.BASE_DN, "(objectClass=inetOrgPerson)", attributes=["uid", "userPassword", "pwdChangedTime", "pwdLastSuccess"])
        entries = [r["attributes"] for r in conn.response if r["type"] == "searchResEntry"]
        found = {e["uid"][0] for e in entries}
        expected = {r["account"] for r in ground_truth() if r["source"] == "ldap"}
        yield "ldap: seeded accounts present", found == expected, f"{len(found)} found, {len(expected)} expected"
        aged = sum(bool(e["pwdChangedTime"]) for e in entries)
        logons = sum(bool(e["pwdLastSuccess"]) for e in entries)
        yield "ldap: backdated ppolicy/last-logon attributes", aged == len(entries) and logons > 0, f"pwdChangedTime {aged}, pwdLastSuccess {logons}"
        leaked = sum(bool(e["userPassword"]) for e in entries)
        yield "ldap: scanner cannot read password hashes", leaked == 0, f"{leaked} hashes readable"

        conn.search(f"ou=Groups,{cfg.BASE_DN}", "(objectClass=groupOfNames)", attributes=["cn"])
        groups = {r["attributes"]["cn"][0] for r in conn.response if r["type"] == "searchResEntry"}
        missing = set(cfg.PRIVILEGED_GROUPS) - groups
        yield "ldap: privileged groups present", not missing, f"missing {sorted(missing)}" if missing else f"{len(groups)} groups"

    yield "ldap: anonymous bind refused", not cfg.ldap_binds(None, None), "olcDisallows: bind_anon"
    # Vault's rotate-root ran in bootstrap, so the password in .env must no longer work.
    yield "ldap: Vault owns the rotator credential", not cfg.ldap_binds(cfg.ROTATOR_DN, cfg.secret("LDAP_ROTATOR_PASSWORD")), "bootstrap password rejected"


def check_vault() -> Iterator[Result]:
    health = cfg.vault_client().sys.read_health_status(method="GET")
    active = isinstance(health, dict) and health["initialized"] and not health["sealed"] and not health["standby"]
    yield "vault: initialised, unsealed, active over TLS", bool(active), f"version {health.get('version') if isinstance(health, dict) else health}"

    vault = cfg.vault_client("auditor")  # read-only AppRole: proves the checks need no credential access
    yield "vault: auditor AppRole login", vault.is_authenticated(), "policies: auditor"
    audit = vault.sys.list_enabled_audit_devices()["data"]
    yield "vault: file audit device enabled", "file/" in audit, audit.get("file/", {}).get("options", {}).get("file_path", "missing")
    mounts = vault.sys.list_mounted_secrets_engines()["data"]
    engines = {p: m["type"] for p, m in mounts.items() if p in ("safes/", "ldap/")}
    yield "vault: safes (kv-v2) and ldap engines mounted", engines == {"safes/": "kv", "ldap/": "ldap"}, str(engines)
    ldap_cfg = (vault.read("ldap/config") or {}).get("data", {})
    yield "vault: ldap engine bound as vault-rotator over LDAPS", ldap_cfg.get("binddn") == cfg.ROTATOR_DN, ldap_cfg.get("url", "not configured")
    auth = vault.sys.list_auth_methods()["data"]
    yield "vault: approle + ldap auth methods enabled", {"approle/", "ldap/"} <= set(auth), ", ".join(sorted(auth))
    in_vault = vault.secrets.kv.v2.read_secret_metadata(cfg.RECON_SECRET, mount_point="safes") is not None
    yield "vault: CPM reconcile key only in Vault", in_vault and not cfg.RECON_KEY.exists(), f"safes/{cfg.RECON_SECRET}"


def check_hosts() -> Iterator[Result]:
    rows = ground_truth()
    key = paramiko.Ed25519Key.from_private_key_file(str(cfg.SCANNER_KEY))
    for host in cfg.HOSTS:
        try:
            with cfg.ssh_connect(host, cfg.SCANNER_USER, key) as ssh:
                _, out, _ = ssh.exec_command(f"getent passwd | cut -d: -f1; sudo -n {cfg.COLLECTOR} | grep -c '^### '", timeout=20)
                *lines, sections = out.read().decode().split()
                names = set(lines)
        except Exception as e:  # noqa: BLE001 - one unreachable host must not hide the others
            yield f"ssh: {host}", False, f"{type(e).__name__}: {e}"
            continue
        expected = {r["account"] for r in rows if r["host"] == host}
        missing = expected - names
        detail = f"missing {sorted(missing)}" if missing else f"{len(expected)} seeded of {len(names)} local accounts"
        yield f"ssh: {host} pinned host key, key auth, accounts present", not missing, detail
        yield f"ssh: {host} scanner may sudo the read-only collector", sections == "7", f"{sections}/7 sections"


def main() -> int:
    logging.basicConfig(level=logging.WARNING)
    checks: list[Callable[[], Iterator[Result]]] = [check_seed, check_ldap, check_vault, check_hosts]
    results: list[Result] = []
    for check in checks:
        try:
            results.extend(check())
        except Exception as e:  # noqa: BLE001 - report and keep checking the rest of the lab
            results.append((check.__name__.removeprefix("check_"), False, f"{type(e).__name__}: {e}"))
    width = max(len(name) for name, _, _ in results)
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<{width}}  {detail}")
    failed = sum(not ok for _, ok, _ in results)
    print(f"\n{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
