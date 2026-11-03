"""Initialise, unseal and configure the lab Vault. Idempotent: re-run after every restart (Vault starts sealed).

Lab trade-offs, made deliberately and documented: a single unseal key share and the initial root
token live in the git-ignored lab/.generated/vault/init.json (0600). Production would use auto-unseal
(cloud KMS / HSM) or Shamir shares held by separate custodians, and would revoke the root token once
setup is done (regenerating one with `vault operator generate-root` when really needed). After this
bootstrap nothing uses the root token: the pipeline runs as three least-privilege AppRoles.
"""

from __future__ import annotations

import json
import logging
import time

import hvac

from autoonboard import config as cfg
from autoonboard.lab.generate import write

log = logging.getLogger(__name__)

AUDIT_LOG = "/vault/logs/audit.log"
POLICY_DIR = cfg.REPO_ROOT / "lab" / "vault" / "policies"
APPROLES = ("onboarder", "cpm", "auditor")  # each gets the ACL policy of the same name


def charset_rules(length: int) -> str:
    """Vault password policy: the analogue of a CyberArk platform's password complexity rules."""
    sets = ("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#%^*-_=+")
    return f"length = {length}\n" + "".join(f'rule "charset" {{\n  charset = "{s}"\n  min-chars = 2\n}}\n' for s in sets)


PASSWORD_POLICIES = {"autoonboard-ldap": charset_rules(32), "autoonboard-unix": charset_rules(24)}


def init_and_unseal(vault: hvac.Client) -> str:
    """Return the root token, initialising and unsealing Vault as needed."""
    if not vault.sys.is_initialized():
        result = vault.sys.initialize(secret_shares=1, secret_threshold=1)
        write(cfg.VAULT_INIT, json.dumps(result, indent=2), 0o600)
        log.info("initialised Vault; unseal key and root token written to %s", cfg.VAULT_INIT)
    elif not cfg.VAULT_INIT.exists():
        raise SystemExit(f"Vault is initialised but {cfg.VAULT_INIT} is missing; run `make lab-reset` to start over")
    init = json.loads(cfg.VAULT_INIT.read_text())
    if vault.sys.is_sealed():
        vault.sys.submit_unseal_key(init["keys"][0])
        log.info("unsealed Vault")
    for _ in range(30):  # raft needs a moment after unseal to elect itself leader
        health = vault.sys.read_health_status(method="GET")
        if isinstance(health, dict) and health.get("initialized") and not health.get("sealed") and not health.get("standby"):
            return str(init["root_token"])
        time.sleep(1)
    raise SystemExit(f"Vault did not become active: {health}")


def configure(vault: hvac.Client) -> None:
    # Audit first, so every configuration change that follows is itself in the audit trail.
    if "file/" not in vault.sys.list_enabled_audit_devices()["data"]:
        vault.sys.enable_audit_device("file", options={"file_path": AUDIT_LOG})
        log.info("enabled file audit device -> %s", AUDIT_LOG)

    mounts = vault.sys.list_mounted_secrets_engines()["data"]
    if "safes/" not in mounts:
        vault.sys.enable_secrets_engine("kv", path="safes", options={"version": "2"}, description="CyberArk-style safes")
        log.info("enabled kv-v2 at safes/")
    if "ldap/" not in mounts:
        vault.sys.enable_secrets_engine("ldap", path="ldap", description="CPM-style rotation of directory accounts")
        log.info("enabled ldap secrets engine at ldap/")

    for name, rules in PASSWORD_POLICIES.items():
        vault.write_data(f"sys/policies/password/{name}", data={"policy": rules})
    for policy in sorted(POLICY_DIR.glob("*.hcl")):
        vault.sys.create_or_update_acl_policy(policy.stem, policy.read_text())

    # Configure once only: after rotate-root the .env password is intentionally stale, and writing it
    # back would break the engine.
    if vault.read("ldap/config") is None:
        vault.write_data(
            "ldap/config",
            data={
                "binddn": cfg.ROTATOR_DN,
                "bindpass": cfg.secret("LDAP_ROTATOR_PASSWORD"),
                "url": cfg.VAULT_LDAP_URL,
                "certificate": cfg.CA_CERT.read_text(),
                "tls_min_version": "tls12",
                "userdn": cfg.BASE_DN,
                "userattr": "uid",
                "schema": "openldap",
                "password_policy": "autoonboard-ldap",
            },
        )
        # Like a CyberArk reconcile account: once Vault owns the bind credential, no human knows it.
        vault.write_data("ldap/rotate-root", data={})
        log.info("configured ldap engine as %s and rotated its bind password", cfg.ROTATOR_DN)

    auth = vault.sys.list_auth_methods()["data"]
    for method in ("approle", "ldap"):
        if f"{method}/" not in auth:
            vault.sys.enable_auth_method(method)
            log.info("enabled %s auth method", method)
    # Human sign-in with directory credentials; group membership decides which safes they can use.
    vault.write_data(
        "auth/ldap/config",
        data={
            "url": cfg.VAULT_LDAP_URL,
            "certificate": cfg.CA_CERT.read_text(),
            "tls_min_version": "tls12",
            "binddn": cfg.SCANNER_DN,  # read-only search account
            "bindpass": cfg.secret("LDAP_SCANNER_PASSWORD"),
            "userdn": cfg.BASE_DN,
            "userattr": "uid",
            "groupdn": f"ou=Groups,{cfg.BASE_DN}",
            "groupfilter": "(&(objectClass=groupOfNames)(member={{.UserDN}}))",
            "groupattr": "cn",
            "deny_null_bind": True,
            "token_ttl": "1h",
        },
    )
    for role in APPROLES:
        vault.auth.approle.create_or_update_approle(role, token_policies=[role], token_ttl="1h", token_max_ttl="4h")
    if not cfg.VAULT_APPROLES.exists():
        creds = {
            role: {
                "role_id": vault.auth.approle.read_role_id(role)["data"]["role_id"],
                "secret_id": vault.auth.approle.generate_secret_id(role)["data"]["secret_id"],
            }
            for role in APPROLES
        }
        write(cfg.VAULT_APPROLES, json.dumps(creds, indent=2), 0o600)
        log.info("issued AppRole credentials for %s -> %s", ", ".join(APPROLES), cfg.VAULT_APPROLES)

    # The Linux reconcile key lives only in Vault (like a CyberArk reconcile account in its own safe).
    secret_path = f"safes/data/{cfg.RECON_SECRET}"
    if vault.read(secret_path) is None:
        if not cfg.RECON_KEY.exists():
            raise SystemExit(f"{cfg.RECON_KEY} is missing and Vault has no reconcile key; run `make lab-reset`")
        vault.secrets.kv.v2.create_or_update_secret(
            cfg.RECON_SECRET, secret={"username": cfg.RECON_USER, "private_key": cfg.RECON_KEY.read_text()}, mount_point="safes"
        )
        log.info("stored the CPM reconcile SSH key in safes/%s", cfg.RECON_SECRET)
    if cfg.RECON_KEY.exists():
        cfg.RECON_KEY.unlink()
        log.info("deleted the local copy of the reconcile key")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    vault = cfg.vault_client()
    vault.token = init_and_unseal(vault)
    configure(vault)
    log.info("Vault ready at %s", cfg.VAULT_ADDR)


if __name__ == "__main__":
    main()
