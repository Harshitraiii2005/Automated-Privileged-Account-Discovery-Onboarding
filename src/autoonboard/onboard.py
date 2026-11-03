"""Phase 4 - onboarding: classification -> reviewed plan -> human approval -> vaulted accounts.

CyberArk mapping:
- Safe          = KV v2 folder `safes/<SAFE>/` + two ACL policies (members, managers) + directory
                  group mappings (safe members are LDAP groups, via Vault's LDAP auth method).
- Platform      = see cpm.PLATFORMS (rotation period, password policy, verify/reconcile method).
- Onboard LDAP  = Vault static role `ldap/static-role/<SAFE>/<uid>`: Vault changes the password
                  immediately on import ("change on onboard"); nobody ever sees the old one.
- Onboard Linux = safe metadata + an immediate CPM change through the reconcile account.
- Pending accounts / approval = the plan file plus an approval bound to the plan's SHA-256: if the
                  plan changes after approval, nothing is applied (no approve-then-swap).

Least privilege in the pipeline itself: the onboarder AppRole can create safes and roles but can
never read or set a credential; credential changes run under the separate CPM AppRole.
"""

from __future__ import annotations

import datetime as dt
import functools
import getpass
import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import hvac
from hvac.exceptions import InvalidPath

from autoonboard import config as cfg
from autoonboard.cpm import MASTER_POLICY, PLATFORMS, Managed, change_unix, reconcile_key, record, verify_ldap

log = logging.getLogger(__name__)

# Safe members: the owning team's directory group may use (retrieve) the safe's credentials.
TEAM_GROUPS = {
    "infra": "IT Operations", "dba": "Database Team", "network": "Network Team", "security": "Security Team",
    "support": "Support", "engineering": "Engineering", "finance": "Finance", "sales": "Sales", "hr": "HR",
    "marketing": "Marketing",
}  # fmt: skip
SAFE_MANAGERS = "Security Team"  # the PAM team manages every safe but cannot retrieve passwords
TOOLING = {cfg.SCANNER_USER, cfg.RECON_USER}  # AutoOnboard's own accounts, managed out of band


def safe_name(a: dict[str, Any]) -> str:
    return f"{'LDAP' if a['source'] == 'ldap' else 'UNIX'}-{a['team'].upper()}"


def decide(a: dict[str, Any], c: dict[str, Any]) -> tuple[str, str, str] | None:
    """(action, platform, reason) for one account, or None when there is nothing to do."""
    label = c["label"]
    if a["source"] == "linux" and a["name"] in TOOLING:
        return None
    if label == "stale":
        return "remediate", "", f"stale ({c['reason']}): disable or delete it instead of vaulting it"
    if a["uid0"] and a["name"] != "root":
        return "remediate", "", "second UID 0 account: remove it (root is the only sanctioned UID 0)"
    if a["source"] == "ldap":
        if label == "service":
            return "onboard", "LDAP-SVC", "service account: vault and rotate"
        if label == "shared":
            return "onboard", "LDAP-SHARED", "shared account: vault, rotate, attribute access via Vault"
        if label == "human_admin":
            if a["mail"]:
                return "remediate", "", "privileges on a mailbox-enabled daily account: move them to a separate admin account"
            return "onboard", "LDAP-ADM", "personal admin account: vault and rotate daily"
        return None
    if a["name"] == "root":
        return "onboard", "UNIX-ROOT", "root: vault, rotate and verify via the reconcile account"
    if label == "shared" and a["interactive"]:
        return "onboard", "UNIX-SHARED", "shared interactive login: vault and rotate"
    if label == "service" and a["privileged"]:
        return "review", "", "privileged key-based service account: needs SSH key management (out of scope)"
    if label == "human_admin":
        return "review", "", "personal local admin account: prefer a directory identity with brokered access"
    return None


def digest(items: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(items, sort_keys=True).encode()).hexdigest()


def build_plan(inventory: list[dict[str, Any]], classes: dict[str, dict[str, Any]], prepared_by: str) -> dict[str, Any]:
    items = []
    for a in inventory:
        c = classes[a["id"]]
        if (decision := decide(a, c)) is None:
            continue
        action, platform, reason = decision
        items.append({
            "id": a["id"], "account": a["name"], "source": a["source"], "host": a["host"], "dn": a["dn"],
            "team": a["team"], "label": c["label"], "risk_score": c["risk_score"], "severity": c["severity"],
            "action": action, "platform": platform, "safe": safe_name(a) if action == "onboard" else "",
            "object": (a["name"] if a["source"] == "ldap" else f"{a['host']}.{a['name']}"), "reason": reason,
        })  # fmt: skip
    order = {"onboard": 0, "remediate": 1, "review": 2}
    items.sort(key=lambda i: (order[i["action"]], -i["risk_score"], i["id"]))
    stamp = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    return {"prepared_by": prepared_by, "prepared_at": stamp, "master_policy": MASTER_POLICY, "items": items, "sha256": digest(items)}


def save_json(path: Any, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1))


def load_plan() -> dict[str, Any]:
    plan: dict[str, Any] = json.loads(cfg.PLAN.read_text())
    if digest(plan["items"]) != plan["sha256"]:
        raise SystemExit(f"{cfg.PLAN} was modified after it was generated (hash mismatch); run `autoonboard plan` again")
    return plan


def approve(plan: dict[str, Any], approver: str, ids: list[str] | None = None, comment: str = "") -> dict[str, Any]:
    """Approve onboarding items (all of them when ids is None). Enforces segregation of duties."""
    if not MASTER_POLICY["self_approval_allowed"] and approver.strip().lower() == plan["prepared_by"].strip().lower():
        raise SystemExit(f"segregation of duties: {approver!r} prepared this plan and cannot approve it")
    onboardable = {i["id"] for i in plan["items"] if i["action"] == "onboard"}
    chosen = sorted(onboardable if ids is None else set(ids))
    if unknown := set(chosen) - onboardable:
        raise SystemExit(f"not onboarding items in this plan: {sorted(unknown)}")
    stamp = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    return {"plan_sha256": plan["sha256"], "approver": approver, "approved_at": stamp, "ids": chosen, "comment": comment}


def safe_policies(safe: str) -> dict[str, str]:
    key = safe.lower()
    users = f"""# Safe {safe}: members (CyberArk List + Retrieve + Use)
path "safes/data/{safe}/*" {{ capabilities = ["read"] }}
path "safes/metadata/{safe}/*" {{ capabilities = ["read", "list"] }}
path "ldap/static-cred/{safe}/*" {{ capabilities = ["read"] }}
"""
    managers = f"""# Safe {safe}: managers (CyberArk Manage Safe + Initiate CPM change). No Retrieve.
path "safes/metadata/{safe}/*" {{ capabilities = ["read", "list"] }}
path "ldap/static-role/{safe}/*" {{ capabilities = ["read", "list"] }}
path "ldap/rotate-role/{safe}/*" {{ capabilities = ["update"] }}
"""
    return {f"safe-{key}-users": users, f"safe-{key}-managers": managers}


def group_mapping(safes: set[str]) -> dict[str, str]:
    groups: dict[str, set[str]] = defaultdict(set)
    for safe in safes:
        team = safe.split("-", 1)[1].lower()
        if team in TEAM_GROUPS:
            groups[TEAM_GROUPS[team]].add(f"safe-{safe.lower()}-users")
        groups[SAFE_MANAGERS].add(f"safe-{safe.lower()}-managers")
    return {g: ",".join(sorted(p)) for g, p in sorted(groups.items())}


def existing_safes(vault: hvac.Client) -> set[str]:
    try:
        keys = vault.secrets.kv.v2.list_secrets("", mount_point="safes")["data"]["keys"]
    except InvalidPath:
        return set()
    return {k.rstrip("/") for k in keys} - {cfg.RECON_SECRET.split("/")[0]}


def is_onboarded(vault: hvac.Client, path: str) -> bool:
    try:
        meta = vault.secrets.kv.v2.read_secret_metadata(path, mount_point="safes")["data"].get("custom_metadata") or {}
    except InvalidPath:
        return False
    return "onboarded_at" in meta


def apply(dry_run: bool = False) -> list[str]:
    """Apply the approved part of the plan. Idempotent; with dry_run nothing is written (reads only)."""
    plan = load_plan()
    if not cfg.APPROVAL.exists():
        raise SystemExit("no approval on file: run `autoonboard approve` first (Master Policy: approval required)")
    approval = json.loads(cfg.APPROVAL.read_text())
    if approval["plan_sha256"] != plan["sha256"]:
        raise SystemExit("the plan changed after it was approved; review and approve it again")
    approved = set(approval["ids"])
    items = [i for i in plan["items"] if i["action"] == "onboard" and i["id"] in approved]

    onboarder = cfg.vault_client("onboarder")
    cpm = None if dry_run else cfg.vault_client("cpm")
    steps: list[str] = []

    def step(description: str, fn: Callable[[], object]) -> None:
        steps.append(("[dry-run] " if dry_run else "") + description)
        if not dry_run:
            fn()

    safes = {i["safe"] for i in items}
    for safe in sorted(safes):
        for name, hcl in safe_policies(safe).items():
            step(f"policy {name}", functools.partial(onboarder.sys.create_or_update_acl_policy, name, hcl))
    # Group mappings replace the previous list, so include safes onboarded by earlier runs too.
    for group, policies in group_mapping(safes | existing_safes(onboarder)).items():
        step(
            f"safe members: LDAP group '{group}' -> {policies}",
            functools.partial(onboarder.write_data, f"auth/ldap/groups/{group}", data={"policies": policies}),
        )

    key = None
    for item in items:
        path = f"{item['safe']}/{item['object']}"
        if is_onboarded(onboarder, path):
            steps.append(f"skip {item['id']}: already onboarded in {path}")
            continue
        platform = PLATFORMS[item["platform"]]
        stamp = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
        meta = {
            "id": item["id"], "platform": item["platform"], "source": item["source"], "host": item["host"],
            "account": item["account"], "dn": item["dn"], "team": item["team"], "label": item["label"],
            "risk_score": str(item["risk_score"]), "approved_by": approval["approver"],
            "approved_at": approval["approved_at"], "plan_sha256": plan["sha256"], "onboarded_at": stamp,
        }  # fmt: skip
        meta = {k: v for k, v in meta.items() if v}  # Vault rejects empty custom-metadata values
        if platform.kind == "ldap":
            role = {"dn": item["dn"], "username": item["account"], "rotation_period": f"{platform.rotation_days * 24}h"}
            step(f"static role ldap/static-role/{path} ({platform.rotation_days}d; Vault changes it now)",
                 functools.partial(onboarder.write_data, f"ldap/static-role/{path}", data=role))  # fmt: skip
        step(f"safe metadata safes/{path} [{item['platform']}]",
             functools.partial(onboarder.secrets.kv.v2.update_metadata, path, max_versions=20, custom_metadata=meta, mount_point="safes"))  # fmt: skip
        how = "verify the new password with an LDAP bind" if platform.kind == "ldap" else f"change it via {cfg.RECON_USER}, verify with su"
        steps.append(("[dry-run] " if dry_run else "") + f"CPM (separate AppRole): {how}")
        if dry_run:
            continue
        assert cpm is not None
        managed = Managed(item["safe"], item["object"], meta)
        if platform.kind == "ldap":
            ok, detail = verify_ldap(cpm, managed), "Vault changed the password on import"
        else:
            key = key or reconcile_key(cpm)
            ok, detail = change_unix(cpm, managed, key)
        record("change", path, "success" if ok else "failure", "info" if ok else "critical", platform=item["platform"],
               detail=f"onboarding: {detail}" + ("" if ok else " (verification failed)"))  # fmt: skip
        record("onboard", path, "success", platform=item["platform"], detail=f"approved by {approval['approver']}")
    return steps


def default_user() -> str:
    return getpass.getuser()
