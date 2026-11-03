"""Phase 6 - reporting & audit evidence.

`build()` gathers pipeline outputs plus a read-only Vault snapshot (auditor AppRole: configuration,
metadata and rotation state, never a credential) and renders one HTML report, optionally as PDF via
headless Chrome. `evidence()` zips everything a compliance reviewer needs, with a SHA-256 manifest.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import shutil
import subprocess
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import jinja2

from autoonboard import config as cfg
from autoonboard.cpm import MASTER_POLICY, PLATFORMS, managed_accounts, read_events

log = logging.getLogger(__name__)

CHROME = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
CONTROLS = (  # indicative mapping for reviewers, not an assessment
    ("NIST 800-53 AC-2", "Account management", "Unified inventory of directory and local accounts; owners and teams"),
    ("NIST 800-53 AC-2(3)", "Disable accounts", "Stale accounts detected with evidence; remediation list"),
    ("NIST 800-53 AC-6", "Least privilege", "Per-safe policies; members vs managers; pipeline split into 3 AppRoles"),
    ("NIST 800-53 AC-6(5)", "Privileged accounts", "Privileged accounts vaulted with approval records"),
    ("NIST 800-53 IA-5(1)", "Password-based authentication", "Vault password policies, scheduled rotation, verification"),
    ("NIST 800-53 AU-2 / AU-12", "Event logging", "Vault file audit device + CPM activity log"),
    ("NIST 800-53 AU-6", "Audit review", "Credential-access table derived from the Vault audit log"),
)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text()) if path.exists() else None


def vault_snapshot() -> dict[str, Any]:
    v = cfg.vault_client("auditor")
    policies = {n: v.sys.read_acl_policy(n)["data"]["policy"] for n in v.sys.list_acl_policies()["data"]["keys"] if n != "root"}
    names = (v.list("auth/ldap/groups") or {"data": {"keys": []}})["data"]["keys"]
    groups = {g: sorted(v.read(f"auth/ldap/groups/{g}")["data"]["policies"]) for g in names}
    accounts = []
    for m in managed_accounts(v):
        row: dict[str, Any] = {"path": m.path, "safe": m.safe, **m.meta, "rotation_days": m.platform.rotation_days}
        if m.platform.kind == "ldap":
            role = v.read(f"ldap/static-role/{m.path}")["data"]
            row["last_change"] = role["last_vault_rotation"][:19] + "Z"
        else:
            versions = v.secrets.kv.v2.read_secret_metadata(m.path, mount_point="safes")["data"]["versions"]
            row["versions"] = len(versions)
            row["last_change"] = max(x["created_time"] for x in versions.values())[:19] + "Z" if versions else ""
        accounts.append(row)
    return {
        "audit_devices": {k: d["options"] for k, d in v.sys.list_enabled_audit_devices()["data"].items()},
        "auth_methods": sorted(v.sys.list_auth_methods()["data"]),
        "policies": policies,
        "group_mappings": groups,
        "password_policies": {n: v.read(f"sys/policies/password/{n}")["data"]["policy"] for n in ("autoonboard-ldap", "autoonboard-unix")},
        "managed": accounts,
    }


def audit_log() -> str | None:
    """Raw Vault audit log (secret values are HMAC'd by Vault). Lab: read via docker; prod: ship to a SIEM."""
    try:
        run = subprocess.run(["docker", "compose", "exec", "-T", "vault", "cat", "/vault/logs/audit.log"],
                             capture_output=True, text=True, check=True, cwd=cfg.REPO_ROOT, timeout=60)  # fmt: skip
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("audit log not collected: %s", e)
        return None
    return run.stdout


def credential_access(raw: str | None) -> list[dict[str, str]]:
    """Who read which credential: responses to reads of static-cred / safes data, from the audit log."""
    rows = []
    for line in (raw or "").splitlines():
        entry = json.loads(line)
        req = entry.get("request", {})
        path = req.get("path", "")
        if entry.get("type") == "response" and req.get("operation") == "read" and path.startswith(("ldap/static-cred/", "safes/data/")):
            auth = entry.get("auth", {})
            role = (auth.get("metadata") or {}).get("role_name")  # AppRole tokens all display as "approle"
            rows.append({
                "time": entry.get("time", "")[:19], "identity": f"approle/{role}" if role else auth.get("display_name", ""),
                "policies": ",".join(auth.get("policies", [])), "path": path, "result": "denied" if entry.get("error") else "ok",
            })  # fmt: skip
    return rows


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def build(snapshot: dict[str, Any] | None, raw_audit: str | None, now: dt.datetime | None = None) -> dict[str, Any]:
    """Assemble every number in the report from files + snapshot (pure function: unit-testable)."""
    now = now or dt.datetime.now(dt.UTC)
    inventory = (load_json(cfg.INVENTORY) or {"accounts": []})["accounts"]
    classes = {c["id"]: c for c in (load_json(cfg.CLASSIFICATION) or {"accounts": []})["accounts"]}
    metrics = load_json(cfg.METRICS) or {}
    plan = load_json(cfg.PLAN) or {"items": [], "sha256": "", "prepared_by": ""}
    approval = load_json(cfg.APPROVAL) or {}
    events = read_events()
    managed = (snapshot or {}).get("managed", [])
    managed_ids = {m.get("id") for m in managed}

    for a in inventory:
        a["c"] = classes.get(a["id"], {})
    privileged = [a for a in inventory if a["privileged"]]
    stale = sorted((a for a in inventory if a["c"].get("label") == "stale"), key=lambda a: -a["c"]["risk_score"])
    by_action = Counter(i["action"] for i in plan["items"])
    onboard_items = [i for i in plan["items"] if i["action"] == "onboard"]

    last: dict[str, dict[str, Any]] = {}
    alerts = []
    for e in events:
        if e["event"] in ("change", "verify", "reconcile", "error"):
            last[e["account"]] = e
        if e["severity"] in ("warning", "critical"):
            alerts.append(e)
    unresolved = [e for e in alerts if e["severity"] == "critical" and last.get(e["account"], e)["result"] != "success"]
    day = dt.timedelta(days=1)
    for m in managed:
        m["last_event"] = last.get(m["path"], {})
        m["overdue"] = bool(m.get("last_change")) and now - parse_time(m["last_change"]) > dt.timedelta(days=m["rotation_days"])
    verified_recently = [m for m in managed if m["last_event"].get("result") == "success" and now - parse_time(m["last_event"]["ts"]) <= day]

    safes: dict[str, dict[str, Any]] = defaultdict(lambda: {"accounts": 0, "platforms": set()})
    for m in managed:
        safes[m["safe"]]["accounts"] += 1
        safes[m["safe"]]["platforms"].add(m["platform"])
    policies = (snapshot or {}).get("policies", {})
    groups = (snapshot or {}).get("group_mappings", {})
    safe_rows = []
    for safe, info in sorted(safes.items()):
        key = safe.lower()
        safe_rows.append({
            "safe": safe, "accounts": info["accounts"], "platforms": ", ".join(sorted(info["platforms"])),
            "users_policy": f"safe-{key}-users" in policies, "managers_policy": f"safe-{key}-managers" in policies,
            "members": [g for g, p in groups.items() if f"safe-{key}-users" in p],
            "managers": [g for g, p in groups.items() if f"safe-{key}-managers" in p],
        })  # fmt: skip

    no_cred_access = [n for n in ("onboarder", "auditor") if n in policies and ("static-cred" in policies[n] or "safes/data" in policies[n])]
    checks = [
        ("File audit device enabled", bool((snapshot or {}).get("audit_devices"))),
        (
            "Every vaulted account carries an approval bound to the current plan",
            bool(managed) and all(m.get("approved_by") and m.get("plan_sha256") == plan["sha256"] for m in managed),
        ),
        ("No self-approval (approver differs from plan author)", bool(approval) and approval.get("approver", "").lower() != plan["prepared_by"].lower()),
        (
            f"Every platform rotates within {MASTER_POLICY['max_rotation_days']} days",
            all(p.rotation_days <= MASTER_POLICY["max_rotation_days"] for p in PLATFORMS.values()),
        ),
        ("Every vaulted account changed within its platform period", bool(managed) and not any(m["overdue"] for m in managed)),
        ("Every vaulted account verified successfully in the last 24h", bool(managed) and len(verified_recently) == len(managed)),
        ("Onboarder and auditor policies grant no credential read", bool(policies) and not no_cred_access),
        ("Every safe has member and manager policies", bool(safe_rows) and all(r["users_policy"] and r["managers_policy"] for r in safe_rows)),
    ]
    access = credential_access(raw_audit)
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "kpi": {
            "discovered": len(inventory),
            "ldap": sum(a["source"] == "ldap" for a in inventory),
            "linux": sum(a["source"] == "linux" for a in inventory),
            "privileged": len(privileged),
            "stale": len(stale),
            "stale_privileged": sum(a["privileged"] for a in stale),
            "planned_onboard": len(onboard_items),
            "approved": len(approval.get("ids", [])),
            "onboarded": len(managed),
            "coverage": round(100 * len(managed) / len(onboard_items)) if onboard_items else 0,
            "privileged_vaulted": sum(a["privileged"] and a["id"] in managed_ids for a in inventory),
            "remediate": by_action["remediate"],
            "review": by_action["review"],
            "warnings": sum(e["severity"] == "warning" for e in alerts),
            "critical": sum(e["severity"] == "critical" for e in alerts),
            "unresolved": len(unresolved),
        },
        "labels": Counter(a["c"].get("label", "?") for a in inventory),
        "by_source_team": sorted(Counter((a["source"], a["team"]) for a in inventory).items()),
        "metrics": metrics,
        "safes": safe_rows,
        "checks": checks,
        "platforms": PLATFORMS,
        "master_policy": MASTER_POLICY,
        "stale": stale,
        "remediation": [i for i in plan["items"] if i["action"] != "onboard"],
        "managed": sorted(managed, key=lambda m: m["path"]),
        "alerts": alerts,
        "unresolved": unresolved,
        "history": [e for e in events if e["event"] in ("onboard", "change", "verify", "reconcile", "error", "simulate", "access-check")][-400:],
        "access": access,
        "access_by_identity": Counter(r["identity"] for r in access).most_common(),
        "approval": approval,
        "plan": {"prepared_by": plan["prepared_by"], "sha256": plan["sha256"], "items": len(plan["items"])},
        "vault": {k: v for k, v in (snapshot or {}).items() if k in ("audit_devices", "auth_methods", "password_policies")},
        "controls": CONTROLS,
    }


def render(data: dict[str, Any], template: str = "report.html.j2") -> str:
    env = jinja2.Environment(loader=jinja2.PackageLoader("autoonboard"), autoescape=True, undefined=jinja2.StrictUndefined)
    return env.get_template(template).render(**data)


def to_pdf(html: Path) -> Path | None:
    chrome = next((c for c in CHROME if shutil.which(c) or Path(c).exists()), None)
    if chrome is None:
        log.warning("no Chrome/Chromium found; skipping PDF (open the HTML and print to PDF instead)")
        return None
    pdf = html.with_suffix(".pdf")
    subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer", f"--print-to-pdf={pdf}", html.resolve().as_uri()],
                   check=True, capture_output=True, timeout=120)  # fmt: skip
    return pdf


def write_report(pdf: bool = False) -> tuple[Path, Path | None, dict[str, Any]]:
    snapshot, raw = vault_snapshot(), audit_log()
    data = build(snapshot, raw)
    cfg.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    html = cfg.REPORT_DIR / "report.html"
    html.write_text(render(data))
    (cfg.REPORT_DIR / "vault_snapshot.json").write_text(json.dumps(snapshot, indent=1))
    if raw is not None:
        (cfg.REPORT_DIR / "vault_audit.log").write_text(raw)
    return html, to_pdf(html) if pdf else None, data


def evidence() -> Path:
    """Zip every artefact with a SHA-256 manifest so the bundle can be checked for tampering."""
    policies = sorted((cfg.REPO_ROOT / "lab" / "vault" / "policies").glob("*.hcl"))
    files = [cfg.INVENTORY, cfg.INVENTORY.with_suffix(".csv"), cfg.CLASSIFICATION, cfg.CLASSIFICATION.with_suffix(".csv"), cfg.METRICS,
             cfg.PLAN, cfg.APPROVAL, cfg.EVENTS, *sorted(cfg.REPORT_DIR.glob("*")), *policies]  # fmt: skip
    files = [f for f in files if f.exists() and f.is_file()]

    def arcname(f: Path) -> str:
        return f.relative_to(cfg.OUT).as_posix() if f.is_relative_to(cfg.OUT) else f.relative_to(cfg.REPO_ROOT).as_posix()

    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=cfg.REPO_ROOT, check=True).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = "unknown"
    manifest = {
        "generated_at": stamp,
        "git_commit": commit,
        "note": "Fictional lab data. Secret values never appear: Vault HMACs them in its audit log and no artefact contains a password.",
        "files": {arcname(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
    }
    cfg.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    bundle = cfg.EVIDENCE_DIR / f"autoonboard-evidence-{stamp}.zip"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        for f in files:
            z.write(f, arcname(f))
        z.writestr("MANIFEST.json", json.dumps(manifest, indent=1))
    return bundle


def repo_url() -> str | None:
    """https URL of the git remote 'origin', if there is one (credentials in the URL are dropped)."""
    try:
        url = subprocess.run(["git", "remote", "get-url", "origin"], capture_output=True, text=True, check=True, cwd=cfg.REPO_ROOT).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    url = url.removesuffix(".git").replace("git@github.com:", "https://github.com/")
    return "https://" + url.split("@", 1)[-1].removeprefix("https://") if url.startswith("https://") else None


def write_site(dest: Path = cfg.REPO_ROOT / "site") -> Path:
    """Static demo page for GitHub Pages, built only from the files of a finished run (no lab needed).

    Everything on the page comes from the same build() as the report; the account explorer embeds
    the inventory joined with classification and plan (fictional data, no credentials).
    """
    snapshot = load_json(cfg.REPORT_DIR / "vault_snapshot.json")
    audit = cfg.REPORT_DIR / "vault_audit.log"
    data = build(snapshot, audit.read_text() if audit.exists() else None)
    plan = {i["id"]: i for i in (load_json(cfg.PLAN) or {"items": []})["items"]}
    accounts = (load_json(cfg.INVENTORY) or {"accounts": []})["accounts"]
    classes = {c["id"]: c for c in (load_json(cfg.CLASSIFICATION) or {"accounts": []})["accounts"]}
    rows = []
    for a in accounts:
        c, item = classes.get(a["id"], {}), plan.get(a["id"], {})
        rows.append({
            "id": a["id"], "src": a["source"], "name": a["name"], "host": a["host"], "team": a["team"],
            "label": c.get("label"), "truth": c.get("truth"), "conf": c.get("confidence"), "reason": c.get("reason", ""),
            "risk": c.get("risk_score", 0), "sev": c.get("severity", "low"), "factors": c.get("risk_factors", []),
            "priv": a["privileged"], "groups": a["privileged_groups"] or [r.split(" ", 1)[0] for r in a["sudo_rules"]],
            "logon": a["last_logon_days"], "pwd": a["pwd_age_days"],
            "action": item.get("action", ""), "target": item.get("safe") or "", "why": item.get("reason", ""),
        })  # fmt: skip
    events = read_events()
    story = [e for e in events if e["event"] in ("simulate", "access-check") or e["severity"] != "info" or e.get("detail") == "recovered"]
    outcome = Counter((e["event"], e["result"]) for e in events)
    data |= {
        "repo": repo_url(),
        "accounts": sorted(rows, key=lambda r: -r["risk"]),
        "story": story,
        "outcome": {f"{k}_{v}": n for (k, v), n in outcome.items()},
        "plan_counts": sorted(Counter((i["action"], i["platform"] or "-") for i in plan.values()).items()),
        "reused_keys": sum(bool(a["key_reused"]) for a in accounts),
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "index.html").write_text(render(data, "site.html.j2"))
    for name in ("report.html", "report.pdf"):
        if (cfg.REPORT_DIR / name).exists():
            shutil.copy2(cfg.REPORT_DIR / name, dest / name)
    return dest / "index.html"
