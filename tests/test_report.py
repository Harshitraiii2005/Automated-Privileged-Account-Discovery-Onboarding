"""The report is a pure function of the pipeline files plus a Vault snapshot."""

import json
import zipfile

from autoonboard import config as cfg
from autoonboard import onboard, report


def test_report_and_evidence(account, out):
    a = account(name="svc-a", team="dba", privileged=True, privileged_groups=["DB Admins"])
    cfg.INVENTORY.write_text(json.dumps({"accounts": [a]}))
    cls = {"id": a["id"], "label": "service", "risk_score": 20, "severity": "medium", "risk_factors": [], "reason": "x"}
    cfg.CLASSIFICATION.write_text(json.dumps({"accounts": [cls]}))
    plan = onboard.build_plan([a], {a["id"]: cls}, "pipeline")
    onboard.save_json(cfg.PLAN, plan)
    onboard.save_json(cfg.APPROVAL, onboard.approve(plan, "security-lead"))
    cfg.EVENTS.write_text(json.dumps({"ts": "2026-01-01T00:00:00+00:00", "event": "verify", "account": "LDAP-DBA/svc-a",
                                      "result": "success", "severity": "info"}) + "\n")  # fmt: skip
    snapshot = {
        "audit_devices": {"file/": {"file_path": "/vault/logs/audit.log"}},
        "policies": {"safe-ldap-dba-users": "...", "safe-ldap-dba-managers": "...", "auditor": "path \"sys/audit\" {}"},
        "group_mappings": {"database team": ["safe-ldap-dba-users"], "security team": ["safe-ldap-dba-managers"]},
        "managed": [{"path": "LDAP-DBA/svc-a", "safe": "LDAP-DBA", "id": a["id"], "platform": "LDAP-SVC", "rotation_days": 30,
                     "approved_by": "security-lead", "plan_sha256": plan["sha256"], "last_change": "2026-01-01T00:00:00Z"}],
    }  # fmt: skip
    audit = json.dumps({"type": "response", "time": "2026-01-01T00:00:00Z", "request": {"operation": "read", "path": "ldap/static-cred/LDAP-DBA/svc-a"},
                        "auth": {"display_name": "approle", "metadata": {"role_name": "cpm"}, "policies": ["cpm"]}})  # fmt: skip
    data = report.build(snapshot, audit)
    assert data["kpi"]["onboarded"] == 1 and data["kpi"]["coverage"] == 100 and data["kpi"]["privileged_vaulted"] == 1
    assert data["access"][0]["identity"] == "approle/cpm"
    assert data["safes"][0]["members"] == ["database team"] and data["safes"][0]["managers"] == ["security team"]
    html = report.render(data)
    assert "Master Policy compliance" in html and "LDAP-DBA/svc-a" in html

    cfg.REPORT_DIR.mkdir()
    (cfg.REPORT_DIR / "report.html").write_text(html)
    with zipfile.ZipFile(report.evidence()) as z:
        manifest = json.loads(z.read("MANIFEST.json"))
        assert "report/report.html" in manifest["files"] and "onboarding_plan.json" in z.namelist()

    (cfg.REPORT_DIR / "vault_snapshot.json").write_text(json.dumps(snapshot))
    page = report.write_site(out / "site").read_text()
    assert "Account explorer" in page and a["id"] in page and (out / "site" / "report.html").exists()
