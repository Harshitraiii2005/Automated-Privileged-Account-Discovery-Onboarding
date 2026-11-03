"""Onboarding decisions and the approval controls (segregation of duties, plan binding, tamper detection)."""

import json

import pytest

from autoonboard import config as cfg
from autoonboard import onboard


def c(label, reason="test", risk=10):
    return {"label": label, "reason": reason, "risk_score": risk, "severity": "low"}


def test_decide(account):
    linux = {"source": "linux", "host": "web01"}
    assert onboard.decide(account(name="svc-a"), c("service"))[:2] == ("onboard", "LDAP-SVC")
    assert onboard.decide(account(name="adm-x"), c("human_admin"))[:2] == ("onboard", "LDAP-ADM")
    assert onboard.decide(account(name="x", mail="x@y"), c("human_admin"))[0] == "remediate", "daily account with admin rights"
    assert onboard.decide(account(name="gone"), c("stale"))[0] == "remediate"
    assert onboard.decide(account(name="root", uid0=True, **linux), c("shared"))[:2] == ("onboard", "UNIX-ROOT")
    assert onboard.decide(account(name="toor", uid0=True, **linux), c("shared"))[0] == "remediate"
    assert onboard.decide(account(name="ops", interactive=True, **linux), c("shared"))[:2] == ("onboard", "UNIX-SHARED")
    assert onboard.decide(account(name=cfg.RECON_USER, **linux), c("service")) is None, "tooling is managed out of band"
    assert onboard.decide(account(name="amoreau", **linux), c("human_admin"))[0] == "review"
    assert onboard.decide(account(name="someone"), c("standard")) is None


def plan_for(account):
    inventory = [account(name="svc-a", team="dba"), account(name="gone")]
    classes = {inventory[0]["id"]: c("service"), inventory[1]["id"]: c("stale")}
    return onboard.build_plan(inventory, classes, prepared_by="pipeline")


def test_plan_and_approval_controls(account):
    plan = plan_for(account)
    assert [i["action"] for i in plan["items"]] == ["onboard", "remediate"]
    assert plan["items"][0]["safe"] == "LDAP-DBA"
    with pytest.raises(SystemExit, match="segregation of duties"):
        onboard.approve(plan, "Pipeline")
    with pytest.raises(SystemExit, match="not onboarding items"):
        onboard.approve(plan, "security-lead", ["ldap:gone"])
    approval = onboard.approve(plan, "security-lead")
    assert approval["ids"] == ["ldap:svc-a"] and approval["plan_sha256"] == plan["sha256"]


def test_tampered_or_changed_plan_is_refused_before_touching_vault(account, out):
    plan = plan_for(account)
    onboard.save_json(cfg.APPROVAL, onboard.approve(plan, "security-lead"))
    plan["items"][0]["platform"] = "LDAP-ADM"  # edited by hand after generation
    onboard.save_json(cfg.PLAN, plan)
    with pytest.raises(SystemExit, match="modified after it was generated"):
        onboard.apply(dry_run=True)
    plan["sha256"] = onboard.digest(plan["items"])  # a regenerated, different plan
    onboard.save_json(cfg.PLAN, plan)
    with pytest.raises(SystemExit, match="changed after it was approved"):
        onboard.apply(dry_run=True)
    assert json.loads(cfg.APPROVAL.read_text())["approver"] == "security-lead"
