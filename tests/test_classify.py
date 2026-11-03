"""Rules, risk scoring and the honest (out-of-fold) evaluation path."""

from autoonboard.classify import classify, risk, rule_label, severity


def test_rules(account):
    assert rule_label(account(disabled=True))[0] == "stale"
    assert rule_label(account(last_logon_days=200))[0] == "stale"
    assert rule_label(account(never_logged_in=True, created_days=300))[0] == "stale"
    assert rule_label(account(source="linux", host="h", name="toor", uid0=True, interactive=True))[0] == "shared"
    assert rule_label(account(name="svc-backup", last_logon_days=1))[0] == "service"
    assert rule_label(account(name="adm-amoreau", ou="Admins", privileged=True, last_logon_days=1))[0] == "human_admin"
    assert rule_label(account(name="dbadmin", display_name="dbadmin", privileged=True, last_logon_days=1))[0] == "shared"
    assert rule_label(account(name="amoreau", display_name="Alice Moreau", last_logon_days=1))[0] == "standard"


def test_risk_is_additive_and_capped(account):
    score, factors = risk(account(uid0=True, sudo_all=True, sudo_nopasswd=True, privileged=True, key_reused=True, pwd_age_days=900), "shared")
    assert score == 100 and any("UID 0" in f for f in factors)
    assert risk(account(display_name="A B", last_logon_days=1), "standard") == (0, [])
    assert [severity(s) for s in (0, 20, 40, 70)] == ["low", "medium", "high", "critical"]


def test_rules_only_without_ground_truth(account):
    results, metrics = classify([account(name="svc-x", last_logon_days=1)], {})
    assert metrics["mode"].startswith("rules-only") and results[0]["label"] == "service"


def test_hybrid_uses_out_of_fold_predictions_and_stale_evidence_wins(account):
    shapes = {
        "human_admin": {"privileged": True, "ou": "Admins", "display_name": "A B (admin)", "last_logon_days": 3},
        "service": {"ou": "ServiceAccounts", "description": "job", "last_logon_days": 1, "pwd_age_days": 900},
        "shared": {"privileged": True, "display_name": "shared", "last_logon_days": 5, "pwd_age_days": 400},
        "stale": {"disabled": True, "display_name": "Gone Person"},
        "standard": {"display_name": "Some Person", "mail": "x@y", "last_logon_days": 2},
    }
    accounts, truth = [], {}
    for label, shape in shapes.items():
        for i in range(8):
            a = account(name=f"{label}{i}", **shape)
            accounts.append(a)
            truth[a["id"]] = label
    results, metrics = classify(accounts, truth)
    assert metrics["mode"].startswith("hybrid") and metrics["labeled"] == 40
    assert all(r["label_ml"] is not None and r["confidence"] is not None for r in results)
    assert all(r["label"] == "stale" for r in results if r["truth"] == "stale")
    assert 0.0 <= metrics["hybrid"]["accuracy"] <= 1.0
