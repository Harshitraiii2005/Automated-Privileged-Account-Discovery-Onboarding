"""Phase 3 - classification: rules + gradient boosting label every account; rules score its risk.

Labels: human_admin | service | shared | stale | standard.

Honest evaluation: every ground-truth account gets an *out-of-fold* prediction from 5-fold stratified
cross-validation, i.e. from a model that never saw that account. The lab is synthetic, so the numbers
say how well the pipeline separates the personas the seed generator models, not real-world accuracy.

Final label ("hybrid"): hard staleness evidence from the rules (disabled, expired, idle >= 90 days,
never used, directory twin gone) always wins; otherwise the model decides. Stale is a fact you can
read off the account, while service vs shared vs admin is the fuzzy part where a model helps.
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import logging
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from autoonboard import config as cfg

log = logging.getLogger(__name__)

LABELS = ("human_admin", "service", "shared", "stale", "standard")
SERVICE_NAME = re.compile(r"^(svc|app|sql|srv)[-_]|[-_](svc|agent|bot)$|bot\d*$")
ADMIN_NAME = re.compile(r"^adm[-_]|[-_]adm$")
SEED = 0


def _days(value: int | None, missing: float = -1.0) -> float:
    return missing if value is None else float(value)


FEATURES: dict[str, Callable[[dict[str, Any]], float]] = {
    "is_ldap": lambda a: a["source"] == "ldap",
    "privileged": lambda a: a["privileged"],
    "n_privileged_groups": lambda a: len(a["privileged_groups"]),
    "uid0": lambda a: a["uid0"],
    "has_sudo": lambda a: bool(a["sudo_rules"]),
    "sudo_all": lambda a: a["sudo_all"],
    "sudo_nopasswd": lambda a: a["sudo_nopasswd"],
    "disabled": lambda a: a["disabled"],
    "expired": lambda a: a["expired"],
    "never_logged_in": lambda a: a["never_logged_in"],
    "last_logon_days": lambda a: _days(a["last_logon_days"], 10_000 if a["never_logged_in"] else -1),
    "pwd_age_days": lambda a: _days(a["pwd_age_days"]),
    "created_days": lambda a: _days(a["created_days"]),
    "password_never_expires": lambda a: a["password_never_expires"],
    "has_credential": lambda a: a["has_credential"],
    "password_set": lambda a: a["password_status"] == "set",
    "interactive": lambda a: a["interactive"],
    "ssh_keys": lambda a: len(a["ssh_keys"]),
    "key_reused": lambda a: a["key_reused"],
    "has_mail": lambda a: bool(a["mail"]),
    "has_employee_type": lambda a: bool(a["employee_type"]),
    "contractor": lambda a: a["employee_type"] == "Contractor",
    "has_owner": lambda a: bool(a["owner"]),
    "owner_inactive": lambda a: a["owner_status"] in ("disabled", "stale", "missing"),
    "has_description": lambda a: bool(a["description"]),
    "ou_people": lambda a: a["ou"] == "People",
    "ou_admins": lambda a: a["ou"] == "Admins",
    "ou_service": lambda a: a["ou"] == "ServiceAccounts",
    "person_like_name": lambda a: " " in a["display_name"].strip(),
    "service_name": lambda a: bool(SERVICE_NAME.search(a["name"])),
    "admin_name": lambda a: bool(ADMIN_NAME.search(a["name"])),
    "directory_inactive": lambda a: a["directory_status"] in ("disabled", "stale"),
    "system_uid": lambda a: a["uid_number"] is not None and 0 < a["uid_number"] < 1000,
}


def features(accounts: list[dict[str, Any]]) -> np.ndarray:
    return np.array([[float(f(a)) for f in FEATURES.values()] for a in accounts])


def stale_evidence(a: dict[str, Any]) -> str | None:
    """Hard, explainable staleness evidence, or None."""
    if a["disabled"]:
        return "account is disabled/locked"
    if a["expired"]:
        return "account has expired"
    if a["source"] == "ldap" and a["never_logged_in"] and (a["created_days"] or 0) > 30:
        return f"never logged in (created {a['created_days']} days ago)"
    if (a["last_logon_days"] or 0) >= cfg.STALE_AFTER_DAYS:
        return f"no logon for {a['last_logon_days']} days"
    if a["directory_status"] in ("disabled", "stale"):
        return f"same-named directory account is {a['directory_status']} (likely a leaver)"
    return None


def rule_label(a: dict[str, Any]) -> tuple[str, str]:
    """Transparent baseline classifier: (label, reason)."""
    if evidence := stale_evidence(a):
        return "stale", evidence
    if a["uid0"]:
        return "shared", "UID 0 account (root-equivalent, not personal)"
    person = FEATURES["person_like_name"](a)
    if (
        FEATURES["service_name"](a)
        or (a["source"] == "ldap" and a["ou"] == "ServiceAccounts" and not person)
        or (a["source"] == "linux" and (not a["interactive"] or (a["password_status"] != "set" and a["ssh_keys"] and not person)))
    ):
        return "service", "service naming, OU, non-interactive shell or key-only login"
    if a["privileged"]:
        if FEATURES["admin_name"](a) or a["ou"] == "Admins" or person:
            return "human_admin", "privileged account tied to a person"
        return "shared", "privileged account not tied to a person"
    if not person:
        return "service", "non-personal, unprivileged account"
    return "standard", "personal account without privileges"


def risk(a: dict[str, Any], label: str) -> tuple[int, list[str]]:
    """Additive, explainable 0-100 risk score (weights are a judgement call, documented in the README)."""
    factors: list[tuple[int, str]] = []
    if a["uid0"]:
        factors.append((40, "UID 0"))
    if "Domain Admins" in a["privileged_groups"]:
        factors.append((35, "effective Domain Admin"))
    elif a["sudo_all"]:
        factors.append((30, "may run any command as root"))
    elif a["privileged"] and not a["uid0"]:  # UID 0 is already counted above
        factors.append((20, "privileged group or sudo rule"))
    if a["sudo_nopasswd"]:
        factors.append((10, "passwordless sudo"))
    if a["password_status"] == "empty":
        factors.append((30, "empty password"))
    if label == "stale" and a["privileged"]:
        factors.append((20, "stale but still privileged"))
    if (a["pwd_age_days"] or 0) > 365:
        factors.append((10, f"password unchanged for {a['pwd_age_days']} days"))
    if a["password_never_expires"] and a["privileged"]:
        factors.append((5, "privileged password never expires"))
    if a["key_reused"]:
        factors.append((10, "SSH key also unlocks another identity"))
    if a["owner_status"] in ("disabled", "stale", "missing"):
        factors.append((10, f"owner is {a['owner_status']}"))
    if a["directory_status"] in ("disabled", "stale"):
        factors.append((15, f"local account outlived its {a['directory_status']} directory identity"))
    if label == "shared" and a["privileged"]:
        factors.append((10, "shared privileged credential (no individual accountability)"))
    return min(100, sum(p for p, _ in factors)), [f"+{p} {why}" for p, why in factors]


def severity(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 20 else "low"


def ground_truth(path: Path = cfg.GROUND_TRUTH) -> dict[str, str]:
    if not path.exists():
        return {}
    with path.open() as f:
        rows = list(csv.DictReader(f))
    return {(f"ldap:{r['account']}" if r["source"] == "ldap" else f"linux:{r['host']}:{r['account']}"): r["label"] for r in rows}


def scores(truth: list[str], predicted: list[str]) -> dict[str, Any]:
    return {
        "accuracy": round(float(accuracy_score(truth, predicted)), 4),
        "macro_f1": round(float(f1_score(truth, predicted, labels=list(LABELS), average="macro", zero_division=0)), 4),
        "per_class": classification_report(truth, predicted, labels=list(LABELS), output_dict=True, zero_division=0),
    }


def classify(accounts: list[dict[str, Any]], truth: dict[str, str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rules = [rule_label(a) for a in accounts]
    labeled = [i for i, a in enumerate(accounts) if a["id"] in truth]
    ml: list[str | None] = [None] * len(accounts)
    confidence: list[float | None] = [None] * len(accounts)
    metrics: dict[str, Any] = {"mode": "rules-only (no ground truth found)", "labeled": len(labeled), "total": len(accounts)}

    if labeled:
        X = features(accounts)
        y = np.array([truth[accounts[i]["id"]] for i in labeled])
        model = GradientBoostingClassifier(random_state=SEED)
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
        proba = cross_val_predict(model, X[labeled], y, cv=cv, method="predict_proba")
        classes = np.array(sorted(set(y)))
        for j, i in enumerate(labeled):  # out-of-fold: predicted by a model that never saw account i
            ml[i], confidence[i] = str(classes[proba[j].argmax()]), round(float(proba[j].max()), 3)
        model.fit(X[labeled], y)  # unlabeled accounts (OS built-ins) get the model trained on everything
        unlabeled = [i for i in range(len(accounts)) if i not in set(labeled)]
        if unlabeled:
            for i, p in zip(unlabeled, model.predict_proba(X[unlabeled]), strict=True):
                ml[i], confidence[i] = str(model.classes_[p.argmax()]), round(float(p.max()), 3)
        importance = sorted(zip(FEATURES, model.feature_importances_, strict=True), key=lambda kv: -kv[1])
        metrics = {
            "mode": "hybrid (stale rules + gradient boosting)",
            "labeled": len(labeled),
            "total": len(accounts),
            "folds": 5,
            "model": "sklearn GradientBoostingClassifier (defaults, random_state=0)",
            "label_distribution": dict(Counter(y.tolist())),
            "top_features": [{"feature": f, "importance": round(float(v), 4)} for f, v in importance[:10]],
        }

    results = []
    for i, a in enumerate(accounts):
        rule, reason = rules[i]
        evidence = stale_evidence(a)
        label = "stale" if evidence else (ml[i] or rule)
        score, factors = risk(a, label)
        results.append({
            "id": a["id"], "label": label, "label_rules": rule, "label_ml": ml[i], "confidence": confidence[i],
            "reason": evidence or (f"model ({confidence[i]:.0%})" if ml[i] else reason), "rule_reason": reason,
            "risk_score": score, "severity": severity(score), "risk_factors": factors, "truth": truth.get(a["id"]),
        })  # fmt: skip

    if labeled:
        t = [results[i]["truth"] for i in labeled]
        for name, key in (("rules", "label_rules"), ("ml", "label_ml"), ("hybrid", "label")):
            metrics[name] = scores(t, [results[i][key] for i in labeled])
        for source in ("ldap", "linux"):
            idx = [i for i in labeled if accounts[i]["source"] == source]
            if not idx:
                continue
            metrics[f"hybrid_accuracy_{source}"] = round(float(accuracy_score([results[i]["truth"] for i in idx], [results[i]["label"] for i in idx])), 4)
        metrics["confusion_matrix"] = {
            "labels": list(LABELS),
            "rows_truth_cols_predicted": confusion_matrix(t, [results[i]["label"] for i in labeled], labels=list(LABELS)).tolist(),
        }
        metrics["misclassified"] = [
            {"id": results[i]["id"], "truth": results[i]["truth"], "predicted": results[i]["label"]}
            for i in labeled
            if results[i]["truth"] != results[i]["label"]
        ]
    return results, metrics


def save(results: list[dict[str, Any]], metrics: dict[str, Any]) -> None:
    cfg.OUT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
    cfg.CLASSIFICATION.write_text(json.dumps({"generated_at": stamp, "accounts": results}, indent=1))
    cfg.METRICS.write_text(json.dumps({"generated_at": stamp, **metrics}, indent=1))
    with cfg.CLASSIFICATION.with_suffix(".csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows({k: "; ".join(v) if isinstance(v, list) else v for k, v in r.items()} for r in results)


def load() -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in json.loads(cfg.CLASSIFICATION.read_text())["accounts"]}
