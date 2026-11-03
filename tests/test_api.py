"""API: open reads, token-protected approval that still enforces segregation of duties."""

import json

from fastapi.testclient import TestClient

from autoonboard import config as cfg
from autoonboard import onboard
from autoonboard.api import app


def test_api(account, out, monkeypatch):
    monkeypatch.setenv("AUTOONBOARD_API_TOKEN", "test-token-123")
    a = account(name="svc-a", team="dba")
    plan = onboard.build_plan([a], {a["id"]: {"label": "service", "reason": "x", "risk_score": 5, "severity": "low"}}, "pipeline")
    onboard.save_json(cfg.PLAN, plan)
    client = TestClient(app)

    assert client.get("/api/health").json()["artifacts"]["plan"] is True
    assert client.get("/api/plan").json()["sha256"] == plan["sha256"]
    assert client.get("/api/inventory").status_code == 404
    assert client.post("/api/approvals", json={"approver": "security-lead"}).status_code == 401
    auth = {"Authorization": "Bearer test-token-123"}
    assert client.post("/api/approvals", json={"approver": "pipeline"}, headers=auth).status_code == 403
    response = client.post("/api/approvals", json={"approver": "security-lead"}, headers=auth)
    assert response.status_code == 200 and json.loads(cfg.APPROVAL.read_text())["ids"] == [a["id"]]
