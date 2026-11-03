"""Phase 7 - HTTP API: read-only views of the pipeline outputs, plus token-protected approval.

`autoonboard serve` binds to 127.0.0.1 only. GET endpoints can be open because no output ever
contains a credential; the one state-changing call (approval) needs
`Authorization: Bearer $AUTOONBOARD_API_TOKEN` and still enforces segregation of duties.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from autoonboard import config as cfg
from autoonboard import onboard
from autoonboard.cpm import read_events

app = FastAPI(title="AutoOnboard", description="Privileged account discovery, classification and vault onboarding (lab).")


def read(path: Path) -> Any:
    if not path.exists():
        raise HTTPException(404, f"{path.name} not generated yet; run the pipeline first")
    return json.loads(path.read_text())


def require_token(authorization: str = Header(default="")) -> None:
    expected = cfg.secret("AUTOONBOARD_API_TOKEN")
    if not secrets.compare_digest(authorization.removeprefix("Bearer ").encode(), expected.encode()):
        raise HTTPException(401, "missing or invalid bearer token")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    report = cfg.REPORT_DIR / "report.html"
    if report.exists():
        return report.read_text()
    return "<h1>AutoOnboard</h1><p>No report yet: run <code>autoonboard report</code>. API docs at <a href='/docs'>/docs</a>.</p>"


@app.get("/api/health")
def health() -> dict[str, Any]:
    files = {"inventory": cfg.INVENTORY, "classification": cfg.CLASSIFICATION, "plan": cfg.PLAN, "approval": cfg.APPROVAL, "events": cfg.EVENTS}
    return {"status": "ok", "artifacts": {name: path.exists() for name, path in files.items()}}


@app.get("/api/inventory")
def inventory(source: str | None = None, privileged: bool | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = read(cfg.INVENTORY)["accounts"]
    return [a for a in rows if (source is None or a["source"] == source) and (privileged is None or a["privileged"] == privileged)]


@app.get("/api/classification")
def classification(label: str | None = None, min_risk: int = 0) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = read(cfg.CLASSIFICATION)["accounts"]
    return [c for c in rows if (label is None or c["label"] == label) and c["risk_score"] >= min_risk]


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return dict(read(cfg.METRICS))


@app.get("/api/plan")
def plan() -> dict[str, Any]:
    return dict(read(cfg.PLAN))


@app.get("/api/events")
def events(severity: str | None = None) -> list[dict[str, Any]]:
    return [e for e in read_events() if severity is None or e["severity"] == severity]


class ApprovalRequest(BaseModel):
    approver: str
    ids: list[str] | None = None  # None approves every onboarding item
    comment: str = ""


@app.post("/api/approvals", dependencies=[Depends(require_token)])
def approve(body: ApprovalRequest) -> dict[str, Any]:
    if not cfg.PLAN.exists():
        raise HTTPException(404, "no plan to approve")
    try:
        approval = onboard.approve(onboard.load_plan(), body.approver, body.ids, body.comment)
    except SystemExit as e:  # segregation of duties, unknown ids, tampered plan
        raise HTTPException(403, str(e)) from None
    onboard.save_json(cfg.APPROVAL, approval)
    return approval
