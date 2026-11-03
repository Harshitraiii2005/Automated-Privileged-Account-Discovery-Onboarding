"""Shared fixtures: an inventory-record factory and an isolated output directory."""

from dataclasses import asdict

import pytest

from autoonboard import config as cfg
from autoonboard.discovery import Account


@pytest.fixture
def account():
    """Factory for inventory records exactly as discovery writes them (defaults = harmless account)."""

    def make(**kw):
        kw.setdefault("source", "ldap")
        kw.setdefault("name", "someone")
        kw.setdefault("host", "")
        kw.setdefault("id", f"ldap:{kw['name']}" if kw["source"] == "ldap" else f"linux:{kw['host']}:{kw['name']}")
        a = Account(**kw)
        return asdict(a) | {"activity": a.activity}

    return make


@pytest.fixture
def out(tmp_path, monkeypatch):
    """Point every pipeline output at a temp dir so tests never touch ./out."""
    for name in ("INVENTORY", "CLASSIFICATION", "METRICS", "PLAN", "APPROVAL", "EVENTS", "SCENARIOS"):
        monkeypatch.setattr(cfg, name, tmp_path / getattr(cfg, name).name)
    monkeypatch.setattr(cfg, "OUT", tmp_path)
    monkeypatch.setattr(cfg, "REPORT_DIR", tmp_path / "report")
    monkeypatch.setattr(cfg, "EVIDENCE_DIR", tmp_path / "evidence")
    return tmp_path
