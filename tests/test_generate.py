"""Seed-generator invariants. If the ground truth is inconsistent, every later accuracy number is meaningless."""

import csv
import datetime as dt
import random
import re
from collections import Counter

from autoonboard import config as cfg
from autoonboard.lab.generate import REQUIRED_SECRETS, SEED, build_directory, generate

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
ENV = {k: f"unit-test-{k.lower()}-value" for k in REQUIRED_SECRETS}


def rows(path):
    with (path / "ground_truth.csv").open() as f:
        return list(csv.DictReader(f))


def test_generate_is_deterministic_consistent_and_leaks_no_secrets(tmp_path):
    generate(tmp_path / "a", ENV, NOW)
    generate(tmp_path / "b", ENV, NOW)
    truth = rows(tmp_path / "a")
    assert truth == rows(tmp_path / "b"), "same seed must give the same ground truth"

    ldap = Counter(r["label"] for r in truth if r["source"] == "ldap")
    assert ldap == {"standard": 118, "human_admin": 24, "service": 30, "shared": 8, "stale": 20}
    assert len({(r["source"], r["host"], r["account"]) for r in truth}) == len(truth), "duplicate ground-truth key"
    assert {r["host"] for r in truth if r["source"] == "linux"} == set(cfg.HOSTS)

    seed = (tmp_path / "a" / "ldap" / "seed.ldif").read_text()
    dns = set(re.findall(r"^dn: (.+)$", seed, re.M))
    for attr in ("member", "manager", "seeAlso", "pwdPolicySubentry"):
        dangling = set(re.findall(rf"^{attr}: (.+)$", seed, re.M)) - dns
        assert not dangling, f"{attr} points at missing entries: {dangling}"
    assert not re.search(r"^userPassword: (?!\{SSHA\})", seed, re.M), "a password is stored unhashed"

    for f in (tmp_path / "a").rglob("*"):
        if f.is_file():
            text = f.read_text(errors="ignore")
            assert not any(v in text for v in ENV.values()), f"plaintext secret in {f.name}"
            if f.name.endswith((".key", "_ed25519_key", "_ed25519", "seed.ldif")):
                assert f.stat().st_mode & 0o077 == 0, f"{f.name} is readable by others"


def test_directory_timestamps_match_labels():
    for a in build_directory(random.Random(SEED), NOW):
        assert a.created <= a.pwd_changed <= NOW, a.uid
        assert a.last_logon is None or a.created <= a.last_logon <= NOW, a.uid
        idle = None if a.last_logon is None else (NOW - a.last_logon).days
        if a.label == "stale":
            assert idle is None or idle >= cfg.STALE_AFTER_DAYS, a.uid
        else:
            assert idle is not None and idle < cfg.STALE_AFTER_DAYS, a.uid
        if a.last_logon and not a.nonexpiring:  # ppolicy would have refused that logon
            assert a.last_logon - a.pwd_changed <= dt.timedelta(days=90), a.uid
