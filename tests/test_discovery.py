"""Collector parsing: the logic that decides who is privileged on a Linux host."""

import datetime as dt

from autoonboard.discovery import correlate, effective_groups, fingerprint, parse_collector, parse_sudoers, rule_power

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO/BQ6lbfiwGuJJbYNNHe/T5d+vPZJ+2g8XTmjr0A3KY ops@old-bastion"
NOW = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(days=20500)  # shadow dates are days since epoch


def shadow(name, status, lastchg="20000", expire=""):
    return ":".join([name, status, lastchg, "0", "99999", "7", "", expire])


COLLECTOR = "\n".join([
    "### hostname", "web01",
    "### passwd",
    "root:x:0:0:root:/root:/bin/bash",
    "toor:x:0:0::/root:/bin/bash",
    "alice:x:10001:10001:Alice Moreau:/home/alice:/bin/bash",
    "deploy:x:950:950::/home/deploy:/bin/bash",
    "nagios:x:951:951::/home/nagios:/usr/sbin/nologin",
    "bob:x:10002:10002:Bob Okafor:/home/bob:/bin/bash",
    "### group", "sudo:x:27:alice", "alice:x:10001:", "dbas:x:3000:bob",
    "### shadow",
    shadow("root", "nopassword"), shadow("toor", "set"), shadow("alice", "set", "20400"),
    shadow("deploy", "nopassword"), shadow("nagios", "nopassword"), shadow("bob", "locked", expire="20100"),
    "### sudoers",
    "# comment", "Defaults\tenv_reset", "root\tALL=(ALL:ALL) ALL", "%sudo\tALL=(ALL:ALL) ALL",
    "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, \\", "    /usr/bin/systemctl reload nginx",
    "%dbas ALL=(postgres) ALL  # trailing comment", "@includedir /etc/sudoers.d",
    "### authorized_keys", f"root:{KEY}", f"toor:{KEY}",
])  # fmt: skip


def test_fingerprint_matches_ssh_keygen():
    assert fingerprint(KEY) == "SHA256:6001y6rx0/xyLa6xTZqoyqubi3oIUtk4ho2Ab5JsErQ ops@old-bastion"
    assert fingerprint("not a key") is None


def test_sudoers_rules():
    rules = dict(parse_sudoers(COLLECTOR.split("### sudoers\n")[1].split("### authorized_keys")[0].splitlines()))
    assert rules["%sudo"] == "ALL=(ALL:ALL) ALL"
    assert rules["deploy"].endswith("/usr/bin/systemctl reload nginx"), "continuation lines must be joined"
    assert rules["%dbas"] == "ALL=(postgres) ALL"
    assert rule_power("ALL=(ALL) NOPASSWD: ALL") == (True, True)
    assert rule_power("ALL=(postgres) ALL") == (False, False), "runas a service account is not root"
    assert rule_power("ALL=(root) NOPASSWD: /usr/bin/rsync") == (False, True)


def test_parse_collector_privilege_and_hygiene():
    accounts = {a.name: a for a in parse_collector("web01", COLLECTOR, NOW)}
    correlate(list(accounts.values()))
    root, toor, alice, deploy, nagios, bob = (accounts[n] for n in ("root", "toor", "alice", "deploy", "nagios", "bob"))
    assert root.uid0 and toor.uid0 and toor.privileged
    assert root.key_reused and toor.key_reused, "the same key unlocks two identities"
    assert alice.sudo_all and alice.privileged_groups == ["sudo"] and alice.pwd_age_days == 100
    assert deploy.privileged and deploy.sudo_nopasswd and not deploy.sudo_all and not deploy.has_credential
    assert bob.privileged and not bob.sudo_all and bob.disabled and bob.expired
    assert not nagios.interactive and not nagios.privileged


def test_nested_groups_resolve_transitively_and_survive_cycles():
    parents = {"uid=svc": ["cn=tier0"], "cn=tier0": ["cn=domain admins"], "cn=domain admins": ["cn=tier0"]}
    assert effective_groups("uid=svc", parents) == {"cn=tier0", "cn=domain admins"}
