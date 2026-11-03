"""Generate the fictional lab: .env secrets, TLS PKI, SSH keys, LDAP seed, Linux host specs, ground truth.

`make lab-gen` runs this. It is idempotent: once lab/.generated/manifest.json exists nothing is
regenerated (`make lab-reset` wipes it). Account *structure* is deterministic (seeded RNG), so the
ground-truth counts never drift between runs; key material and passwords are random.

Account passwords are written only as salted hashes and the plaintext is discarded immediately:
nobody knows them, which is the point. Onboarding (phase 4) has Vault take each account over with
an immediate rotation, the way CyberArk changes/reconciles a password when an account is onboarded.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import logging
import os
import random
import secrets
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from autoonboard import config as cfg

log = logging.getLogger(__name__)

SEED = 42
REQUIRED_SECRETS = ("LDAP_ADMIN_PASSWORD", "LDAP_SCANNER_PASSWORD", "LDAP_ROTATOR_PASSWORD")
MAIL_DOMAIN = "autoonboard.lab"
NOLOGIN = "/usr/sbin/nologin"
LOCKED = "000001010000Z"  # ppolicy: administratively locked until an admin clears it (OpenLDAP's "disabled")

FIRST = (
    "Alice Bruno Chen Dana Elif Farid Greta Hiro Ines Jonas Kavya Liam Mara Nikos Olga Priya Quinn Rafael "
    "Sana Tomas Uma Victor Wen Ximena Yusuf Zoe Amara Bjorn Carmen Dmitri Esme Femi Gael Hana Ivan Jae Kofi "
    "Lena Mateo Nadia Omar Pia Ravi Sofia Theo Ugo Vera Wanda"
).split()
LAST = (
    "Moreau Okafor Lindqvist Tanaka Haddad Kowalski Ferreira Novak Brennan Achebe Rossi Varga Petrov Nakamura "
    "Silva Dubois Ibrahim Jensen Kaur Larsen Mensah Nilsson Ortega Park Quist Reyes Sato Torres Ueda Vasquez "
    "Weber Xu Yilmaz Zhang Alvarez Becker Castillo Diaz Eriksen Fischer Garcia Horvat Ito Jovanovic Kim Lopez "
    "Murphy Nguyen"
).split()

# department -> (team, current headcount, tiered admins (separate adm- account), admins on their daily account)
DEPARTMENTS: dict[str, tuple[str, int, int, int]] = {
    "IT Operations": ("infra", 14, 6, 2),
    "Database Team": ("dba", 8, 4, 2),
    "Network Team": ("network", 6, 3, 1),
    "Security Team": ("security", 6, 3, 1),
    "Support": ("support", 14, 0, 2),
    "Engineering": ("engineering", 30, 0, 0),
    "Sales": ("sales", 18, 0, 0),
    "Finance": ("finance", 12, 0, 0),
    "Marketing": ("marketing", 10, 0, 0),
    "HR": ("hr", 8, 0, 0),
}
BUSINESS_DEPTS = ("Engineering", "Sales", "Finance", "Marketing", "HR", "Support")
ADMIN_GROUPS = {
    "infra": ("Domain Admins", "Linux Sudo"),
    "dba": ("DB Admins",),
    "network": ("Network Admins",),
    "security": ("Domain Admins",),
    "support": ("Helpdesk",),
}
EXTRA_ADMIN_GROUP = {"infra": "Backup Operators", "dba": "Linux Sudo", "security": "Linux Sudo"}  # granted 50%
TITLES = {
    "infra": ("Systems Engineer", "Site Reliability Engineer", "Infrastructure Lead"),
    "dba": ("Database Administrator", "Data Platform Engineer"),
    "network": ("Network Engineer", "Network Architect"),
    "security": ("Security Engineer", "SOC Analyst", "Security Architect"),
    "support": ("Service Desk Analyst", "Support Engineer"),
    "engineering": ("Software Engineer", "Senior Software Engineer", "QA Engineer", "Engineering Manager"),
    "sales": ("Account Executive", "Sales Manager", "Sales Operations Analyst"),
    "finance": ("Accountant", "Financial Analyst", "Controller"),
    "marketing": ("Marketing Specialist", "Content Strategist"),
    "hr": ("HR Business Partner", "Recruiter"),
}
# Leavers: the first three keep their privileged groups (a classic audit finding).
LEAVER_DEPTS = ("IT Operations", "Database Team", "Network Team", "Engineering", "Sales", "Finance", "Support", "Marketing")
NEVER_LOGGED_IN = 5

# uid, description, owning team, groups
SERVICES = (
    ("svc-backup", "Nightly file-server backup agent", "infra", ("Backup Operators",)),
    ("svc-dbbackup", "Database dump and offsite copy", "dba", ("DB Admins", "Backup Operators")),
    ("svc-patching", "Patch orchestration runner", "infra", ("Linux Sudo", "Tier0 Operators")),
    ("svc-monitoring", "Infrastructure monitoring poller", "infra", ()),
    ("svc-dirsync", "HR feed to directory sync", "infra", ("Domain Admins",)),
    ("svc-mailrelay", "SMTP relay authentication", "infra", ()),
    ("svc-print", "Print server queue manager", "infra", ()),
    ("svc-sqlreport", "SQL reporting jobs", "dba", ("DB Admins",)),
    ("svc-etl", "Data warehouse ETL loader", "dba", ("DB Admins",)),
    ("sql_agent", "SQL agent job owner", "dba", ("DB Admins",)),
    ("svc-netconfig", "Network device config backup", "network", ("Network Admins",)),
    ("svc-radius", "VPN RADIUS directory bind", "network", ()),
    ("svc-siem", "Log shipper to SIEM", "security", ()),
    ("svc-vulnscan", "Credentialed vulnerability scans", "security", ("Domain Admins", "Linux Sudo")),
    ("svc-jenkins", "CI build agent", "engineering", ("Linux Sudo",)),
    ("svc-deploy", "Release deployment pipeline", "engineering", ("Linux Sudo",)),
    ("svc-artifacts", "Artifact repository LDAP bind", "engineering", ()),
    ("svc-wiki", "Wiki LDAP bind", "engineering", ()),
    ("svc_k8s_ingress", "Cluster ingress controller bind", "engineering", ()),
    ("jenkins2", "Secondary CI agent", "engineering", ()),
    ("svc-payroll", "Payroll batch integration", "finance", ()),
    ("app-billing", "Billing application runtime", "finance", ()),
    ("tableau", "BI dashboard refresh", "finance", ()),
    ("svc-crm", "CRM connector", "sales", ()),
    ("app-quotes", "Quote generator runtime", "sales", ()),
    ("svc-hrportal", "HR portal backend", "hr", ()),
    ("svc-ticketing", "Ticketing system mailbox poller", "support", ()),
    ("app-analytics", "Marketing analytics importer", "marketing", ()),
    ("reportbot", "Scheduled finance reports", "finance", ()),
    ("scanner01", "Scan-to-email multifunction printer", "support", ()),
)
ORPHANED_SERVICES = (
    ("svc-legacyftp", "Legacy FTP drop (decommission pending)", "infra", ("Backup Operators",)),
    ("svc-oldcrm", "Previous CRM connector", "sales", ()),
    ("app-intranet", "Old intranet CMS", "engineering", ()),
    ("svc-migration", "One-off data migration", "dba", ("DB Admins",)),
)
MISFILED = {"reportbot", "scanner01", "tableau"}  # service accounts sitting in ou=People
CLONED_FROM_HUMAN = {"reportbot", "scanner01"}  # created by copying a user template: mail, employeeType...
# uid, description, team, groups, ou
SHARED = (
    ("dbadmin", "Shared DBA account", "dba", ("DB Admins",), "People"),
    ("oracle", "Oracle software owner", "dba", ("DB Admins",), "ServiceAccounts"),
    ("netadmin", "Network team shared login", "network", ("Network Admins",), "People"),
    ("sysadmin", "Ops team shared admin", "infra", ("Domain Admins", "Linux Sudo"), "People"),
    ("backupadmin", "Backup console shared login", "infra", ("Backup Operators",), "ServiceAccounts"),
    ("helpdesk", "Helpdesk shared desk login", "support", ("Helpdesk",), "People"),
    ("breakglass", "Emergency access account", "security", ("Domain Admins",), "People"),
    ("socanalyst", "SOC shared analyst console", "security", ("Linux Sudo",), "ServiceAccounts"),
)
SHARED_MAILBOXES = {"dbadmin": "dba-team", "netadmin": "netops", "helpdesk": "helpdesk"}
OUS = ("People", "Admins", "ServiceAccounts", "Groups", "Policies", "System")
KEY_COMMENTS = {"ci-deploy": "jenkins@ci01", "backup-agent": "backup@bkp01", "legacy-ops": "ops@old-bastion"}


@dataclass
class Account:
    """A seeded directory account. `label`/`persona` are the ground truth the classifier is scored on."""

    uid: str
    label: str
    persona: str
    team: str
    created: dt.datetime
    pwd_changed: dt.datetime
    last_logon: dt.datetime | None
    ou: str = "People"
    groups: set[str] = field(default_factory=set)
    attrs: dict[str, str] = field(default_factory=dict)
    locked: bool = False
    nonexpiring: bool = False

    @property
    def dn(self) -> str:
        return f"uid={self.uid},ou={self.ou},{cfg.BASE_DN}"


@dataclass
class LocalAccount:
    """A local account on a lab Linux host, with its ground-truth label."""

    name: str
    uid: int
    label: str
    persona: str
    team: str
    shell: str = "/bin/bash"
    groups: tuple[str, ...] = ()
    password: str = "set"  # set | none (no usable password, key-only) | locked
    lastchg: dt.date | None = None
    expire: dt.date | None = None
    gecos: str = ""
    keys: tuple[str, ...] = ()  # key ids, see generate()
    sudo: str = ""  # sudoers rule body, e.g. "ALL=(ALL) ALL"
    provision: bool = True  # False for accounts the base image already ships (root, ubuntu)


@dataclass
class HostSpec:
    name: str
    accounts: list[LocalAccount]
    extra_sudoers: tuple[str, ...] = ()


def group_dn(name: str) -> str:
    return f"cn={name},ou=Groups,{cfg.BASE_DN}"


def policy_dn(name: str) -> str:
    return f"cn={name},ou=Policies,{cfg.BASE_DN}"


def build_directory(rng: random.Random, now: dt.datetime) -> list[Account]:
    """Create the 200 directory accounts. Every timestamp obeys created <= pwd_changed <= now."""

    def ago(lo: float, hi: float) -> dt.datetime:
        return now - dt.timedelta(days=rng.uniform(lo, hi))

    def after(t: dt.datetime, within_days: float | None = None) -> dt.datetime:
        """Random instant between t (or now - within_days, if later) and now."""
        start = max(t, now - dt.timedelta(days=within_days)) if within_days else t
        return start + (now - start) * rng.random()

    def age(t: dt.datetime) -> float:
        return (now - t).total_seconds() / 86400

    def grant(acct: Account) -> None:
        acct.groups.update(ADMIN_GROUPS[acct.team])
        if acct.team in EXTRA_ADMIN_GROUP and rng.random() < 0.5:
            acct.groups.add(EXTRA_ADMIN_GROUP[acct.team])

    headcount = sum(d[1] for d in DEPARTMENTS.values()) + len(LEAVER_DEPTS) + NEVER_LOGGED_IN
    names = iter(person_names(rng, headcount))
    accounts: list[Account] = []

    def person(dept: str, label: str, persona: str, created: dt.datetime, pwd: dt.datetime, last: dt.datetime | None) -> Account:
        uid, given, sn = next(names)
        team = DEPARTMENTS[dept][0]
        acct = Account(
            uid, label, persona, team, created, pwd, last, groups={dept, "All Staff"},
            attrs={
                "cn": f"{given} {sn}", "givenName": given, "sn": sn, "mail": f"{uid}@{MAIL_DOMAIN}",
                "employeeType": "Employee", "departmentNumber": team, "title": rng.choice(TITLES[team]),
            },
        )  # fmt: skip
        if rng.random() < 0.6:
            acct.groups.add("VPN Users")
        accounts.append(acct)
        return acct

    def admin_account(owner: Account, label: str, persona: str, created: dt.datetime, pwd: dt.datetime, last: dt.datetime) -> Account:
        uid = f"adm-{owner.uid}" if rng.random() < 0.75 else f"{owner.uid}-adm"
        acct = Account(
            uid, label, persona, owner.team, created, pwd, last, ou="Admins" if rng.random() < 0.7 else "People",
            attrs={
                "cn": f"{owner.attrs['cn']} (admin)", "givenName": owner.attrs["givenName"], "sn": owner.attrs["sn"],
                "seeAlso": owner.dn, "description": f"Privileged account for {owner.attrs['cn']}",
            },
        )  # fmt: skip
        if rng.random() < 0.5:
            acct.attrs["employeeType"] = owner.attrs["employeeType"]
        grant(acct)
        accounts.append(acct)
        return acct

    def service_account(spec: tuple[str, str, str, tuple[str, ...]], label: str, persona: str,
                        created: dt.datetime, pwd: dt.datetime, last: dt.datetime, owner: Account) -> Account:  # fmt: skip
        uid, description, team, groups = spec
        acct = Account(
            uid, label, persona, team, created, pwd, last, groups=set(groups),
            ou="People" if uid in MISFILED else "ServiceAccounts",
            attrs={"cn": uid, "sn": uid, "description": description, "manager": owner.dn},
        )  # fmt: skip
        if uid in CLONED_FROM_HUMAN:
            acct.attrs |= {"givenName": uid.capitalize(), "mail": f"{uid}@{MAIL_DOMAIN}", "employeeType": "Employee", "departmentNumber": team}
        accounts.append(acct)
        return acct

    # Current staff: daily accounts, some used directly for admin work, some owning a tiered adm- account.
    staff: dict[str, list[Account]] = {}
    for dept, (team, count, tiered, untiered) in DEPARTMENTS.items():
        for i in range(count):
            created = ago(30, 2500)
            pwd = ago(0, min(89, age(created)))
            acct = person(dept, "standard", "employee", created, pwd, after(pwd, 30))
            staff.setdefault(team, []).append(acct)
            if i < untiered:
                acct.label, acct.persona, acct.last_logon = "human_admin", "admin_using_daily_account", after(pwd, 14)
                grant(acct)
            elif i < untiered + tiered:
                adm_created = ago(0, age(created))
                adm_pwd = ago(0, min(89, age(adm_created)))
                admin_account(acct, "human_admin", "tiered_admin_account", adm_created, adm_pwd, after(adm_pwd, 14))
    tier0 = next(a for a in accounts if a.persona == "tiered_admin_account" and a.team == "infra")
    tier0.groups.discard("Domain Admins")
    tier0.groups.add("Tier0 Operators")  # privileged only through group nesting (Tier0 Operators -> Domain Admins)

    business_teams = {DEPARTMENTS[d][0] for d in BUSINESS_DEPTS}
    business = [a for a in accounts if a.label == "standard" and a.team in business_teams]
    for i, acct in enumerate(rng.sample(business, 6)):
        acct.attrs["employeeType"] = "Contractor"
        if i < 2:
            del acct.attrs["mail"]
    for acct in rng.sample([a for a in business if age(a.created) > 120], 3):  # long leave: quiet but not stale
        acct.last_logon = ago(45, 85)
        acct.pwd_changed = ago(age(acct.last_logon), min(89, age(acct.created)))

    leavers = []
    for i, dept in enumerate(LEAVER_DEPTS):
        created = ago(400, 3000)
        last = ago(120, min(700, age(created) - 1))
        acct = person(dept, "stale", "leaver", created, max(created, last - dt.timedelta(days=rng.uniform(0, 80))), last)
        if i < 3:
            acct.persona = "leaver_still_privileged"
            grant(acct)
        if i % 2:
            acct.locked = True
            acct.attrs.pop("mail")
        if i in (4, 6):
            acct.attrs["description"] = "Leaver - pending deprovisioning"
        leavers.append(acct)

    for dept in rng.sample(BUSINESS_DEPTS, NEVER_LOGGED_IN):
        created = ago(100, 600)
        acct = person(dept, "stale", "never_logged_in", created, created, None)
        acct.attrs["employeeType"] = rng.choice(("Employee", "Contractor"))

    veteran = next(a for a in staff["infra"] if a.label == "standard" and age(a.created) > 500 and not any(x.attrs.get("seeAlso") == a.dn for x in accounts))
    for owner in (leavers[0], leavers[1], veteran):
        created = owner.created + (now - dt.timedelta(days=160) - owner.created) * rng.random()
        last = ago(150, min(400, age(created) - 1))
        admin_account(owner, "stale", "stale_admin_account", created, max(created, last - dt.timedelta(days=rng.uniform(0, 80))), last)

    for orphan in ORPHANED_SERVICES:
        created = ago(1000, 3000)
        acct = service_account(orphan, "stale", "orphaned_service_account", created, created, ago(200, 990), owner=rng.choice(leavers))
        acct.nonexpiring = True

    for spec in SERVICES:
        created = ago(200, 3000)
        pwd = created if rng.random() < 0.7 else ago(30, min(300, age(created)))  # most were never rotated
        acct = service_account(spec, "service", "service_account", created, pwd, ago(0, 2), owner=rng.choice(staff[spec[2]]))
        acct.nonexpiring = rng.random() < 0.85

    for uid, description, team, groups, ou in SHARED:
        created = ago(400, 3000)
        acct = Account(uid, "shared", "shared_account", team, created, ago(100, min(1500, age(created))), ago(0, 10),
                       ou=ou, groups=set(groups), attrs={"cn": uid, "sn": uid, "description": description})  # fmt: skip
        if uid in SHARED_MAILBOXES:
            acct.attrs["mail"] = f"{SHARED_MAILBOXES[uid]}@{MAIL_DOMAIN}"
        acct.nonexpiring = rng.random() < 0.5
        accounts.append(acct)

    # ppolicy enforces a 90-day maximum age, so an account with an expiring policy cannot have logged on
    # more than 90 days after its last password change. Keep the seed physically possible.
    for acct in accounts:
        if acct.last_logon and not acct.nonexpiring and acct.last_logon - acct.pwd_changed > dt.timedelta(days=89):
            acct.pwd_changed = max(acct.created, acct.last_logon - dt.timedelta(days=rng.uniform(0, 89)))
    return accounts


def person_names(rng: random.Random, n: int) -> list[tuple[str, str, str]]:
    """n unique fictional (uid, given, sn) triples; uid is first initial + surname, de-duplicated with a digit."""
    seen: set[str] = set()
    out = []
    for given, sn in rng.sample([(f, s) for f in FIRST for s in LAST], n):
        base = uid = (given[0] + sn).lower()
        suffix = 2
        while uid in seen:
            uid, suffix = f"{base}{suffix}", suffix + 1
        seen.add(uid)
        out.append((uid, given, sn))
    return out


def build_hosts(rng: random.Random, now: dt.datetime, directory: list[Account]) -> list[HostSpec]:
    """Local accounts on the three lab hosts, reusing directory identities so discovery can correlate them."""
    today = now.date()

    def days_ago(lo: int, hi: int) -> dt.date:
        return today - dt.timedelta(days=rng.randint(lo, hi))

    uid_numbers: dict[str, int] = {}

    def person(a: Account, label: str, persona: str, **overrides: object) -> LocalAccount:
        number = uid_numbers.setdefault(a.uid, 10001 + len(uid_numbers))
        fields = {"lastchg": days_ago(0, 80), "keys": (a.uid,), "gecos": a.attrs["cn"]} | overrides
        return LocalAccount(a.uid, number, label, persona, a.team, **fields)  # type: ignore[arg-type]

    by_dn = {a.dn: a for a in directory}

    def operators(team: str) -> list[Account]:
        """People who do admin work for a team: untiered admins and the owners of tiered admin accounts."""
        admins = [a for a in directory if a.team == team and a.label == "human_admin"]
        return list({p.uid: p for p in (by_dn.get(a.attrs.get("seeAlso", ""), a) for a in admins)}.values())

    infra_ops, dba_ops = rng.sample(operators("infra"), 4), rng.sample(operators("dba"), 2)
    dba_busy = {p.uid for p in operators("dba")}
    dba_staff = [a for a in directory if a.team == "dba" and a.label == "standard" and a.uid not in dba_busy]
    engineers = rng.sample([a for a in directory if a.team == "engineering" and a.label == "standard"], 6)
    analyst = rng.choice([a for a in directory if a.team == "finance" and a.label == "standard"])
    leavers = [a for a in directory if a.persona.startswith("leaver")]

    def tooling() -> list[LocalAccount]:
        # Separation of duties: discovery may only run the read-only collector; the CPM may only set
        # passwords. `""` in sudoers means "no arguments allowed".
        return [
            LocalAccount(cfg.SCANNER_USER, 990, "service", "discovery_scanner", "security", password="none", lastchg=days_ago(0, 5),
                         gecos="AutoOnboard discovery scanner", keys=("scanner",), sudo=f'ALL=(root) NOPASSWD: {cfg.COLLECTOR} ""'),
            LocalAccount(cfg.RECON_USER, 991, "service", "cpm_reconcile_account", "security", password="none", lastchg=days_ago(0, 5),
                         gecos="AutoOnboard CPM reconcile account", keys=("recon",), sudo=f"ALL=(root) NOPASSWD: {cfg.SETPW}"),
        ]  # fmt: skip

    def backupsvc() -> LocalAccount:
        return LocalAccount("backupsvc", 962, "service", "backup_agent", "infra", password="none", lastchg=days_ago(500, 1200),
                            keys=("backup-agent",), sudo="ALL=(root) NOPASSWD: /usr/bin/rsync", gecos="Backup agent")  # fmt: skip

    web01 = HostSpec("web01", [
        LocalAccount("root", 0, "shared", "builtin_root", "infra", keys=("legacy-ops",), provision=False),
        LocalAccount("toor", 0, "shared", "duplicate_uid0", "infra", lastchg=days_ago(400, 900)),
        person(infra_ops[0], "human_admin", "linux_admin", groups=("sudo",)),
        person(infra_ops[1], "human_admin", "linux_admin", groups=("sudo",)),
        person(infra_ops[2], "human_admin", "linux_admin", sudo="ALL=(ALL) ALL"),
        LocalAccount("deploy", 950, "service", "deploy_account", "engineering", password="none", lastchg=days_ago(400, 900),
                     keys=("ci-deploy",), sudo="ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx"),
        LocalAccount("nagios", 951, "service", "monitoring_agent", "infra", shell=NOLOGIN, password="none", lastchg=days_ago(400, 1200)),
        LocalAccount("webadmin", 1500, "shared", "shared_login", "infra", groups=("sudo",), lastchg=days_ago(300, 900),
                     keys=(infra_ops[0].uid, infra_ops[1].uid, infra_ops[2].uid), gecos="Web team shared admin"),
        person(leavers[0], "stale", "leaver_local_account", lastchg=days_ago(300, 700)),
        LocalAccount("contractor1", 1600, "stale", "expired_temp_account", "engineering", lastchg=days_ago(250, 400),
                     expire=days_ago(150, 240), gecos="Temp contractor"),
        person(engineers[0], "standard", "developer"),
        person(engineers[1], "standard", "developer"),
        *tooling(),
    ])  # fmt: skip
    db01 = HostSpec("db01", [
        LocalAccount("root", 0, "shared", "builtin_root", "infra", provision=False),
        LocalAccount("postgres", 960, "service", "database_service", "dba", password="none", lastchg=days_ago(500, 1500), gecos="PostgreSQL Server"),
        LocalAccount("oracle", 961, "shared", "shared_login", "dba", lastchg=days_ago(600, 1200), sudo="ALL=(ALL) NOPASSWD: ALL",
                     gecos="Oracle software owner"),
        backupsvc(),
        person(dba_ops[0], "human_admin", "linux_admin", groups=("wheel",)),
        person(dba_ops[1], "human_admin", "linux_admin", groups=("wheel",)),
        person(dba_staff[0], "human_admin", "sudo_to_service_account", groups=("dbas",)),
        person(leavers[1], "stale", "leaver_locked_still_privileged", groups=("wheel",), password="locked", lastchg=days_ago(200, 500)),
        person(analyst, "standard", "analyst"),
        *tooling(),
    ], extra_sudoers=("%dbas ALL=(postgres) ALL",))  # fmt: skip
    app01 = HostSpec("app01", [
        LocalAccount("root", 0, "shared", "builtin_root", "infra", provision=False),
        LocalAccount("ubuntu", 1000, "stale", "vendor_default_account", "infra", provision=False),  # ships in sudo group
        LocalAccount("jenkins", 970, "service", "ci_agent", "engineering", password="none", lastchg=days_ago(300, 900),
                     keys=("ci-deploy",), sudo="ALL=(ALL) NOPASSWD: ALL", gecos="Jenkins"),
        backupsvc(),
        LocalAccount("appsvc", 971, "service", "app_runtime", "engineering", shell=NOLOGIN, password="none", lastchg=days_ago(300, 900)),
        LocalAccount("ops", 1501, "shared", "shared_login", "infra", groups=("sudo",), lastchg=days_ago(200, 700),
                     keys=(infra_ops[0].uid, infra_ops[3].uid, engineers[2].uid, engineers[3].uid), gecos="Ops shared login"),
        person(infra_ops[3], "human_admin", "linux_admin", groups=("sudo",)),
        person(engineers[2], "human_admin", "developer_with_sudo", sudo="ALL=(ALL) ALL"),
        person(engineers[3], "standard", "developer"),
        person(engineers[4], "standard", "developer"),
        person(engineers[5], "standard", "developer"),
        person(leavers[3], "stale", "leaver_local_account", lastchg=days_ago(200, 600)),
        *tooling(),
    ])  # fmt: skip
    return [web01, db01, app01]


# --- serialisation -------------------------------------------------------------------------------


def write(path: Path, data: str | bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data.encode() if isinstance(data, str) else data)
    os.chmod(path, mode)  # O_CREAT's mode is umask-filtered and ignored for existing files


def ssha(password: str) -> str:
    salt = os.urandom(8)
    # {SSHA} is salted SHA-1 by definition; only used for random, never-known seed passwords (see module docstring).
    return "{SSHA}" + base64.b64encode(hashlib.sha1(password.encode() + salt).digest() + salt).decode()  # noqa: S324


def gtime(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).strftime("%Y%m%d%H%M%SZ")


def ldif(entries: list[tuple[str, dict[str, list[str]]]]) -> str:
    def line(attr: str, value: str) -> str:
        if value.isascii() and value.isprintable() and not value.startswith((" ", ":", "<")):
            return f"{attr}: {value}"
        return f"{attr}:: {base64.b64encode(value.encode()).decode()}"

    return "\n".join("\n".join([line("dn", dn), *(line(k, v) for k, vs in attrs.items() for v in vs)]) + "\n" for dn, attrs in entries)


def directory_ldif(accounts: list[Account], env: dict[str, str]) -> str:
    common_policy = {
        "pwdAttribute": "userPassword", "pwdMinAge": "0", "pwdInHistory": "5", "pwdCheckQuality": "1",
        "pwdMinLength": "12", "pwdMustChange": "FALSE", "pwdAllowUserChange": "TRUE", "pwdSafeModify": "FALSE",
    }  # fmt: skip
    policies = {
        "default": {"pwdMaxAge": "7776000", "pwdLockout": "TRUE", "pwdMaxFailure": "5", "pwdLockoutDuration": "900", "pwdFailureCountInterval": "900"},
        # Never-expiring and no lockout: an expired or locked-out service account is an outage.
        "service-accounts": {"pwdMaxAge": "0", "pwdLockout": "FALSE"},
    }
    entries: list[tuple[str, dict[str, list[str]]]] = [
        (cfg.BASE_DN, {"objectClass": ["dcObject", "organization"], "dc": ["autoonboard"], "o": ["AutoOnboard Lab (fictional)"]}),
        *((f"ou={ou},{cfg.BASE_DN}", {"objectClass": ["organizationalUnit"], "ou": [ou]}) for ou in OUS),
        *((policy_dn(name), {"objectClass": ["device", "pwdPolicy"], "cn": [name], **{k: [v] for k, v in (common_policy | p).items()}})
          for name, p in policies.items()),
    ]  # fmt: skip
    for dn, cn, description, var in (
        (cfg.SCANNER_DN, "discovery-scanner", "AutoOnboard discovery (read-only, cannot read password hashes)", "LDAP_SCANNER_PASSWORD"),
        (cfg.ROTATOR_DN, "vault-rotator", "Vault LDAP secrets engine bind account (password rotated by Vault)", "LDAP_ROTATOR_PASSWORD"),
    ):
        entries.append((dn, {
            "objectClass": ["applicationProcess", "simpleSecurityObject"], "cn": [cn], "description": [description],
            "userPassword": [ssha(env[var])], "pwdPolicySubentry": [policy_dn("service-accounts")],
        }))  # fmt: skip

    for a in accounts:
        attrs = {
            "objectClass": ["inetOrgPerson"], "uid": [a.uid], **{k: [v] for k, v in a.attrs.items()},
            "userPassword": [ssha(secrets.token_urlsafe(24))],  # plaintext discarded: nobody knows it
            "createTimestamp": [gtime(a.created)], "pwdChangedTime": [gtime(a.pwd_changed)],
        }  # fmt: skip
        if a.last_logon:
            attrs["pwdLastSuccess"] = [gtime(a.last_logon)]
        if a.locked:
            attrs["pwdAccountLockedTime"] = [LOCKED]
        if a.nonexpiring:
            attrs["pwdPolicySubentry"] = [policy_dn("service-accounts")]
        entries.append((a.dn, attrs))

    members: dict[str, list[str]] = {}
    for a in accounts:
        for g in sorted(a.groups):
            members.setdefault(g, []).append(a.dn)
    members["Domain Admins"].append(group_dn("Tier0 Operators"))  # nested group
    entries += [(group_dn(g), {"objectClass": ["groupOfNames"], "cn": [g], "member": m}) for g, m in sorted(members.items())]
    return ldif(entries)


def make_pki(out: Path, now: dt.datetime) -> None:
    """Lab CA plus server certs for ldap and vault. The CA key stays in memory and is never written."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AutoOnboard Lab"), x509.NameAttribute(NameOID.COMMON_NAME, "AutoOnboard Lab CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())

    def usage(**on: bool) -> x509.KeyUsage:
        names = ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment", "key_agreement",
                 "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")  # fmt: skip
        return x509.KeyUsage(**{n: on.get(n, False) for n in names})

    def builder(subject: x509.Name, key: ec.EllipticCurvePrivateKey) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )  # fmt: skip

    ca = (
        builder(ca_name, ca_key)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(usage(key_cert_sign=True, crl_sign=True), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write(out / "ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    for service in ("ldap", "vault"):
        key = ec.generate_private_key(ec.SECP256R1())
        san = [x509.DNSName(service), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        cert = (
            builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)]), key)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(usage(digital_signature=True), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        write(out / f"{service}.crt", cert.public_bytes(serialization.Encoding.PEM))
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        write(out / f"{service}.key", pem, 0o600)


def ssh_keypair(comment: str) -> tuple[bytes, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} {comment}"


def write_host(d: Path, spec: HostSpec, public_key: Callable[[str], str]) -> str:
    """Write one host's seed directory (mounted at /seed); returns its public host key."""
    rows = ["# name|uid|shell|groups|password|lastchg|expire|gecos  (generated, fictional)"]
    for a in spec.accounts:
        if a.provision:
            rows.append("|".join([a.name, str(a.uid), a.shell, ",".join(a.groups), a.password, str(a.lastchg or ""), str(a.expire or ""), a.gecos]))
        if a.keys:
            write(d / "keys" / a.name, "".join(public_key(k) + "\n" for k in a.keys))
    write(d / "accounts.psv", "\n".join(rows) + "\n")
    rules = [f"{a.name} {a.sudo}" for a in spec.accounts if a.sudo] + list(spec.extra_sudoers)
    write(d / "sudoers", "# AutoOnboard lab seed (fictional accounts)\n" + "\n".join(rules) + "\n")
    private, public = ssh_keypair(f"root@{spec.name}")
    write(d / "ssh_host_ed25519_key", private, 0o600)
    return public


def generate(out: Path, env: dict[str, str], now: dt.datetime, seed: int = SEED) -> dict[str, object]:
    rng = random.Random(seed)
    directory = build_directory(rng, now)
    hosts = build_hosts(rng, now, directory)

    make_pki(out / "certs", now)
    write(out / "ldap" / "seed.ldif", directory_ldif(directory, env), 0o600)

    scanner_private, scanner_public = ssh_keypair(f"{cfg.SCANNER_USER}@autoonboard")
    write(out / "ssh" / "scanner_ed25519", scanner_private, 0o600)
    write(out / "ssh" / "scanner_ed25519.pub", scanner_public + "\n")
    recon_private, recon_public = ssh_keypair(f"{cfg.RECON_USER}@autoonboard")
    write(out / "ssh" / "recon_ed25519", recon_private, 0o600)
    keys = {"scanner": scanner_public, "recon": recon_public}

    def public_key(key_id: str) -> str:
        if key_id not in keys:  # private halves of seeded user keys are discarded
            keys[key_id] = ssh_keypair(KEY_COMMENTS.get(key_id, f"{key_id}@laptop"))[1]
        return keys[key_id]

    known_hosts = []
    for spec in hosts:
        host_key = write_host(out / "hosts" / spec.name, spec, public_key)
        known_hosts.append(f"[127.0.0.1]:{cfg.HOSTS[spec.name].port} {host_key.rsplit(' ', 1)[0]}")
    write(out / "ssh" / "known_hosts", "\n".join(known_hosts) + "\n")

    rows = [{"source": "ldap", "host": "", "account": a.uid, "label": a.label, "persona": a.persona, "team": a.team} for a in directory]
    rows += [{"source": "linux", "host": h.name, "account": a.name, "label": a.label, "persona": a.persona, "team": a.team} for h in hosts for a in h.accounts]
    with (out / "ground_truth.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    manifest: dict[str, object] = {
        "generated_at": now.isoformat(timespec="seconds"),
        "seed": seed,
        "base_dn": cfg.BASE_DN,
        "labels": {src: dict(Counter(r["label"] for r in rows if r["source"] == src)) for src in ("ldap", "linux")},
        "scope": "Ground truth labels every seeded directory account, every local account the seed creates, root, "
        "and the image's vendor default user. Other OS built-ins (daemon, bin, nobody, ...) are deliberately unlabeled.",
    }
    write(out / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    return manifest


def ensure_env() -> dict[str, str]:
    """Create .env from .env.example with random secrets; later runs only append keys added to the example."""
    env = cfg.read_env_file(cfg.ENV_FILE)
    new = [k for k, v in cfg.read_env_file(cfg.ENV_EXAMPLE).items() if v == "change-me" and k not in env]
    if new:
        lines = cfg.ENV_FILE.read_text().splitlines() if cfg.ENV_FILE.exists() else []
        lines += [f"{k}={secrets.token_urlsafe(24)}" for k in new]
        write(cfg.ENV_FILE, "\n".join(lines) + "\n", 0o600)
        log.info("wrote random lab secrets to %s: %s", cfg.ENV_FILE.name, ", ".join(new))
        env = cfg.read_env_file(cfg.ENV_FILE)
    missing = [k for k in REQUIRED_SECRETS if env.get(k, "") in ("", "change-me")]
    if missing:
        raise SystemExit(f".env has no value for: {', '.join(missing)}")
    return env


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    env = ensure_env()
    if cfg.MANIFEST.exists():
        log.info("lab material already generated in %s (make lab-reset to regenerate)", cfg.GENERATED)
        return
    manifest = generate(cfg.GENERATED, env, dt.datetime.now(dt.UTC))
    log.info("generated lab material in %s: %s", cfg.GENERATED, json.dumps(manifest["labels"]))


if __name__ == "__main__":
    main()
