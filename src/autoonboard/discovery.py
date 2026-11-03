"""Phase 2 - discovery: scan the directory and every Linux host, emit one unified inventory (JSON + CSV).

Mirrors CyberArk Accounts Discovery: find accounts, their privileges and credential hygiene without
ever reading a credential. The LDAP scanner's ACL hides password hashes; the Linux collector reports
only *whether* a usable password exists.
"""

from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import json
import logging
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import ldap3
import paramiko

from autoonboard import config as cfg

log = logging.getLogger(__name__)

NON_INTERACTIVE_SHELLS = {"nologin", "false", "sync", "shutdown", "halt"}
LOCKED_FOREVER = "000001010000Z"
# Fallback team when an account has neither a department nor an owner (most specific group first).
GROUP_TEAM = (("DB Admins", "dba"), ("Network Admins", "network"), ("Helpdesk", "support"),
              ("Backup Operators", "infra"), ("Domain Admins", "infra"), ("Linux Sudo", "infra"))  # fmt: skip


@dataclass
class Account:
    """One discovered account. LDAP- or Linux-only fields stay at their defaults for the other source."""

    id: str  # ldap:<uid> | linux:<host>:<name>
    source: str
    host: str
    name: str
    display_name: str = ""
    dn: str = ""
    ou: str = ""
    team: str = "unassigned"
    owner: str = ""  # uid from manager/seeAlso
    owner_status: str = ""  # active | disabled | stale | missing
    mail: str = ""
    employee_type: str = ""
    description: str = ""
    groups: list[str] = field(default_factory=list)  # LDAP: effective (nested) groups; Linux: local groups
    privileged_groups: list[str] = field(default_factory=list)  # groups that confer the privilege
    privileged: bool = False
    disabled: bool = False  # LDAP ppolicy permanent lock / Linux locked password
    expired: bool = False  # Linux account expiry date has passed
    password_status: str = ""  # Linux: set | locked | nopassword | empty; LDAP: not visible to the scanner
    password_never_expires: bool = False
    pwd_age_days: int | None = None
    last_logon_days: int | None = None  # None: never (LDAP) or not collected (Linux)
    never_logged_in: bool = False
    created_days: int | None = None
    uid_number: int | None = None
    shell: str = ""
    interactive: bool = False
    uid0: bool = False
    sudo_rules: list[str] = field(default_factory=list)
    sudo_all: bool = False  # may run any command as root
    sudo_nopasswd: bool = False
    ssh_keys: list[str] = field(default_factory=list)  # "SHA256:<fp> <comment>"
    key_reused: bool = False  # a key here also authorises another account
    directory_status: str = ""  # Linux: state of the same-named directory account
    has_credential: bool = True  # Linux: usable password or authorised key

    @property
    def activity(self) -> str:
        """active | disabled | stale - as discovery sees it (used to judge owners and correlated accounts)."""
        if self.disabled or self.expired:
            return "disabled"
        if self.source == "ldap" and (self.never_logged_in or (self.last_logon_days or 0) >= cfg.STALE_AFTER_DAYS):
            return "stale"
        return "active"


def days_since(t: dt.datetime | None, now: dt.datetime) -> int | None:
    return None if t is None else max(0, (now - t).days)


def gtime(value: str | None) -> dt.datetime | None:
    return dt.datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(tzinfo=dt.UTC) if value else None


def first(attrs: dict[str, list[str]], name: str) -> str:
    values = attrs.get(name) or []
    return str(values[0]) if values else ""


def rdn_value(dn: str) -> str:
    return dn.split(",", 1)[0].split("=", 1)[-1]


# --- directory ------------------------------------------------------------------------------------


def effective_groups(dn: str, parents: dict[str, list[str]]) -> set[str]:
    """Transitive group membership: walk member -> group edges upwards (handles nesting and cycles)."""
    seen: set[str] = set()
    todo = list(parents.get(dn, []))
    while todo:
        group = todo.pop()
        if group not in seen:
            seen.add(group)
            todo.extend(parents.get(group, []))
    return seen


def discover_ldap(now: dt.datetime) -> list[Account]:
    attrs = ["uid", "cn", "mail", "employeeType", "departmentNumber", "description", "manager", "seeAlso",
             "createTimestamp", "pwdChangedTime", "pwdLastSuccess", "pwdAccountLockedTime", "pwdPolicySubentry"]  # fmt: skip
    with ldap3.Connection(cfg.ldap_server(), cfg.SCANNER_DN, cfg.secret("LDAP_SCANNER_PASSWORD"), auto_bind=True) as conn:

        def search(filt: str, wanted: list[str]) -> list[tuple[str, dict[str, list[str]]]]:
            results = conn.extend.standard.paged_search(cfg.BASE_DN, filt, attributes=wanted, paged_size=500, generator=False)
            return [(r["dn"], dict(r["attributes"])) for r in results if r["type"] == "searchResEntry"]

        groups = search("(objectClass=groupOfNames)", ["cn", "member"])
        people = search("(objectClass=inetOrgPerson)", attrs)
        policies = search("(objectClass=pwdPolicy)", ["pwdMaxAge"])

    group_name = {dn.lower(): first(a, "cn") for dn, a in groups}
    parents: dict[str, list[str]] = defaultdict(list)
    for dn, a in groups:
        for member in a.get("member", []):
            parents[member.lower()].append(dn.lower())
    never_expiring = {dn.lower() for dn, a in policies if first(a, "pwdMaxAge") in ("", "0")}

    accounts: dict[str, Account] = {}
    owners: dict[str, str] = {}
    for dn, a in people:
        names = sorted(group_name[g] for g in effective_groups(dn.lower(), parents))
        privileged = sorted(set(names) & set(cfg.PRIVILEGED_GROUPS))
        last_logon = gtime(first(a, "pwdLastSuccess"))
        acct = Account(
            id=f"ldap:{first(a, 'uid')}", source="ldap", host="", name=first(a, "uid"), display_name=first(a, "cn"),
            dn=dn, ou=dn.split(",")[1].split("=", 1)[-1], mail=first(a, "mail"), employee_type=first(a, "employeeType"),
            description=first(a, "description"), team=first(a, "departmentNumber") or "unassigned",
            groups=names, privileged_groups=privileged, privileged=bool(privileged),
            disabled=first(a, "pwdAccountLockedTime") == LOCKED_FOREVER, password_status="not visible",
            password_never_expires=first(a, "pwdPolicySubentry").lower() in never_expiring,
            pwd_age_days=days_since(gtime(first(a, "pwdChangedTime")), now), last_logon_days=days_since(last_logon, now),
            never_logged_in=last_logon is None, created_days=days_since(gtime(first(a, "createTimestamp")), now),
        )  # fmt: skip
        accounts[acct.name] = acct
        owner_dn = first(a, "manager") or first(a, "seeAlso")
        if owner_dn:
            owners[acct.name] = rdn_value(owner_dn)

    for name, owner in owners.items():
        acct, boss = accounts[name], accounts.get(owner)
        acct.owner, acct.owner_status = owner, boss.activity if boss else "missing"
        if acct.team == "unassigned" and boss:
            acct.team = boss.team
    for acct in accounts.values():
        if acct.team == "unassigned":
            acct.team = next((team for group, team in GROUP_TEAM if group in acct.privileged_groups), "unassigned")
    return list(accounts.values())


# --- Linux ----------------------------------------------------------------------------------------


def sections(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    current = ""
    for line in text.splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
        elif current:
            out[current].append(line)
    return out


SUDO_RULE = re.compile(r"^\S+\s*=\s*(?:\((?P<runas>[^)]*)\))?\s*(?P<tags>(?:[A-Z_]+:\s*)*)(?P<cmds>.*)$")


def parse_sudoers(lines: list[str]) -> list[tuple[str, str]]:
    """(principal, rule) pairs from user specifications. Aliases and Defaults are not
    expanded; a principal or command alias is reported verbatim, so nothing is silently dropped."""
    joined, buf = [], ""
    for line in lines:
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        joined.append(buf + line)
        buf = ""
    rules = []
    for line in joined:
        line = line.split("#", 1)[0].strip()  # '#' starts a comment (and #include lines are already inlined)
        if not line or line.startswith(("Defaults", "@include")) or re.match(r"^[A-Z_]+_Alias\b", line):
            continue
        who, rule = (line.split(None, 1) + [""])[:2]
        for principal in who.split(","):
            rules.append((principal.strip(), rule))
    return rules


def rule_power(rule: str) -> tuple[bool, bool]:
    """(runs ALL commands as root, NOPASSWD) for one rule body such as 'ALL=(ALL:ALL) NOPASSWD: ALL'."""
    m = SUDO_RULE.match(rule)
    if not m:
        return False, False
    runas_user = (m["runas"] or "root").split(":")[0]
    as_root = any(u.strip() in ("ALL", "root") for u in runas_user.split(",")) or not runas_user.strip()
    commands = [c.strip() for c in m["cmds"].split(",")]
    return as_root and "ALL" in commands, "NOPASSWD" in m["tags"]


def fingerprint(key_line: str) -> str | None:
    """OpenSSH-style SHA256 fingerprint (identical to `ssh-keygen -lf`), or None for unparsable lines."""
    for i, part in enumerate(parts := key_line.split()):
        if part.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
            except ValueError:
                return None
            digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            comment = " ".join(parts[i + 2 :])
            return f"SHA256:{digest} {comment}".strip()
    return None


def parse_collector(host: str, text: str, now: dt.datetime) -> list[Account]:
    s = sections(text)
    today = now.date().toordinal() - dt.date(1970, 1, 1).toordinal()  # shadow dates are days since epoch
    groups_of: dict[str, set[str]] = defaultdict(set)
    gid_name: dict[str, str] = {}
    for line in s["group"]:
        name, _, gid, members = (line.split(":") + [""] * 4)[:4]
        gid_name[gid] = name
        for member in filter(None, members.split(",")):
            groups_of[member].add(name)
    shadow = {f[0]: f for f in (line.split(":") for line in s["shadow"]) if len(f) >= 8}
    rules = parse_sudoers(s["sudoers"])
    keys: dict[str, list[str]] = defaultdict(list)
    for line in s["authorized_keys"]:
        user, _, key_line = line.partition(":")
        if (fp := fingerprint(key_line)) is not None:
            keys[user].append(fp)

    accounts = []
    for line in s["passwd"]:
        name, _, uid, gid, gecos, _home, shell = (line.split(":") + [""] * 7)[:7]
        groups = sorted(groups_of[name] | ({gid_name[gid]} if gid in gid_name else set()))
        mine = [f"{p} {r}" for p, r in rules if p == name or (p.startswith("%") and p[1:] in groups)]
        powers = [rule_power(r) for p, r in rules if p == name or (p.startswith("%") and p[1:] in groups)]
        via_groups = sorted({p[1:] for p, _ in rules if p.startswith("%") and p[1:] in groups})
        sh = shadow.get(name, [name, "nopassword", "", "", "", "", "", ""])
        status, lastchg, expire = sh[1], sh[2], sh[7]
        interactive = shell.rsplit("/", 1)[-1] not in NON_INTERACTIVE_SHELLS
        acct = Account(
            id=f"linux:{host}:{name}", source="linux", host=host, name=name, display_name=gecos.split(",")[0],
            team=cfg.HOSTS[host].team, groups=groups, privileged_groups=via_groups,
            privileged=uid == "0" or bool(mine), disabled=status == "locked",
            expired=bool(expire) and int(expire) <= today, password_status=status,
            password_never_expires=not sh[4] or sh[4] == "99999",
            pwd_age_days=today - int(lastchg) if lastchg.isdigit() and int(lastchg) > 0 else None,
            uid_number=int(uid), shell=shell, interactive=interactive, uid0=uid == "0",
            sudo_rules=mine, sudo_all=any(a for a, _ in powers), sudo_nopasswd=any(n for _, n in powers),
            ssh_keys=keys[name], has_credential=status in ("set", "empty") or bool(keys[name]),
        )  # fmt: skip
        accounts.append(acct)
    return accounts


def discover_host(host: str, key: paramiko.PKey, now: dt.datetime) -> list[Account]:
    with cfg.ssh_connect(host, cfg.SCANNER_USER, key) as ssh:
        _, out, err = ssh.exec_command(f"sudo -n {cfg.COLLECTOR}", timeout=60)
        text = out.read().decode()
        if out.channel.recv_exit_status() != 0:
            raise RuntimeError(f"collector failed on {host}: {err.read().decode().strip()}")
    return parse_collector(host, text, now)


def correlate(accounts: list[Account]) -> None:
    """Cross-source facts: SSH keys that unlock more than one identity, and local accounts whose
    directory twin is disabled or idle. The same account name on several hosts counts as one identity."""
    holders: dict[str, set[str]] = defaultdict(set)
    for a in accounts:
        for k in a.ssh_keys:
            holders[k.split()[0]].add(a.name)
    directory = {a.name: a for a in accounts if a.source == "ldap"}
    for a in accounts:
        a.key_reused = any(len(holders[k.split()[0]]) > 1 for k in a.ssh_keys)
        if a.source == "linux" and a.name in directory:
            twin = directory[a.name]
            a.directory_status = twin.activity
            if a.display_name == "":
                a.display_name = twin.display_name
            a.team = twin.team if twin.team != "unassigned" else a.team


def discover(now: dt.datetime | None = None) -> list[Account]:
    now = now or dt.datetime.now(dt.UTC)
    accounts = discover_ldap(now)
    log.info("ldap: %d accounts", len(accounts))
    key = paramiko.Ed25519Key.from_private_key_file(str(cfg.SCANNER_KEY))
    for host in cfg.HOSTS:
        found = discover_host(host, key, now)
        log.info("%s: %d local accounts", host, len(found))
        accounts += found
    correlate(accounts)
    return accounts


def save(accounts: list[Account], path: Path = cfg.INVENTORY) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [asdict(a) | {"activity": a.activity} for a in accounts]
    path.write_text(json.dumps({"generated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "accounts": rows}, indent=1))
    with path.with_suffix(".csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows({k: "; ".join(v) if isinstance(v, list) else v for k, v in r.items()} for r in rows)


def load(path: Path = cfg.INVENTORY) -> list[dict]:
    return list(json.loads(path.read_text())["accounts"])
