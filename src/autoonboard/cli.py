"""AutoOnboard command line: one subcommand per pipeline stage. Run `autoonboard -h`."""

from __future__ import annotations

import argparse
import logging
import time
from collections import Counter
from collections.abc import Iterable, Sequence

from rich.console import Console
from rich.logging import RichHandler
from rich.prompt import Confirm, Prompt
from rich.table import Table

from autoonboard import classify, cpm, discovery, onboard, report
from autoonboard import config as cfg

console = Console()


def table(title: str, columns: list[str], rows: Iterable[Sequence[object]]) -> None:
    t = Table(title=title, title_justify="left")
    for c in columns:
        t.add_column(c)
    for r in rows:
        t.add_row(*(str(x) for x in r))
    console.print(t)


def cmd_discover(_: argparse.Namespace) -> int:
    accounts = discovery.discover()
    discovery.save(accounts)
    rows = [[src, sum(a.source == src for a in accounts), sum(a.privileged for a in accounts if a.source == src),
             sum(a.activity != "active" for a in accounts if a.source == src), sum(a.key_reused for a in accounts if a.source == src)]
            for src in ("ldap", "linux")]  # fmt: skip
    table("Discovery", ["source", "accounts", "privileged", "disabled/stale", "reused SSH keys"], rows)
    console.print(f"inventory -> {cfg.INVENTORY} (+ .csv)")
    return 0


def cmd_classify(_: argparse.Namespace) -> int:
    results, metrics = classify.classify(discovery.load(), classify.ground_truth())
    classify.save(results, metrics)
    table("Labels", ["label", "accounts"], [[k, v] for k, v in Counter(r["label"] for r in results).most_common()])
    if "hybrid" in metrics:
        rows = [[k, f"{metrics[k]['accuracy']:.1%}", f"{metrics[k]['macro_f1']:.3f}"] for k in ("rules", "ml", "hybrid")]
        table(f"Accuracy vs ground truth ({metrics['labeled']} accounts, out-of-fold)", ["classifier", "accuracy", "macro F1"], rows)
    else:
        console.print("[yellow]no ground truth: rules-only labels, no accuracy reported[/]")
    console.print(f"classification -> {cfg.CLASSIFICATION}, metrics -> {cfg.METRICS}")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    plan = onboard.build_plan(discovery.load(), classify.load(), args.prepared_by)
    onboard.save_json(cfg.PLAN, plan)
    cfg.APPROVAL.unlink(missing_ok=True)  # a new plan always needs a new approval
    counts = Counter((i["action"], i["platform"] or "-") for i in plan["items"])
    table("Onboarding plan", ["action", "platform", "accounts"], [[a, p, n] for (a, p), n in sorted(counts.items())])
    console.print(f"plan sha256 {plan['sha256'][:16]}... prepared by {plan['prepared_by']} -> {cfg.PLAN}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    plan = onboard.load_plan()
    items = [i for i in plan["items"] if i["action"] == "onboard"]
    table("Pending onboarding", ["id", "platform", "safe", "label", "risk"],
          [[i["id"], i["platform"], i["safe"], i["label"], i["risk_score"]] for i in items])  # fmt: skip
    ids: list[str] | None
    if args.all or args.ids:
        ids = None if args.all else args.ids
        n = len(items) if ids is None else len(ids)
        if not args.yes and not Confirm.ask(f"Approve {n} onboarding item(s) as [bold]{args.approver}[/]?"):
            return 1
    else:
        choice = Prompt.ask("Approve [a]ll, [s]elect one by one, or [n]one", choices=["a", "s", "n"], default="n")
        if choice == "n":
            return 1
        ids = None if choice == "a" else [i["id"] for i in items if Confirm.ask(f"  onboard {i['id']} -> {i['safe']} ({i['platform']})?")]
    approval = onboard.approve(plan, args.approver, ids, args.comment)
    onboard.save_json(cfg.APPROVAL, approval)
    console.print(f"approved {len(approval['ids'])} item(s) as {approval['approver']}, bound to plan {approval['plan_sha256'][:16]}...")
    return 0


def cmd_onboard(args: argparse.Namespace) -> int:
    steps = onboard.apply(dry_run=args.dry_run)
    for s in steps if args.dry_run else steps[-12:]:
        console.print(f"  {s}")
    console.print(f"{len(steps)} step(s){' planned (nothing written)' if args.dry_run else ' applied'}")
    return 0


def cmd_cpm(args: argparse.Namespace) -> int:
    while True:
        outcome = cpm.run(force=args.force)
        table("CPM cycle", ["outcome", "accounts"], [[k, v] for k, v in sorted(outcome.items())])
        if not args.loop:
            return 1 if outcome["failed"] else 0
        time.sleep(args.loop)


def cmd_simulate(args: argparse.Namespace) -> int:
    from autoonboard.lab import scenarios  # lab-only tooling

    if args.scenario == "failures":
        for name, target in scenarios.failures().items():
            console.print(f"  {name}: {target['path']}")
    elif args.scenario == "restore":
        scenarios.restore()
        console.print("  expiry removed")
    else:
        results = scenarios.access_check()
        table("Safe membership check", ["safe object", "as expected", "detail"], [[p, ok, d] for p, ok, d in results])
        return 0 if all(ok for _, ok, _ in results) else 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    html, pdf, data = report.write_report(pdf=args.pdf)
    k = data["kpi"]
    table("Report", ["metric", "value"], [[name, value] for name, value in k.items()])
    failed = [name for name, ok in data["checks"] if not ok]
    console.print(f"Master Policy checks: {len(data['checks']) - len(failed)}/{len(data['checks'])} pass" + (f" (failing: {failed})" if failed else ""))
    console.print(f"report -> {html}" + (f", {pdf}" if pdf else ""))
    return 0


def cmd_evidence(_: argparse.Namespace) -> int:
    bundle = report.evidence()
    console.print(f"evidence bundle -> {bundle}")
    return 0


def cmd_site(_: argparse.Namespace) -> int:
    page = report.write_site()
    console.print(f"demo page -> {page} (deployed to GitHub Pages by .github/workflows/pages.yml)")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("autoonboard.api:app", host="127.0.0.1", port=args.port)  # loopback only
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="autoonboard", description="Privileged account discovery, classification and vault onboarding.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover", help="scan LDAP and Linux hosts -> unified inventory")
    sub.add_parser("classify", help="label accounts (rules + gradient boosting) and score risk")
    p = sub.add_parser("plan", help="build the onboarding plan from the classification")
    p.add_argument("--prepared-by", default=onboard.default_user())
    p = sub.add_parser("approve", help="human-in-the-loop approval of onboarding items")
    p.add_argument("--approver", default=onboard.default_user())
    group = p.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="approve every onboarding item")
    group.add_argument("--ids", nargs="+", help="approve only these account ids")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.add_argument("--comment", default="")
    p = sub.add_parser("onboard", help="apply the approved plan to Vault")
    p.add_argument("--dry-run", action="store_true", help="show every Vault change without writing anything")
    p = sub.add_parser("cpm", help="verify / rotate / reconcile onboarded credentials")
    p.add_argument("--force", action="store_true", help="rotate everything now, not just what is due")
    p.add_argument("--loop", type=int, metavar="SECONDS", help="run forever, one cycle every SECONDS")
    p = sub.add_parser("simulate", help="lab scenarios: out-of-band changes, restore, safe access check")
    p.add_argument("scenario", choices=["failures", "restore", "access-check"])
    p = sub.add_parser("report", help="HTML (and --pdf) report of discovery, onboarding and rotation")
    p.add_argument("--pdf", action="store_true")
    sub.add_parser("evidence", help="zip all artefacts with a SHA-256 manifest for auditors")
    sub.add_parser("site", help="static demo page in site/ for GitHub Pages, built from the last run")
    p = sub.add_parser("serve", help="HTTP API + report on http://127.0.0.1:8000")
    p.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[RichHandler(console=console, show_path=False)])
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    handlers = {"discover": cmd_discover, "classify": cmd_classify, "plan": cmd_plan, "approve": cmd_approve, "onboard": cmd_onboard,
                "cpm": cmd_cpm, "simulate": cmd_simulate, "report": cmd_report, "evidence": cmd_evidence, "site": cmd_site, "serve": cmd_serve}  # fmt: skip
    return handlers[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
