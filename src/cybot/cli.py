"""Command-line interface: `cybot serve | index | ingest | analyze | intel | actions | demo`."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from cybot.config import get_settings

SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"


def _services():
    from cybot.main import build_services

    return build_services(get_settings())


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, default=str))


def cmd_serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run(
        "cybot.main:create_app", factory=True, host=args.host, port=args.port, reload=args.reload
    )


def cmd_index(_: argparse.Namespace) -> None:
    services = _services()
    count = services.knowledge.index_directory(services.settings.knowledge_dir)
    print(f"Indexed {count} chunks.")
    _print_json(services.knowledge.stats())


def cmd_ingest(args: argparse.Namespace) -> None:
    services = _services()
    payload = json.loads(Path(args.file).read_text())
    result = services.ingestion.ingest(args.source, payload)
    print(
        f"{result.source}: received={result.received} ingested={len(result.alerts)} "
        f"duplicates={result.duplicates} errors={len(result.errors)}"
    )
    for err in result.errors:
        print(f"  error at index {err.index}: {err.error}", file=sys.stderr)
    for alert in result.alerts:
        print(f"  {alert.id}  [{alert.severity}] {alert.title}")
        if args.analyze:
            _report(services, *services.analyzer.analyze(alert))


def cmd_analyze(args: argparse.Namespace) -> None:
    services = _services()
    alert = services.repo.get_alert(args.alert_id)
    if alert is None:
        sys.exit(f"Alert {args.alert_id} not found")
    analysis, trace = services.analyzer.analyze(alert)
    if args.json:
        _print_json({"analysis": analysis.model_dump(mode="json"), "trace": trace})
    else:
        _report(services, analysis, trace)


def cmd_intel(args: argparse.Namespace) -> None:
    from cybot.ingestion.extract import detect_indicator_type
    from cybot.models import Indicator, IndicatorType

    services = _services()
    if services.intel is None:
        sys.exit("Threat intelligence is disabled or no providers are configured")
    itype = IndicatorType(args.type) if args.type else detect_indicator_type(args.value)
    if itype is None:
        sys.exit("Could not detect the indicator type; pass --type")
    result = services.intel.lookup(Indicator(type=itype, value=args.value))
    if args.json:
        _print_json(result.model_dump(mode="json"))
        return
    print(f"{itype}:{args.value} -> {result.verdict.upper()} (score {result.score})")
    if not result.results:
        print(f"  no configured provider supports this indicator ({services.intel.provider_names})")
    for r in result.results:
        status = f"ERROR {r.error}" if r.error else f"{r.verdict} ({r.score}) {r.summary}"
        print(f"  {r.provider:<11} {status}{'  [cached]' if r.cached else ''}")
        if r.reference:
            print(f"  {'':<11} {r.reference}")


def cmd_demo(args: argparse.Namespace) -> None:
    """Load all sample alerts, then analyze the most severe ones."""
    services = _services()
    ingested = []
    for path in sorted(SAMPLES_DIR.glob("*.json")):
        result = services.ingestion.ingest(path.stem, json.loads(path.read_text()))
        ingested.extend(result.alerts)
        print(f"Ingested {len(result.alerts)} {path.stem} alert(s) ({result.duplicates} duplicate)")
    targets = sorted(ingested, key=lambda a: a.severity.rank, reverse=True)[: args.top]
    for alert in targets:
        print(f"\n=== {alert.title} ({alert.source}, {alert.severity}) ===")
        _report(services, *services.analyzer.analyze(alert))


def cmd_actions(args: argparse.Namespace) -> None:
    from collections import defaultdict

    from cybot.agent import Decision, DecisionError
    from cybot.models import ActionStatus

    services = _services()
    if args.actions_command == "list":
        status = ActionStatus(args.status) if args.status else None
        actions = services.repo.list_actions(alert_id=args.alert, status=status)
        if not actions:
            print("No actions.")
        for a in actions:
            print(f"{a.id}  {a.status:<16} {a.type:<17} {a.target}")
            print(f"    analysis {a.analysis_id}; {a.policy_reason}")
        return

    by_analysis: dict[str, list[Decision]] = defaultdict(list)
    for action_id in args.action_ids:
        action = services.repo.get_action(action_id)
        if action is None:
            sys.exit(f"Action {action_id} not found")
        by_analysis[action.analysis_id].append(
            Decision(action_id, args.actions_command == "approve", args.note)
        )
    for analysis_id, decisions in by_analysis.items():
        try:
            trace = services.analyzer.decide(analysis_id, decisions, args.analyst)
        except DecisionError as exc:
            sys.exit(str(exc))
        for d in decisions:
            a = services.repo.get_action(d.action_id)
            print(
                f"{a.id}  {a.status:<16} {a.type} {a.target}"
                + (f"  ({a.result})" if a.result else "")
            )
        print("  Trace: " + " | ".join(trace))


def _report(services, analysis, trace) -> None:
    a = analysis.assessment
    print(f"  Risk: {a.risk_score}/100 ({a.risk_level}), confidence {a.confidence:.0%}")
    print(f"  Summary: {a.summary}")
    print(f"  Rationale: {a.rationale}")
    if a.mitre_techniques:
        print(f"  MITRE: {', '.join(a.mitre_techniques)}")
    print(f"  Related alerts: {len(analysis.related_alert_ids)}")
    print("  Recommended actions:")
    for rec in analysis.recommendations:
        print(f"    - [{rec.priority}/{rec.phase}] {rec.action}")
    flagged = [i for i in analysis.intel if i.verdict in ("malicious", "suspicious")]
    if analysis.intel:
        print(f"  Threat intel: {len(analysis.intel)} indicator(s) checked, {len(flagged)} flagged")
        for i in flagged:
            print(f"    - {i.indicator.type}:{i.indicator.value} {i.verdict} ({i.score})")
    if analysis.references:
        print("  References: " + "; ".join(r.title for r in analysis.references))
    actions = services.repo.list_actions(analysis_id=analysis.id)
    if actions:
        print(f"  Response actions (analysis {analysis.id}):")
        for act in actions:
            print(f"    - {act.status:<16} {act.type} {act.target}  [{act.id}]")
    print("  Trace: " + " | ".join(trace))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cybot", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the REST API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)

    sub.add_parser("index", help="Rebuild the knowledge-base vector index").set_defaults(
        func=cmd_index
    )

    ingest = sub.add_parser("ingest", help="Ingest alerts from a JSON file")
    ingest.add_argument("source", help="suricata | wazuh | crowdstrike | splunk | generic")
    ingest.add_argument("file", help="JSON file with one alert object or an array")
    ingest.add_argument("--analyze", action="store_true", help="Analyze each ingested alert")
    ingest.set_defaults(func=cmd_ingest)

    analyze = sub.add_parser("analyze", help="Analyze a stored alert by id")
    analyze.add_argument("alert_id")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(func=cmd_analyze)

    intel = sub.add_parser("intel", help="Threat-intel reputation lookup for one indicator")
    intel.add_argument("value", help="IP, domain, URL, email or file hash")
    intel.add_argument("--type", help="Indicator type (auto-detected when omitted)")
    intel.add_argument("--json", action="store_true")
    intel.set_defaults(func=cmd_intel)

    actions = sub.add_parser("actions", help="Review and approve response actions")
    actions_sub = actions.add_subparsers(dest="actions_command", required=True)
    act_list = actions_sub.add_parser("list", help="List actions (default: pending approval)")
    act_list.add_argument("--status", default="pending_approval", help="Status filter, '' for all")
    act_list.add_argument("--alert", help="Only actions for this alert id")
    for verb in ("approve", "reject"):
        decide = actions_sub.add_parser(verb, help=f"{verb.title()} pending actions")
        decide.add_argument("action_ids", nargs="+")
        decide.add_argument(
            "--analyst", required=True, help="Your name (recorded in the audit log)"
        )
        decide.add_argument("--note", default="")
    actions.set_defaults(func=cmd_actions)

    demo = sub.add_parser("demo", help="Ingest sample alerts and analyze the most severe")
    demo.add_argument("--top", type=int, default=2)
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    args.func(args)


if __name__ == "__main__":
    main()
