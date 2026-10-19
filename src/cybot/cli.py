"""Command-line interface: `cybot serve | index | ingest | analyze | demo`."""

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
            _report(*services.analyzer.analyze(alert))


def cmd_analyze(args: argparse.Namespace) -> None:
    services = _services()
    alert = services.repo.get_alert(args.alert_id)
    if alert is None:
        sys.exit(f"Alert {args.alert_id} not found")
    analysis, trace = services.analyzer.analyze(alert)
    if args.json:
        _print_json({"analysis": analysis.model_dump(mode="json"), "trace": trace})
    else:
        _report(analysis, trace)


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
        _report(*services.analyzer.analyze(alert))


def _report(analysis, trace) -> None:
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
    if analysis.references:
        print("  References: " + "; ".join(r.title for r in analysis.references))
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
