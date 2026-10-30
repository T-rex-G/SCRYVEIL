"""Small machine-readable CLI; never echo evidence paths in errors."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Never

from .diagnostic_intelligence import narrative
from .engine import RuleConfig
from .investigation import disclosure, investigate
from .investigation_tools import ReadOnlyTools, diagnostic_coverage, snapshot_case
from .models import SCHEMA, ScryveilError
from .parse import canonical, load_json
from .privacy import build_privacy_report, privacy_markdown
from .providers import load_config
from .report import build_report, markdown
from .store import CaseStore


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise ScryveilError("invalid_arguments")


def parser() -> Parser:
    p = Parser(
        prog="scryveil",
        description="Offline evidence-bound mobile research; no device safety certification.",
    )
    p.add_argument("--root", type=Path, default=Path(".cases"), help="Private local case directory")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor")
    case = sub.add_parser("case").add_subparsers(dest="action", required=True)
    create = case.add_parser("create")
    create.add_argument("--label", required=True)
    create.add_argument("--consent", choices=["self", "authorized"], required=True)
    case.add_parser("list")
    collections = sub.add_parser("collection").add_subparsers(dest="action", required=True)
    collection = collections.add_parser("import")
    collection.add_argument("--case", required=True)
    collection.add_argument("--synthetic", action="store_true")
    collection.add_argument("source", type=Path)
    collections.add_parser("inventory").add_argument("--case", required=True)
    imp = (
        sub.add_parser("evidence").add_subparsers(dest="action", required=True).add_parser("import")
    )
    imp.add_argument("--case", required=True)
    imp.add_argument("--format", choices=["ndjson", "ips"], default="ndjson")
    imp.add_argument(
        "--synthetic",
        action="store_true",
        help="Declare generated test data; required for fixtures",
    )
    imp.add_argument("source", type=Path)
    run = sub.add_parser("analyze")
    run.add_argument("--case", required=True)
    run.add_argument("--min-events", type=int, default=5)
    run.add_argument("--min-window", type=float, default=240)
    sub.add_parser("findings").add_argument("--case", required=True)
    report = (
        sub.add_parser("report").add_subparsers(dest="action", required=True).add_parser("export")
    )
    report.add_argument("--case", required=True)
    report.add_argument("--format", choices=["json", "markdown"], default="json")
    privacy = (
        sub.add_parser("privacy").add_subparsers(dest="action", required=True).add_parser("report")
    )
    privacy.add_argument("--case", required=True)
    privacy.add_argument("--format", choices=["json", "markdown"], default="json")
    privacy.add_argument(
        "--include-identifiers",
        action="store_true",
        help="Include private app/domain identifiers in local JSON output",
    )
    review = sub.add_parser("review")
    review.add_argument("--case", required=True)
    review.add_argument("--finding", required=True)
    review.add_argument(
        "--decision", choices=["review_needed", "accepted_benign", "inconclusive"], required=True
    )
    diagnostic_commands = sub.add_parser("diagnostics").add_subparsers(dest="action", required=True)
    diagnostics = diagnostic_commands.add_parser("report")
    diagnostics.add_argument("--case", required=True)
    diagnostics.add_argument("--include-identifiers", action="store_true")
    diagnostics.add_argument("--format", choices=["json", "markdown"], default="json")
    diagnostics.add_argument(
        "--all-events",
        action="store_true",
        help="Query the complete bounded case or fail; no chronological truncation",
    )
    diagnostics.add_argument(
        "--diagnostic-details",
        action="store_true",
        help="Authorize process names, source symbols and exception/OS details; excludes paths and unrelated identifiers",
    )
    coverage = diagnostic_commands.add_parser("coverage")
    coverage.add_argument("--case", required=True)
    coverage.add_argument("--max-events", type=int, default=2000)
    compare = diagnostic_commands.add_parser("compare")
    compare.add_argument("--case", required=True)
    compare.add_argument("--finding", required=True)
    compare.add_argument("--all-events", action="store_true")
    compare.add_argument("--diagnostic-details", action="store_true")
    compare.add_argument("--include-identifiers", action="store_true")
    timeline = (
        sub.add_parser("timeline").add_subparsers(dest="action", required=True).add_parser("query")
    )
    timeline.add_argument("--case", required=True)
    for flag in ("event-type", "process-ref", "start-time", "end-time", "text"):
        timeline.add_argument("--" + flag)
    timeline.add_argument("--cursor", type=int, default=0)
    timeline.add_argument("--limit", type=int, default=25)
    timeline.add_argument("--diagnostic-details", action="store_true")
    timeline.add_argument("--where", help="JSON object of exact diagnostic field filters")
    investigation = sub.add_parser("investigate").add_subparsers(dest="action", required=True)
    for name in ("preview", "run"):
        command = investigation.add_parser(name)
        command.add_argument("--case", required=True)
        command.add_argument("--question", required=True)
        command.add_argument("--provider-config", type=Path)
        command.add_argument("--include-identifiers", action="store_true")
        command.add_argument("--all-events", action="store_true")
        command.add_argument("--diagnostic-details", action="store_true")
        command.add_argument("--max-events", type=int, default=2000)
        if name == "run":
            command.add_argument("--consent-sha256")
    return p


def execute(args: argparse.Namespace) -> Any:
    if args.command == "doctor":
        return {
            "version": SCHEMA,
            "offline": True,
            "network_access": "disabled_by_default_explicit_provider_only",
            "case_storage": "available" if os.name == "posix" else "unsupported",
            "validated_host": "Linux/Python 3.12",
            "hardware": "not_tested",
            "apr_import": "experimental",
            "apr_privacy_review": "documented_subset_synthetic_tested",
            "ios_usb": "unsupported",
            "backup": "unsupported",
            "sysdiagnose": "unsupported",
            "pcap": "unsupported",
            "android": "unsupported",
            "ips_import": "documented_json_subset_experimental",
            "ai": "optional_mock_or_configured_provider",
            "investigator_isolation": "requires_linux_libseccomp",
            "external_tools": "not_configured",
        }
    store = CaseStore(args.root)
    if args.command == "timeline":
        snapshot = snapshot_case(
            store, args.case, all_events=True, diagnostic_details=args.diagnostic_details
        )
        query = {
            k: getattr(args, k)
            for k in (
                "event_type",
                "process_ref",
                "start_time",
                "end_time",
                "text",
                "cursor",
                "limit",
            )
            if getattr(args, k) is not None
        }
        if args.where is not None:
            if len(args.where) > 4096:
                raise ScryveilError("invalid_tool_arguments")
            query["where"] = load_json(args.where.encode())
        return ReadOnlyTools(snapshot).call("timeline.query", query)
    if args.command == "collection":
        return (
            store.collection_inventory(args.case)
            if args.action == "inventory"
            else store.import_collection(args.case, args.source, args.synthetic)
        )
    if args.command == "diagnostics":
        if args.action == "coverage":
            return diagnostic_coverage(snapshot_case(store, args.case, max_events=args.max_events))
        result = snapshot_case(
            store,
            args.case,
            args.include_identifiers,
            all_events=args.all_events,
            diagnostic_details=args.diagnostic_details,
        )
        if args.action == "compare":
            return ReadOnlyTools(result).call("hypotheses.compare", {"finding_id": args.finding})
        return narrative(result) if args.format == "markdown" else result
    if args.command == "investigate":
        config = load_config(args.provider_config)
        if args.action == "preview":
            return disclosure(
                snapshot_case(
                    store,
                    args.case,
                    args.include_identifiers,
                    args.max_events,
                    all_events=args.all_events,
                    diagnostic_details=args.diagnostic_details,
                ),
                args.question,
                config,
            )
        return investigate(
            store,
            args.case,
            args.question,
            config,
            consent_sha256=args.consent_sha256,
            include_identifiers=args.include_identifiers,
            max_events=args.max_events,
            all_events=args.all_events,
            diagnostic_details=args.diagnostic_details,
        )
    if args.command == "privacy":
        if args.include_identifiers and args.format != "json":
            raise ScryveilError("private_identifiers_require_json")
        privacy_report = build_privacy_report(store, args.case, args.include_identifiers)
        return privacy_markdown(privacy_report) if args.format == "markdown" else privacy_report
    if args.command == "case":
        return (
            store.create(args.label, args.consent)
            if args.action == "create"
            else store.list_cases()
        )
    if args.command == "evidence":
        return store.import_file(args.case, args.source, args.synthetic, args.format)
    if args.command == "analyze":
        return store.run(
            args.case, RuleConfig(min_events=args.min_events, min_window_seconds=args.min_window)
        )
    if args.command == "review":
        return store.review(args.case, args.finding, args.decision)
    report = build_report(store, args.case)
    if args.command == "findings":
        return {
            "provenance": report["provenance_mode"],
            "findings": report["analysis"]["findings"],
            "scope": report["analysis"]["scope_statement"],
        }
    return markdown(report) if args.format == "markdown" else report


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        result = execute(args)
        if isinstance(result, str):
            sys.stdout.write(result)
        else:
            sys.stdout.write(canonical(result).decode())
        if (
            isinstance(result, dict)
            and result.get("schema_version") == "scryveil.investigation/1"
            and result["status"] != "completed"
        ):
            return 130 if result["status"] == "cancelled" else 3
        return 2 if isinstance(result, dict) and result.get("warning_count", 0) else 0
    except ScryveilError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled"}), file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print(json.dumps({"error": "local_io_or_state_error"}), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
