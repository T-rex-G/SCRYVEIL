"""Redacted allowlist exports. Original bytes are never embedded."""

from typing import Any

from .models import SCHEMA, ScryveilError
from .parse import canonical, digest
from .store import CaseStore


def build_report(store: CaseStore, case_id: str) -> dict[str, Any]:
    state = store.snapshot(case_id)
    result = dict(state["analysis"])
    result["findings"] = [dict(finding) for finding in result["findings"]]
    for finding in result["findings"]:
        decisions = [r for r in state["reviews"] if r["finding_id"] == finding["finding_id"]]
        if decisions:
            finding["analyst_review_status"] = decisions[-1]["decision"]
    artifact_keys = [
        "artifact_id",
        "sha256",
        "size",
        "format",
        "synthetic",
        "imported_at",
        "collection_time",
        "collection_mode",
        "tool_version",
        "warnings",
    ]
    event_keys = [
        "event_id",
        "artifact_id",
        "source_locator",
        "byte_offset",
        "byte_length",
        "event_type",
        "event_time",
        "source_offset",
        "time_precision",
        "synthetic",
        "parser",
        "parser_version",
        "limitations",
    ]
    report = {
        "schema_version": SCHEMA,
        "case_id": case_id,
        "provenance_mode": "synthetic"
        if state["artifacts"] and all(a["synthetic"] for a in state["artifacts"])
        else "mixed_or_imported"
        if state["artifacts"]
        else "no_evidence",
        "redaction": "raw fields, labels, filenames, identifiers and domains omitted; timestamps and hashes remain sensitive",
        "artifacts": [{k: a[k] for k in artifact_keys} for a in state["artifacts"]],
        "timeline": [
            {k: e[k] for k in event_keys}
            for e in sorted(
                state["events"],
                key=lambda e: (e["event_time"] is None, e["event_time"] or "", e["event_id"]),
            )
        ],
        "analysis": result,
        "audit": state["audit"],
        "rule_run": state["rule_run"],
        "analyst_decisions": state["reviews"],
        "reproduction": f"scryveil report export --case {case_id} --format json",
    }
    validate_report(report)
    report["report_sha256"] = digest(canonical(report))
    return report


def validate_report(report: dict[str, Any]) -> None:
    events = {e["event_id"]: e for e in report["timeline"]}
    artifacts = {a["artifact_id"]: a for a in report["artifacts"]}
    if len(events) != len(report["timeline"]) or len(artifacts) != len(report["artifacts"]):
        raise ScryveilError("duplicate_export_identity", 4)
    for event in events.values():
        if event["artifact_id"] not in artifacts:
            raise ScryveilError("missing_artifact_reference", 4)
        if (
            event["byte_offset"] < 0
            or event["byte_length"] <= 0
            or event["byte_offset"] + event["byte_length"] > artifacts[event["artifact_id"]]["size"]
        ):
            raise ScryveilError("invalid_source_locator", 4)
    findings = report["analysis"]["findings"]
    for finding in findings:
        if not finding["supporting_evidence_ids"]:
            raise ScryveilError("unsupported_finding", 4)
        for eid in finding["supporting_evidence_ids"] + finding["contradictory_evidence_ids"]:
            if eid not in events:
                raise ScryveilError("missing_event_reference", 4)
        for eid in finding["supporting_evidence_ids"]:
            stamp = events[eid]["event_time"]
            if stamp is not None and (
                finding["first_observed_utc"] is None
                or finding["last_observed_utc"] is None
                or not finding["first_observed_utc"] <= stamp <= finding["last_observed_utc"]
            ):
                raise ScryveilError("finding_interval_mismatch", 4)
    nodes = set(events) | set(artifacts) | {f["finding_id"] for f in findings}
    for edge in report["analysis"]["graph"]:
        if (
            edge["source"] not in nodes
            or edge["target"] not in nodes
            or not edge["supporting_event_ids"]
            or any(e not in events for e in edge["supporting_event_ids"])
        ):
            raise ScryveilError("invalid_graph_reference", 4)


def markdown(report: dict[str, Any]) -> str:
    validate_report(report)
    lines = [
        "# SCRYVEIL investigation report",
        "",
        f"Provenance: **{report['provenance_mode']}**",
        "",
        report["analysis"]["scope_statement"],
        "",
        "This is a redacted local report, not an anonymous public artifact.",
        "",
        "## Findings",
        "",
    ]
    for finding in report["analysis"]["findings"]:
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                f"Assessment: {finding['assessment']}; severity: {finding['severity']}; analyst: {finding['analyst_review_status']}",
                "",
                finding["explanation"],
                "",
                "Supporting evidence: " + ", ".join(finding["supporting_evidence_ids"]),
                "",
                "Contradictory context: "
                + (", ".join(finding["contradictory_evidence_ids"]) or "not collected"),
                "",
                "Alternatives: " + "; ".join(finding["alternative_explanations"]),
                "",
                "Missing evidence: " + "; ".join(finding["missing_evidence"]),
                "",
            ]
        )
    if not report["analysis"]["findings"]:
        lines.extend(
            [
                "No findings emitted. Evidence may be insufficient; this is not a device safety verdict.",
                "",
            ]
        )
    lines.extend(["## Scope and parser coverage", ""])
    for item in report["analysis"]["coverage"]:
        lines.append(
            f"- {item['source_family']}: {item['status']}; source: {item.get('artifact_id', 'not collected')}"
        )
    lines.extend(
        [
            "",
            "## Evidence locators",
            "",
            "| Event | Artifact | Locator | UTC time |",
            "|---|---|---|---|",
        ]
    )
    for e in report["timeline"]:
        lines.append(
            f"| {e['event_id']} | {e['artifact_id']} | {e['source_locator']}, byte {e['byte_offset']} + {e['byte_length']} | {e['event_time'] or 'unknown'} |"
        )
    lines.extend(["", "## Original integrity manifest", ""])
    for a in report["artifacts"]:
        lines.append(
            f"- {a['artifact_id']}: SHA-256 `{a['sha256']}`, {a['size']} bytes, synthetic={a['synthetic']}"
        )
    lines.extend(
        [
            "",
            "Canonical JSON includes full rule parameters, hypotheses, graph, audit and statistics.",
            "",
            f"Canonical JSON payload digest: `{report['report_sha256']}` (before adding the digest field).",
            "",
        ]
    )
    return "\n".join(lines)
