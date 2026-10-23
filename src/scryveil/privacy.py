"""Evidence-bound APR review, derived from verified originals without case migration.

Documented interval identifiers are scoped to one artifact. Reported network
counts remain per source summary; overlapping exports are never added together.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .models import ScryveilError
from .parse import MAX_BYTES, canonical, digest, load_json, text_field
from .store import CaseStore, read_regular

REVIEW_SCHEMA = "scryveil.privacy-review/1"
REVIEW_VERSION = "1.0.0"
RESOURCES = {
    "camera",
    "contacts",
    "location",
    "mediaLibrary",
    "microphone",
    "photos",
    "screenRecording",
}
BOUNDARIES = {"intervalBegin", "intervalEnd"}
LIMITATIONS = [
    "Experimental documented-format interpretation; real-device/version conformance NOT TESTED.",
    "APR records activity after enablement, with limited history; private browser activity can be absent.",
    "Intervals are source-clock observations, not proof of user intent, recording contents or exfiltration.",
    "Intervals are paired only within one artifact; overlapping exports remain separate.",
    "Network hits are reported aggregates, never packet timings, bytes transferred or summed across summaries.",
    "Network attribution and tracking classification are source declarations, not compromise verdicts.",
    "App references group declared identifiers, not verified devices or application installations.",
    "Redaction retains times, hashes and relationships; this report is not anonymous.",
]


@dataclass
class Access:
    event_id: str
    artifact_id: str
    interval_key: str
    app_ref: str | None
    resource: str
    boundary: str | None
    time: str
    fingerprint: str
    eligible: bool
    broadcaster: tuple[str | None, str | None]


class Review:
    def __init__(self, include_identifiers: bool):
        self.include_identifiers = include_identifiers
        self.apps: dict[tuple[str | None, str], str] = {}
        self.domains: dict[str, str] = {}
        self.issues: list[dict[str, str]] = []
        self.accesses: list[Access] = []
        self.networks: dict[tuple[str, str], dict[str, Any]] = {}

    def issue(self, event_id: str, code: str) -> None:
        self.issues.append({"event_id": event_id, "code": code})

    def optional_text(self, value: Any, event_id: str, field: str) -> str | None:
        if value is None or value == "":
            return None
        try:
            return text_field(value)
        except ScryveilError:
            self.issue(event_id, "invalid_" + field)
            return None

    def app(self, identifier: str | None, kind: str | None) -> str | None:
        if identifier is None:
            return None
        key = kind, identifier
        if key not in self.apps:
            self.apps[key] = f"app-{len(self.apps) + 1:06d}"
        return self.apps[key]

    def add(self, event: dict[str, Any], rec: dict[str, Any], fingerprint: str) -> None:
        eid, aid, attrs = event["event_id"], event["artifact_id"], event["attributes"]
        if event["event_type"] == "privacy.access":
            identifier = self.optional_text(rec.get("identifier"), eid, "interval_identifier")
            if identifier is None:
                self.issue(eid, "missing_interval_identifier")
            resource = attrs["category"] if attrs["category"] in RESOURCES else "unknown"
            if resource == "unknown":
                self.issue(eid, "unsupported_resource")
            boundary = attrs["kind"] if attrs["kind"] in BOUNDARIES else None
            if boundary is None:
                self.issue(eid, "unsupported_boundary")
            app_ref = self.app(attrs["app"], attrs["identifier_type"])
            identity_known = app_ref is not None and attrs["identifier_type"] == "bundleID"
            if not identity_known:
                self.issue(eid, "unresolved_accessor")
            broadcaster: tuple[str | None, str | None] = (None, None)
            broadcaster_valid = True
            if "broadcaster" in rec:
                obj = rec["broadcaster"]
                if not isinstance(obj, dict):
                    self.issue(eid, "invalid_broadcaster")
                    broadcaster_valid = False
                else:
                    broadcaster = (
                        self.optional_text(obj.get("identifierType"), eid, "broadcaster_type"),
                        self.optional_text(obj.get("identifier"), eid, "broadcaster_identifier"),
                    )
                    broadcaster_valid = broadcaster[0] == "bundleID" and broadcaster[1] is not None
                    if not broadcaster_valid:
                        self.issue(eid, "unresolved_broadcaster")
            self.accesses.append(
                Access(
                    eid,
                    aid,
                    identifier or eid,
                    app_ref,
                    resource,
                    boundary,
                    event["event_time"],
                    fingerprint,
                    identifier is not None
                    and identity_known
                    and resource != "unknown"
                    and boundary is not None
                    and broadcaster_valid,
                    broadcaster,
                )
            )
            return
        app_ref = self.app(attrs["app"], "bundleID")
        if app_ref is None:
            self.issue(eid, "unresolved_accessor")
        domain = attrs["domain"]
        if domain not in self.domains:
            self.domains[domain] = f"domain-{len(self.domains) + 1:06d}"
        initiated = rec.get("initiatedType")
        attribution = initiated if initiated in ("AppInitiated", "NonAppInitiated") else "unknown"
        if attribution == "unknown":
            self.issue(eid, "unknown_network_attribution")
        dtype = rec.get("domainType")
        tracking = (
            {1: "flagged_by_source", 2: "not_flagged_by_source"}.get(dtype, "unknown")
            if type(dtype) is int
            else "unknown"
        )
        if tracking == "unknown":
            self.issue(eid, "unknown_tracking_classification")
        context = self.optional_text(rec.get("context"), eid, "network_context")
        context_present = (
            True if context is not None else False if rec.get("context") == "" else None
        )
        if context_present is None:
            self.issue(eid, "unknown_network_context")
        owner = self.optional_text(rec.get("domainOwner"), eid, "domain_owner")
        if attrs["first_recorded_time"] is None or event["event_time"] is None:
            self.issue(eid, "incomplete_network_interval")
        key = aid, fingerprint
        if key in self.networks:
            self.networks[key]["evidence_ids"].append(eid)
            self.networks[key]["duplicate_record_count"] += 1
            return
        row = {
            "summary_id": "net-" + digest(canonical([aid, fingerprint])),
            "artifact_id": aid,
            "app_ref": app_ref,
            "domain_ref": self.domains[domain],
            "first_reported_time": attrs["first_recorded_time"],
            "last_reported_time": event["event_time"],
            "reported_hits": attrs["hits"],
            "attribution": attribution,
            "tracking_classification": tracking,
            "web_context_present": context_present,
            "evidence_ids": [eid],
            "duplicate_record_count": 0,
        }
        if self.include_identifiers:
            row["context"] = context
            row["domain_owner"] = owner
        self.networks[key] = row

    def intervals(self) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str], list[Access]] = defaultdict(list)
        for access in self.accesses:
            groups[(access.artifact_id, access.interval_key)].append(access)
        result = []
        for (aid, _), group in groups.items():
            unique = {item.fingerprint: item for item in group}
            begins = [a for a in unique.values() if a.boundary == "intervalBegin"]
            ends = [a for a in unique.values() if a.boundary == "intervalEnd"]
            identities = {(a.app_ref, a.resource, a.broadcaster) for a in group}
            begin_ids = sorted(a.event_id for a in group if a.boundary == "intervalBegin")
            end_ids = sorted(a.event_id for a in group if a.boundary == "intervalEnd")
            start = end = duration = None
            if len(identities) != 1 or len(begins) > 1 or len(ends) > 1:
                status = "ambiguous"
            elif not all(a.eligible for a in group):
                status = "unresolved_identity_or_kind"
            else:
                start = begins[0].time if begins else None
                end = ends[0].time if ends else None
                if start is None:
                    status = "missing_begin"
                elif end is None:
                    status = "missing_end"
                elif end < start:
                    status = "invalid_time_order"
                else:
                    status = "complete"
                    delta = datetime.fromisoformat(end) - datetime.fromisoformat(start)
                    duration = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
            ids = sorted(a.event_id for a in group)
            result.append(
                {
                    "interval_id": "interval-" + digest(canonical(ids)),
                    "artifact_id": aid,
                    "app_ref": group[0].app_ref if len(identities) == 1 else None,
                    "resource": group[0].resource if len(identities) == 1 else "unknown",
                    "status": status,
                    "start_time": start,
                    "end_time": end,
                    "duration_microseconds": duration,
                    "evidence_ids": ids,
                    "begin_evidence_ids": begin_ids,
                    "end_evidence_ids": end_ids,
                    "duplicate_record_count": len(group) - len(unique),
                }
            )
        return sorted(result, key=lambda r: r["interval_id"])


def build_privacy_report(
    store: CaseStore, case_id: str, include_identifiers: bool = False
) -> dict[str, Any]:
    review = Review(include_identifiers)
    sources = []
    coverage = []
    with store.locked(case_id) as (path, state):
        store.verify(path, state)
        by_artifact: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in state["events"]:
            by_artifact[event["artifact_id"]].append(event)
        for artifact in state["artifacts"]:
            aid = artifact["artifact_id"]
            selected = [e for e in by_artifact[aid] if e["parser"] == "apple_apr_experimental"]
            coverage.append(
                {
                    "artifact_id": aid,
                    "apr_records": len(selected),
                    "other_parsed_records": len(by_artifact[aid]) - len(selected),
                    "unparsed_records": sum(
                        w["code"] != "source_order_not_chronological" for w in artifact["warnings"]
                    ),
                    "source_order_warning": any(
                        w["code"] == "source_order_not_chronological" for w in artifact["warnings"]
                    ),
                }
            )
            if not selected:
                continue
            # Read a second time under the case lock, and bind THESE bytes to the
            # original hash too; never interpret bytes checked only before a read.
            data = read_regular(path / "originals" / artifact["sha256"], MAX_BYTES)
            if digest(data) != artifact["sha256"]:
                raise ScryveilError("source_integrity_failed", 4)
            for event in selected:
                start, length = event["byte_offset"], event["byte_length"]
                raw = data[start : start + length]
                rec = load_json(raw)
                review.add(event, rec, digest(raw.rstrip(b"\r\n")))
                sources.append(
                    {
                        k: event[k]
                        for k in (
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
                        )
                    }
                )
        intervals = review.intervals()
        report = {
            "schema_version": REVIEW_SCHEMA,
            "analyzer_version": REVIEW_VERSION,
            "case_id": case_id,
            "source_audit_head": state["audit"][-1]["hash"],
            "identifiers_included": include_identifiers,
            "provenance_mode": "no_evidence"
            if not sources
            else "synthetic"
            if all(e["synthetic"] for e in sources)
            else "mixed_or_imported",
            "scope": "Observed privacy activity in supplied APR records; no device safety or compromise verdict.",
            "artifacts": [
                {k: a[k] for k in ("artifact_id", "sha256", "size", "synthetic", "warnings")}
                for a in state["artifacts"]
            ],
            "sources": sources,
            "coverage": coverage,
            "apps": [
                {
                    "app_ref": ref,
                    **(
                        {"identifier_type": kind, "identifier": name} if include_identifiers else {}
                    ),
                }
                for (kind, name), ref in review.apps.items()
            ],
            "domains": [
                {"domain_ref": ref, **({"domain": name} if include_identifiers else {})}
                for name, ref in review.domains.items()
            ],
            "access_intervals": intervals,
            "network_summaries": sorted(review.networks.values(), key=lambda n: n["summary_id"]),
            "issues": review.issues,
            "summary": {
                "access_records": len(review.accesses),
                "interval_status_counts": dict(
                    sorted(Counter(r["status"] for r in intervals).items())
                ),
                "network_records": sum(len(n["evidence_ids"]) for n in review.networks.values()),
                "network_summaries": len(review.networks),
                "apps": len(review.apps),
                "domains": len(review.domains),
            },
            "limitations": LIMITATIONS,
        }
    validate_privacy_report(report)
    report["report_sha256"] = digest(canonical(report))
    return report


def validate_privacy_report(report: dict[str, Any]) -> None:
    """Check references and interval arithmetic, independent of the grouping path."""

    def require(condition: bool) -> None:
        if not condition:
            raise ScryveilError("privacy_report_lineage_failed", 4)

    sources = {e["event_id"]: e for e in report["sources"]}
    artifacts = {a["artifact_id"]: a for a in report["artifacts"]}
    require(len(sources) == len(report["sources"]))
    require(len(artifacts) == len(report["artifacts"]))
    apps = {a["app_ref"] for a in report["apps"]}
    domains = {d["domain_ref"] for d in report["domains"]}
    require(len(apps) == len(report["apps"]) and len(domains) == len(report["domains"]))
    for event in sources.values():
        require(event["artifact_id"] in artifacts)
        require(0 <= event["byte_offset"] and event["byte_length"] > 0)
        require(
            event["byte_offset"] + event["byte_length"] <= artifacts[event["artifact_id"]]["size"]
        )
    used = []
    for row in report["access_intervals"] + report["network_summaries"]:
        ids = row["evidence_ids"]
        require(bool(ids) and len(ids) == len(set(ids)))
        require(all(e in sources and sources[e]["artifact_id"] == row["artifact_id"] for e in ids))
        require(row["app_ref"] is None or row["app_ref"] in apps)
        used.extend(ids)
    require(len(used) == len(sources) and set(used) == set(sources))
    for row in report["access_intervals"]:
        begins, ends = row["begin_evidence_ids"], row["end_evidence_ids"]
        require(not set(begins) & set(ends))
        require(set(begins + ends) <= set(row["evidence_ids"]))
        require(all(sources[e]["event_type"] == "privacy.access" for e in row["evidence_ids"]))
        if row["status"] == "complete":
            require(bool(begins) and bool(ends))
            require(all(sources[e]["event_time"] == row["start_time"] for e in begins))
            require(all(sources[e]["event_time"] == row["end_time"] for e in ends))
            delta = datetime.fromisoformat(row["end_time"]) - datetime.fromisoformat(
                row["start_time"]
            )
            expected = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
            require(
                expected >= 0
                and type(row["duration_microseconds"]) is int
                and row["duration_microseconds"] == expected
            )
        else:
            require(row["duration_microseconds"] is None)
    for row in report["network_summaries"]:
        require(row["domain_ref"] in domains)
        require(all(sources[e]["event_type"] == "network.summary" for e in row["evidence_ids"]))
    require(all(i["event_id"] in sources for i in report["issues"]))
    summary = report["summary"]
    require(
        summary["access_records"]
        == sum(e["event_type"] == "privacy.access" for e in sources.values())
    )
    require(
        summary["network_records"]
        == sum(e["event_type"] == "network.summary" for e in sources.values())
    )
    require(
        summary["interval_status_counts"]
        == dict(Counter(r["status"] for r in report["access_intervals"]))
    )
    require(summary["network_summaries"] == len(report["network_summaries"]))
    require(summary["apps"] == len(apps) and summary["domains"] == len(domains))
    if "report_sha256" in report:
        require(
            report["report_sha256"]
            == digest(canonical({k: v for k, v in report.items() if k != "report_sha256"}))
        )


def privacy_markdown(report: dict[str, Any]) -> str:
    """Only generated references and fixed enums are rendered, never raw strings."""
    validate_privacy_report(report)
    if report["identifiers_included"]:
        raise ScryveilError("private_identifiers_require_json")
    lines = [
        "# SCRYVEIL privacy review",
        "",
        report["scope"],
        "",
        f"Provenance: {report['provenance_mode']}. Real-device validation: NOT TESTED.",
        "",
        "## Resource access intervals",
        "",
        "| App reference | Resource | Status | Start UTC | End UTC | Duration (microseconds) |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["access_intervals"]:
        lines.append(
            f"| {row['app_ref'] or 'unknown'} | {row['resource']} | {row['status']} | {row['start_time'] or 'unknown'} | {row['end_time'] or 'unknown'} | {row['duration_microseconds'] if row['duration_microseconds'] is not None else 'unknown'} |"
        )
    lines.extend(["", "Interval evidence:", ""])
    for row in report["access_intervals"]:
        lines.append(f"- {row['interval_id']}: " + ", ".join(row["evidence_ids"]))
    if not report["access_intervals"]:
        lines.extend(["", "No APR access intervals available in the supplied records.", ""])
    lines.extend(
        [
            "",
            "## Reported network summaries",
            "",
            "Counts remain separate for every summary and export.",
            "",
        ]
    )
    for row in report["network_summaries"]:
        lines.extend(
            [
                f"- {row['app_ref'] or 'unknown'} → {row['domain_ref']}: hits={row['reported_hits'] if row['reported_hits'] is not None else 'unknown'}; attribution={row['attribution']}; tracking={row['tracking_classification']}",
                "  Evidence: " + ", ".join(row["evidence_ids"]),
            ]
        )
    lines.extend(["", "## Coverage", ""])
    for row in report["coverage"]:
        lines.append(
            f"- {row['artifact_id']}: APR records={row['apr_records']}; unparsed={row['unparsed_records']}; other records={row['other_parsed_records']}; source order warning={row['source_order_warning']}"
        )
    lines.extend(["", "## Review issues", ""])
    for issue in report["issues"]:
        lines.append(f"- {issue['event_id']}: {issue['code']}")
    lines.extend(["", "## Source locators", ""])
    for source in report["sources"]:
        lines.append(
            f"- {source['event_id']}: {source['artifact_id']}, {source['source_locator']}, byte {source['byte_offset']} + {source['byte_length']}"
        )
    lines.extend(
        [
            "",
            "## Limits",
            "",
            *["- " + limit for limit in report["limitations"]],
            "",
            f"Canonical JSON digest: {report['report_sha256']}",
            "",
        ]
    )
    return "\n".join(lines)
