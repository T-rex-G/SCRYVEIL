"""Versioned, case-bound queries over a minimized, verified in-memory snapshot."""

import json
from collections import Counter
from copy import deepcopy
from typing import Any

from .diagnostics import diagnostic_findings
from .engine import analyze
from .models import ScryveilError
from .parse import canonical, digest, text_field, timestamp
from .state import same_json
from .store import CaseStore

VERSION = "scryveil.tools/1"
MAX_SNAPSHOT = 16 * 1024 * 1024
MAX_RESULT = 64 * 1024
STRING = {"type": "string", "minLength": 1, "maxLength": 128}
ID = {"type": "string", "minLength": 1, "maxLength": 80}
QUERY = {
    "event_type": STRING,
    "process_ref": ID,
    "app_ref": ID,
    "domain_ref": ID,
    "start_time": STRING,
    "end_time": STRING,
    "text": STRING,
    "cursor": {"type": "integer", "minimum": 0, "maximum": 20000},
    "limit": {"type": "integer", "minimum": 1, "maximum": 25},
}


def object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


TOOL_SCHEMAS = {
    name: object_schema(props, required)
    for name, props, required in [
        ("case.inspect", {}, []),
        ("coverage.inspect", {}, []),
        ("evidence.list", {}, []),
        ("integrity.verify", {}, []),
        ("timeline.query", QUERY, []),
        ("diagnostics.search", QUERY, []),
        ("network.query", QUERY, []),
        ("process.inspect", {"process_ref": ID}, ["process_ref"]),
        ("evidence.read_excerpt", {"event_id": ID}, ["event_id"]),
        ("findings.inspect", {}, []),
        ("hypotheses.compare", {"finding_id": ID}, ["finding_id"]),
    ]
}


def validate(value: Any, schema: dict[str, Any]) -> None:
    """Strict subset used by our own closed schemas; never loads remote schemas."""
    kind = schema["type"]
    valid = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": type(value) is int,
        "boolean": type(value) is bool,
    }.get(kind, False)
    if not valid:
        raise ScryveilError("invalid_tool_arguments")
    if kind == "object":
        if set(value) - set(schema["properties"]) or not set(schema["required"]) <= set(value):
            raise ScryveilError("invalid_tool_arguments")
        for k, item in value.items():
            validate(item, schema["properties"][k])
    elif kind == "array":
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", 64):
            raise ScryveilError("invalid_tool_arguments")
        for item in value:
            validate(item, schema["items"])
    elif kind == "string":
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 1024):
            raise ScryveilError("invalid_tool_arguments")
        text_field(value)
    elif kind == "integer" and not schema["minimum"] <= value <= schema["maximum"]:
        raise ScryveilError("invalid_tool_arguments")


def snapshot_case(
    store: CaseStore, cid: str, include_identifiers: bool = False, max_events: int = 2000
) -> dict[str, Any]:
    if type(include_identifiers) is not bool:
        raise ScryveilError("invalid_identifier_option")
    if type(max_events) is not int or not 1 <= max_events <= 20000:
        raise ScryveilError("invalid_snapshot_limit")
    with store.locked(cid) as (path, state):
        store.verify(path, state)
        if state["analysis"] is not None:
            store.verify_analysis(state)
        state_hash = digest(canonical(state))
        original = sorted(
            state["events"],
            key=lambda e: (e["event_time"] is None, e["event_time"] or "", e["event_id"]),
        )[:max_events]
        refs: dict[tuple[str, str], str] = {}

        def ref(kind: str, value: str | None) -> str | None:
            if value is None:
                return None
            key = kind, value
            if key not in refs:
                refs[key] = f"{kind}-{len(refs) + 1:06d}"
            return refs[key]

        projected = []
        for event in original:
            a = event["attributes"]
            row = {
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
                    "parser",
                    "parser_version",
                )
            }
            row.update(
                process_ref=ref("process", a.get("process")),
                app_ref=ref("app", a.get("app")),
                domain_ref=ref("domain", a.get("domain")),
            )
            for key in (
                "json_pointer",
                "pid",
                "nonfatal",
                "simulated",
                "termination_code",
                "resident_pages",
                "page_size",
                "footprint_bytes",
                "hits",
                "first_recorded_time",
                "format_profile",
                "schema_status",
                "interpretation_status",
                "lightweight_corpse",
                "resource_kind",
                "event_time_role",
                "event_end_time",
                "writes_caused",
                "writes_limit",
                "writes_duration_seconds",
                "limit_duration_seconds",
                "duration_seconds",
                "sampled_duration_seconds",
                "sample_start_gap_seconds",
                "sample_end_gap_seconds",
                "header_duration_ms",
                "field_locations",
            ):
                if key in a:
                    row[key] = a[key]
            if "action_taken" in a:
                row["action_taken"] = (
                    a["action_taken"]
                    if a["action_taken"] in (None, "none", "terminated")
                    else "other"
                )
            for key, known in {
                "exception_type": {
                    "EXC_BAD_ACCESS",
                    "EXC_BAD_INSTRUCTION",
                    "EXC_ARITHMETIC",
                    "EXC_RESOURCE",
                    "EXC_CRASH",
                    "EXC_SOFTWARE",
                    "EXC_GUARD",
                    "EXC_BREAKPOINT",
                },
                "termination_namespace": {
                    "SIGNAL",
                    "WATCHDOG",
                    "JETSAM",
                    "RUNNINGBOARD",
                    "FRONTBOARD",
                    "CODESIGNING",
                },
                "reason": {
                    "per-process-limit",
                    "vm-pageshortage",
                    "vnode-limit",
                    "highwater",
                    "fc-thrashing",
                    "jettisoned",
                },
            }.items():
                if key in a:
                    row[key] = a[key] if a[key] in known else "other" if a[key] else None
            if include_identifiers:
                for key in (
                    "process",
                    "app",
                    "domain",
                    "process_path",
                    "bundle_id",
                    "parent_process",
                    "exception_subtype",
                    "termination_reason",
                    "os_version",
                    "os_build",
                    "frames",
                    "exception_codes",
                    "exception_raw_codes",
                    "exception_message",
                    "writes_summary",
                    "duration_text",
                    "sampled_duration_text",
                ):
                    if key in a:
                        row[key] = a[key]
            projected.append(row)
        findings = diagnostic_findings(original)
        for finding in findings:
            finding["process_ref"] = ref("process", finding.pop("process"))
        # Deterministic legacy detectors remain usable without mutating case state.
        deterministic = analyze(original, state["artifacts"])
        findings.extend(
            {
                "finding_id": f["finding_id"],
                "rule": f["rule_id"],
                "assessment": f["assessment"],
                "supporting_evidence_ids": f["supporting_evidence_ids"],
                "contradictory_evidence_ids": f["contradictory_evidence_ids"],
                "observation": f["explanation"],
                "alternatives": f["alternative_explanations"],
                "limitations": f["limitations"],
            }
            for f in deterministic["findings"]
        )
        result = {
            "schema_version": "scryveil.snapshot/1",
            "case_id": cid,
            "source_state_sha256": state_hash,
            "source_audit_head": state["audit"][-1]["hash"],
            "identifiers_included": include_identifiers,
            "events": projected,
            "findings": findings,
            "artifacts": [
                {
                    k: a[k]
                    for k in ("artifact_id", "sha256", "size", "format", "synthetic", "warnings")
                }
                for a in state["artifacts"]
            ],
            "coverage": {
                "total_events": len(state["events"]),
                "selected_events": len(projected),
                "omitted_events": len(state["events"]) - len(projected),
                "families": dict(sorted(Counter(e["parser"] for e in projected).items())),
                "not_collected_or_supported": [
                    "ios_backup",
                    "sysdiagnose_archive",
                    "pcap",
                    "configuration_profiles",
                    "live_device",
                    "android",
                ],
                "real_export_qualification": "open",
                "clock_accuracy": "unknown",
                "same_device_identity": "unverified",
                "complete_device_history": False,
            },
        }
        if len(canonical(result)) > MAX_SNAPSHOT:
            raise ScryveilError("snapshot_too_large")
        result["snapshot_sha256"] = digest(canonical(result))
        return result


def diagnostic_coverage(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Owner-facing inventory of the verified selection, not inferred device history.

    Kept separate from the frozen default snapshot/tool projection so existing
    cases and model action contracts retain their recorded interpretation.
    """
    events = snapshot["events"]
    diagnostics = [e for e in events if e["event_type"].startswith("diagnostic.")]
    categories = {
        k: 0
        for k in (
            "diagnostic.crash",
            "diagnostic.exception",
            "diagnostic.resource",
            "diagnostic.jetsam",
        )
    }
    categories.update(Counter(e["event_type"] for e in diagnostics))
    represented = {e["artifact_id"] for e in events}
    return {
        "schema_version": "scryveil.diagnostic-coverage/1",
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "source_state_sha256": snapshot["source_state_sha256"],
        "scope": "verified_selected_snapshot_only",
        "coverage": deepcopy(snapshot["coverage"]),
        "imported_artifacts": len(snapshot["artifacts"]),
        "artifacts_without_selected_events": [
            a["artifact_id"] for a in snapshot["artifacts"] if a["artifact_id"] not in represented
        ],
        "diagnostic_categories": categories,
        "not_observed_in_snapshot": sorted(k for k, count in categories.items() if count == 0),
        "profiles": dict(
            sorted(
                Counter(
                    e.get("format_profile", "not_reported_by_reader") for e in diagnostics
                ).items()
            )
        ),
        "schema_status": dict(
            sorted(
                Counter(
                    e.get("schema_status", "not_reported_by_reader") for e in diagnostics
                ).items()
            )
        ),
        "interpretation_status": dict(
            sorted(
                Counter(
                    e.get("interpretation_status", "not_reported_by_reader") for e in diagnostics
                ).items()
            )
        ),
        "events_without_source_time": sum(e["event_time"] is None for e in events),
        "source_warnings": [
            {"artifact_id": a["artifact_id"], **warning}
            for a in snapshot["artifacts"]
            for warning in a["warnings"]
        ],
        "unimported_or_rejected_files": "unknown_not_recorded",
        "rejected_record_count": None,
        "limits": {
            "case_artifacts": 32,
            "case_events": 20000,
            "snapshot_selection": "earliest_known_times_then_unknown",
        },
        "limitations": [
            "Not observed means absent from this selected snapshot, not absent from the device or complete case.",
            "Unimported and rejected files are outside the accepted-case inventory; their count and contents are unknown.",
            "Warnings are reported warnings, not a complete rejected-record count. Parsers may interpret only a documented subset.",
            "Legacy projections may omit profile/schema metadata; not_reported_by_reader is not qualified parsing.",
            "Source clock accuracy, shared device identity, missing historical records and events after snapshot creation remain unverified.",
            "A missing IOC or diagnostic category does not establish a clean device or exclude compromise.",
        ],
    }


class ReadOnlyTools:
    def __init__(self, snapshot: dict[str, Any]):
        self.snapshot = snapshot
        self.events = {e["event_id"]: e for e in snapshot["events"]}
        self.findings = {f["finding_id"]: f for f in snapshot["findings"]}
        self.seen_events: set[str] = set()
        self.read_events: set[str] = set()
        self.seen_findings: set[str] = set()

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        try:
            if name not in TOOL_SCHEMAS:
                raise ScryveilError("tool_not_allowed")
            validate(args, TOOL_SCHEMAS[name])
            data, ids, truncated = self._query(name, args)
            result = {
                "schema_version": VERSION,
                "ok": True,
                "data": data,
                "evidence_ids": ids,
                "truncated": truncated,
            }
            if len(canonical(result)) > MAX_RESULT:
                raise ScryveilError("tool_result_too_large")
            self.seen_events.update(ids)
            if name in {
                "timeline.query",
                "diagnostics.search",
                "network.query",
                "process.inspect",
                "evidence.read_excerpt",
            }:
                self.read_events.update(ids)
            if name == "findings.inspect":
                self.seen_findings.update(f["finding_id"] for f in data)
            if name == "hypotheses.compare":
                self.seen_findings.add(args["finding_id"])
            return deepcopy(result)
        except ScryveilError as exc:
            return {
                "schema_version": VERSION,
                "ok": False,
                "error": exc.code,
                "evidence_ids": [],
                "truncated": False,
            }

    def _query(self, name: str, args: dict[str, Any]) -> tuple[Any, list[str], bool]:
        if name == "case.inspect":
            return (
                {
                    "snapshot_sha256": self.snapshot["snapshot_sha256"],
                    "events": len(self.events),
                    "findings": len(self.findings),
                    "identifiers_included": self.snapshot["identifiers_included"],
                },
                [],
                False,
            )
        if name == "coverage.inspect":
            return self.snapshot["coverage"], [], False
        if name == "evidence.list":
            return self.snapshot["artifacts"], [], False
        if name == "integrity.verify":
            return (
                {
                    "status": "verified_at_snapshot_creation",
                    "source_state_sha256": self.snapshot["source_state_sha256"],
                    "snapshot_sha256": self.snapshot["snapshot_sha256"],
                },
                [],
                False,
            )
        if name == "evidence.read_excerpt":
            if args["event_id"] not in self.events:
                raise ScryveilError("reference_out_of_scope")
            return self.events[args["event_id"]], [args["event_id"]], False
        if name in {"findings.inspect", "hypotheses.compare"}:
            if name == "hypotheses.compare" and args["finding_id"] not in self.findings:
                raise ScryveilError("reference_out_of_scope")
            selected = (
                list(self.findings.values())
                if name == "findings.inspect"
                else [self.findings[args["finding_id"]]]
            )
            ids = sorted(
                {
                    e
                    for f in selected
                    for k in ("supporting_evidence_ids", "contradictory_evidence_ids")
                    for e in f[k]
                }
            )
            return selected, ids, False
        rows = list(self.events.values())
        if name == "diagnostics.search":
            rows = [e for e in rows if e["event_type"].startswith("diagnostic.")]
        if name == "network.query":
            rows = [e for e in rows if e["event_type"].startswith("network.")]
        for k in ("event_type", "process_ref", "app_ref", "domain_ref"):
            if k in args:
                rows = [e for e in rows if e.get(k) == args[k]]
        for key in ("start_time", "end_time"):
            if key in args:
                normalized = timestamp(args[key])[0]
                rows = [
                    e
                    for e in rows
                    if e["event_time"] is not None
                    and (
                        e["event_time"] >= normalized
                        if key == "start_time"
                        else e["event_time"] <= normalized
                    )
                ]
        if "text" in args:
            # Search displayed Unicode, not the ASCII escape spelling used for
            # canonical hashes. This does not interpret regex or instructions.
            rows = [
                e
                for e in rows
                if args["text"].casefold() in json.dumps(e, ensure_ascii=False).casefold()
            ]
        cursor, limit = args.get("cursor", 0), args.get("limit", 25)
        selected = rows[cursor : cursor + limit]
        truncated = cursor + limit < len(rows)
        return (
            {
                "events": selected,
                "matched": len(rows),
                "next_cursor": cursor + limit if truncated else None,
            },
            [e["event_id"] for e in selected],
            truncated,
        )

    def ground_final(self, action: dict[str, Any]) -> dict[str, Any]:
        facts = []
        for fact in action["facts"]:
            eid, field = fact["event_id"], fact["field"]
            if (
                eid not in self.read_events
                or field not in self.events[eid]
                or not same_json(self.events[eid][field], fact["value"])
            ):
                raise ScryveilError("unsupported_factual_claim")
            event = self.events[eid]
            location = event.get("field_locations", {}).get(field, {})
            facts.append(
                {
                    **fact,
                    "artifact_id": event["artifact_id"],
                    "source_locator": location.get("source_locator", event["source_locator"]),
                    "byte_offset": location.get("byte_offset", event["byte_offset"]),
                    "byte_length": location.get("byte_length", event["byte_length"]),
                    "json_pointer": location.get("json_pointer", event.get("json_pointer")),
                }
            )
        measurements = []
        for fid in action["measurements"]:
            if fid not in self.seen_findings:
                raise ScryveilError("unsupported_measurement")
            measurements.append(self.findings[fid])
        for hypothesis in action["hypotheses"]:
            if not set(hypothesis["support"] + hypothesis["contradictions"]) <= self.seen_events:
                raise ScryveilError("unsupported_hypothesis_reference")
        return {
            "observed_facts": facts,
            "derived_measurements": measurements,
            "hypotheses": [
                {
                    **h,
                    "status": "unresolved_model_hypothesis",
                    "entailment": "not_independently_verified",
                }
                for h in action["hypotheses"]
            ],
            "unanswered_questions": action["unanswered_questions"],
            "scope": "No device safety verdict. Valid references do not establish hypothesis truth.",
        }
