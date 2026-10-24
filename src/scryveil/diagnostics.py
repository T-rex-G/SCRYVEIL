"""Original bounded Apple IPS JSON interpretation and diagnostic observations.

An explicit import route preserves the interpretation of existing NDJSON cases.
Offsets select the exact JSON body; json_pointer selects a process within it.
"""

import re
from collections import defaultdict
from typing import Any

from .models import Event, ScryveilError
from .parse import MAX_BYTES, MAX_LINE, canonical, digest, load_json, text_field, timestamp

IPS = "apple_ips_json_v1"
IPS_DIAGNOSTIC = "apple_ips_diagnostic_v2"
IPS_RESOURCE = "apple_ips_resource_text_v1"
APPLE_TIME = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d(?:\.\d{1,6})?) ([+-]\d\d)(\d\d)$")


def bounded_json(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100_000:
            raise ScryveilError("ips_structure_limit")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)


def ips_time(value: Any) -> tuple[str | None, str | None, str]:
    if value is None:
        return None, None, "unknown"
    if isinstance(value, str) and (match := APPLE_TIME.fullmatch(value)):
        value = f"{match[1]}T{match[2]}{match[3]}:{match[4]}"
    return timestamp(value)


def parse_ips(
    data: bytes, aid: str, synthetic: bool, *, extended: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    if len(data) > MAX_BYTES:
        raise ScryveilError("input_too_large")
    header, separator, body = data.partition(b"\n")
    if not separator or len(header) > MAX_LINE or not body.strip():
        raise ScryveilError("invalid_ips_envelope")
    meta, rec = load_json(header), load_json(body)
    if not isinstance(meta, dict) or not isinstance(rec, dict):
        raise ScryveilError("invalid_ips_envelope")
    bounded_json(rec)
    bug = meta.get("bug_type")
    if bug not in (("309", "308", "298") if extended else ("309", "298")):
        raise ScryveilError("unsupported_ips_type")
    warnings: list[dict[str, Any]] = []

    def warn(code: str) -> None:
        if {"line": 2, "code": code} not in warnings:
            warnings.append({"line": 2, "code": code})

    def string(value: Any, field: str) -> str | None:
        if value is None:
            return None
        try:
            return text_field(value)
        except ScryveilError:
            warn("invalid_ips_" + field)
            return None

    def integer(value: Any, field: str) -> int | None:
        if value is None:
            return None
        if type(value) is not int or not 0 <= value < 2**63:
            warn("invalid_ips_" + field)
            return None
        return int(value)

    def obj(value: Any, field: str) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            warn("invalid_ips_" + field)
            return {}
        return value

    source_time = rec.get("captureTime") if bug in ("309", "308") else rec.get("date")
    try:
        utc, zone, precision = ips_time(source_time)
    except ScryveilError:
        utc, zone, precision = None, None, "unknown"
        warn("invalid_ips_event_time")
    if utc is None:
        warn("missing_ips_event_time")
    incident = string(rec.get("incident"), "incident")
    if meta.get("incident_id") is not None and meta["incident_id"] != incident:
        warn("ips_incident_conflict")
    os_info = obj(rec.get("osVersion"), "os_version")
    common = {
        "bug_type": bug,
        "incident": incident,
        "os_version": string(os_info.get("train", rec.get("build")), "os_version"),
        "os_build": string(os_info.get("build"), "os_build"),
        "report_tracking_time": string(meta.get("timestamp"), "tracking_time"),
    }
    rows: list[tuple[str, dict[str, Any]]] = []
    if bug in ("309", "308"):
        version = integer(rec.get("version"), "version")
        if version != (2 if extended else 104):
            warn("ips_schema_version_unqualified")
        exc, term = (
            obj(rec.get("exception"), "exception"),
            obj(rec.get("termination"), "termination"),
        )
        nonfatal, simulated = rec.get("isNonFatal"), rec.get("isSimulated")
        for value in (nonfatal, simulated):
            if value is not None and type(value) is not bool:
                warn("invalid_ips_condition_flag")
        attrs: dict[str, Any] = {
            **common,
            "json_pointer": "",
            "report_version": version,
            "process": string(rec.get("procName"), "process"),
            "pid": integer(rec.get("pid"), "pid"),
            "process_path": string(rec.get("procPath"), "process_path"),
            "parent_process": string(rec.get("parentProc"), "parent_process"),
            "bundle_id": string(
                obj(rec.get("bundleInfo"), "bundle_info").get("CFBundleIdentifier"), "bundle_id"
            ),
            "exception_type": string(exc.get("type"), "exception_type"),
            "exception_signal": string(exc.get("signal"), "exception_signal"),
            "exception_subtype": string(exc.get("subtype"), "exception_subtype"),
            "termination_namespace": string(term.get("namespace"), "termination_namespace"),
            "termination_code": integer(term.get("code"), "termination_code"),
            "termination_reason": string(term.get("indicator"), "termination_reason"),
            "nonfatal": nonfatal if type(nonfatal) is bool else None,
            "simulated": simulated if type(simulated) is bool else None,
            "frames": [],
        }
        if extended:
            attrs.update(
                interpretation_status="partial",
                schema_status="recognized_subset" if version == 2 else "unqualified_version",
                format_profile=f"ips.json.{bug}.v{version if version is not None else 'unknown'}",
                exception_codes=string(exc.get("codes"), "exception_codes"),
                exception_message=string(exc.get("message"), "exception_message"),
                exception_raw_codes=None,
                lightweight_corpse=None,
                field_locations={},
            )

            def location(pointer: str, metadata: bool = False) -> dict[str, Any]:
                return {
                    "source_locator": "line:1" if metadata else "line:2",
                    "byte_offset": 0 if metadata else len(header) + 1,
                    "byte_length": len(header) if metadata else len(body),
                    "json_pointer": pointer,
                }

            for field, pointer in {
                "event_time": "/captureTime",
                "process": "/procName",
                "pid": "/pid",
                "exception_type": "/exception/type",
                "exception_codes": "/exception/codes",
                "exception_message": "/exception/message",
                "exception_raw_codes": "/exception/rawCodes",
                "termination_code": "/termination/code",
                "nonfatal": "/isNonFatal",
                "simulated": "/isSimulated",
                "lightweight_corpse": "/isLightWeightCorpse",
            }.items():
                current: Any = rec
                for part in pointer.lstrip("/").split("/"):
                    current = current.get(part) if isinstance(current, dict) else None
                if current is not None:
                    attrs["field_locations"][field] = location(pointer)
            raw_codes = exc.get("rawCodes")
            if raw_codes is not None:
                if (
                    isinstance(raw_codes, list)
                    and len(raw_codes) <= 4
                    and all(type(v) is int and -(2**63) <= v < 2**64 for v in raw_codes)
                ):
                    attrs["exception_raw_codes"] = raw_codes
                else:
                    warn("invalid_ips_exception_raw_codes")
            # Apple reports can declare simulation in envelope metadata. Keep
            # this distinct from proof of termination or a device compromise.
            declared = meta.get("is_simulated")
            if declared is not None:
                if type(declared) in (bool, int) and declared in (0, 1):
                    if attrs["simulated"] is not None and attrs["simulated"] != bool(declared):
                        attrs["simulated"] = None
                        warn("ips_simulation_flag_conflict")
                    elif attrs["simulated"] is None:
                        attrs["simulated"] = bool(declared)
                        attrs["field_locations"]["simulated"] = location("/is_simulated", True)
                else:
                    warn("invalid_ips_simulation_metadata")
            corpse = rec.get("isLightWeightCorpse")
            if corpse is not None:
                if type(corpse) in (bool, int) and corpse in (0, 1):
                    attrs["lightweight_corpse"] = bool(corpse)
                else:
                    warn("invalid_ips_lightweight_corpse")
            if rec.get("bug_type") is not None and rec["bug_type"] != bug:
                warn("ips_bug_type_conflict")
        threads = rec.get("threads", [])
        index = integer(rec.get("faultingThread"), "faulting_thread")
        if not isinstance(threads, list) or len(threads) > 256:
            warn("invalid_ips_threads")
        elif index is not None:
            if index >= len(threads) or not isinstance(threads[index], dict):
                warn("invalid_ips_faulting_thread")
            else:
                frames = threads[index].get("frames", [])
                if not isinstance(frames, list):
                    warn("invalid_ips_frames")
                else:
                    if len(frames) > 32:
                        warn("ips_frames_truncated")
                    for frame in frames[:32]:
                        if not isinstance(frame, dict):
                            warn("invalid_ips_frame")
                            continue
                        attrs["frames"].append(
                            {
                                "symbol": string(frame.get("symbol"), "symbol"),
                                "image_index": integer(frame.get("imageIndex"), "image_index"),
                                "image_offset": integer(frame.get("imageOffset"), "image_offset"),
                            }
                        )
        kind = (
            "diagnostic.resource"
            if attrs["exception_type"] == "EXC_RESOURCE"
            else "diagnostic.exception"
            if bug == "308"
            else "diagnostic.crash"
        )
        rows.append((kind, attrs))
    else:
        processes = rec.get("processes")
        if not isinstance(processes, list) or not 1 <= len(processes) <= 5000:
            raise ScryveilError("invalid_ips_processes")
        memory = obj(rec.get("memoryStatus"), "memory_status")
        page_size = integer(memory.get("pageSize", rec.get("pageSize")), "page_size")
        if page_size == 0:
            warn("invalid_ips_page_size")
            page_size = None
        if (
            memory.get("pageSize") is not None
            and rec.get("pageSize") is not None
            and memory["pageSize"] != rec["pageSize"]
        ):
            warn("ips_page_size_conflict")
            page_size = None
        for i, process in enumerate(processes):
            if not isinstance(process, dict):
                warn("invalid_ips_process")
                continue
            pages = integer(process.get("rpages"), "resident_pages")
            rows.append(
                (
                    "diagnostic.jetsam",
                    {
                        **common,
                        "json_pointer": f"/processes/{i}",
                        "process": string(process.get("name"), "process"),
                        "pid": integer(process.get("pid"), "pid"),
                        "reason": string(process.get("reason"), "reason"),
                        "resident_pages": pages,
                        "page_size": page_size,
                        "footprint_bytes": pages * page_size
                        if pages is not None and page_size is not None
                        else None,
                    },
                )
            )
    events = []
    for i, (kind, attrs) in enumerate(rows):
        if attrs["process"] is None:
            warn("missing_ips_process")
        events.append(
            Event(
                event_id="evt-" + digest(f"{aid}:ips:{i}".encode()),
                artifact_id=aid,
                source_locator="line:2",
                byte_offset=len(header) + 1,
                byte_length=len(body),
                event_type=kind,
                event_time=utc,
                source_timestamp=source_time if isinstance(source_time, str) else None,
                source_offset=zone,
                time_precision=precision,
                synthetic=synthetic,
                parser=IPS_DIAGNOSTIC if extended else IPS,
                parser_version="2.0.0" if extended else "1.0.0",
                attributes=attrs,
                limitations=[
                    "Documented IPS subset; real-export/version conformance remains open.",
                    "Source clock accuracy and same-device identity are unverified.",
                    *(["synthetic fixture; not device evidence"] if synthetic else []),
                ],
            ).json()
        )
    return events, warnings, IPS_DIAGNOSTIC if extended else IPS


def parse_diagnostic(
    data: bytes, aid: str, synthetic: bool, *, resource_v1: bool = True
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """New imports dispatch by declared format, never by filename alone.

    Stored v1 cases continue to use parse_ips with its original interpretation.
    Legacy 104/Jetsam behavior stays unchanged; v2/308 and text get a new family.
    """
    if len(data) > MAX_BYTES:
        raise ScryveilError("input_too_large")
    head, separator, body = data.partition(b"\n")
    if not separator or len(head) > MAX_LINE or not body.strip():
        raise ScryveilError("invalid_ips_envelope")
    meta = load_json(head)
    if not isinstance(meta, dict):
        raise ScryveilError("invalid_ips_envelope")
    bug = meta.get("bug_type")
    if bug == "145":
        from .diagnostic_text import parse_resource_text

        return parse_resource_text(data, aid, synthetic, extended=resource_v1)
    if bug not in ("309", "308", "298"):
        raise ScryveilError("unsupported_ips_type")
    rec = load_json(body)
    legacy = bug == "298" or (
        bug == "309"
        and isinstance(rec, dict)
        and type(rec.get("version")) is int
        and rec["version"] == 104
    )
    return parse_ips(data, aid, synthetic, extended=not legacy)


def parse_diagnostic_v2(
    data: bytes, aid: str, synthetic: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Recorded v2 cases retain their original text interpretation on verification."""
    return parse_diagnostic(data, aid, synthetic, resource_v1=False)


def diagnostic_findings(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group declared process names; never infer a shared device or causal link."""
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_type"].startswith("diagnostic.") and event["attributes"].get("process"):
            groups[event["attributes"]["process"]].append(event)
    findings = []
    for process, group in sorted(groups.items()):
        failures = [
            e
            for e in group
            if e["event_type"] != "diagnostic.jetsam" or e["attributes"].get("reason")
        ]
        # Missing incident IDs and identical incident IDs do not establish separate incidents.
        incidents = {e["attributes"]["incident"] for e in failures if e["attributes"]["incident"]}
        if len(incidents) < 2:
            continue
        ids = sorted({e["event_id"] for e in failures})
        contrary = [
            e["event_id"]
            for e in failures
            if e["attributes"].get("nonfatal") is True
            or e["attributes"].get("simulated") is True
            or e["attributes"].get("action_taken") == "none"
        ]
        times = sorted({e["event_time"] for e in failures if e["event_time"] is not None})
        findings.append(
            {
                "finding_id": "diag-" + digest(canonical(ids)),
                "rule": "diagnostics.recurrent_reports/1",
                "process": process,
                "assessment": "review_needed",
                "distinct_reported_incidents": len(incidents),
                "supporting_evidence_ids": ids,
                "contradictory_evidence_ids": sorted(contrary),
                "first_observed_utc": times[0] if times else None,
                "last_observed_utc": times[-1] if times else None,
                "observation": "Multiple distinct incident identifiers name the same process in supplied diagnostic reports.",
                "alternatives": [
                    "software defect",
                    "resource pressure or policy termination",
                    "different devices or process versions",
                    "malicious cause remains unestablished",
                ],
                "limitations": [
                    "Incident IDs and process names are source declarations, not authenticated identity.",
                    "Nonfatal and simulated reports do not prove process termination.",
                    "Report recurrence alone does not establish spyware or its absence.",
                ],
            }
        )
    return findings
