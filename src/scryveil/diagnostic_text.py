"""Bounded type-145 disk-write summary reader; never a stack/packet decoder."""

import re
from typing import Any

from .diagnostics import IPS_DIAGNOSTIC, ips_time
from .models import Event, ScryveilError
from .parse import MAX_BYTES, MAX_LINE, digest, load_json, text_field

FIELDS = {
    "Date/Time",
    "End time",
    "OS Version",
    "Report Version",
    "Incident Identifier",
    "Data Source",
    "Command",
    "Path",
    "PID",
    "Event",
    "Action taken",
    "Writes",
    "Writes limit",
    "Limit duration",
    "Writes caused",
    "Writes duration",
    "Duration",
    "Duration Sampled",
}
QUANTITY = re.compile(r"^(\d{1,20}(?:\.\d{1,9})?) (bytes|KB|MB|GB|KiB|MiB|GiB)$")
SECONDS = re.compile(r"^(\d{1,20}(?:\.\d{1,9})?)(?:s| seconds)?$")


def parse_resource_text(
    data: bytes, aid: str, synthetic: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    if len(data) > MAX_BYTES:
        raise ScryveilError("input_too_large")
    head, separator, body = data.partition(b"\n")
    if not separator or len(head) > MAX_LINE or not body.strip():
        raise ScryveilError("invalid_ips_envelope")
    meta = load_json(head)
    if not isinstance(meta, dict) or meta.get("bug_type") != "145":
        raise ScryveilError("unsupported_ips_type")
    try:
        body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScryveilError("invalid_ips_text_encoding") from exc
    if b"\x00" in body:
        raise ScryveilError("invalid_ips_text_control")
    warnings: list[dict[str, Any]] = []
    fields: dict[str, str | None] = {}
    locations: dict[str, dict[str, Any]] = {}

    def warn(code: str, line: int = 2) -> None:
        item = {"line": line, "code": code}
        if item not in warnings and len(warnings) < 64:
            warnings.append(item)

    offset = len(head) + 1
    # Only the top summary. Repeated times/paths in per-process powerstats and
    # stacks have different semantics and must not overwrite the report header.
    for index, raw in enumerate(body.splitlines(keepends=True), start=2):
        if index > 201:
            warn("ips_text_header_limit")
            break
        if len(raw) > MAX_LINE:
            raise ScryveilError("ips_text_line_limit")
        line = raw.decode("utf-8").rstrip("\r\n")
        if line.startswith(("Heaviest stack", "Powerstats for:", "Binary Images:")):
            break
        key, colon, value = line.partition(":")
        if colon and key in FIELDS:
            if key in fields:
                fields[key] = None
                locations.pop(key, None)
                warn("ips_text_duplicate_field", index)
            else:
                try:
                    fields[key] = text_field(value.strip())
                except ScryveilError:
                    fields[key] = None
                    warn("invalid_ips_text_field", index)
                locations[key] = {
                    "source_locator": f"line:{index}",
                    "byte_offset": offset,
                    "byte_length": len(raw),
                    "json_pointer": "",
                }
        offset += len(raw)
    if fields.get("Event") != "disk writes":
        raise ScryveilError("unsupported_ips_resource_event")

    def number(key: str) -> int | None:
        value = fields.get(key)
        if value is None:
            return None
        if not re.fullmatch(r"\d{1,18}", value):
            warn("invalid_ips_text_integer")
            return None
        return int(value)

    def seconds(key: str) -> str | None:
        value = fields.get(key)
        if value is None:
            return None
        match = SECONDS.fullmatch(value)
        if not match:
            warn("invalid_ips_text_duration")
            return None
        return match[1]

    def quantity(key: str) -> dict[str, str] | None:
        value = fields.get(key)
        if value is None:
            return None
        match = QUANTITY.fullmatch(value)
        if not match:
            warn("unparsed_ips_text_quantity")
            return None
        # Preserve the displayed unit/precision. MB is not silently treated as
        # MiB, nor is rounded display accounting an exact byte count.
        return {"value": match[1], "unit": match[2]}

    def time_value(key: str) -> tuple[str | None, str | None, str]:
        try:
            result = ips_time(fields.get(key))
        except ScryveilError:
            warn("invalid_ips_text_time")
            result = (None, None, "unknown")
        if result[0] is None:
            warn("missing_ips_text_time")
        return result

    start, zone, precision = time_value("Date/Time")
    end, end_zone, end_precision = time_value("End time")
    if start is not None and end is not None and end < start:
        warn("ips_text_reversed_interval")
    version = number("Report Version")
    if version != 29:
        warn("ips_schema_version_unqualified")
    incident = fields.get("Incident Identifier")
    if meta.get("incident_id") is not None and meta["incident_id"] != incident:
        warn("ips_incident_conflict")
    process = fields.get("Command")
    if process is None:
        warn("missing_ips_process")
    tracking = meta.get("timestamp")
    try:
        tracking = text_field(tracking, optional=True)
    except ScryveilError:
        tracking = None
        warn("invalid_ips_tracking_time")
    attrs: dict[str, Any] = {
        "bug_type": "145",
        "report_version": version,
        "format_profile": f"ips.text.145.v{version if version is not None else 'unknown'}",
        "schema_status": "recognized_subset" if version == 29 else "unqualified_version",
        "interpretation_status": "partial",
        "incident": incident,
        "process": process,
        "pid": number("PID"),
        "process_path": fields.get("Path"),
        "os_version": fields.get("OS Version"),
        "report_tracking_time": tracking,
        "resource_kind": "disk_writes",
        "action_taken": fields.get("Action taken"),
        "nonfatal": None,
        "simulated": None,
        "exception_type": None,
        "event_time_role": "interval_start",
        "event_end_time": end,
        "end_source_timestamp": fields.get("End time"),
        "end_source_offset": end_zone,
        "end_time_precision": end_precision,
        "writes_caused": quantity("Writes caused"),
        "writes_limit": quantity("Writes limit"),
        "writes_duration_seconds": seconds("Writes duration"),
        "limit_duration_seconds": seconds("Limit duration"),
        "duration_seconds": seconds("Duration"),
        "sampled_duration_seconds": seconds("Duration Sampled"),
        "writes_summary": fields.get("Writes"),
        "data_source": fields.get("Data Source"),
        "field_locations": {},
        "json_pointer": "",
    }
    for field, key in {
        "event_time": "Date/Time",
        "event_end_time": "End time",
        "process": "Command",
        "pid": "PID",
        "resource_kind": "Event",
        "action_taken": "Action taken",
        "writes_caused": "Writes caused",
        "writes_limit": "Writes limit",
        "writes_duration_seconds": "Writes duration",
        "limit_duration_seconds": "Limit duration",
        "duration_seconds": "Duration",
        "sampled_duration_seconds": "Duration Sampled",
    }.items():
        if key in locations:
            attrs["field_locations"][field] = locations[key]
    event = Event(
        event_id="evt-" + digest(f"{aid}:ips:0".encode()),
        artifact_id=aid,
        source_locator="line:2",
        byte_offset=len(head) + 1,
        byte_length=len(body),
        event_type="diagnostic.resource",
        event_time=start,
        source_timestamp=fields.get("Date/Time"),
        source_offset=zone,
        time_precision=precision,
        synthetic=synthetic,
        parser=IPS_DIAGNOSTIC,
        parser_version="2.0.0",
        attributes=attrs,
        limitations=[
            "Partial disk-write summary; stacks and per-process powerstats are not interpreted.",
            "Displayed accounting is aggregate and rounded, not individual writes or exact bytes.",
            "Action taken describes this report; no independent process-termination or security verdict.",
            "Real-export/version conformance, source clock and device identity remain unqualified.",
            *(["synthetic fixture; not device evidence"] if synthetic else []),
        ],
    ).json()
    return [event], warnings, IPS_DIAGNOSTIC
