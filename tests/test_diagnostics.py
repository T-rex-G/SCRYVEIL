import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scryveil.diagnostics import diagnostic_findings, parse_ips
from scryveil.investigation_tools import snapshot_case
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest, parse
from scryveil.report import build_report
from scryveil.store import CaseStore

FIXTURES = Path(__file__).parents[1] / "fixtures/synthetic"


def raw_ips(body=None, meta=None):
    return canonical(meta or {"bug_type": "309"}) + canonical(
        body
        if body is not None
        else {
            "version": 104,
            "procName": "com.example.searchd",
            "incident": "fictional-one",
            "captureTime": "2026-01-01 12:00:00.125 +0100",
            "exception": {"type": "EXC_BAD_ACCESS"},
        }
    )


def parsed(raw):
    return parse_ips(raw, "artifact-" + digest(raw), True)


def test_explicit_ips_envelope_exact_body_and_timestamp():
    raw = (FIXTURES / "diagnostic-0.ips").read_bytes()
    events, warnings, family = parsed(raw)
    assert not warnings and family == "apple_ips_json_v1"
    event = events[0]
    assert event["event_time"] == "2026-01-01T11:00:00.125000Z"
    assert event["source_offset"] == "+01:00"
    body = json.loads(raw[event["byte_offset"] : event["byte_offset"] + event["byte_length"]])
    assert body["procName"] == event["attributes"]["process"]
    assert event["attributes"]["frames"][0]["symbol"] == "fictional_lookup"
    assert event["attributes"]["report_tracking_time"] != event["source_timestamp"]


def test_jetsam_presence_does_not_mean_every_process_was_killed():
    events, warnings, _ = parsed((FIXTURES / "diagnostic-jetsam.ips").read_bytes())
    assert not warnings and len(events) == 2
    assert events[0]["attributes"]["footprint_bytes"] == 172032
    assert events[0]["attributes"]["reason"] == "highwater"
    assert events[1]["attributes"]["reason"] is None
    assert events[1]["attributes"]["json_pointer"] == "/processes/1"


@pytest.mark.parametrize(
    "source", [None, "2026-01-01T12:00:00", "2026-01-01 12:00:00 -0000", {}, "2026-01-01T12:00:60Z"]
)
def test_unknown_time_not_replaced_by_report_or_host_clock(source):
    body = json.loads(raw_ips().split(b"\n", 1)[1])
    body["captureTime"] = source
    events, warnings, _ = parsed(
        raw_ips(body, {"bug_type": "309", "timestamp": "2026-01-01T00:00:00Z"})
    )
    assert events[0]["event_time"] is None and warnings


@pytest.mark.parametrize(
    "field,value",
    [
        ("procName", []),
        ("exception", []),
        ("termination", []),
        ("threads", {}),
        ("pid", True),
        ("pid", -1),
        ("version", 999),
        ("isNonFatal", "true"),
        ("captureTime", "private-unparseable"),
    ],
)
def test_known_malformed_fields_have_explicit_warnings(field, value):
    body = json.loads(raw_ips().split(b"\n", 1)[1])
    body[field] = value
    _, warnings, _ = parsed(raw_ips(body))
    assert warnings
    assert "private-unparseable" not in canonical(warnings).decode()


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        b"{}\n{}",
        b'{"bug_type":"142"}\n{}',
        b'{"bug_type":"309"}\n[]',
        b'{"bug_type":"309"}\n{"pid":1,"pid":2}',
        b'{"bug_type":"309"}\n{"unknown":NaN}',
    ],
)
def test_invalid_or_unsupported_reports_rejected(raw):
    with pytest.raises(ScryveilError):
        parsed(raw)


def test_nested_input_limit_and_oversized_threads():
    body = json.loads(raw_ips().split(b"\n", 1)[1])
    item = body
    for _ in range(35):
        item["extra"] = {}
        item = item["extra"]
    with pytest.raises(ScryveilError, match="ips_structure_limit"):
        parsed(raw_ips(body))
    body = json.loads(raw_ips().split(b"\n", 1)[1])
    body["threads"] = [{}] * 257
    assert {"line": 2, "code": "invalid_ips_threads"} in parsed(raw_ips(body))[1]


def test_recurrence_counts_incidents_not_repeated_exports_or_nonvictims():
    events = []
    for name in (
        "diagnostic-0.ips",
        "diagnostic-1.ips",
        "diagnostic-2.ips",
        "diagnostic-jetsam.ips",
    ):
        events.extend(parsed((FIXTURES / name).read_bytes())[0])
    events.append(copy.deepcopy(events[0]))
    findings = diagnostic_findings(events)
    assert len(findings) == 1
    assert findings[0]["distinct_reported_incidents"] == 4
    assert findings[0]["contradictory_evidence_ids"] == [events[2]["event_id"]]
    assert events[4]["event_id"] not in findings[0]["supporting_evidence_ids"]


def test_missing_incident_does_not_establish_recurrence():
    body = json.loads(raw_ips().split(b"\n", 1)[1])
    del body["incident"]
    events = parsed(raw_ips(body))[0]
    assert diagnostic_findings(events * 3) == []


def test_explicit_route_preserves_ndjson_and_existing_case_report(tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    store.import_file(cid, FIXTURES / "periodic.ndjson", True)
    store.run(cid)
    before = canonical(build_report(store, cid))
    snapshot_case(store, cid)
    assert canonical(build_report(store, cid)) == before
    source = FIXTURES / "diagnostic-0.ips"
    # Default parser remains NDJSON, not a silently changed format guess.
    assert (
        parse(source.read_bytes(), "artifact-" + digest(source.read_bytes()), True)[2] == "unknown"
    )
    store.import_file(cid, source, True, "ips")
    store.run(cid)
    report = build_report(store, cid)
    schema = json.loads(
        (FIXTURES.parents[1] / "schemas/case-and-report-v0.1.0.schema.json").read_text()
    )
    Draft202012Validator(schema).validate(store.snapshot(cid))
    Draft202012Validator(dict(schema, **{"$ref": "#/$defs/Report"})).validate(report)
    assert any(e["event_type"] == "diagnostic.crash" for e in report["timeline"])


def test_reimport_different_parser_is_explicit_conflict(tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    source = FIXTURES / "diagnostic-0.ips"
    store.import_file(cid, source, True)
    with pytest.raises(ScryveilError, match="parser_selection_conflict"):
        store.import_file(cid, source, True, "ips")
