"""Independent APR review oracles; no real phone exports or identifiers."""

import copy
import json
import random
import socket
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scryveil.cli import main
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest
from scryveil.privacy import build_privacy_report, privacy_markdown, validate_privacy_report
from scryveil.report import build_report
from scryveil.store import CaseStore


def access(kind="intervalBegin", timestamp="2026-01-01T12:00:00.000001Z", **extra):
    return {
        "type": "access",
        "accessor": {"identifier": "com.example.recorder", "identifierType": "bundleID"},
        "category": "microphone",
        "identifier": "synthetic-session-1",
        "kind": kind,
        "timeStamp": timestamp,
        **extra,
    }


def network(**extra):
    return {
        "type": "networkActivity",
        "bundleID": "com.example.browser",
        "domain": "api.example.invalid",
        "hits": 25,
        "firstTimeStamp": "2026-01-01T01:00:00Z",
        "timeStamp": "2026-01-01T02:00:00Z",
        "domainType": 2,
        "initiatedType": "NonAppInitiated",
        "context": "site.example.invalid",
        "domainOwner": "Fictional owner",
        **extra,
    }


def case(tmp_path, *exports):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic-only", "self")["case_id"]
    for index, records in enumerate(exports):
        source = tmp_path / f"synthetic-{index}.ndjson"
        source.write_bytes(b"".join(canonical(r) for r in records))
        store.import_file(cid, source, True)
    return store, cid


def test_paired_offset_interval_exact_microseconds_and_original_locators(tmp_path):
    records = [access(), access("intervalEnd", "2026-01-01T13:00:02.000003+01:00"), network()]
    store, cid = case(tmp_path, records)
    before = (store.path(cid) / "state.json").read_bytes()
    report = build_privacy_report(store, cid)
    interval = report["access_intervals"][0]
    assert interval["status"] == "complete"
    assert interval["duration_microseconds"] == 2_000_002
    assert report["network_summaries"][0]["reported_hits"] == 25
    assert report["network_summaries"][0]["attribution"] == "NonAppInitiated"
    assert not report["issues"]
    assert canonical(report) == canonical(build_privacy_report(store, cid))
    assert before == (store.path(cid) / "state.json").read_bytes()
    assert report["report_sha256"] == digest(
        canonical({k: v for k, v in report.items() if k != "report_sha256"})
    )
    for e in report["sources"]:
        raw = (
            store.path(cid) / "originals" / e["artifact_id"].removeprefix("artifact-")
        ).read_bytes()
        assert json.loads(raw[e["byte_offset"] : e["byte_offset"] + e["byte_length"]]) in records


@pytest.mark.parametrize(
    "records,status",
    [
        ([access()], "missing_end"),
        ([access("intervalEnd")], "missing_begin"),
        ([access(), access("intervalEnd", "2026-01-01T11:00:00Z")], "invalid_time_order"),
        (
            [
                access(),
                access(timestamp="2026-01-01T12:01:00Z"),
                access("intervalEnd", "2026-01-01T13:00:00Z"),
            ],
            "ambiguous",
        ),
        ([access(), access("intervalEnd", category="camera")], "ambiguous"),
        (
            [
                access(),
                access(
                    "intervalEnd",
                    accessor={"identifier": "com.example.other", "identifierType": "bundleID"},
                ),
            ],
            "ambiguous",
        ),
        ([access(identifier=None)], "unresolved_identity_or_kind"),
        ([access(identifier={"hostile": True})], "unresolved_identity_or_kind"),
        ([access(kind="futureBoundary")], "unresolved_identity_or_kind"),
        ([access(category="futureResource")], "unresolved_identity_or_kind"),
        ([access(accessor={"identifier": "com.example.recorder"})], "unresolved_identity_or_kind"),
        (
            [access(broadcaster={"identifierType": "future", "identifier": "com.example.screen"})],
            "unresolved_identity_or_kind",
        ),
        ([access(broadcaster=[])], "unresolved_identity_or_kind"),
    ],
)
def test_uncertainty_never_gets_a_duration(tmp_path, records, status):
    store, cid = case(tmp_path, records)
    interval = build_privacy_report(store, cid)["access_intervals"][0]
    assert interval["status"] == status
    assert interval["duration_microseconds"] is None


def test_duplicates_retain_all_supports_without_inflating_counts(tmp_path):
    begin, end, net = access(), access("intervalEnd", "2026-01-01T12:00:03Z"), network()
    store, cid = case(tmp_path, [begin, begin, end, end, net, net])
    report = build_privacy_report(store, cid)
    assert report["access_intervals"][0]["status"] == "complete"
    assert report["access_intervals"][0]["duplicate_record_count"] == 2
    assert len(report["access_intervals"][0]["evidence_ids"]) == 4
    assert report["network_summaries"][0]["reported_hits"] == 25
    assert report["network_summaries"][0]["duplicate_record_count"] == 1
    assert report["summary"]["network_records"] == 2


def test_no_pairing_or_hit_summing_across_exports(tmp_path):
    store, cid = case(tmp_path, [access(), network()], [access("intervalEnd"), network()])
    report = build_privacy_report(store, cid)
    assert {r["status"] for r in report["access_intervals"]} == {"missing_begin", "missing_end"}
    assert [n["reported_hits"] for n in report["network_summaries"]] == [25, 25]
    assert "total_hits" not in canonical(report).decode()


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("initiatedType", "futureType", "unknown_network_attribution"),
        ("initiatedType", {}, "unknown_network_attribution"),
        ("domainType", True, "unknown_tracking_classification"),
        ("domainType", 3, "unknown_tracking_classification"),
        ("context", ["untrusted"], "invalid_network_context"),
        ("domainOwner", "secret\ncontrol", "invalid_domain_owner"),
        ("firstTimeStamp", None, "incomplete_network_interval"),
        ("timeStamp", None, "incomplete_network_interval"),
    ],
)
def test_unknown_network_fields_are_visible(tmp_path, field, value, code):
    store, cid = case(tmp_path, [network(**{field: value})])
    report = build_privacy_report(store, cid)
    assert code in {i["code"] for i in report["issues"]}
    assert len(report["network_summaries"]) == 1


def test_private_strings_omitted_by_default_and_explicitly_available_as_json(tmp_path):
    store, cid = case(tmp_path, [access(), network()])
    report = build_privacy_report(store, cid)
    for output in (canonical(report).decode(), privacy_markdown(report)):
        for token in (
            "com.example.recorder",
            "api.example.invalid",
            "site.example.invalid",
            "Fictional owner",
            "synthetic-session-1",
        ):
            assert token not in output
    private = build_privacy_report(store, cid, include_identifiers=True)
    assert private["apps"][0]["identifier"] == "com.example.recorder"
    assert private["domains"][0]["domain"] == "api.example.invalid"
    assert private["network_summaries"][0]["context"] == "site.example.invalid"
    with pytest.raises(ScryveilError, match="private_identifiers_require_json"):
        privacy_markdown(private)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_source",
        "wrong_artifact",
        "wrong_duration",
        "invented_end",
        "bad_domain",
        "double_use",
    ],
)
def test_output_lineage_validation_rejects_fabricated_observations(tmp_path, mutation):
    store, cid = case(
        tmp_path, [access(), access("intervalEnd", "2026-01-01T12:00:03Z"), network()]
    )
    report = build_privacy_report(store, cid)
    interval = report["access_intervals"][0]
    if mutation == "missing_source":
        report["sources"].pop()
    elif mutation == "wrong_artifact":
        interval["artifact_id"] = "artifact-" + "0" * 64
    elif mutation == "wrong_duration":
        interval["duration_microseconds"] += 1
    elif mutation == "invented_end":
        interval["end_time"] = "2099-01-01T00:00:00.000000Z"
    elif mutation == "bad_domain":
        report["network_summaries"][0]["domain_ref"] = "domain-absent"
    else:
        report["access_intervals"].append(copy.deepcopy(interval))
    with pytest.raises(ScryveilError, match="privacy_report_lineage_failed"):
        validate_privacy_report(report)


@pytest.mark.parametrize("seed", range(10))
def test_generated_ground_truth_survives_order_duplicates_and_timezone_changes(tmp_path, seed):
    rng = random.Random(seed)
    records, expected = [], Counter()
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(100):
        microseconds = rng.randrange(0, 10_000_000)
        start = base + timedelta(seconds=i * 15)
        finish = start + timedelta(microseconds=microseconds)
        zone = timezone(timedelta(minutes=rng.choice([-720, -210, 0, 345, 840])))
        begin = access(timestamp=start.astimezone(zone).isoformat(), identifier=f"synthetic-{i}")
        end = access("intervalEnd", finish.isoformat(), identifier=f"synthetic-{i}")
        records.extend([begin, end])
        if rng.choice([True, False]):
            records.append(copy.deepcopy(begin))
        expected[microseconds] += 1
    rng.shuffle(records)
    store, cid = case(tmp_path, records)
    report = build_privacy_report(store, cid)
    assert report["summary"]["interval_status_counts"] == {"complete": 100}
    assert Counter(r["duration_microseconds"] for r in report["access_intervals"]) == expected
    assert len(report["sources"]) == len(records)


def test_no_data_is_explicit_and_existing_reports_unchanged(tmp_path):
    store, cid = case(tmp_path, [])
    store.run(cid)
    before = canonical(build_report(store, cid))
    report = build_privacy_report(store, cid)
    assert report["provenance_mode"] == "no_evidence"
    assert report["access_intervals"] == report["network_summaries"] == []
    assert before == canonical(build_report(store, cid))


def test_privacy_command_runs_offline_and_sanitizes_errors(tmp_path, monkeypatch, capsys):
    def no_network(*args, **kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket, "socket", no_network)
    store, cid = case(tmp_path, [access()])
    args = ["--root", str(store.root), "privacy", "report", "--case", cid]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["access_records"] == 1
    assert main(args + ["--format", "markdown"]) == 0
    assert "missing_end" in capsys.readouterr().out
    assert main(args + ["--format", "markdown", "--include-identifiers"]) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "private_identifiers_require_json"}


def test_altered_original_rejected_before_review(tmp_path):
    store, cid = case(tmp_path, [access()])
    source = next((store.path(cid) / "originals").iterdir())
    source.chmod(0o600)
    source.write_bytes(canonical(network()))
    with pytest.raises(ScryveilError, match="source_integrity_failed"):
        build_privacy_report(store, cid)


@pytest.mark.parametrize("private", [False, True])
def test_versioned_report_schema(tmp_path, private):
    store, cid = case(tmp_path, [access(), network()])
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/privacy-review-v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(build_privacy_report(store, cid, private))


def test_unknown_huge_numeric_metadata_remains_in_original_only(tmp_path):
    store, cid = case(tmp_path)
    raw = canonical(access()).rstrip()[:-1] + b',"unknown":1e999}\n'
    source = tmp_path / "synthetic.ndjson"
    source.write_bytes(raw)
    store.import_file(cid, source, True)
    report = build_privacy_report(store, cid)
    assert report["summary"]["access_records"] == 1
    assert "Infinity" not in canonical(report).decode()


def test_screen_recording_broadcaster_conflict_is_ambiguous(tmp_path):
    records = [
        access(
            category="screenRecording",
            broadcaster={"identifierType": "bundleID", "identifier": "com.example.screen1"},
        ),
        access(
            "intervalEnd",
            category="screenRecording",
            broadcaster={"identifierType": "bundleID", "identifier": "com.example.screen2"},
        ),
    ]
    store, cid = case(tmp_path, records)
    assert build_privacy_report(store, cid)["access_intervals"][0]["status"] == "ambiguous"


def test_same_visible_boundary_with_different_raw_metadata_is_not_deduplicated(tmp_path):
    store, cid = case(tmp_path, [access(), access(extra="unknown_field"), access("intervalEnd")])
    assert build_privacy_report(store, cid)["access_intervals"][0]["status"] == "ambiguous"


@pytest.mark.parametrize(
    "context,expected", [(None, None), ([], None), ("", False), ("site.example.invalid", True)]
)
def test_context_presence_preserves_unknown(tmp_path, context, expected):
    store, cid = case(tmp_path, [network(context=context)])
    row = build_privacy_report(store, cid)["network_summaries"][0]
    assert row["web_context_present"] is expected
