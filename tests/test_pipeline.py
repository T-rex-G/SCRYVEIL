"""End-to-end behavior, falsification and reproducible export contracts."""

import copy
import json
import socket
from pathlib import Path

import pytest

from scryveil.cli import main
from scryveil.engine import RuleConfig, analyze
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest, parse
from scryveil.report import build_report, markdown, validate_report
from scryveil.store import CaseStore

FIXTURES = Path(__file__).parents[1] / "fixtures/synthetic"


def make_case(tmp_path, names):
    store = CaseStore(tmp_path / "cases")
    case_id = store.create("private-label-should-not-leak", "self")["case_id"]
    for name in names:
        store.import_file(case_id, FIXTURES / name, synthetic=True)
    store.run(case_id)
    return store, case_id


@pytest.mark.parametrize(
    "name,assessments",
    [
        ("periodic.ndjson", ["review_needed"]),
        ("benign_sync.ndjson", ["inconclusive"]),
        ("insufficient.ndjson", []),
        ("noisy.ndjson", []),
        ("empty.ndjson", []),
    ],
)
def test_honest_outcomes(tmp_path, name, assessments):
    store, case_id = make_case(tmp_path, [name])
    report = build_report(store, case_id)
    assert [f["assessment"] for f in report["analysis"]["findings"]] == assessments
    assert report["analysis"]["overall_assessment"] != "device_clean"
    if name == "benign_sync.ndjson":
        assert report["analysis"]["overall_assessment"] == "inconclusive"
        assert report["analysis"]["findings"][0]["contradictory_evidence_ids"]


def test_report_reproduction_redaction_and_source_links(tmp_path):
    store, case_id = make_case(tmp_path, ["periodic.ndjson", "indicators.ndjson"])
    report = build_report(store, case_id)
    assert canonical(report) == canonical(build_report(store, case_id))
    store.run(case_id)
    assert canonical(report) == canonical(build_report(store, case_id))
    assert report["report_sha256"] == digest(
        canonical({k: v for k, v in report.items() if k != "report_sha256"})
    )
    for output in [canonical(report).decode(), markdown(report)]:
        for private in [
            "com.example.research",
            "beacon.example.invalid",
            "private-label-should-not-leak",
            "periodic.ndjson",
        ]:
            assert private not in output
    ids = {e["event_id"] for e in report["timeline"]}
    assert all(set(f["supporting_evidence_ids"]) <= ids for f in report["analysis"]["findings"])


def test_apr_and_ioc_real_parser_path(tmp_path):
    store, case_id = make_case(tmp_path, ["privacy_report.ndjson", "indicators.ndjson"])
    report = build_report(store, case_id)
    assert {e["event_type"] for e in report["timeline"]} == {
        "privacy.access",
        "network.summary",
        "indicator.domain",
    }
    assert [f["rule_id"] for f in report["analysis"]["findings"]] == ["ioc.domain.exact"]
    assert all(e["synthetic"] for e in report["timeline"])
    summary = next(
        e for e in store.snapshot(case_id)["events"] if e["event_type"] == "network.summary"
    )
    assert summary["attributes"]["first_recorded_time"] == "2026-01-01T00:00:00.000000Z"


def test_invalid_reference_and_interval_fail_export(tmp_path):
    store, case_id = make_case(tmp_path, ["periodic.ndjson"])
    original = build_report(store, case_id)
    for field, value in [
        ("supporting_evidence_ids", ["evt-absent"]),
        ("first_observed_utc", "2099-01-01T00:00:00Z"),
    ]:
        report = copy.deepcopy(original)
        report["analysis"]["findings"][0][field] = value
        with pytest.raises(ScryveilError):
            validate_report(report)


def test_parse_failures_retained_and_exit_nonzero(tmp_path, capsys):
    store, case_id = make_case(tmp_path, [])
    rc = main(
        [
            "--root",
            str(store.root),
            "evidence",
            "import",
            "--case",
            case_id,
            "--synthetic",
            str(FIXTURES / "malformed.ndjson"),
        ]
    )
    assert rc == 2
    output = json.loads(capsys.readouterr().out)
    assert output["warning_count"] == 1
    store.run(case_id)
    report = build_report(store, case_id)
    assert report["analysis"]["coverage"][0]["partial"]
    assert report["artifacts"][0]["warnings"][0]["line"] == 1


def test_cli_errors_do_not_expose_paths_or_arguments(tmp_path, capsys):
    for args in [
        ["--secret-filename-contact"],
        [
            "--root",
            str(tmp_path / "cases"),
            "evidence",
            "import",
            "--case",
            "../private",
            "/private/secret-phone-export",
        ],
    ]:
        assert main(args) != 0
        output = capsys.readouterr()
        assert "secret" not in output.err and "/private" not in output.err
        assert "error" in json.loads(output.err)


def test_offline_core_never_opens_socket(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network attempted")

    monkeypatch.setattr(socket, "socket", denied)
    store, case_id = make_case(tmp_path, ["periodic.ndjson", "indicators.ndjson"])
    assert build_report(store, case_id)["analysis"]["findings"]


def test_review_is_audited_without_removing_finding(tmp_path):
    store, case_id = make_case(tmp_path, ["periodic.ndjson"])
    before = build_report(store, case_id)
    fid = before["analysis"]["findings"][0]["finding_id"]
    store.review(case_id, fid, "accepted_benign")
    after = build_report(store, case_id)
    assert after["analysis"]["findings"][0]["analyst_review_status"] == "accepted_benign"
    assert after["analysis"]["findings"][0]["assessment"] == "review_needed"
    assert after["audit"][-1]["operation"] == "analyst.review"


def test_ioc_join_is_bounded_not_cartesian():
    indicator = dict(
        schema="scryveil.indicators/1",
        domain="example.invalid",
        source="synthetic",
        license="MIT",
        created="2026-01-01T00:00:00Z",
        updated="2026-01-01T00:00:00Z",
    )
    net = dict(
        type="networkActivity", domain="example.invalid", bundleID="com.example.research", hits=1
    )
    raw = b"".join(canonical(r) for r in [indicator] * 100 + [net] * 100)
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), True)
    assert not warnings
    findings = analyze(events, [])["findings"]
    assert len(findings) == 1
    assert len(findings[0]["supporting_evidence_ids"]) == 200


@pytest.mark.parametrize("value", [[], {}, 12, None])
def test_wrong_event_type_is_visible_warning(value):
    raw = canonical(dict(schema="scryveil.events/1", synthetic=True, event_type=value))
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), True)
    assert events == [] and warnings


@pytest.mark.parametrize(
    "config",
    [
        RuleConfig(min_events=1),
        RuleConfig(min_window_seconds=float("nan")),
        RuleConfig(min_window_seconds=-1),
    ],
)
def test_rule_parameters_reject_invalid_values(config):
    with pytest.raises(ScryveilError):
        analyze([], [], config)
