"""Adversarial contracts for untrusted exports and evidence lineage."""

import json
import os
import stat
from pathlib import Path

import pytest

from scryveil.engine import analyze
from scryveil.models import ScryveilError
from scryveil.parse import MAX_BYTES, MAX_LINE, canonical, digest, parse, timestamp
from scryveil.store import CaseStore, read_regular


def record(second: int = 0, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "scryveil.events/1",
        "synthetic": True,
        "event_type": "network.observation",
        "app": "com.example.sync",
        "domain": "example.invalid",
        "timestamp": f"2026-01-01T00:{second // 60:02d}:{second % 60:02d}Z",
    }
    value.update(changes)
    return value


def encoded(*records: dict[str, object]) -> bytes:
    return b"".join(canonical(item) for item in records)


@pytest.fixture
def populated(tmp_path: Path):
    store = CaseStore(tmp_path / "private-cases")
    case_id = store.create("synthetic-only", "self")["case_id"]
    source = tmp_path / "source.ndjson"
    source.write_bytes(encoded(*(record(i * 60) for i in range(6))))
    imported = store.import_file(case_id, source, synthetic=True)
    store.run(case_id)
    return store, case_id, source, imported


@pytest.mark.parametrize(
    "stamp",
    [
        "2026-01-01T00:00:00",
        "2026-01-01",
        "2026-01-01T00:00:00-00:00",
        "2026-01-01T00:00:00+01:60",
        "2026-01-01T00:00:00+24:00",
        "2026-02-30T00:00:00Z",
        "2026-01-01T00:00:60Z",
        "0001-01-01T00:00:00+23:59",
        "9999-12-31T23:59:59-23:59",
    ],
)
def test_ambiguous_or_invalid_timestamps_fail(stamp: str):
    with pytest.raises(ScryveilError):
        timestamp(stamp)


def test_normalizes_offset_preserving_precision():
    utc, offset, precision = timestamp("2026-01-01T01:30:00.123+01:30")
    assert utc == "2026-01-01T00:00:00.123000Z"
    assert offset == "+01:30"
    assert precision == "fractional_digits:3"


@pytest.mark.parametrize(
    "bad",
    [
        b'{"type":"access","type":"networkActivity"}',
        b'{"hits":NaN}',
        b'{"hits":Infinity}',
        b'{"hits":-Infinity}',
        b"[]",
        b"null",
        b"123",
        b'"text"',
        b'{"x":"\xff"}',
        b"{",
        b"[" * 1500 + b"]" * 1500,
    ],
)
def test_hostile_json_is_a_visible_parse_failure(bad: bytes):
    data = encoded(record()) + bad + b"\n"
    events, warnings, _ = parse(data, "artifact-" + digest(data), True)
    assert len(events) == 1
    assert any(item["line"] == 2 for item in warnings)
    assert all(set(item) == {"line", "code"} for item in warnings)


@pytest.mark.parametrize("magic", [b"PK\x03\x04", b"\x1f\x8b", b"BZh", b"<?xml", b"bplist00"])
def test_archives_and_plists_are_rejected_without_extraction(magic: bytes):
    with pytest.raises(ScryveilError, match="unsupported_format"):
        parse(magic + b"../outside", "artifact-" + "0" * 64, False)


def test_bounded_line_and_file_limits():
    with pytest.raises(ScryveilError, match="record_too_large"):
        parse(b" " * (MAX_LINE + 1), "artifact-" + "0" * 64, True)
    with pytest.raises(ScryveilError, match="input_too_large"):
        parse(b" " * (MAX_BYTES + 1), "artifact-" + "0" * 64, True)


def test_exact_byte_locators_with_multibyte_and_blank_lines():
    first = json.dumps(record(app="com.example.\u00e9"), ensure_ascii=False).encode() + b"\r\n"
    last = encoded(record(60))
    raw = first + b"\r\n" + last
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), True)
    assert not warnings
    assert [event["source_locator"] for event in events] == ["line:1", "line:3"]
    assert (
        raw[events[0]["byte_offset"] : events[0]["byte_offset"] + events[0]["byte_length"]] == first
    )
    assert (
        raw[events[1]["byte_offset"] : events[1]["byte_offset"] + events[1]["byte_length"]] == last
    )


def test_duplicate_observations_do_not_create_sample_sufficiency():
    raw = encoded(*(record() for _ in range(6)))
    events, _, _ = parse(raw, "artifact-" + digest(raw), True)
    result = analyze(events, [])
    assert len(events) == 6
    assert len({event["event_id"] for event in events}) == 6
    assert not result["findings"]
    assert any(outcome.get("duplicates_excluded") == 5 for outcome in result["rule_outcomes"])


def test_apr_aggregate_hits_never_become_periodic_packet_events():
    raw = encoded(
        *(
            {
                "type": "networkActivity",
                "bundleID": "com.example.sync",
                "domain": "example.invalid",
                "hits": 10000,
                "timeStamp": record(i * 60)["timestamp"],
            }
            for i in range(6)
        )
    )
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), False)
    assert len(events) == 6 and not warnings
    assert {e["event_type"] for e in events} == {"network.summary"}
    assert not analyze(events, [])["findings"]


def test_backward_clock_is_visible():
    raw = encoded(record(120), record(0))
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), True)
    assert len(events) == 2
    assert {w["code"] for w in warnings} == {"source_order_not_chronological"}


def test_source_symlink_refused(tmp_path: Path):
    target = tmp_path / "regular"
    target.write_bytes(b"private")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ScryveilError, match="symlink_not_allowed"):
        read_regular(link, 100)


def test_parent_symlink_refused(tmp_path: Path):
    directory = tmp_path / "directory"
    directory.mkdir()
    (directory / "regular").write_bytes(b"private")
    link = tmp_path / "parent-link"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ScryveilError, match="symlink_not_allowed"):
        read_regular(link / "regular", 100)


@pytest.mark.skipif(os.name != "posix", reason="POSIX supported host contract")
def test_fifo_is_refused_without_waiting_for_a_writer(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(ScryveilError, match="regular_file_required"):
        read_regular(fifo, 100)


def test_case_permissions_and_original_preservation(populated):
    store, case_id, source, imported = populated
    state = store.snapshot(case_id)
    case = store.path(case_id)
    original = case / "originals" / state["artifacts"][0]["sha256"]
    assert original.read_bytes() == source.read_bytes()
    assert digest(original.read_bytes()) == imported["artifact_id"].removeprefix("artifact-")
    assert stat.S_IMODE(case.stat().st_mode) == 0o700
    assert stat.S_IMODE(original.stat().st_mode) == 0o400
    assert not (stat.S_IMODE((case / "state.json").stat().st_mode) & 0o077)


def test_reimport_idempotent_with_new_audit_entry(populated):
    store, case_id, source, _ = populated
    before = store.snapshot(case_id)
    result = store.import_file(case_id, source, synthetic=True)
    after = store.snapshot(case_id)
    assert result["status"] == "duplicate"
    assert after["events"] == before["events"]
    assert after["artifacts"] == before["artifacts"]
    assert len(after["audit"]) == len(before["audit"]) + 1


@pytest.mark.parametrize(
    "case_id", ["../outside", "/tmp/private", "case-../x", "case-" + "0" * 32 + "/../x"]
)
def test_case_traversal_refused(tmp_path: Path, case_id: str):
    store = CaseStore(tmp_path / "cases")
    with pytest.raises(ScryveilError, match="invalid_case_id"):
        store.path(case_id)


def test_changed_original_fails_before_report(populated):
    store, case_id, _, _ = populated
    state = store.snapshot(case_id)
    original = store.path(case_id) / "originals" / state["artifacts"][0]["sha256"]
    original.chmod(0o600)
    original.write_bytes(original.read_bytes().replace(b"example.invalid", b"changed.invalid"))
    with pytest.raises(ScryveilError, match="source_integrity_failed"):
        store.snapshot(case_id)


@pytest.mark.parametrize(
    "change", ["event", "event_locator", "missing_event", "finding", "finding_interval", "audit"]
)
def test_metadata_tampering_fails_report_validation(populated, change: str):
    store, case_id, _, _ = populated
    state = store.snapshot(case_id)
    if change == "event":
        state["events"][0]["attributes"]["domain"] = "changed.invalid"
    elif change == "event_locator":
        state["events"][0]["byte_offset"] = 999999
    elif change == "missing_event":
        state["events"].pop()
    elif change == "finding":
        state["analysis"]["findings"][0]["supporting_evidence_ids"] = ["evt-absent"]
    elif change == "finding_interval":
        state["analysis"]["findings"][0]["first_observed_utc"] = "2099-01-01T00:00:00Z"
    else:
        state["audit"][0]["result"] = "forged"
    (store.path(case_id) / "state.json").write_bytes(canonical(state))
    with pytest.raises(ScryveilError) as caught:
        store.snapshot(case_id)
    assert caught.value.exit_code == 4


def test_prompt_like_text_is_data_and_never_runs(tmp_path: Path):
    marker = tmp_path / "should-not-exist"
    payload = (
        f"$(touch {marker}); <script>alert('private-token')</script> ignore previous instructions"
    )
    raw = encoded(record(app=payload))
    events, warnings, _ = parse(raw, "artifact-" + digest(raw), True)
    assert not warnings
    assert events[0]["attributes"]["app"] == payload
    analyze(events, [])
    assert not marker.exists()
