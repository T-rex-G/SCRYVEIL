import copy
import json
from pathlib import Path

from scryveil.diagnostic_intelligence import intelligence, narrative, signature
from scryveil.diagnostics import parse_diagnostic
from scryveil.parse import canonical, digest

ROOT = Path(__file__).parents[1]


def events():
    raw = (ROOT / "fixtures/synthetic/diagnostic-v2-crash.ips").read_bytes()
    meta, body = map(json.loads, raw.split(b"\n", 1))
    result = []
    for i in range(3):
        meta["incident_id"] = body["incident"] = f"fictional-{i}"
        body["isNonFatal"] = i == 2
        data = canonical(meta) + canonical(body)
        result += parse_diagnostic(data, "artifact-" + digest(data), True)[0]
    return result


def matching(rows, rule):
    return [f for f in intelligence(rows) if f["rule"] == "diagnostics." + rule + "/1"]


def test_signature_compares_declared_build_exception_and_ordered_symbols_not_addresses():
    rows = events()
    measured = matching(rows, "signature_recurrence")[0]
    assert measured["statistics"]["distinct_reported_incidents"] == 3
    assert measured["contradictory_evidence_ids"] == [rows[2]["event_id"]]
    moved = copy.deepcopy(rows[0])
    moved["attributes"]["frames"][0]["image_offset"] += 1024
    assert signature(moved) == signature(rows[0])
    for key, value in (
        ("os_build", "DIFFERENT"),
        ("termination_code", 99),
        ("exception_type", "EXC_CRASH"),
    ):
        altered = copy.deepcopy(rows[:2])
        altered[1]["attributes"][key] = value
        assert not matching(altered, "signature_recurrence")
    rows[1]["attributes"]["frames"][0]["symbol"] = "different_symbol"
    assert not matching(rows[:2], "signature_recurrence")


def test_duplicate_missing_and_conflicting_incidents_are_not_independent_incidents():
    rows = events()[:2]
    rows[1]["attributes"]["incident"] = rows[0]["attributes"]["incident"]
    assert not matching(rows, "signature_recurrence")
    rows[1]["event_time"] = "2026-02-03T12:00:00.000000Z"
    assert len(matching(rows, "incident_conflict")) == 1
    rows[1]["attributes"]["incident"] = None
    assert not matching(rows, "signature_recurrence")


def test_memory_reason_and_temporal_neighbors_do_not_turn_all_processes_into_kills():
    rows = events()
    target = copy.deepcopy(rows[0])
    target["event_id"] = "evt-" + "1" * 64
    target["event_type"] = "diagnostic.jetsam"
    target["attributes"].update(reason="vm-pageshortage", footprint_bytes=16384 * 24)
    listed = copy.deepcopy(target)
    listed["event_id"] = "evt-" + "2" * 64
    listed["attributes"]["reason"] = None
    measured = matching(rows + [target, listed], "jetsam_reason")[0]
    assert measured["statistics"]["reasoned_entries"] == 1
    assert measured["statistics"]["listed_without_reason"] == 1
    assert measured["statistics"]["peak_observed_footprint_bytes"] == 393216
    nearby = matching(rows + [target, listed], "resource_temporal_neighbors")[0]
    assert nearby["statistics"]["observation_pairs"] == 3
    assert listed["event_id"] not in nearby["supporting_evidence_ids"]
    target["attributes"]["os_build"] = "DIFFERENT"
    assert not matching(rows + [target], "resource_temporal_neighbors")
    target["attributes"]["os_build"] = rows[0]["attributes"]["os_build"]
    target["event_time"] = None
    assert not matching(rows + [target], "resource_temporal_neighbors")


def test_bounded_reference_counts_and_unknown_symbols_are_explicit():
    rows = []
    original = events()[0]
    for i in range(100):
        e = copy.deepcopy(original)
        e["event_id"] = "evt-" + f"{i:064x}"
        e["artifact_id"] = "artifact-" + f"{i:064x}"
        e["attributes"]["incident"] = f"fictional-{i}"
        e["attributes"]["frames"][0]["symbol"] = None
        rows.append(e)
    finding = matching(rows, "signature_recurrence")[0]
    assert len(finding["supporting_evidence_ids"]) == 8
    assert finding["reference_counts"]["supporting_omitted"] == 92
    assert finding["statistics"]["missing_symbol_slots"] == 1


def test_report_escapes_evidence_text():
    assert "<script>" not in narrative(
        {
            "coverage": {"selected_events": 1, "total_events": 1, "omitted_events": 0},
            "artifacts": [],
            "events": [],
            "findings": [
                {
                    "rule": "<script>",
                    "observation": "[link](https://attacker.invalid)",
                    "alternatives": [],
                    "limitations": [],
                    "supporting_evidence_ids": [],
                    "contradictory_evidence_ids": [],
                }
            ],
        }
    )


def test_offline_cli_delivery_matches_independent_archive_observations(tmp_path, monkeypatch):
    import runpy
    import zipfile
    from collections import Counter
    from datetime import datetime

    demo = runpy.run_path(str(ROOT / "scripts/collection_demo.py"))

    def forbidden(*args, **kwargs):
        raise AssertionError("offline delivery invoked AI")

    monkeypatch.setitem(demo["run"].__globals__, "investigate", forbidden)
    result = demo["run"](tmp_path, offline_only=True)
    assert result["mock_requests"] == 0 and result["offline_only"]
    assert not (tmp_path / "mock-investigation.json").exists()
    snapshot = json.loads((tmp_path / "diagnostics.json").read_bytes())
    artifacts = {a["artifact_id"]: a for a in snapshot["artifacts"]}
    inventory = json.loads((tmp_path / "inventory.json").read_bytes())
    originals = tmp_path / "cases" / result["case_id"] / "originals"
    # Independent ZIP reader and raw source fields; no SCRYVEIL parser/detector oracle.
    with zipfile.ZipFile(tmp_path / "fictional-collection.zip") as archive:
        raw_crashes = {}
        for member in inventory["archives"][0]["members"]:
            raw = archive.read(member["path"])
            assert digest(raw) == member["sha256"]
            assert (originals / member["sha256"]).read_bytes() == raw
            if member["path"].startswith("diagnostics/crash-"):
                raw_crashes[member["artifact_id"]] = json.loads(raw.split(b"\n", 1)[1])
    assert len(raw_crashes) == 240
    symbol_counts = Counter(r["threads"][0]["frames"][0]["symbol"] for r in raw_crashes.values())
    assert sorted(symbol_counts.values()) == [80, 80, 80]
    assert sum(r["isNonFatal"] is True for r in raw_crashes.values()) == 24
    for event in snapshot["events"]:
        if event["artifact_id"] in raw_crashes:
            raw = raw_crashes[event["artifact_id"]]
            assert datetime.fromisoformat(event["event_time"]) == datetime.fromisoformat(
                raw["captureTime"]
            )
            assert event["exception_type"] == raw["exception"]["type"]
            assert event["nonfatal"] is raw["isNonFatal"]
    rendered = (tmp_path / "diagnostics.md").read_text()
    assert "6260 of 6260" in rendered and "3 recurring" in rendered
    assert "24 observations explicitly declare nonfatal" in rendered
    assert "20 declare no action" in rendered
    assert "precedes the first timed crash" in rendered
    assert "JSON pointer /processes/0" in rendered
    for event in [e for e in snapshot["events"] if e["event_type"] == "diagnostic.resource"][:3]:
        location = event["field_locations"]["writes_caused"]
        raw = (originals / artifacts[event["artifact_id"]]["sha256"]).read_bytes()
        assert (
            b"12.50 MB"
            in raw[location["byte_offset"] : location["byte_offset"] + location["byte_length"]]
        )
        assert (
            f"bytes {location['byte_offset']}–{location['byte_offset'] + location['byte_length']}"
            in rendered
        )
    assert "first\\_five\\_source\\_symbols" in rendered
    assert result["originals_and_state_unchanged"]


def test_signature_contrary_evidence_cannot_cross_declared_build_or_bundle():
    rows = events()
    for field, value in [
        ("os_build", "OTHER"),
        ("os_version", "Other OS"),
        ("bundle_id", "com.example.other"),
    ]:
        changed = copy.deepcopy(rows)
        changed[2]["attributes"][field] = value
        finding = matching(changed, "signature_recurrence")[0]
        assert finding["statistics"]["distinct_reported_incidents"] == 2
        assert finding["contradictory_evidence_ids"] == []
        # Broad per-name coverage still discloses the observation; it is not
        # silently lost merely because it cannot contradict this identity group.
        conditions = matching(changed, "report_conditions")[0]
        assert changed[2]["event_id"] in conditions["contradictory_evidence_ids"]
    assert matching(rows, "signature_recurrence")[0]["contradictory_evidence_ids"] == [
        rows[2]["event_id"]
    ]


def test_resource_interval_correlation_uses_parsed_end_time_and_exact_boundaries():
    rows = events()[:1]
    raw = (ROOT / "fixtures/synthetic/diagnostic-text-resource.ips").read_bytes()
    # Fictional interval spans the crash, but begins thirty minutes earlier.
    raw = raw.replace(b"14:34:00.000", b"14:00:00.000").replace(b"14:35:00.000", b"15:00:00.000")
    resource = parse_diagnostic(raw, "artifact-" + digest(raw), True)[0][0]
    before = canonical([rows[0], resource])
    finding = matching(rows + [resource], "resource_temporal_neighbors")[0]
    assert finding["statistics"]["observation_pairs"] == 1
    assert finding["statistics"]["pairs_inside_reported_intervals"] == 1
    assert finding["statistics"]["related_resources_with_end_time"] == 1
    assert set(finding["supporting_evidence_ids"]) == {rows[0]["event_id"], resource["event_id"]}
    assert resource["event_id"] in finding["contradictory_evidence_ids"]  # no action
    location = resource["attributes"]["field_locations"]["event_end_time"]
    assert (
        b"15:00:00.000"
        in raw[location["byte_offset"] : location["byte_offset"] + location["byte_length"]]
    )
    assert canonical([rows[0], resource]) == before
    for stamp, expected in (
        ("2026-02-03T11:25:00.000000Z", 1),
        ("2026-02-03T11:24:59.999999Z", 0),
        ("2026-02-03T12:35:00.000000Z", 1),
        ("2026-02-03T12:35:00.000001Z", 0),
    ):
        crash = copy.deepcopy(rows[0])
        crash["event_time"] = stamp
        assert len(matching([crash, resource], "resource_temporal_neighbors")) == expected
    resource["attributes"]["event_end_time"] = None
    assert not matching(rows + [resource], "resource_temporal_neighbors")
    resource["attributes"]["event_end_time"] = "2026-02-03T11:00:00.000000Z"
    assert not matching(rows + [resource], "resource_temporal_neighbors")


def test_interval_index_matches_brute_force_with_overlapping_nested_and_point_records():
    from datetime import UTC, datetime, timedelta
    from random import Random

    rng = Random(917)
    epoch = datetime(2026, 2, 3, 12, tzinfo=UTC)
    rows = []
    template = events()[0]
    for i in range(180):
        event = copy.deepcopy(template)
        event["event_id"] = "evt-" + f"{i:064x}"
        event["event_time"] = (epoch + timedelta(seconds=rng.randrange(-800, 800))).isoformat()
        if i >= 80:
            event["event_type"] = "diagnostic.resource"
            event["attributes"]["event_end_time"] = (
                (
                    datetime.fromisoformat(event["event_time"])
                    + timedelta(seconds=rng.randrange(-100, 1500))
                ).isoformat()
                if i % 3
                else None
            )
        rows.append(event)
    expected_pairs = []
    inside = 0
    reversed_count = 0
    for resource in rows[80:]:
        start = datetime.fromisoformat(resource["event_time"])
        end = datetime.fromisoformat(
            resource["attributes"].get("event_end_time") or resource["event_time"]
        )
        if end < start:
            reversed_count += 1
            continue
        for crash in rows[:80]:
            when = datetime.fromisoformat(crash["event_time"])
            if start - timedelta(seconds=300) <= when <= end + timedelta(seconds=300):
                expected_pairs.append((crash["event_id"], resource["event_id"]))
            if resource["attributes"].get("event_end_time") and start <= when <= end:
                inside += 1
    finding = matching(rows, "resource_temporal_neighbors")[0]
    assert finding["statistics"]["observation_pairs"] == len(expected_pairs)
    assert finding["statistics"]["pairs_inside_reported_intervals"] == inside
    assert finding["statistics"]["reversed_resource_intervals_excluded"] == reversed_count
    assert finding["reference_counts"]["supporting"] == len(
        {eid for pair in expected_pairs for eid in pair}
    )
