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
