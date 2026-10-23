"""Exercise the three newly recognized profiles using generated evidence only."""

import json
import tempfile
from pathlib import Path

from scryveil.investigation import investigate
from scryveil.investigation_tools import ReadOnlyTools, snapshot_case
from scryveil.parse import canonical, digest
from scryveil.providers import DEFAULT_CONFIG
from scryveil.store import CaseStore


def main():
    fixtures = Path(__file__).resolve().parents[1] / "fixtures/synthetic"
    with tempfile.TemporaryDirectory(prefix="scryveil-format-demo-") as tmp:
        store = CaseStore(Path(tmp) / "cases")
        cid = store.create("synthetic-format-qualification", "self")["case_id"]
        for name in (
            "diagnostic-v2-crash.ips",
            "diagnostic-v2-exception.ips",
            "diagnostic-text-resource.ips",
        ):
            store.import_file(cid, fixtures / name, True, "ips")
        snapshot = snapshot_case(store, cid)
        findings = snapshot["findings"]
        assert findings[0]["distinct_reported_incidents"] == 3
        assert len(findings[0]["contradictory_evidence_ids"]) == 2
        # Demonstrate a field-level text citation in addition to report pointers.
        tools = ReadOnlyTools(snapshot)
        event = next(
            e
            for e in tools.call("diagnostics.search", {})["data"]["events"]
            if e.get("resource_kind")
        )
        grounded = tools.ground_final(
            {
                "facts": [
                    {
                        "event_id": event["event_id"],
                        "field": "writes_caused",
                        "value": event["writes_caused"],
                    }
                ],
                "measurements": [],
                "hypotheses": [],
                "unanswered_questions": [],
            }
        )
        fact = grounded["observed_facts"][0]
        original = (fixtures / "diagnostic-text-resource.ips").read_bytes()
        assert original[fact["byte_offset"] : fact["byte_offset"] + fact["byte_length"]].startswith(
            b"Writes caused:"
        )
        config = {**DEFAULT_CONFIG, "max_total_tokens": 200000}
        first = investigate(store, cid, "Do all supplied reports establish fatal crashes?", config)
        second = investigate(store, cid, "Do all supplied reports establish fatal crashes?", config)
        assert first["status"] == "completed" and canonical(first) == canonical(second)
        assert snapshot_case(store, cid)["source_state_sha256"] == snapshot["source_state_sha256"]
        print(
            json.dumps(
                {
                    "synthetic": True,
                    "profiles": sorted(e["format_profile"] for e in snapshot["events"]),
                    "observations": 3,
                    "distinct_incidents": 3,
                    "contrary_records": 2,
                    "originals_and_state_unchanged": True,
                    "repeated_report_identical": True,
                    "text_field_citation_valid": True,
                    "fixture_sha256": digest(original),
                    "mock_steps": first["requests"],
                    "genuine_export_qualification": "OPEN",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
