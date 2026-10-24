"""Exercise the three newly recognized profiles using generated evidence only."""

import json
import tempfile
from pathlib import Path

from scryveil.investigation import investigate
from scryveil.investigation_tools import ReadOnlyTools, diagnostic_coverage, snapshot_case
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
        # A separate fictional v73 case demonstrates partial shared fields; its
        # version remains unqualified and is never promoted by this demo.
        partial = store.create("synthetic-unqualified-version", "self")["case_id"]
        store.import_file(partial, fixtures / "diagnostic-text-annotated.ips", True, "ips")
        selection = snapshot_case(store, partial)
        detail = diagnostic_coverage(selection)
        assert detail["schema_status"] == {"unqualified_version": 1}
        assert detail["coverage"]["real_export_qualification"] == "open"
        viewed = ReadOnlyTools(selection)
        row = viewed.call("diagnostics.search", {})["data"]["events"][0]
        cited = viewed.ground_final(
            {
                "facts": [
                    {
                        "event_id": row["event_id"],
                        "field": "sampled_duration_seconds",
                        "value": "67.25",
                    }
                ],
                "measurements": [],
                "hypotheses": [],
                "unanswered_questions": [],
            }
        )["observed_facts"][0]
        annotation_raw = (fixtures / "diagnostic-text-annotated.ips").read_bytes()
        assert annotation_raw[
            cited["byte_offset"] : cited["byte_offset"] + cited["byte_length"]
        ].startswith(b"Duration Sampled: 67.25s")
        annotation_report = investigate(
            store, partial, "Which observations are partial or unqualified?", config
        )
        assert annotation_report["status"] == "completed"
        assert (
            snapshot_case(store, partial)["source_state_sha256"] == selection["source_state_sha256"]
        )
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
                    "annotated_resource": {
                        "version_73": "unqualified",
                        "sampled_duration_seconds": row["sampled_duration_seconds"],
                        "exact_line_citation_checked": True,
                        "unknown_rejected_record_count": detail["rejected_record_count"],
                        "mock_status": annotation_report["status"],
                        "original_sha256": digest(annotation_raw),
                    },
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
