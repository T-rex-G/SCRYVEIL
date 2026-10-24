import json
from pathlib import Path

from jsonschema import Draft202012Validator

from scryveil.cli import main
from scryveil.investigation_tools import ReadOnlyTools, diagnostic_coverage, snapshot_case
from scryveil.parse import canonical
from scryveil.store import CaseStore

ROOT = Path(__file__).parents[1]


def test_coverage_distinguishes_selected_missing_partial_unqualified_and_rejected(tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    for name in (
        "diagnostic-v2-crash.ips",
        "diagnostic-text-annotated.ips",
        "diagnostic-jetsam.ips",
    ):
        store.import_file(cid, ROOT / "fixtures/synthetic" / name, True, "ips")
    snap = snapshot_case(store, cid)
    detailed = diagnostic_coverage(snap)
    schema = json.loads((ROOT / "schemas/diagnostic-coverage-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(detailed)
    assert detailed["schema_status"]["unqualified_version"] == 1
    assert detailed["profiles"]["ips.text.145.v73"] == 1
    assert detailed["interpretation_status"]["partial"] == 2
    assert detailed["not_observed_in_snapshot"] == ["diagnostic.exception"]
    assert any(w["code"] == "ips_schema_version_unqualified" for w in detailed["source_warnings"])
    assert detailed["unimported_or_rejected_files"] == "unknown_not_recorded"
    assert detailed["rejected_record_count"] is None
    assert "com.example" not in canonical(detailed).decode()
    restricted = diagnostic_coverage(snapshot_case(store, cid, max_events=1))
    assert restricted["coverage"]["omitted_events"] == len(snap["events"]) - 1
    assert len(restricted["artifacts_without_selected_events"]) == 2
    assert restricted["coverage"]["same_device_identity"] == "unverified"
    # The established default coverage tool and snapshot contract are unchanged.
    assert ReadOnlyTools(snap).call("coverage.inspect", {})["data"] == snap["coverage"]


def test_coverage_cli_is_offline_read_only_and_explicit_for_empty_case(tmp_path, capsys):
    root = tmp_path / "cases"
    store = CaseStore(root)
    cid = store.create("synthetic", "self")["case_id"]
    before = (store.path(cid) / "state.json").read_bytes()
    assert main(["--root", str(root), "diagnostics", "coverage", "--case", cid]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["imported_artifacts"] == 0 and len(result["not_observed_in_snapshot"]) == 4
    assert result["coverage"]["real_export_qualification"] == "open"
    assert result["rejected_record_count"] is None
    assert (store.path(cid) / "state.json").read_bytes() == before
