import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from scryveil.report import build_report
from scryveil.store import CaseStore

ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "schemas/case-and-report-v0.1.0.schema.json").read_text())


@pytest.mark.parametrize(
    "name",
    [
        "periodic.ndjson",
        "privacy_report.ndjson",
        "benign_sync.ndjson",
        "malformed.ndjson",
        "empty.ndjson",
    ],
)
def test_private_case_and_redacted_report_match_interoperable_contract(tmp_path, name):
    Draft202012Validator.check_schema(SCHEMA)
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    store.import_file(cid, ROOT / "fixtures/synthetic" / name, True)
    store.run(cid)
    Draft202012Validator(SCHEMA).validate(store.snapshot(cid))
    report_schema = dict(SCHEMA, **{"$ref": "#/$defs/Report"})
    Draft202012Validator(report_schema).validate(build_report(store, cid))
