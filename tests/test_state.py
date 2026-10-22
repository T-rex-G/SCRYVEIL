"""Corruption must fail closed before saved metadata reaches a report."""

import json
from pathlib import Path

import pytest

from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest
from scryveil.report import build_report
from scryveil.store import CaseStore

FIXTURES = Path(__file__).parents[1] / "fixtures/synthetic"


@pytest.fixture
def case(tmp_path):
    store = CaseStore(tmp_path / "cases")
    cid = store.create("synthetic", "self")["case_id"]
    store.import_file(cid, FIXTURES / "periodic.ndjson", True)
    store.run(cid)
    state = store.snapshot(cid)
    store.review(cid, state["analysis"]["findings"][0]["finding_id"], "inconclusive")
    return store, cid


@pytest.mark.parametrize(
    "path,value",
    [
        (("consent_scope",), "unknown"),
        (("audit",), []),
        (("artifacts", 0, "synthetic"), 1),
        (("artifacts", 0, "size"), True),
        (("artifacts", 0, "collection_mode"), "imported"),
        (("artifacts", 0, "collection_time"), "2026-01-01T00:00:00.000000Z"),
        (("artifacts", 0, "sensitivity"), "public"),
        (("artifacts", 0, "imported_at"), "2026-02-30T00:00:00.000000Z"),
        (("rule_run", "runtime"), "private-untrusted-text"),
        (("rule_run", "runtime_seconds"), True),
        (("rule_run", "runtime_seconds"), -1),
        (("rule_run", "input_artifact_ids"), []),
        (("rule_run", "config_sha256"), "0" * 64),
        (("rule_run", "extra"), "private-untrusted-text"),
        (("reviews", 0, "decision"), "device_clean"),
        (("reviews", 0, "decision"), "accepted_benign"),
        (("reviews", 0, "extra"), "private-untrusted-text"),
        (("reviews",), []),
        (("audit", 0, "actor"), "private-untrusted-text"),
        (("audit", 0, "result"), "private-untrusted-text"),
        (("audit", 1, "affected_ids"), []),
    ],
)
def test_metadata_corruption_rejected_even_with_rehashed_audit(case, path, value):
    store, cid = case
    filename = store.path(cid) / "state.json"
    state = json.loads(filename.read_bytes())
    target = state
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    previous = None
    for entry in state["audit"]:
        entry["previous_hash"] = previous
        entry["hash"] = digest(canonical({k: v for k, v in entry.items() if k != "hash"}))
        previous = entry["hash"]
    filename.write_bytes(canonical(state))
    with pytest.raises(ScryveilError, match="invalid_case_state"):
        build_report(store, cid)
    assert filename.read_bytes() == canonical(state)


def test_historical_reviews_survive_import_and_reanalysis(case):
    store, cid = case
    before = build_report(store, cid)
    store.import_file(cid, FIXTURES / "indicators.ndjson", True)
    store.run(cid)
    report = build_report(store, cid)
    assert report["analyst_decisions"] == before["analyst_decisions"]
    assert len(report["analysis"]["findings"]) == 2
    assert canonical(report) == canonical(build_report(store, cid))
