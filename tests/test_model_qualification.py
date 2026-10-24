import runpy
from pathlib import Path

score = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))["score"]


def test_quality_scoring_does_not_count_missing_answers_as_accuracy():
    result = score({"status": "request_budget_exhausted", "trace": []}, [], {"events": []})
    assert result["field_fact_accuracy"] is None
    assert not result["completed"] and not result["multiple_queries"]
    assert result["hypothesis_semantic_accuracy"] is None


def test_quality_scoring_counts_untrusted_fabrication_without_crashing():
    actions = [
        {"kind": "tool", "name": []},
        {
            "kind": "final",
            "facts": [
                {"event_id": {}, "field": "nonfatal", "value": True},
                {"event_id": "event-one", "field": "nonfatal", "value": 1},
                {"event_id": "event-one", "field": "nonfatal", "value": True},
            ],
        },
    ]
    result = score(
        {"status": "request_budget_exhausted", "trace": []},
        actions,
        {"events": [{"event_id": "event-one", "nonfatal": True}]},
    )
    assert result["unsupported_field_fact_attempts"] == 2
    assert result["field_fact_accuracy"] == 1 / 3
    assert result["forbidden_tool_attempts"] == 1
    assert result["accepted_forbidden_tools"] == 0


def test_query_names_and_case_event_counts_are_not_event_retrieval():
    trace = [
        {"ok": True, "tool": "case.inspect", "result": {"data": {"events": 3}}},
        {"ok": True, "tool": "coverage.inspect", "result": {"data": {"selected_events": 3}}},
        {"ok": True, "tool": "diagnostics.search", "result": {"data": {"events": []}}},
    ]
    result = score({"status": "completed", "trace": trace}, [], {"events": []})
    assert result["multiple_queries"]
    assert result["successful_nonempty_event_queries"] == 0
    assert result["unique_events_retrieved"] == 0
    trace.append(
        {
            "ok": True,
            "tool": "timeline.query",
            "result": {"data": {"events": [{"event_id": "event-one"}]}},
        }
    )
    result = score({"status": "completed", "trace": trace}, [], {"events": []})
    assert result["successful_nonempty_event_queries"] == result["unique_events_retrieved"] == 1
