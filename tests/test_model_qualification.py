import runpy
from pathlib import Path

import pytest

from scryveil.models import ScryveilError
from scryveil.providers import Reply

score = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))["score"]
RecordedProvider = runpy.run_path(
    str(Path(__file__).parents[1] / "scripts/model_qualification.py")
)["RecordedProvider"]


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


def test_request_timing_records_failure_and_cancellation_without_claiming_server_stop():
    class Failed:
        def next(self, messages):
            raise ScryveilError("provider_timeout")

    provider = RecordedProvider(Failed())
    with pytest.raises(ScryveilError, match="provider_timeout"):
        provider.next([{"role": "user", "content": "fictional"}])
    assert provider.contexts[0]["outcome"] == "provider_timeout"
    assert provider.contexts[0]["elapsed_seconds"] >= 0
    assert provider.contexts[0]["server_cancellation_confirmed"] is False
    assert provider.actions == []

    class Cancelled:
        def next(self, messages):
            raise KeyboardInterrupt

    provider = RecordedProvider(Cancelled())
    with pytest.raises(KeyboardInterrupt):
        provider.next([])
    assert provider.contexts[0]["outcome"] == "cancelled"

    class Completed:
        def next(self, messages):
            return Reply({"kind": "plan"}, {"input_tokens": 20, "output_tokens": 10})

    provider = RecordedProvider(Completed())
    provider.next([])
    assert provider.contexts[0]["usage"] == {"input_tokens": 20, "output_tokens": 10}


def test_numeric_server_telemetry_does_not_retain_untrusted_log_text():
    parse = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_timing.py"))[
        "parse_server_line"
    ]
    assert parse("private prompt content or provider instruction", 1) is None
    metric = parse("slot print_timings: id 0 | task 4 | prompt eval time = 123.4 ms / 25 tokens", 2)
    assert metric == {
        "slot": 0,
        "task": 4,
        "kind": "prompt_eval",
        "milliseconds": 123.4,
        "tokens": 25,
        "observed_elapsed_seconds": 2,
    }
    assert (
        parse("slot release: id 0 | task 4 | stop processing: n_tokens = 33, truncated = 0", 3)[
            "kind"
        ]
        == "slot_release"
    )
