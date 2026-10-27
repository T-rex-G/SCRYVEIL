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
    assert (
        parse(
            "slot print_timings_pp: id  0 | task 4 | prompt processing, n_tokens =    512, progress = 0.25, t =   6.00 s / 85.33 tokens per second",
            4,
        )["tokens"]
        == 512
    )
    assert (
        parse(
            "slot print_timings_tg: id  0 | task 4 | n_gen =    100, tg =  10.00 t/s, tg_3s =   9.50 t/s",
            5,
        )["kind"]
        == "generation_progress"
    )


def test_large_actual_model_scenario_is_skipped_when_baseline_floor_is_missing():
    evaluate = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))[
        "evaluate"
    ]
    result = evaluate(mock=True, scenarios=["collection"], require_recurrence=True)
    assert result["runs"] == []
    assert result["skipped_scenarios"] == [
        {"scenario": "collection", "reason": "recurrence_fact_coverage_contradiction_floor_not_met"}
    ]


def test_remote_benchmark_preview_binds_scope_without_credentials_or_provider_calls(monkeypatch):
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))
    evaluate = module["evaluate"]
    cfg = {
        "adapter": "messages-tools",
        "mode": "remote",
        "endpoint": "https://api.minimax.io/anthropic/v1/messages",
        "model": "MiniMax-M3.1-Flash",
        "messages_profile": "minimax-v1",
        "reasoning_effort": "low",
        "api_key_env": "SCRYVEIL_ABSENT_QUALIFICATION_KEY",
    }
    calls = []

    def forbidden(config):
        calls.append(config)
        raise AssertionError("A preview or unapproved run must not construct a provider")

    monkeypatch.setitem(evaluate.__globals__, "MessagesToolsProvider", forbidden)
    kwargs = {"provider_config": cfg, "scenarios": ["recurrence"]}
    first = evaluate(**kwargs, preview=True)
    assert evaluate(**kwargs, preview=True) == first  # New case IDs/clocks do not change the plan.
    assert first["scenarios"][0]["quantities"]["events"] == 3
    assert first["maximum_requests"] == 12
    with pytest.raises(ScryveilError, match="synthetic_disclosure_plan_approval_required"):
        evaluate(**kwargs)
    with pytest.raises(ScryveilError, match="synthetic_disclosure_plan_approval_required"):
        evaluate(**kwargs, approved_plan="0" * 64)
    changed = {**cfg, "reasoning_effort": "medium"}
    assert (
        evaluate(provider_config=changed, scenarios=["recurrence"], preview=True)["plan_sha256"]
        != first["plan_sha256"]
    )
    with pytest.raises(ScryveilError, match="synthetic_disclosure_plan_approval_required"):
        evaluate(
            provider_config=changed, scenarios=["recurrence"], approved_plan=first["plan_sha256"]
        )
    assert calls == []


def test_remote_benchmark_approval_is_translated_to_exact_fresh_case_consent(monkeypatch, capsys):
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))
    evaluate = module["evaluate"]
    from scryveil.providers import MockProvider

    cfg = {
        "adapter": "messages-tools",
        "mode": "remote",
        "endpoint": "https://model.example.invalid/v1/messages",
        "model": "fictional-remote-peer",
        "max_total_tokens": 200000,
    }
    # Mock transport ONLY for this unit test; the real consent and worker still execute.
    monkeypatch.setitem(
        evaluate.__globals__, "MessagesToolsProvider", lambda config: MockProvider()
    )
    plan = evaluate(provider_config=cfg, scenarios=["recurrence"], preview=True)
    result = evaluate(
        provider_config=cfg, scenarios=["recurrence"], approved_plan=plan["plan_sha256"]
    )
    run = result["runs"][0]
    assert run["report"]["status"] == "completed"
    assert run["disclosure"]["consent_sha256"] == run["report"]["disclosure_sha256"]
    assert run["originals_and_state_unchanged"]
    assert result["model"] == "fictional-remote-peer" and result["expected_model_sha256"] is None
    assert "SCRYVEIL_MODEL_DISCLOSURE=" in capsys.readouterr().out


def test_actual_benchmark_never_silently_selects_qwen_or_labels_mock_as_model():
    evaluate = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))[
        "evaluate"
    ]
    with pytest.raises(ScryveilError, match="qualification_provider_config_required"):
        evaluate()
    with pytest.raises(ScryveilError, match="mock_requires_explicit_mock_flag"):
        evaluate(provider_config={})
    with pytest.raises(ScryveilError, match="mock_provider_config_conflict"):
        evaluate(mock=True, provider_config={})


def test_failed_remote_baseline_stops_other_scenarios_without_more_provider_requests(
    monkeypatch, capsys
):
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))
    evaluate = module["evaluate"]
    cfg = {
        "adapter": "messages-tools",
        "mode": "remote",
        "endpoint": "https://model.example.invalid/v1/messages",
        "model": "fictional-failure-peer",
    }
    calls = []

    class Failed:
        def next(self, messages):
            calls.append(messages)
            raise ScryveilError("provider_timeout")

    monkeypatch.setitem(evaluate.__globals__, "MessagesToolsProvider", lambda config: Failed())
    kwargs = {
        "provider_config": cfg,
        "scenarios": ["recurrence", "mixed_formats"],
        "require_recurrence": True,
    }
    plan = evaluate(**kwargs, preview=True)
    result = evaluate(**kwargs, approved_plan=plan["plan_sha256"])
    assert len(calls) == 1 and len(result["runs"]) == 1
    assert not result["runs"][0]["automatic_floor"]["passed"]
    assert result["skipped_scenarios"] == [
        {"scenario": "mixed_formats", "reason": "remote_recurrence_floor_failed_no_further_spend"}
    ]
    capsys.readouterr()


def test_injection_exposure_is_required_and_floor_is_not_semantic_accuracy():
    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))
    metrics = {
        "completed": True,
        "multiple_queries": True,
        "coverage_queried": True,
        "unanswered_questions": 1,
        "forbidden_tool_attempts": 0,
        "accepted_forbidden_tools": 0,
        "unique_events_retrieved": 3,
        "accepted_field_facts": 3,
        "field_fact_accuracy": 1,
        "deterministic_findings_queried": True,
        "expected_contrary_records": 1,
        "contrary_records_cited_in_hypotheses": 1,
    }
    record = {
        "scenario": "injection",
        "report": {},
        "metrics": metrics,
        "originals_and_state_unchanged": True,
        "attack_text_delivered_to_provider": False,
    }
    assert not module["automatic_floor"](record)["passed"]
    record["attack_text_delivered_to_provider"] = True
    result = module["automatic_floor"](record)
    assert result["passed"] and "hypothesis revision" in result["unmeasured"]


def test_benchmark_rejects_an_installed_runtime_different_from_recorded_source(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    module = runpy.run_path(str(Path(__file__).parents[1] / "scripts/model_qualification.py"))
    evaluate = module["evaluate"]
    different = tmp_path / "__init__.py"
    different.write_text("# fictional different installed distribution\n")
    monkeypatch.setitem(evaluate.__globals__, "scryveil", SimpleNamespace(__file__=str(different)))
    with pytest.raises(ScryveilError, match="qualification_runtime_source_mismatch"):
        evaluate(mock=True, scenarios=["recurrence"], preview=True)
