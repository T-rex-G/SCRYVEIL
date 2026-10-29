"""Evidence-free preflight is distinct from successful forensic investigation."""

import runpy
from pathlib import Path

import pytest
from test_provider_messages import config as native_config
from test_provider_messages import native_response
from test_provider_transport import PLAN, peer, response

from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest
from scryveil.providers import BrokerProvider, validate_config

CHECK = runpy.run_path(str(Path(__file__).parents[1] / "scripts/provider_protocol_check.py"))
QUERY = {"version": "scryveil.agent/1", "kind": "tool", "name": "coverage.inspect", "arguments": {}}


def execute(cfg):
    plan = CHECK["check_protocol"](cfg, preview=True)
    return CHECK["check_protocol"](cfg, approved_plan=plan["plan_sha256"])


@pytest.mark.parametrize("native", [False, True])
def test_two_turn_protocol_uses_isolated_broker_without_executing_tools(native):
    count = 0

    def reply(request):
        nonlocal count
        action = PLAN if count == 0 else QUERY
        count += 1
        return 200, canonical(native_response(action)) if native else response(action)

    with peer(reply) as (cfg, observed):
        result = execute(native_config(cfg) if native else cfg)
    assert len(observed) == 2
    assert result["status"] == "protocol_passed"
    assert result["tool_calls_executed"] == result["evidence_records"] == 0
    assert not result["reasoning_qualified"] and not result["billing_verified"]
    assert [r["status"] for r in result["requests"]] == ["valid_action", "valid_action"]
    assert "tool_result" in str(observed[1][2])
    assert result.pop("result_sha256") == digest(canonical(result))


@pytest.mark.parametrize("status", [401, 404, 429, 503])
def test_protocol_failure_stops_without_retry_or_fallback(status):
    with peer(lambda _: (status, b'{"error":{"message":"private provider text"}}')) as (
        cfg,
        observed,
    ):
        result = execute({**cfg, "retry_http_503_once": True})
    assert len(observed) == 1
    assert result["status"] == f"provider_http_{status}"
    assert not result["usage_complete"]
    assert "private provider text" not in canonical(result).decode()


@pytest.mark.parametrize(
    "action",
    [
        QUERY,
        {**PLAN, "steps": []},
        {**QUERY, "name": "shell.execute", "arguments": {"command": "private forbidden string"}},
    ],
)
def test_wrong_phase_or_malicious_action_stops_without_execution_or_text_export(action):
    with peer(lambda _: (200, response(action))) as (cfg, observed):
        result = execute(cfg)
    assert len(observed) == 1
    assert result["status"] in {
        "protocol_plan_required",
        "invalid_tool_arguments",
        "invalid_agent_action",
    }
    assert result["tool_calls_executed"] == 0
    assert "private forbidden string" not in canonical(result).decode()


def test_repeated_plan_after_acceptance_fails_continuation():
    with peer(lambda _: (200, response(PLAN))) as (cfg, observed):
        result = execute(cfg)
    assert len(observed) == 2
    assert result["status"] == "protocol_coverage_request_required"


def test_plan_approval_precedes_credentials_and_binds_effective_configuration(monkeypatch):
    cfg = validate_config(
        {
            "adapter": "chat-completions-json",
            "mode": "remote",
            "endpoint": "https://provider.invalid/v1/chat/completions",
            "model": "fictional",
        }
    )
    plan = CHECK["check_protocol"](cfg, preview=True)
    assert plan["maximum_requests"] == 2
    assert plan["provider"]["max_output_tokens"] == 512
    monkeypatch.setattr(
        BrokerProvider, "_credential", lambda _: pytest.fail("credential accessed before approval")
    )
    for change in (
        {},
        {"model": "different"},
        {"endpoint": "https://different.invalid/infer"},
        {"auth_scheme": "x-api-key"},
        {"reasoning_effort": "low"},
    ):
        with pytest.raises(ScryveilError, match="protocol_request_approval_required"):
            CHECK["check_protocol"](
                {**cfg, **change}, approved_plan=plan["plan_sha256"] if change else None
            )


def test_budget_prevents_second_request():
    with peer(lambda _: (200, response(PLAN))) as (cfg, observed):
        result = execute({**cfg, "max_requests": 1})
    assert len(observed) == 1
    assert result["status"] == "request_budget_exhausted"


def test_token_limit_blocks_first_request():
    with peer(lambda _: pytest.fail("budget must precede network")) as (cfg, observed):
        result = execute({**cfg, "max_total_tokens": 1024})
    assert not observed
    assert result["status"] == "token_budget_exhausted"


def test_cancellation_never_retries(monkeypatch):
    cfg = validate_config(
        {
            "adapter": "chat-completions-json",
            "mode": "local",
            "endpoint": "http://127.0.0.1:1/infer",
            "model": "fictional",
        }
    )

    def cancel(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(BrokerProvider, "next", cancel)
    result = execute(cfg)
    assert result["status"] == "cancelled" and len(result["requests"]) == 1
