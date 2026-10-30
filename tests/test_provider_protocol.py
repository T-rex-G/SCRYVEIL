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


def google_config():
    return validate_config(
        {
            "adapter": "chat-completions-json",
            "mode": "remote",
            "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "model": "gemini-3.8-flash",
            "api_key_env": "SCRYVEIL_TEST_CREDENTIAL",
            "reasoning_effort": "low",
        }
    )


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("status", [200, 302, 401, 503])
def test_independent_wire_client_uses_fixed_origin_and_never_exports_provider_text(
    monkeypatch, native, status
):
    import http.client
    import json

    captured = []
    closed = []

    class Connection:
        def __init__(self, host, **kwargs):
            assert host == "generativelanguage.googleapis.com"

        def request(self, method, path, body, headers):
            captured.append((method, path, json.loads(body), headers))

        def getresponse(self):
            return self

        def read(self, limit):
            if status != 200:
                pytest.fail("Do not read or export untrusted HTTP error bodies")
            action = {**PLAN, "steps": ["Untrusted response content must stay private"]}
            data = (
                {
                    "candidates": [
                        {
                            "finishReason": "STOP",
                            "content": {"parts": [{"text": json.dumps(action)}]},
                        }
                    ],
                    "usageMetadata": {
                        "promptTokenCount": 33,
                        "candidatesTokenCount": 12,
                        "other": "private",
                    },
                }
                if native
                else json.loads(response(action))
            )
            if not native:
                data["choices"][0]["finish_reason"] = "stop"
            return canonical(data)

        def close(self):
            closed.append(True)

    Connection.status = status
    monkeypatch.setattr(http.client, "HTTPSConnection", Connection)
    cfg = CHECK["protocol_plan"](google_config())["provider"]
    result = CHECK["wire_request"](cfg, int(native), "fictional-secret")
    assert result["status"] == ("valid_plan" if status == 200 else f"provider_http_{status}")
    assert closed and len(captured) == 1
    method, path, payload, headers = captured[0]
    assert method == "POST" and headers["Connection"] == "close"
    assert headers["x-goog-api-key" if native else "Authorization"] == (
        "fictional-secret" if native else "Bearer fictional-secret"
    )
    assert path == (
        "/v1beta/models/gemini-3.8-flash:generateContent"
        if native
        else "/v1beta/openai/chat/completions"
    )
    assert "private" not in str(result) and "fictional-secret" not in str(result)
    assert (
        payload["generationConfig"]["maxOutputTokens"] if native else payload["max_tokens"]
    ) == 512


def test_wire_control_is_approved_bounded_and_has_no_evidence_input(monkeypatch):
    import json
    import subprocess

    cfg = google_config()
    plan = CHECK["check_wire"](cfg, preview=True)
    assert plan["evidence_records"] == plan["tool_calls_executed"] == 0
    assert len(plan["wire_control"]) == 2
    with pytest.raises(ScryveilError, match="protocol_request_approval_required"):
        CHECK["check_wire"](cfg)
    calls = []
    monkeypatch.setenv("SCRYVEIL_TEST_CREDENTIAL", "fictional-secret")

    def child(command, **kwargs):
        req = json.loads(kwargs["input"])
        calls.append(req)
        assert command[-1] == "--wire-child" and command[1] == "-I"
        assert kwargs["env"] == {"LANG": "C.UTF-8"}
        assert kwargs["timeout"] == cfg["timeout_seconds"]
        if req["index"] == 0:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, b'{"status":"valid_plan","usage":{}}')

    monkeypatch.setattr(subprocess, "run", child)
    result = CHECK["check_wire"](cfg, approved_plan=plan["plan_sha256"])
    assert [r["status"] for r in result["requests"]] == ["provider_timeout", "valid_plan"]
    assert len(calls) == 2 and not result["reasoning_qualified"]
    assert "fictional-secret" not in str(result)
    with pytest.raises(ScryveilError, match="wire_control_requires_google_endpoint"):
        CHECK["check_wire"]({**cfg, "endpoint": "https://other.invalid/infer"}, preview=True)
    tiny = {**cfg, "max_total_tokens": 1024}
    result = CHECK["check_wire"](
        tiny, approved_plan=CHECK["check_wire"](tiny, preview=True)["plan_sha256"]
    )
    assert result["requests"][0]["status"] == "token_budget_exhausted" and len(calls) == 2
