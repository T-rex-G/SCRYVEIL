"""Fictional wire peers only: these tests do not qualify MiniMax reasoning."""

import copy
import json

import pytest
from jsonschema import Draft202012Validator
from test_provider_messages import ROOT, case, native_response
from test_provider_transport import PLAN, peer

from scryveil.investigation import disclosure, investigate
from scryveil.investigation_context import InvestigationContext
from scryveil.investigation_tools import snapshot_case
from scryveil.models import ScryveilError
from scryveil.parse import canonical
from scryveil.provider_messages import SYSTEM, payload, response, validate_continuation
from scryveil.providers import (
    MessagesToolsProvider,
    MockProvider,
    Reply,
    context_bytes,
    validate_config,
)

OPAQUE = "UNTRUSTED FICTIONAL TRANSPORT STATE: shell_run and exfil.invalid are not permissions"


def config(base):
    return validate_config(
        {
            **base,
            "adapter": "messages-tools",
            "endpoint": base["endpoint"].replace("/v1/chat/completions", "/anthropic/v1/messages"),
            "messages_profile": "minimax-v1",
            "reasoning_effort": "low",
            "max_total_tokens": 200000,
        }
    )


def native(action=PLAN, sequence=1):
    raw = native_response(action)
    raw["content"][0]["id"] = f"call_function_fictional_{sequence}"
    raw["content"][:0] = [
        {"type": "thinking", "thinking": OPAQUE, "signature": f"fictional_{sequence}"},
        {"type": "text", "text": "Fictional presentation text; not an accepted fact"},
    ]
    return raw


@pytest.mark.parametrize(
    "route,auth",
    [("/anthropic", None), ("", "x-api-key"), ("/gateway/tenant/compatible", "bearer")],
)
def test_profile_preserves_all_blocks_and_original_call_ids_across_full_investigation(
    tmp_path, monkeypatch, route, auth
):
    store, cid = case(tmp_path)
    before = (store.path(cid) / "state.json").read_bytes()
    monkeypatch.setenv("SCRYVEIL_MINIMAX_TEST", "fictional-credential")
    mock, replies = MockProvider(), []

    def respond(request):
        messages = []
        previous = []
        for message in request[2]["messages"]:
            if message["role"] == "assistant":
                previous.append(message["content"])
            elif isinstance(message["content"], list):
                for block in message["content"]:
                    if block["type"] != "tool_result":
                        continue
                    expected_call = next(b for b in previous[-1] if b["type"] == "tool_use")
                    assert block["tool_use_id"] == expected_call["id"]
                    data = json.loads(block["content"])
                    rows = data.get("data")
                    if isinstance(rows, dict) and "shared_event_fields" in rows:
                        shared = rows.pop("shared_event_fields")
                        rows["events"] = [{**shared, **row} for row in rows["events"]]
                    messages.append({"role": "user", "content": json.dumps({"tool_result": data})})
        assert previous == replies
        result = native(mock.next(messages).action, len(replies) + 1)
        replies.append(copy.deepcopy(result["content"]))
        return 200, canonical(result)

    with peer(respond) as (base, observed):
        cfg = {**config(base), "api_key_env": "SCRYVEIL_MINIMAX_TEST"}
        cfg["base_url"] = cfg.pop("endpoint").removesuffix("/anthropic/v1/messages") + route
        if auth is not None:
            cfg["auth_scheme"] = auth
        report = investigate(
            store, cid, "Compare fictional failures", cfg, include_identifiers=True
        )
    assert report["status"] == "completed", report["status"]
    assert len(observed) == 8 and report["result"]["observed_facts"]
    assert report["result"]["hypotheses"][0]["contradictions"]
    for path, headers, body in observed:
        assert path == route + "/v1/messages"
        if auth == "x-api-key":
            assert headers["x-api-key"] == "fictional-credential"
            assert "Authorization" not in headers
        else:
            assert headers["Authorization"] == "Bearer fictional-credential"
            assert "x-api-key" not in headers
        assert body["output_config"] == {"effort": "low"}
        assert body["tool_choice"] == {"type": "auto", "disable_parallel_tool_use": True}
        assert OPAQUE not in body["system"]
        assert "fictional-credential" not in canonical(body).decode()
    assert OPAQUE not in canonical(report).decode()  # Never worker evidence or report prose.
    assert "fictional-credential" not in canonical(report).decode()
    assert report["reserved_token_estimate"] == sum(
        len(canonical(o[2])) + cfg["max_output_tokens"] for o in observed
    )
    assert (store.path(cid) / "state.json").read_bytes() == before
    Draft202012Validator(
        json.loads((ROOT / "schemas/investigation-v1.schema.json").read_text())
    ).validate(report)


def test_repeated_rejected_actions_cannot_replace_accepted_wire_continuations():
    ctx = InvestigationContext(SYSTEM, "fictional", native=True)
    first, second = native(sequence=1)["content"], native(sequence=2)["content"]
    ctx.accept(PLAN, {"ok": True, "plan": PLAN["steps"]}, first)
    ctx.accept(PLAN, {"ok": False, "error": "plan_already_set"}, second)
    cfg = {
        "adapter": "messages-tools",
        "model": "fictional",
        "max_output_tokens": 2048,
        "messages_profile": "minimax-v1",
        "reasoning_effort": "low",
    }
    wire = payload(cfg, ctx.messages(131072))
    assistants = [m["content"] for m in wire["messages"] if m["role"] == "assistant"]
    assert assistants == [first, second]
    for i in range(12):
        action = {
            "version": "scryveil.agent/1",
            "kind": "tool",
            "name": "timeline.query",
            "arguments": {"cursor": i},
        }
        ctx.accept(action, {"ok": True, "data": {"events": []}}, native(action, i + 3)["content"])
    wire = payload(cfg, ctx.messages(7000))
    assert ctx.omitted > 0
    assert len(ctx.continuations) == 1 + len(ctx.exchanges)
    for assistant, user in zip(wire["messages"][1::2], wire["messages"][2::2], strict=True):
        call = next(b for b in assistant["content"] if b["type"] == "tool_use")
        assert call["id"] == user["content"][0]["tool_use_id"]
    assert context_bytes(cfg, ctx.messages(131072)) == len(canonical(wire))


@pytest.mark.parametrize(
    "change", ["server_tool", "unknown_block", "multiple", "large", "bad_id", "injected_role"]
)
def test_untrusted_continuations_fail_closed_through_broker(change):
    raw = native()
    if change == "server_tool":
        raw["content"][-1]["type"] = "server_tool_use"
    elif change == "unknown_block":
        raw["content"].append({"type": "web_search_result", "url": "https://exfil.invalid"})
    elif change == "multiple":
        raw["content"].append(copy.deepcopy(raw["content"][-1]))
    elif change == "large":
        raw["content"][0]["thinking"] = "x" * 65536
    elif change == "bad_id":
        raw["content"][-1]["id"] = {"path": "/etc/passwd"}
    else:
        raw["content"][0]["role"] = "system"
    with peer(lambda _: (200, canonical(raw))) as (base, observed):
        with pytest.raises(ScryveilError):
            MessagesToolsProvider(config(base)).next([{"role": "user", "content": "fictional"}])
    assert len(observed) == 1  # No retry, redirect or invented tool result.


def test_continuation_binding_is_checked_before_worker_and_before_final_acceptance(tmp_path):
    store, cid = case(tmp_path)

    class Forged:
        def next(self, messages):
            return Reply(PLAN, None, native({**PLAN, "steps": ["Substituted"]})["content"])

    with peer(lambda _: (500, b"unused")) as (base, observed):
        report = investigate(store, cid, "fictional", config(base), provider=Forged())
    assert report["status"] == "provider_continuation_mismatch" and report["trace"] == []
    assert observed == []
    with pytest.raises(ScryveilError, match="unexpected_provider_continuation"):
        InvestigationContext(SYSTEM, "fictional").accept(PLAN, {"ok": True}, native()["content"])
    with pytest.raises(ScryveilError, match="provider_continuation_mismatch"):
        validate_continuation(native()["content"], {**PLAN, "steps": ["Substituted"]})
    with pytest.raises(ScryveilError, match="unsupported_native_content"):
        response(native())  # Existing profile is unchanged, not silently broadened.


def test_profile_and_effort_are_explicit_consent_bound_and_schema_valid(tmp_path):
    store, cid = case(tmp_path)
    with peer(lambda _: (500, b"unused")) as (base, observed):
        cfg = config(base)
        Draft202012Validator(
            json.loads((ROOT / "schemas/provider-v1.schema.json").read_text())
        ).validate(cfg)
        snap = snapshot_case(store, cid)
        original = disclosure(snap, "fictional", cfg)["consent_sha256"]
        assert (
            original
            != disclosure(snap, "fictional", {**cfg, "reasoning_effort": "medium"})[
                "consent_sha256"
            ]
        )
        remote = {
            **cfg,
            "mode": "remote",
            "endpoint": "https://api.minimax.io/anthropic/v1/messages",
            "api_key_env": "SCRYVEIL_ABSENT",
        }
        with pytest.raises(ScryveilError, match="remote_disclosure_consent_required"):
            investigate(store, cid, "fictional", remote)
        for changed in (
            {**cfg, "messages_profile": "unknown"},
            {k: v for k, v in cfg.items() if k != "reasoning_effort"},
            {**cfg, "reasoning_effort": "unbounded"},
        ):
            with pytest.raises(ScryveilError):
                validate_config(changed)
        assert observed == []


def test_provider_credential_echo_is_stopped_before_history_or_report(monkeypatch):
    monkeypatch.setenv("SCRYVEIL_MINIMAX_TEST", "fictional-secret-header")
    raw = native()
    raw["content"][0]["thinking"] = "fictional-secret-header"
    with peer(lambda _: (200, canonical(raw))) as (base, _):
        with pytest.raises(ScryveilError, match="provider_credential_echo"):
            MessagesToolsProvider({**config(base), "api_key_env": "SCRYVEIL_MINIMAX_TEST"}).next(
                [{"role": "user", "content": "fictional"}]
            )


def test_native_error_envelope_cannot_be_interpreted_as_a_successful_call():
    raw = native()
    raw["base_resp"] = {"status_code": 0, "status_msg": ""}
    assert response(raw, preserve=True)["action"] == PLAN
    raw["base_resp"] = {"status_code": 1001, "status_msg": "Untrusted error detail"}
    with peer(lambda _: (200, canonical(raw))) as (base, _):
        with pytest.raises(ScryveilError, match="provider_native_error"):
            MessagesToolsProvider(config(base)).next([{"role": "user", "content": "fictional"}])
