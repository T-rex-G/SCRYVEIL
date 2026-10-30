"""Explicit, evidence-free two-turn adapter check; never forensic qualification.

Uses the production isolated broker and action validator, but executes no tools.
Stops at the first error. No retries, model discovery or provider fallback.
"""

import argparse
import http.client
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import scryveil
from scryveil.investigation_context import InvestigationContext
from scryveil.investigation_tools import TOOL_SCHEMAS, validate
from scryveil.investigation_worker import validate_action
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest, load_json
from scryveil.provider_messages import SYSTEM as NATIVE_SYSTEM
from scryveil.provider_messages import safe_error
from scryveil.providers import BrokerProvider, context_bytes, load_config, validate_config

ROOT = Path(__file__).resolve().parents[1]
QUESTION = (
    "This is an evidence-free protocol check. No case or evidence is available. "
    "First return a short plan. After it is accepted, request coverage.inspect with empty "
    "arguments. The request will be validated but not executed. Do not invent observations."
)
SYSTEM = (
    'Return one JSON action per turn. Plan: {"version":"scryveil.agent/1",'
    '"kind":"plan","steps":["Check coverage"]}. Next action: '
    '{"version":"scryveil.agent/1","kind":"tool","name":"coverage.inspect",'
    '"arguments":{}}. No prose outside JSON. No tools are executed in this protocol check.'
)


def wire_requests(config):
    """Fixed evidence-free control; no investigator or arbitrary destination access."""
    if (
        config["adapter"] != "chat-completions-json"
        or config["mode"] != "remote"
        or config["endpoint"]
        != "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        or not re.fullmatch(r"gemini-[a-z0-9.-]{1,80}", config["model"])
    ):
        raise ScryveilError("wire_control_requires_google_endpoint")
    messages = InvestigationContext(SYSTEM, QUESTION).messages(config["max_context_bytes"])
    return [
        {
            "protocol": "chat-completions-reference",
            "path": "/v1beta/openai/chat/completions",
            "payload": {
                "model": config["model"],
                "messages": messages,
                "max_tokens": config["max_output_tokens"],
                "stream": False,
                "response_format": {"type": "json_object"},
                **(
                    {"reasoning_effort": config["reasoning_effort"]}
                    if "reasoning_effort" in config
                    else {}
                ),
            },
        },
        {
            "protocol": "google-generate-content-reference",
            "path": f"/v1beta/models/{config['model']}:generateContent",
            "payload": {
                "system_instruction": {"parts": [{"text": messages[0]["content"]}]},
                "contents": [{"role": "user", "parts": [{"text": QUESTION}]}],
                "generationConfig": {
                    "maxOutputTokens": config["max_output_tokens"],
                    "responseMimeType": "application/json",
                    **(
                        {"thinkingConfig": {"thinkingLevel": config["reasoning_effort"]}}
                        if "reasoning_effort" in config
                        else {}
                    ),
                },
            },
        },
    ][: config["max_requests"]]


def wire_request(config, index, credential):
    """Independent stdlib HTTPS control, outside the investigation runtime.

    Receives only the fixed probe, never a case, caller prompt or tool result.
    Parent enforces a wall deadline. No redirects, proxies, retries or raw output.
    """
    request = wire_requests(config)[index]
    native = index == 1
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "close",
    }
    headers["x-goog-api-key" if native else "Authorization"] = (
        credential if native else "Bearer " + credential
    )
    connection = http.client.HTTPSConnection(
        "generativelanguage.googleapis.com", timeout=config["timeout_seconds"]
    )
    try:
        connection.request(
            "POST", request["path"], body=canonical(request["payload"]), headers=headers
        )
        response = connection.getresponse()
        if response.status != 200:
            return {"status": f"provider_http_{response.status}"}
        raw = response.read(1048577)
        if len(raw) > 1048576 or credential.encode() in raw:
            return {"status": "invalid_provider_response"}
        data = load_json(raw)
        if native:
            choice = data["candidates"][0]
            if choice.get("finishReason") != "STOP":
                return {"status": "provider_finish_unsupported"}
            content = "".join(
                p.get("text", "") for p in choice["content"]["parts"] if not p.get("thought")
            )
            usage = data.get("usageMetadata", {})
            usage_keys = ("promptTokenCount", "candidatesTokenCount", "thoughtsTokenCount")
        else:
            choice = data["choices"][0]
            if choice.get("finish_reason") != "stop":
                return {"status": "provider_finish_unsupported"}
            content = choice["message"]["content"]
            usage = data.get("usage", {})
            usage_keys = ("prompt_tokens", "completion_tokens")
        if usage is None:
            usage = {}
        if not isinstance(usage, dict):
            return {"status": "invalid_provider_response"}
        action = load_json(content.encode())
        validate_action(action)
        return {
            "status": "valid_plan" if action["kind"] == "plan" else "protocol_plan_required",
            "usage": {
                k: usage[k]
                for k in usage_keys
                if type(usage.get(k)) is int and 0 <= usage[k] <= 10**9
            },
        }
    except TimeoutError:
        return {"status": "provider_timeout"}
    except (
        OSError,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        ScryveilError,
        http.client.HTTPException,
    ):
        return {"status": "invalid_provider_response"}
    finally:
        connection.close()


def protocol_plan(config, *, wire_control=False):
    config = validate_config(config)
    if config["adapter"] == "mock":
        raise ScryveilError("unsupported_provider")
    # Cap rather than expand owner budgets; disclose every effective value.
    config = validate_config(
        {
            **config,
            "max_requests": min(2, config["max_requests"]),
            "max_output_tokens": min(512, config["max_output_tokens"]),
            "max_context_bytes": min(32768, config["max_context_bytes"]),
            "max_total_tokens": min(70000, config["max_total_tokens"]),
            "retry_http_503_once": False,
        }
    )
    files = sorted((ROOT / "src/scryveil").glob("*.py"))
    installed = Path(scryveil.__file__).resolve().parent
    if {p.name: digest(p.read_bytes()) for p in files} != {
        p.name: digest(p.read_bytes()) for p in installed.glob("*.py")
    }:
        raise ScryveilError("qualification_runtime_source_mismatch")
    files += [
        Path(__file__).resolve(),
        ROOT / ".github/workflows/provider-protocol-check.yml",
        ROOT / "configs/qualification-provider.json",
    ]
    plan = {
        "schema_version": "scryveil.provider-protocol-plan/1",
        "provider": config,
        "question": QUESTION,
        "system": NATIVE_SYSTEM if config["adapter"] == "messages-tools" else SYSTEM,
        "evidence_records": 0,
        "tool_calls_executed": 0,
        "maximum_requests": config["max_requests"],
        "code_sha256": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in files},
        "limitations": "Protocol availability only; no forensic reasoning, billing or model-identity qualification.",
    }
    if wire_control:
        plan["wire_control"] = wire_requests(config)
        plan["limitations"] += (
            " Independent HTTPS client control, not isolated investigator execution. Two distinct protocol probes, no retries."
        )
    plan["plan_sha256"] = digest(canonical(plan))
    return plan


def check_wire(config, *, approved_plan=None, preview=False):
    plan = protocol_plan(config, wire_control=True)
    if preview:
        return plan
    if approved_plan != plan["plan_sha256"]:
        raise ScryveilError("protocol_request_approval_required")
    config = plan["provider"]
    result = {
        "schema_version": "scryveil.provider-wire-control/1",
        "plan_sha256": plan["plan_sha256"],
        "requests": [],
        "evidence_records": 0,
        "tool_calls_executed": 0,
        "reasoning_qualified": False,
        "billing_verified": False,
    }
    reserved = 0
    for index, request in enumerate(plan["wire_control"]):
        size = len(canonical(request["payload"]))
        if (
            size > config["max_context_bytes"]
            or reserved + size + config["max_output_tokens"] > config["max_total_tokens"]
        ):
            result["requests"].append(
                {
                    "protocol": request["protocol"],
                    "status": "token_budget_exhausted",
                    "attempted": False,
                }
            )
            break
        reserved += size + config["max_output_tokens"]
        started = time.monotonic()
        record = {"protocol": request["protocol"], "attempted": False}
        try:
            credential = BrokerProvider(config)._credential()
            if not credential:
                raise ScryveilError("provider_credential_unavailable")
            record["attempted"] = True
            child = subprocess.run(
                [sys.executable, "-I", str(Path(__file__).resolve()), "--wire-child"],
                input=canonical({"config": config, "index": index, "credential": credential}),
                capture_output=True,
                check=True,
                timeout=config["timeout_seconds"],
                env={"LANG": "C.UTF-8"},
                close_fds=True,
            )
            record.update(load_json(child.stdout))
        except subprocess.TimeoutExpired:
            record["status"] = "provider_timeout"
        except ScryveilError:
            record["status"] = "provider_credential_unavailable"
        except subprocess.SubprocessError:
            record["status"] = "wire_control_failed"
        except KeyboardInterrupt:
            record["status"] = "cancelled"
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
        result["requests"].append(record)
        if record["status"] in {"cancelled", "provider_credential_unavailable"}:
            break
    result["reserved_token_estimate"] = reserved
    result["status"] = "wire_control_completed"
    result["result_sha256"] = digest(canonical(result))
    return result


def check_protocol(config, *, approved_plan=None, preview=False):
    plan = protocol_plan(config)
    if preview:
        return plan
    if approved_plan != plan["plan_sha256"]:
        raise ScryveilError("protocol_request_approval_required")
    config = plan["provider"]
    context = InvestigationContext(
        plan["system"], QUESTION, native=config["adapter"] == "messages-tools"
    )
    broker = BrokerProvider(config)
    result = {
        "schema_version": "scryveil.provider-protocol-result/1",
        "plan_sha256": plan["plan_sha256"],
        "status": "request_budget_exhausted",
        "requests": [],
        "evidence_records": 0,
        "tool_calls_executed": 0,
        "reasoning_qualified": False,
        "billing_verified": False,
    }
    reserved = 0
    for index in range(config["max_requests"]):
        started = time.monotonic()
        record = {"stage": "plan" if index == 0 else "tool_request", "attempted": False}
        result["requests"].append(record)
        try:
            messages = context.messages(config["max_context_bytes"])
            size = context_bytes(config, messages)
            if size > config["max_context_bytes"]:
                raise ScryveilError("context_budget_exhausted")
            reservation = size + config["max_output_tokens"]
            if reserved + reservation > config["max_total_tokens"]:
                raise ScryveilError("token_budget_exhausted")
            reserved += reservation
            record.update(
                context_sha256=digest(canonical(messages)), context_bytes=size, attempted=True
            )
            reply = broker.next(messages)
            record["usage"] = reply.usage
            validate_action(reply.action)
            if index == 0:
                if reply.action["kind"] != "plan":
                    raise ScryveilError("protocol_plan_required")
                context.accept(
                    reply.action, {"ok": True, "plan": reply.action["steps"]}, reply.continuation
                )
            else:
                if reply.action != {
                    "version": "scryveil.agent/1",
                    "kind": "tool",
                    "name": "coverage.inspect",
                    "arguments": {},
                }:
                    raise ScryveilError("protocol_coverage_request_required")
                validate(reply.action["arguments"], TOOL_SCHEMAS["coverage.inspect"])
                # Validate native continuation too, without executing the request.
                context.accept(
                    reply.action,
                    {"ok": False, "error": "probe_does_not_execute_tools"},
                    reply.continuation,
                )
                result["status"] = "protocol_passed"
            record["status"] = "valid_action"
        except ScryveilError as exc:
            # No raw provider exception/action/continuation is exported.
            allowed = {
                "invalid_agent_action",
                "invalid_tool_arguments",
                "context_budget_exhausted",
                "token_budget_exhausted",
                "provider_failed",
                "provider_timeout",
                "provider_credential_unavailable",
                "protocol_plan_required",
                "protocol_coverage_request_required",
            }
            result["status"] = (
                exc.code if safe_error(exc.code) or exc.code in allowed else "protocol_failed"
            )
            record["status"] = result["status"]
            break
        except KeyboardInterrupt:
            result["status"] = record["status"] = "cancelled"
            break
        finally:
            record["elapsed_seconds"] = round(time.monotonic() - started, 6)
    result["reserved_token_estimate"] = reserved
    result["usage_complete"] = all(
        r.get("usage") is not None for r in result["requests"] if r["attempted"]
    )
    result["result_sha256"] = digest(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--approve-plan-sha256")
    parser.add_argument("--google-wire-control", action="store_true")
    args = parser.parse_args()
    result = (check_wire if args.google_wire_control else check_protocol)(
        load_config(args.provider_config),
        approved_plan=args.approve_plan_sha256,
        preview=args.preview,
    )
    print("SCRYVEIL_PROTOCOL_RESULT=" + json.dumps(result, separators=(",", ":")), flush=True)
    if not args.preview and result["status"] not in {"protocol_passed", "wire_control_completed"}:
        raise SystemExit(2)


if __name__ == "__main__":
    if sys.argv[1:] == ["--wire-child"]:
        request = load_json(sys.stdin.buffer.read(65536))
        print(
            json.dumps(
                wire_request(
                    validate_config(request["config"]), request["index"], request["credential"]
                )
            )
        )
    else:
        main()
