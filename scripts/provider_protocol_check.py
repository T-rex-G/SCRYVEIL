"""Explicit, evidence-free two-turn adapter check; never forensic qualification.

Uses the production isolated broker and action validator, but executes no tools.
Stops at the first error. No retries, model discovery or provider fallback.
"""

import argparse
import json
import time
from pathlib import Path

import scryveil
from scryveil.investigation_context import InvestigationContext
from scryveil.investigation_tools import TOOL_SCHEMAS, validate
from scryveil.investigation_worker import validate_action
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest
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


def protocol_plan(config):
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
    plan["plan_sha256"] = digest(canonical(plan))
    return plan


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
    args = parser.parse_args()
    result = check_protocol(
        load_config(args.provider_config),
        approved_plan=args.approve_plan_sha256,
        preview=args.preview,
    )
    print("SCRYVEIL_PROTOCOL_RESULT=" + json.dumps(result, separators=(",", ":")), flush=True)
    if not args.preview and result["status"] != "protocol_passed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
