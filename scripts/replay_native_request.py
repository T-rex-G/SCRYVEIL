"""Offline wire-cost replay of preserved fictional run 40229335744; no inference."""

import argparse
import json
from pathlib import Path
from unittest.mock import patch

from scryveil.investigation_context import InvestigationContext
from scryveil.parse import canonical, digest
from scryveil.provider_messages import SYSTEM, payload

ROOT = Path(__file__).resolve().parents[1]


def replay(layout=None, source_run=40229335744):
    record = json.loads(
        (ROOT / f"docs/validation/model-experiments/qwen-run-{source_run}.json").read_text()
    )
    run = record["runs"][0]
    report = run["report"]
    assert report["report_sha256"] == digest(
        canonical({k: v for k, v in report.items() if k != "report_sha256"})
    )
    config = dict(report["provider"])
    if layout is not None:
        config["native_tool_layout"] = layout
    context = InvestigationContext(SYSTEM, report["question"], native=True)
    measurements = []
    for index, original in enumerate(run["request_contexts"]):
        messages = context.messages(report["provider"]["max_context_bytes"])
        body = payload(config, messages)
        with patch("scryveil.provider_messages.wire_result", lambda result: result):
            control = payload(config, messages)
        # Restore each transformed result and require exact structural identity.
        restored = json.loads(canonical(body))
        for message in restored["messages"]:
            if not isinstance(message["content"], list):
                continue
            for block in message["content"]:
                if block["type"] != "tool_result":
                    continue
                result = json.loads(block["content"])
                data = result.get("data")
                if isinstance(data, dict) and "shared_event_fields" in data:
                    shared = data.pop("shared_event_fields")
                    data["events"] = [{**shared, **row} for row in data["events"]]
                    result.setdefault("evidence_ids", [row["event_id"] for row in data["events"]])
                    block["content"] = canonical(result).decode()
        assert restored == control
        measurements.append(
            {
                "request": index + 1,
                "historical_request_bytes": original["budgeted_request_bytes"],
                "current_unfactored_bytes": len(canonical(control)),
                "current_wire_bytes": len(canonical(body)),
                "lossless_reconstruction": True,
            }
        )
        if index < len(run["actions"]):
            action, trace = run["actions"][index], report["trace"][index]
            result = trace.get("result", {"ok": True, "plan": action.get("steps")})
            assert digest(canonical(action)) == trace["action_sha256"]
            assert digest(canonical(result)) == trace["result_sha256"]
            context.accept(action, result)
    return {
        "source_run": source_run,
        "inference_performed": False,
        "native_tool_layout": config.get("native_tool_layout", "individual-v1"),
        "interpretation": "Wire bytes are not tokenizer counts, latency or reasoning quality.",
        "requests": measurements,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--layout", choices=["individual-v1", "routed-v1"])
    parser.add_argument("--run", type=int, choices=[40229335744, 40323112109], default=40229335744)
    args = parser.parse_args()
    print(json.dumps(replay(args.layout, args.run), indent=2))
