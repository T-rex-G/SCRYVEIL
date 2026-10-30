"""Opt-in MiniMax Flash benchmark: fixed fictional inputs, never owner case paths.

Preview works offline without credentials. An exact approved plan digest is
required for remote inference. Set the dedicated secret outside this program.
"""

import argparse
import json

from model_qualification import evaluate

CONFIG = {
    "adapter": "messages-tools",
    "mode": "remote",
    "endpoint": "https://api.minimax.io/anthropic/v1/messages",
    "model": "MiniMax-M3.1-Flash",
    "messages_profile": "minimax-v1",
    "reasoning_effort": "medium",
    "api_key_env": "SCRYVEIL_MINIMAX_API_KEY",
    "max_requests": 12,
    "timeout_seconds": 60,
    "max_context_bytes": 131072,
    "max_output_tokens": 4096,
    "max_total_tokens": 200000,
    "input_usd_per_million": 0.15,
    "output_usd_per_million": 0.60,
}
SCENARIOS = [
    "recurrence",
    "mixed_formats",
    "collection",
    "injection",
    "tool_failure",
    "missing_evidence",
    "request_limit",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--approve-plan-sha256")
    args = parser.parse_args()
    result = evaluate(
        scenarios=SCENARIOS,
        provider_config=CONFIG,
        require_recurrence=True,
        approved_plan=args.approve_plan_sha256,
        preview=args.preview,
    )
    print("SCRYVEIL_MODEL_RESULT=" + json.dumps(result, separators=(",", ":")), flush=True)
    if not args.preview:
        passed = not result["skipped_scenarios"] and all(
            run["automatic_floor"]["passed"] for run in result["runs"]
        )
        print("SCRYVEIL_AUTOMATIC_QUALITY_FLOOR=" + str(passed).lower(), flush=True)
        print("SCRYVEIL_SEMANTIC_QUALIFICATION=manual_evidence_review_required", flush=True)
        if not passed:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
