"""Opt-in model benchmark with owner-selected URL, protocol, model and credentials.

Only freshly generated fictional inputs. Preview is offline; actual remote
inference requires the exact reviewed disclosure digest. Never accepts keys
or original evidence paths as arguments. No model or vendor is implicit.
"""

import argparse
import json
from pathlib import Path

from model_qualification import evaluate

from scryveil.providers import load_config

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
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--approve-plan-sha256")
    args = parser.parse_args()
    result = evaluate(
        scenarios=SCENARIOS,
        provider_config=load_config(args.provider_config),
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
