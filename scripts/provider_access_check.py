"""One owner-selected model-catalog GET, with no evidence or inference request.

Not an investigator tool. A catalog is a provider declaration, not proof of
free access, actual model identity, tool compatibility or reasoning quality.
No redirects, automatic model changes, purchases or inference follow this check.
"""

import argparse
import json
from pathlib import Path

import scryveil
from scryveil.models import ScryveilError
from scryveil.parse import canonical, digest
from scryveil.providers import (
    BrokerProvider,
    load_config,
    validate_catalog_request,
    validate_config,
)

ROOT = Path(__file__).resolve().parents[1]


def access_plan(config, endpoint, candidates):
    endpoint = validate_catalog_request(config, endpoint, candidates)
    files = sorted((ROOT / "src/scryveil").glob("*.py"))
    installed = Path(scryveil.__file__).resolve().parent
    if {p.name: digest(p.read_bytes()) for p in files} != {
        p.name: digest(p.read_bytes()) for p in installed.glob("*.py")
    }:
        raise ScryveilError("qualification_runtime_source_mismatch")
    files += [
        Path(__file__).resolve(),
        ROOT / ".github/workflows/provider-access-check.yml",
        ROOT / "configs/qualification-provider.json",
    ]
    plan = {
        "schema_version": "scryveil.provider-access-plan/1",
        "provider": config,
        "catalog_endpoint": endpoint,
        "candidates": candidates,
        "method": "GET",
        "maximum_requests": 1,
        "request_body": None,
        "evidence_records": 0,
        "inference_requests": 0,
        "code_sha256": {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in files},
    }
    plan["plan_sha256"] = digest(canonical(plan))
    return plan


def check_access(config, endpoint, candidates, *, approved_plan=None, preview=False):
    plan = access_plan(config, endpoint, candidates)
    if preview:
        return plan
    if approved_plan != plan["plan_sha256"]:
        raise ScryveilError("catalog_request_approval_required")
    # Authorization/destination validation precede access to the credential.
    try:
        result = BrokerProvider(config).inspect_catalog(endpoint, candidates)
        return {"plan_sha256": plan["plan_sha256"], "status": "catalog_received", **result}
    except ScryveilError as exc:
        return {
            "plan_sha256": plan["plan_sha256"],
            "status": exc.code,
            "inference_tested": False,
            "billing_verified": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-config", type=Path, required=True)
    parser.add_argument("--catalog-endpoint", required=True)
    parser.add_argument("--candidate-model", action="append", required=True)
    parser.add_argument("--catalog-auth-scheme", choices=["bearer", "x-api-key"])
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--approve-plan-sha256")
    args = parser.parse_args()
    config = load_config(args.provider_config)
    if args.catalog_auth_scheme:
        config = validate_config({**config, "auth_scheme": args.catalog_auth_scheme})
    result = check_access(
        config,
        args.catalog_endpoint,
        args.candidate_model,
        approved_plan=args.approve_plan_sha256,
        preview=args.preview,
    )
    print("SCRYVEIL_ACCESS_RESULT=" + json.dumps(result, separators=(",", ":")), flush=True)
    if not args.preview and result["status"] != "catalog_received":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
