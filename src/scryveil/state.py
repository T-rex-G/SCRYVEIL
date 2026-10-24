"""Validate persisted metadata before it can influence operations or exports.

Events are independently reparsed and analysis is recomputed by CaseStore.
This module validates metadata that cannot be reconstructed from source bytes.
"""

import math
import re
from datetime import datetime
from typing import Any

from .models import SCHEMA, ScryveilError

DECISIONS = {"review_needed", "accepted_benign", "inconclusive"}


def require(condition: bool) -> None:
    if not condition:
        raise ScryveilError("invalid_case_state", 4)


def fields(value: Any, names: str) -> None:
    require(isinstance(value, dict) and set(value) == set(names.split()))


def stamp(value: Any) -> None:
    require(isinstance(value, str))
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value) is not None)
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise ScryveilError("invalid_case_state", 4) from exc


def validate_metadata(state: dict[str, Any]) -> None:
    fields(
        state,
        "schema_version case_id label consent_scope created_at evidence_root retention_policy artifacts events audit analysis rule_run reviews",
    )
    require(state["schema_version"] == SCHEMA)
    require(isinstance(state["label"], str) and 0 < len(state["label"]) <= 200)
    require(state["consent_scope"] in ("self", "authorized"))
    require(state["evidence_root"] == "originals")
    require(state["retention_policy"] == "local_owner_managed")
    stamp(state["created_at"])
    for key in ("artifacts", "events", "audit", "reviews"):
        require(isinstance(state[key], list))
    require(len(state["artifacts"]) <= 32 and len(state["events"]) <= 20000)
    require(bool(state["audit"]))
    for artifact in state["artifacts"]:
        fields(
            artifact,
            "schema_version artifact_id sha256 original_filename size format imported_at collection_time collection_mode synthetic tool_version capture_interval source_machine sensitivity warnings",
        )
        require(artifact["schema_version"] == artifact["tool_version"] == SCHEMA)
        for key in ("artifact_id", "sha256", "original_filename", "format"):
            require(isinstance(artifact[key], str))
        require(type(artifact["synthetic"]) is bool)
        require(type(artifact["size"]) is int and 0 <= artifact["size"] <= 8 * 1024 * 1024)
        require(
            artifact["collection_mode"] == ("synthetic" if artifact["synthetic"] else "imported")
        )
        require(artifact["collection_time"] is None and artifact["capture_interval"] is None)
        require(artifact["source_machine"] == "unknown" and artifact["sensitivity"] == "private")
        require(isinstance(artifact["warnings"], list))
        stamp(artifact["imported_at"])
    imported: list[str] = []
    audited_reviews = []
    analysis_current = False
    for index, entry in enumerate(state["audit"]):
        fields(entry, "sequence operation actor timestamp affected_ids result previous_hash hash")
        require(type(entry["sequence"]) is int and entry["sequence"] == index)
        require(entry["actor"] == "local_operator")
        stamp(entry["timestamp"])
        require(isinstance(entry["hash"], str))
        require(re.fullmatch(r"[0-9a-f]{64}", entry["hash"]) is not None)
        require(entry["previous_hash"] is None or isinstance(entry["previous_hash"], str))
        ids = entry["affected_ids"]
        require(isinstance(ids, list) and all(isinstance(i, str) for i in ids))
        operation = entry["operation"]
        if index == 0:
            require(operation == "case.create" and ids == [state["case_id"]])
            require(entry["result"] == "created")
        elif operation == "evidence.import":
            require(len(ids) == 1 and ids[0] not in imported)
            require(entry["result"] in ("imported", "partial_or_failed"))
            imported.extend(ids)
            analysis_current = False
        elif operation == "evidence.reimport":
            require(len(ids) == 1 and ids[0] in imported and entry["result"] == "duplicate")
        elif operation == "analyze":
            require(ids == imported and entry["result"] == "completed")
            analysis_current = True
        elif operation == "analyst.review":
            require(analysis_current and len(ids) == 1)
            require(entry["result"] in tuple(DECISIONS))
            audited_reviews.append((ids[0], entry["result"]))
        else:
            require(False)
    require(imported == [a["artifact_id"] for a in state["artifacts"]])
    reviews = []
    for review in state["reviews"]:
        fields(review, "finding_id decision timestamp")
        require(isinstance(review["finding_id"], str))
        require(re.fullmatch(r"finding-[0-9a-f]{64}", review["finding_id"]) is not None)
        require(review["decision"] in tuple(DECISIONS))
        stamp(review["timestamp"])
        reviews.append((review["finding_id"], review["decision"]))
    require(reviews == audited_reviews)
    analysis, run = state["analysis"], state["rule_run"]
    require((analysis is not None) == analysis_current)
    require((run is None) == (analysis is None))
    if run is not None:
        require(isinstance(analysis, dict) and isinstance(analysis.get("config"), dict))
        fields(
            run, "started_at runtime_seconds runtime tool_version input_artifact_ids config_sha256"
        )
        stamp(run["started_at"])
        duration = run["runtime_seconds"]
        require(type(duration) in (int, float))
        try:
            require(math.isfinite(duration) and duration >= 0)
        except OverflowError as exc:
            raise ScryveilError("invalid_case_state", 4) from exc
        require(isinstance(run["runtime"], str))
        require(re.fullmatch(r"\d+\.\d+\.\d+", run["runtime"]) is not None)
        require(run["tool_version"] == SCHEMA)
        require(run["input_artifact_ids"] == imported)
        require(run["config_sha256"] == analysis.get("config_sha256"))


def same_json(left: Any, right: Any) -> bool:
    """JSON provenance equality must distinguish bool, int and float values."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            same_json(value, right[key]) for key, value in left.items()
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            same_json(a, b) for a, b in zip(left, right, strict=True)
        )
    return bool(left == right)
