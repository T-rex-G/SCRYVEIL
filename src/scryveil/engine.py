"""Deterministic, scoped observations with explicit competing hypotheses."""

import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from statistics import mean, median, pstdev
from typing import Any

from .models import SCHEMA, Finding, ScryveilError
from .parse import canonical, digest


@dataclass(frozen=True)
class RuleConfig:
    min_events: int = 5
    min_window_seconds: float = 240.0
    max_cv: float = 0.15
    max_relative_mad: float = 0.10

    def validate(self) -> None:
        if type(self.min_events) is not int or not 3 <= self.min_events <= 5000:
            raise ScryveilError("invalid_rule_config")
        for value in [self.min_window_seconds, self.max_cv, self.max_relative_mad]:
            if type(value) not in (int, float):
                raise ScryveilError("invalid_rule_config")
            try:
                finite = math.isfinite(value)
            except OverflowError as exc:
                raise ScryveilError("invalid_rule_config") from exc
            if not finite or value < 0:
                raise ScryveilError("invalid_rule_config")
        if self.min_window_seconds == 0 or self.max_cv > 1 or self.max_relative_mad > 1:
            raise ScryveilError("invalid_rule_config")


DEFAULT_CONFIG = RuleConfig()


def _seconds(stamp: str) -> float:
    return datetime.fromisoformat(stamp).timestamp()


def _finding(
    rule: str,
    evs: list[dict[str, Any]],
    *,
    assessment: str,
    explanation: str,
    stats: dict[str, Any],
    contradict: list[str] | None = None,
) -> dict[str, Any]:
    ids = sorted(e["event_id"] for e in evs)
    times = sorted(e["event_time"] for e in evs if e["event_time"] is not None)
    contrary = sorted(contradict or [])
    ioc = rule == "ioc.domain.exact"
    alternatives = (
        ["shared infrastructure", "stale or inaccurate user-supplied indicator"]
        if ioc
        else ["authorized background sync", "analytics or push service", "observation artifacts"]
    )
    limits = [
        "No compromise determination or actor attribution.",
        "Only imported records were examined; missing history remains unknown.",
    ]
    return Finding(
        finding_id="finding-" + digest(canonical([rule, ids])),
        title="Exact domain indicator match" if ioc else "Recurring metadata observation",
        category="indicator" if ioc else "periodicity",
        severity="unknown" if ioc else "informational",
        assessment=assessment,
        rule_id=rule,
        supporting_evidence_ids=ids,
        contradictory_evidence_ids=contrary,
        first_observed_utc=times[0] if times else None,
        last_observed_utc=times[-1] if times else None,
        explanation=explanation,
        statistics=stats,
        missing_evidence=[
            "payload contents",
            "device-wide history",
            "source clock accuracy",
            "independent corroboration",
        ],
        alternative_explanations=alternatives,
        limitations=limits,
        hypotheses=[
            {
                "hypothesis": "malicious activity is possible, not established",
                "support": ids,
                "contradictions": contrary,
                "status": "unproven",
            },
            {
                "hypothesis": "benign activity or measurement artifact",
                "support": contrary,
                "contradictions": [],
                "status": "unresolved",
            },
        ],
    ).json()


def analyze(
    events: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    config: RuleConfig = DEFAULT_CONFIG,
) -> dict[str, Any]:
    config.validate()
    findings: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    contexts = [e for e in events if e["event_type"] == "context.approved_sync"]
    for event in events:
        if event["event_type"] == "network.observation":
            attrs = event["attributes"]
            if attrs["app"] is None or event["event_time"] is None:
                outcomes.append(
                    {
                        "rule": "periodic.metadata",
                        "assessment": "insufficient_evidence",
                        "evidence_ids": [event["event_id"]],
                        "reason": "missing_app_or_time",
                    }
                )
            else:
                groups[(event["artifact_id"], attrs["app"], attrs["domain"])].append(event)
    for key, group in sorted(groups.items()):
        ordered = sorted(group, key=lambda e: (e["event_time"], e["event_id"]))
        times = sorted({_seconds(e["event_time"]) for e in group})
        span = times[-1] - times[0]
        base = {
            "rule": "periodic.metadata",
            "evidence_ids": sorted(e["event_id"] for e in group),
            "distinct_times": len(times),
            "duplicates_excluded": len(group) - len(times),
        }
        if len(times) < config.min_events or span < config.min_window_seconds:
            outcomes.append(
                {
                    **base,
                    "assessment": "insufficient_evidence",
                    "reason": "sample_or_window_too_short",
                }
            )
            continue
        intervals = [b - a for a, b in zip(times, times[1:], strict=False)]
        med = median(intervals)
        mad = median(abs(i - med) for i in intervals)
        cv = pstdev(intervals) / mean(intervals)
        stats = {
            "observed_events": len(group),
            "distinct_times": len(times),
            "duplicate_times": len(group) - len(times),
            "window_seconds": span,
            "median_interval_seconds": med,
            "mad_seconds": mad,
            "coefficient_of_variation": round(cv, 8),
            "relative_mad": round(mad / med, 8),
            "missing_observations": "unknown",
            "observation_confidence": "recorded_metadata_only",
        }
        if cv > config.max_cv or mad / med > config.max_relative_mad:
            outcomes.append(
                {
                    **base,
                    "assessment": "not_observed_in_scope",
                    "reason": "irregular_intervals",
                    "statistics": stats,
                }
            )
            continue
        contrary = [
            e["event_id"]
            for e in contexts
            if e["attributes"]["app"] == key[1]
            and e["attributes"]["domain"] == key[2]
            and e["event_time"] <= ordered[0]["event_time"]
            and e["attributes"]["valid_until"] >= ordered[-1]["event_time"]
        ]
        findings.append(
            _finding(
                "periodic.metadata",
                ordered,
                assessment="inconclusive" if contrary else "review_needed",
                explanation="Repeated recorded timings meet the configured regularity thresholds. Regularity alone cannot distinguish malicious beaconing from legitimate scheduling. Context records are unverified declarations.",
                stats=stats,
                contradict=contrary,
            )
        )
        outcomes.append({**base, "assessment": "inconclusive" if contrary else "review_needed"})
    indicators: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_type"] == "indicator.domain":
            indicators[event["attributes"]["domain"]].append(event)
    networks = [e for e in events if e["event_type"] in {"network.observation", "network.summary"}]
    network_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in networks:
        network_groups[event["attributes"]["domain"]].append(event)
    for destination in sorted(network_groups.keys() & indicators.keys()):
        findings.append(
            _finding(
                "ioc.domain.exact",
                network_groups[destination] + indicators[destination],
                assessment="indicator_match",
                explanation=(
                    "Observed domains equal user-supplied indicators after IDNA, lowercase "
                    "and trailing-dot normalization. Dataset authenticity and campaign "
                    "relevance are not established."
                ),
                stats={
                    "comparison": "exact_normalized_domain",
                    "indicator_freshness": "unverified",
                },
            )
        )
    ioc_status = (
        "indicator_match"
        if any(f["rule_id"] == "ioc.domain.exact" for f in findings)
        else "not_observed_in_scope"
        if indicators and networks
        else "insufficient_evidence"
    )
    outcomes.append(
        {
            "rule": "ioc.domain.exact",
            "assessment": ioc_status,
            "evidence_ids": sorted(e["event_id"] for e in networks) if indicators else [],
            "reason": "user_supplied_dataset_only" if indicators else "no_indicator_dataset",
        }
    )
    coverage = []
    for artifact in artifacts:
        selected = [e for e in events if e["artifact_id"] == artifact["artifact_id"]]
        times = sorted(e["event_time"] for e in selected if e["event_time"] is not None)
        coverage.append(
            {
                "artifact_id": artifact["artifact_id"],
                "source_family": artifact["format"],
                "ios_version": "unknown",
                "permission": "authorized_local_export",
                "status": "failed"
                if artifact["warnings"]
                else "analyzed"
                if selected
                else "not_present",
                "partial": bool(selected and artifact["warnings"]),
                "failure_reasons": sorted({w["code"] for w in artifact["warnings"]}),
                "record_count": len(selected),
                "untimed_records": sum(e["event_time"] is None for e in selected),
                "first_recorded_time": times[0] if times else None,
                "last_recorded_time": times[-1] if times else None,
                "interval_is_complete": False,
                "capture_interval": "unknown",
            }
        )
    for family in ["ios_backup", "sysdiagnose", "pcap", "ios_usb", "android"]:
        coverage.append(
            {"source_family": family, "status": "not_collected", "capability": "unsupported"}
        )
    graph = [
        {
            "source": e["event_id"],
            "target": e["artifact_id"],
            "relation": "observed_in",
            "supporting_event_ids": [e["event_id"]],
            "method": "byte_locator",
            "version": SCHEMA,
        }
        for e in events
    ]
    for finding in findings:
        for relation, field in [
            ("supports", "supporting_evidence_ids"),
            ("context_weakens", "contradictory_evidence_ids"),
        ]:
            graph.extend(
                {
                    "source": eid,
                    "target": finding["finding_id"],
                    "relation": relation,
                    "supporting_event_ids": [eid],
                    "method": finding["rule_id"],
                    "version": SCHEMA,
                }
                for eid in finding[field]
            )
    findings.sort(key=lambda f: f["finding_id"])
    return {
        "schema_version": SCHEMA,
        "rules_version": SCHEMA,
        "config": asdict(config),
        "config_sha256": digest(canonical(asdict(config))),
        "findings": findings,
        "rule_outcomes": outcomes,
        "coverage": coverage,
        "graph": graph,
        "overall_assessment": (
            "review_needed"
            if any(f["assessment"] in {"review_needed", "indicator_match"} for f in findings)
            else "inconclusive"
            if findings
            else "insufficient_evidence"
        ),
        "scope_statement": "No device-wide safety verdict. Only supplied records and configured rules were examined.",
    }
