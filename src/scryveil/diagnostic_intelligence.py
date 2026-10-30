"""Cross-report measurements over declared identities, never causal verdicts.

This opt-in analysis profile leaves historical reports/reader outputs unchanged.
Signatures compare exact declared exception/termination fields and symbol order;
unsymbolicated addresses are not portable identities and are not compared.
"""

import html
import json
import re
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime
from typing import Any

from .parse import canonical, digest

PROFILE = "scryveil.diagnostic-intelligence/1"
REFERENCE_LIMIT = 8


def os_key(attributes: dict[str, Any]) -> tuple[Any, Any]:
    version, build = attributes.get("os_version"), attributes.get("os_build")
    if build is None and isinstance(version, str):
        match = re.fullmatch(r"(.+) \(([A-Za-z0-9.-]{1,64})\)", version)
        if match:
            return match[1], match[2]
    return version, build


def signature(event: dict[str, Any]) -> dict[str, Any] | None:
    a = event["attributes"]
    if (
        event["event_type"] not in ("diagnostic.crash", "diagnostic.exception")
        or not a.get("process")
        or not a.get("exception_type")
    ):
        return None
    frames = a.get("frames", [])[:5]
    return {
        "process": a["process"],
        "bundle_id": a.get("bundle_id"),
        "os_version": os_key(a)[0],
        "os_build": os_key(a)[1],
        "exception_type": a.get("exception_type"),
        "exception_subtype": a.get("exception_subtype"),
        "exception_signal": a.get("exception_signal"),
        "termination_namespace": a.get("termination_namespace"),
        "termination_code": a.get("termination_code"),
        "stack_symbols": [f.get("symbol") for f in frames],
    }


def _measurement(
    rule: str,
    process: str,
    group: list[dict[str, Any]],
    observation: str,
    statistics: dict[str, Any],
    contrary: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    ids = sorted({e["event_id"] for e in group})
    others = sorted({e["event_id"] for e in contrary or []})
    times = sorted(e["event_time"] for e in group if e["event_time"] is not None)
    return {
        "finding_id": "diag-" + digest(canonical([rule, ids, statistics])),
        "rule": rule,
        "process": process,
        "assessment": "review_needed",
        "observation": observation,
        "statistics": statistics,
        "supporting_evidence_ids": ids[:REFERENCE_LIMIT],
        "contradictory_evidence_ids": others[:REFERENCE_LIMIT],
        "reference_counts": {
            "supporting": len(ids),
            "contradictory": len(others),
            "supporting_omitted": max(0, len(ids) - REFERENCE_LIMIT),
            "contradictory_omitted": max(0, len(others) - REFERENCE_LIMIT),
        },
        "first_observed_utc": times[0] if times else None,
        "last_observed_utc": times[-1] if times else None,
        "alternatives": [
            "software defect or workload",
            "resource policy or operating-system behavior",
            "different devices or executable versions sharing source-declared names",
        ],
        "limitations": [
            "Source-declared process/build/incident values are not authenticated identities.",
            "A crash, repeated stack, resource warning or temporal neighbor does not establish spyware or causation.",
            "Unknown clocks and absent complementary records prevent a complete device history.",
            "Reference lists are bounded; omitted counts are explicit. Query the named process and time range for further records.",
        ],
    }


def intelligence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[bytes, list[dict[str, Any]]] = defaultdict(list)
    by_process: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        a = e["attributes"]
        if e["event_type"].startswith("diagnostic.") and a.get("process"):
            by_process[a["process"]].append(e)
        if (s := signature(e)) is not None:
            groups[canonical(s)].append(e)
    results = []
    for key, group in sorted(groups.items()):
        reported = [e for e in group if e["attributes"].get("incident")]
        incidents = {e["attributes"]["incident"] for e in reported}
        if len(incidents) < 2 or len({e["artifact_id"] for e in reported}) < 2:
            continue
        a = reported[0]["attributes"]
        contrary = [
            e
            for e in by_process[a["process"]]
            if os_key(e["attributes"]) == os_key(a)
            and e["attributes"].get("bundle_id") == a.get("bundle_id")
            and (
                e["attributes"].get("nonfatal") is True
                or e["attributes"].get("simulated") is True
                or e["attributes"].get("action_taken") == "none"
            )
        ]
        results.append(
            _measurement(
                "diagnostics.signature_recurrence/1",
                a["process"],
                reported,
                "Distinct source artifacts declare multiple incident IDs with matching observed exception/termination fields and available symbol slots within the same declared process/OS/build group.",
                {
                    "signature_sha256": digest(key),
                    "distinct_reported_incidents": len(incidents),
                    "source_artifacts": len({e["artifact_id"] for e in reported}),
                    "repeated_incident_observations": len(reported) - len(incidents),
                    "missing_incident_observations": len(group) - len(reported),
                    "symbol_slots_compared": len(a.get("frames", [])[:5]),
                    "missing_symbol_slots": sum(
                        f.get("symbol") is None for f in a.get("frames", [])[:5]
                    ),
                    "symbolication": "source_symbols_only_no_address_resolution",
                    "signature_fields": "process,bundle,OS/build,exception type/subtype/signal,termination namespace/code,first five symbol slots",
                },
                contrary,
            )
        )
    for process, group in sorted(by_process.items()):
        declarations = [e for e in group if e["event_type"] != "diagnostic.jetsam"]
        if declarations:
            conditions: dict[str, int] = defaultdict(int)
            contrary = []
            for e in declarations:
                a = e["attributes"]
                if (
                    a.get("nonfatal") is True
                    or a.get("simulated") is True
                    or a.get("action_taken") == "none"
                ):
                    contrary.append(e)
                if a.get("nonfatal") is True:
                    conditions["declared_nonfatal"] += 1
                if a.get("simulated") is True:
                    conditions["declared_simulated"] += 1
                if a.get("action_taken") == "none":
                    conditions["declared_no_action"] += 1
                if a.get("termination_namespace") == "WATCHDOG" or (
                    a.get("termination_namespace") in ("FRONTBOARD", "RUNNINGBOARD")
                    and a.get("termination_code") == 0x8BADF00D
                ):
                    conditions["reported_watchdog_namespace_or_code"] += 1
                conditions[e["event_type"]] += 1
            results.append(
                _measurement(
                    "diagnostics.report_conditions/1",
                    process,
                    declarations,
                    "Report categories and explicit condition flags are counted separately. Nonfatal/simulated conditions and resource reports declaring no action contradict the claim that every supplied report proves a fatal crash.",
                    {
                        "condition_counts": dict(sorted(conditions.items())),
                        "categories_and_flags_overlap": True,
                    },
                    contrary,
                )
            )
        incidents_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for e in declarations:
            if e["attributes"].get("incident"):
                incidents_by_id[e["attributes"]["incident"]].append(e)
        conflicts = []
        for observations in incidents_by_id.values():
            variants = {
                canonical(
                    [
                        signature(e),
                        e["event_time"],
                        e["attributes"].get("nonfatal"),
                        e["attributes"].get("simulated"),
                    ]
                )
                for e in observations
            }
            if len(variants) > 1:
                conflicts.extend(observations)
        if conflicts:
            results.append(
                _measurement(
                    "diagnostics.incident_conflict/1",
                    process,
                    conflicts,
                    "A repeated declared incident ID has differing signatures, condition flags or event times in supplied artifacts. These observations must not be treated as independent confirmed incidents.",
                    {"conflicting_observations": len(conflicts)},
                    conflicts,
                )
            )
        jetsam = [e for e in group if e["event_type"] == "diagnostic.jetsam"]
        reasoned = [e for e in jetsam if e["attributes"].get("reason")]
        if reasoned:
            reasons: dict[str, int] = defaultdict(int)
            for e in reasoned:
                declared = e["attributes"]["reason"]
                reasons[
                    declared
                    if declared
                    in {
                        "per-process-limit",
                        "vm-pageshortage",
                        "vnode-limit",
                        "highwater",
                        "fc-thrashing",
                        "jettisoned",
                    }
                    else "other"
                ] += 1
            footprints = [
                e["attributes"]["footprint_bytes"]
                for e in reasoned
                if e["attributes"].get("footprint_bytes") is not None
            ]
            results.append(
                _measurement(
                    "diagnostics.jetsam_reason/1",
                    process,
                    reasoned,
                    "Jetsam process entries carry explicit reason values. Other listed processes without a reason are not counted as terminations. Resident pages times reported page size is a footprint measurement, not a memory limit.",
                    {
                        "reasoned_entries": len(reasoned),
                        "listed_without_reason": len(jetsam) - len(reasoned),
                        "reason_counts": dict(sorted(reasons.items())),
                        "peak_observed_footprint_bytes": max(footprints) if footprints else None,
                    },
                    [e for e in jetsam if not e["attributes"].get("reason")],
                )
            )
        crashes = [e for e in group if signature(e) is not None and e["event_time"] is not None]
        reasoned_ids = {e["event_id"] for e in reasoned}
        resources = [
            e
            for e in group
            if e["event_time"] is not None
            and (e["event_type"] == "diagnostic.resource" or e["event_id"] in reasoned_ids)
        ]
        # Bounded scan by time; match declared OS/build only. A shared name is
        # insufficient to pool demonstrably different OS/build declarations.
        buckets: dict[tuple[Any, Any], list[list[dict[str, Any]]]] = {}
        for side, rows in enumerate((crashes, resources)):
            for e in rows:
                a = e["attributes"]
                buckets.setdefault(os_key(a), [[], []])[side].append(e)
        pair_count = 0
        related: dict[str, dict[str, Any]] = {}
        interval_count = 0
        start_only_count = 0
        reversed_count = 0
        overlap_count = 0
        conflicting_bundle_pairs = 0
        unknown_bundle_pairs = 0
        for left, right in buckets.values():
            crash_times = sorted(datetime.fromisoformat(e["event_time"]).timestamp() for e in left)
            crash_by_bundle: dict[str | None, list[float]] = defaultdict(list)
            for e in left:
                crash_by_bundle[e["attributes"].get("bundle_id")].append(
                    datetime.fromisoformat(e["event_time"]).timestamp()
                )
            for values in crash_by_bundle.values():
                values.sort()
            spans = []
            by_bundle: dict[str | None, list[tuple[float, float]]] = defaultdict(list)
            for e in right:
                start = datetime.fromisoformat(e["event_time"]).timestamp()
                end_value = (
                    e["attributes"].get("event_end_time")
                    if e["event_type"] == "diagnostic.resource"
                    else None
                )
                end = datetime.fromisoformat(end_value).timestamp() if end_value else start
                if end < start:
                    reversed_count += 1
                    continue
                spans.append((start, end))
                bundle = e["attributes"].get("bundle_id")
                by_bundle[bundle].append((start, end))
                # Unknown bundle is compatible, not evidence of equal identity.
                # Known conflicting bundle declarations must never be pooled.
                candidates = (
                    [crash_times]
                    if bundle is None
                    else [crash_by_bundle.get(bundle, []), crash_by_bundle.get(None, [])]
                )
                count = sum(
                    bisect_right(times, end + 300) - bisect_left(times, start - 300)
                    for times in candidates
                )
                if count:
                    related[e["event_id"]] = e
                    if end_value is not None:
                        interval_count += 1
                        overlap_count += sum(
                            bisect_right(times, end) - bisect_left(times, start)
                            for times in candidates
                        )
                    else:
                        start_only_count += 1
            # Two binary searches per selected bucket; no pair materialization
            # or repeated scan of unknown-identity records for each application.
            starts = sorted(start for start, _ in spans)
            ends = sorted(end for _, end in spans)
            indexes = {
                bundle: (sorted(a for a, _ in values), sorted(b for _, b in values))
                for bundle, values in by_bundle.items()
            }
            for e in left:
                stamp = datetime.fromisoformat(e["event_time"]).timestamp()
                bundle = e["attributes"].get("bundle_id")
                interval_indexes = (
                    [(starts, ends)]
                    if bundle is None
                    else [indexes.get(bundle, ([], [])), indexes.get(None, ([], []))]
                )
                count = sum(
                    bisect_right(a, stamp + 300) - bisect_left(b, stamp - 300)
                    for a, b in interval_indexes
                )
                all_count = bisect_right(starts, stamp + 300) - bisect_left(ends, stamp - 300)
                conflicting_bundle_pairs += all_count - count
                unknown_starts, unknown_ends = indexes.get(None, ([], []))
                unknown_bundle_pairs += (
                    count
                    if bundle is None
                    else (
                        bisect_right(unknown_starts, stamp + 300)
                        - bisect_left(unknown_ends, stamp - 300)
                    )
                )
                if count:
                    related[e["event_id"]] = e
                    pair_count += count
        if pair_count:
            results.append(
                _measurement(
                    "diagnostics.resource_temporal_neighbors/1",
                    process,
                    list(related.values()),
                    "Crash/exception times fall within, or at most five minutes outside, reported resource intervals or point observations in the same declared process/OS/build group without conflicting reported bundle IDs. Unknown bundle IDs remain unverified. This is temporal proximity, not a demonstrated causal relationship or proof of resource activity at the crash time.",
                    {
                        "window_seconds": 300,
                        "observation_pairs": pair_count,
                        "conflicting_bundle_pairs_excluded": conflicting_bundle_pairs,
                        "pairs_with_unknown_bundle_identity": unknown_bundle_pairs,
                        "pairs_inside_reported_intervals": overlap_count,
                        "related_resources_with_end_time": interval_count,
                        "related_resource_points_or_unknown_end": start_only_count,
                        "reversed_resource_intervals_excluded": reversed_count,
                        "clock_accuracy": "unknown",
                        "same_device_identity": "unverified",
                    },
                    [
                        e
                        for e in related.values()
                        if e["attributes"].get("action_taken") == "none"
                        or e["attributes"].get("nonfatal") is True
                    ],
                )
            )
    return sorted(results, key=lambda f: f["finding_id"])


def compare_hypotheses(
    finding: dict[str, Any], events: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    """Test explicit propositions over authorized projected fields, not raw evidence.

    A nonfatal declaration refutes an all-fatal interpretation; it does not
    refute recurrence or a common cause. Missing declarations are unknown,
    never positive evidence for the opposite proposition.
    """
    ids = sorted(set(finding["supporting_evidence_ids"] + finding["contradictory_evidence_ids"]))
    rows = [events[eid] for eid in ids if eid in events]
    diagnostic = finding["rule"].startswith("diagnostics.")
    facts = []
    fatal_counterexamples = []
    for event in rows:
        if not event["event_type"].startswith("diagnostic."):
            continue
        for field, value in (("nonfatal", True), ("action_taken", "none"), ("simulated", True)):
            if type(event.get(field)) is not type(value) or event.get(field) != value:
                continue
            if field != "simulated":
                fatal_counterexamples.append(event["event_id"])
            location = event.get("field_locations", {}).get(field, event)
            facts.append(
                {
                    "event_id": event["event_id"],
                    "field": field,
                    "value": value,
                    "artifact_id": event["artifact_id"],
                    "source_locator": location["source_locator"],
                    "byte_offset": location["byte_offset"],
                    "byte_length": location["byte_length"],
                    "json_pointer": location.get("json_pointer", event.get("json_pointer")),
                }
            )
    tests: list[dict[str, Any]] = []
    if diagnostic:
        tests.append(
            {
                "test_id": "all_reports_fatal",
                "proposition": "Every diagnostic report referenced by this finding establishes a fatal termination.",
                "status": "contradicted" if fatal_counterexamples else "not_established",
                "supporting_evidence_ids": [],
                "contradictory_evidence_ids": sorted(set(fatal_counterexamples)),
                "explanation": "Explicit nonfatal or no-action declarations contradict this proposition. A false/missing nonfatal flag or a simulated report does not independently prove termination. This test does not establish survival or continuous service execution.",
                "needed_evidence": [
                    "Validated termination observations for each incident; missing flags alone are insufficient."
                ],
            }
        )
        if finding["rule"] in {
            "diagnostics.signature_recurrence/1",
            "diagnostics.recurrent_reports/1",
        }:
            tests.append(
                {
                    "test_id": "reported_recurrence",
                    "proposition": "The deterministic rule found multiple source-declared incidents in its stated identity/signature scope.",
                    "status": "supported_as_reported",
                    "supporting_evidence_ids": finding["supporting_evidence_ids"],
                    "contradictory_evidence_ids": [],
                    "explanation": "Nonfatal, simulated and no-action observations may recur; those conditions do not contradict report recurrence. Incident declarations are not authenticated independent events or a common-device identity.",
                    "needed_evidence": [
                        "Independent acquisition and device identity to establish that the declarations describe one device's history."
                    ],
                }
            )
        tests.append(
            {
                "test_id": "common_cause",
                "proposition": "A common software defect or resource condition caused the reported failures.",
                "status": "not_established",
                "supporting_evidence_ids": [],
                "contradictory_evidence_ids": [],
                "explanation": "Repeated signatures, resource labels and temporal neighbors do not discriminate a shared defect from workload, policy or mixed-device explanations. Nonfatal reports neither prove nor disprove these causes. No causal support or contradiction is established by these rules.",
                "needed_evidence": [
                    "Verified common device/build and source-clock relationship.",
                    "Faulting-thread context and resource measurements at each incident, including comparison periods without failures.",
                ],
            }
        )
    for test in tests:
        counts = {}
        for role in ("supporting", "contradictory"):
            key = role + "_evidence_ids"
            counts[role] = len(test[key])
            counts[role + "_omitted"] = max(0, len(test[key]) - REFERENCE_LIMIT)
            test[key] = test[key][:REFERENCE_LIMIT]
        test["reference_counts"] = counts
    return {
        "schema_version": "scryveil.hypothesis-tests/1",
        "scope": "Only this finding's retained references in the authorized snapshot; no whole-device inference.",
        "status": "evaluated" if diagnostic else "no_rule_specific_test",
        "referenced_events": len(rows),
        "missing_reference_ids": [eid for eid in ids if eid not in events],
        "tests": tests,
        "observations": facts[:REFERENCE_LIMIT],
        "observations_omitted": max(0, len(facts) - REFERENCE_LIMIT),
    }


def narrative(snapshot: dict[str, Any]) -> str:
    """Deterministic operator report; evidence text is escaped, never executed."""

    def safe(value: str) -> str:
        value = html.escape(value)
        value = value.replace("\r", " ").replace("\n", " ")
        for character in ("\\", "`", "[", "]", "*", "_", "#", "|"):
            value = value.replace(character, "\\" + character)
        return value

    coverage = snapshot["coverage"]
    rows = {e["event_id"]: e for e in snapshot["events"]}
    lines = [
        "# SCRYVEIL diagnostic investigation",
        "",
        f"Examined {coverage['selected_events']} of {coverage['total_events']} normalized events across {len(snapshot['artifacts'])} retained artifacts. Omitted events: {coverage['omitted_events']}.",
        "",
        "These are deterministic measurements, not an AI diagnosis or device safety verdict. Genuine Apple-export qualification remains open. Source clocks and common device identity are unverified.",
        "",
    ]
    counts = coverage.get("collection_member_status_counts")
    if counts:
        lines += ["Collection inventory: " + safe(json.dumps(counts, sort_keys=True)), ""]
    repeated = [
        f for f in snapshot["findings"] if f["rule"] == "diagnostics.signature_recurrence/1"
    ]
    nonfatal = sum(e.get("nonfatal") is True for e in rows.values())
    no_action = sum(e.get("action_taken") == "none" for e in rows.values())
    lines += [
        "## Assessment",
        "",
        f"- {len(repeated)} recurring declared exception/stack signature groups were identified. A repeated signature identifies a pattern for follow-up, not its cause.",
        f"- {nonfatal} observations explicitly declare nonfatal conditions; {no_action} declare no action taken. These flags must not be counted as proof of fatal crashes.",
        "- Software defects, workload/resource policy and mixed-device collections remain competing explanations. The supplied observations do not establish spyware or a clean device.",
        "",
    ]
    lines += [
        "## Timeline overview",
        "",
        "Times below are normalized source observations, not acquisition times. Unknown clock accuracy prevents causal ordering across devices. The JSON report retains every selected event and its original offset/precision.",
        "",
        "| Category | Observations | First source time (UTC) | Last source time (UTC) | Unknown times |",
        "| --- | ---: | --- | --- | ---: |",
    ]
    for category in sorted({e["event_type"] for e in rows.values()}):
        group = [e for e in rows.values() if e["event_type"] == category]
        times = sorted(e["event_time"] for e in group if e["event_time"] is not None)
        lines.append(
            f"| {safe(category)} | {len(group)} | {safe(times[0]) if times else 'unknown'} | {safe(times[-1]) if times else 'unknown'} | {len(group) - len(times)} |"
        )
    memory_times = [
        e["event_time"]
        for e in rows.values()
        if e["event_type"] == "diagnostic.jetsam" and e["event_time"] is not None
    ]
    crash_times = [
        e["event_time"]
        for e in rows.values()
        if e["event_type"] == "diagnostic.crash" and e["event_time"] is not None
    ]
    if memory_times and crash_times and max(memory_times) < min(crash_times):
        lines += [
            "",
            "Every timed Jetsam observation in this selection precedes the first timed crash. These records do not show memory pressure at the later crash times; unknown clock accuracy and missing history remain limitations.",
        ]
    lines += [
        "",
        "Missing or unsupported source families: "
        + ", ".join(safe(family) for family in coverage.get("not_collected_or_supported", []))
        + ".",
        "",
    ]
    artifacts = {a["artifact_id"]: a for a in snapshot["artifacts"]}

    def citation(event: dict[str, Any], field: str | None = None) -> str:
        location = event.get("field_locations", {}).get(field, event) if field else event
        pointer = location.get("json_pointer", event.get("json_pointer", ""))
        original = artifacts.get(event["artifact_id"], {}).get("sha256", "unavailable")
        return (
            f"`{event['event_id']}` — `{event['artifact_id']}`; "
            f"SHA-256 `{original}`; {safe(location['source_locator'])}; "
            f"bytes {location['byte_offset']}–{location['byte_offset'] + location['byte_length']} (end exclusive); "
            f"JSON pointer {safe(pointer) if pointer else '(record root/text)'}; "
            f"time {safe(event['event_time'] or 'unknown')}."
        )

    for finding in snapshot["findings"]:
        process_ref = finding.get("process_ref")
        name = next(
            (
                e.get("process", process_ref)
                for e in rows.values()
                if e.get("process_ref") == process_ref
            ),
            process_ref,
        )
        lines += [
            "## " + safe(finding["rule"]) + (" — " + safe(name) if name else ""),
            "",
            safe(finding["observation"]),
            "",
        ]
        if "statistics" in finding:
            lines += [
                "Measured values: " + safe(json.dumps(finding["statistics"], sort_keys=True)),
                "",
            ]
        # Describe the actual authorized signature, not just its opaque hash.
        if finding["rule"] == "diagnostics.signature_recurrence/1":
            example = rows[finding["supporting_evidence_ids"][0]]
            details = {
                key: example[key]
                for key in (
                    "exception_type",
                    "termination_namespace",
                    "termination_code",
                    "os_build",
                )
                if key in example
            }
            if "frames" in example:
                details["first_five_source_symbols"] = [
                    f.get("symbol") for f in example["frames"][:5]
                ]
            lines += [
                "Observed signature details: " + safe(json.dumps(details, sort_keys=True)),
                "",
            ]
        comparison = compare_hypotheses(finding, rows)
        for test in comparison["tests"]:
            lines += [
                safe(test["proposition"])
                + " **"
                + safe(test["status"])
                + "**. "
                + safe(test["explanation"]),
                "",
            ]
        for key, title in (
            ("supporting_evidence_ids", "Supporting observations"),
            (
                "contradictory_evidence_ids",
                "Observations requiring proposition-specific interpretation",
            ),
        ):
            lines += [title + ":", ""]
            for eid in finding[key][:3]:
                e = rows[eid]
                lines += ["- " + citation(e)]
            if not finding[key]:
                lines.append(
                    "- None identified by this rule; this does not establish that none exist."
                )
            if len(finding[key]) > 3:
                lines.append(
                    f"- {len(finding[key]) - 3} further retained references are in the JSON report."
                )
            lines.append("")
        if "reference_counts" in finding:
            lines += [
                "Reference coverage: "
                + safe(json.dumps(finding["reference_counts"], sort_keys=True)),
                "",
            ]
        lines += [
            "Competing explanations: " + "; ".join(safe(s) for s in finding["alternatives"]) + ".",
            "",
            "Limits: " + " ".join(safe(s) for s in finding["limitations"]),
            "",
        ]
    resources = [e for e in rows.values() if e["event_type"] == "diagnostic.resource"]
    if resources:
        lines += [
            "## Resource accounting examples",
            "",
            "Reported writes and limits have separate accounting windows. These values are not packet observations, measured rates or proof that a limit caused a crash. No unit conversion or same-window comparison is assumed.",
            "",
        ]
        for e in resources[:3]:
            for field in (
                "writes_caused",
                "writes_duration_seconds",
                "writes_limit",
                "limit_duration_seconds",
                "sampled_duration_seconds",
                "action_taken",
            ):
                if field in e:
                    lines += [
                        f"- {safe(field)} = {safe(json.dumps(e[field], sort_keys=True))}; "
                        + citation(e, field)
                    ]
            lines.append("")
        if len(resources) > 3:
            lines += [
                f"Showing 3 of {len(resources)} resource records; all selected records remain in the JSON report.",
                "",
            ]
    lines += [
        "## Outstanding questions",
        "",
        "- Do independent records establish one device and the executable versions involved?",
        "- Do symbolicated stacks or reproducible software failures support a common defect?",
        "- Do authorized resource histories corroborate the reported pressure and timestamps?",
        "- Which unsupported or malformed members need another qualified reader?",
        "",
        "Archive/member relationships are available through collection inventory. No original bytes were modified by this report.",
        "",
    ]
    return "\n".join(lines)
