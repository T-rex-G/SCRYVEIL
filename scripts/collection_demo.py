"""Reproducible fictional collection: no device access or private input.

Without arguments, generate, import and verify in a temporary directory. With
--output DIR, retain the fictional ZIP, ordinary CLI-readable case, reports and
measurements for an operator to inspect. DIR must not already exist.
"""

import argparse
import io
import json
import resource
import tempfile
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scryveil.diagnostic_intelligence import narrative
from scryveil.investigation import investigate
from scryveil.investigation_tools import ReadOnlyTools, snapshot_case
from scryveil.parse import canonical, digest
from scryveil.providers import DEFAULT_CONFIG
from scryveil.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]


def generate():
    stream = io.BytesIO()
    start = datetime(2026, 2, 3, 12, 0, tzinfo=UTC)
    fixtures = ROOT / "fixtures/synthetic"
    head, body = (fixtures / "diagnostic-v2-crash.ips").read_bytes().split(b"\n", 1)
    metadata, crash = json.loads(head), json.loads(body)
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:

        def write(name, content):
            info = zipfile.ZipInfo(name, date_time=(2026, 2, 3, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100600 << 16
            archive.writestr(info, content)

        for i in range(240):
            metadata["incident_id"] = crash["incident"] = f"fictional-bulk-{i}"
            crash["captureTime"] = (start + timedelta(minutes=i)).isoformat()
            crash["threads"][0]["frames"][0]["symbol"] = f"fictional_search_path_{i % 3}"
            crash["isNonFatal"] = i % 10 == 0
            write(f"diagnostics/crash-{i:03}.ips", canonical(metadata) + canonical(crash))
        for i in range(20):
            text = (fixtures / "diagnostic-text-resource.ips").read_bytes()
            text = text.replace(b"fictional-text-resource", f"fictional-resource-{i}".encode())
            write(f"diagnostics/resource-{i:03}.ips", text)
        for i in range(3):
            meta = {
                "bug_type": "298",
                "incident_id": f"fictional-jetsam-{i}",
                "scryveil_fixture": True,
            }
            data = {
                "incident": meta["incident_id"],
                "date": (start - timedelta(days=1, minutes=i)).isoformat(),
                "osVersion": {"train": "Fictional OS", "build": "FICT-2"},
                "pageSize": 16384,
                "processes": [
                    {"name": f"com.example.background{n}", "pid": n, "rpages": n % 200 + 1}
                    for n in range(2000)
                ],
            }
            data["processes"][0].update(name="com.example.searchd", reason="vm-pageshortage")
            write(f"diagnostics/memory-{i}.ips", canonical(meta) + canonical(data))
        write(
            "unparsed/system.plist",
            b"<?xml version='1.0'?><plist><dict><key>Fictional</key><true/></dict></plist>",
        )
        write("unparsed/unsupported.ips", b'{"bug_type":"509","scryveil_fixture":true}\n{}')
        write("unparsed/malformed.ips", b'{"bug_type":"309","scryveil_fixture":true}\n{broken')
    return stream.getvalue()


def run(base):
    timings = {}
    raw = generate()
    source = base / "fictional-collection.zip"
    source.write_bytes(raw)
    store = CaseStore(base / "cases")
    cid = store.create("fictional service investigation", "self")["case_id"]
    (base / "case-id.txt").write_text(cid + "\n")
    mock_config = base / "mock-provider.json"
    mock_config.write_bytes(canonical({**DEFAULT_CONFIG, "max_total_tokens": 200000}))
    mock_config.chmod(0o600)
    start = time.perf_counter()
    imported = store.import_collection(cid, source, True)
    timings["import_seconds"] = time.perf_counter() - start
    start = time.perf_counter()
    snapshot = snapshot_case(store, cid, all_events=True, diagnostic_details=True)
    timings["verified_snapshot_seconds"] = time.perf_counter() - start
    assert len(snapshot["events"]) == 6260
    assert snapshot["coverage"]["omitted_events"] == 0
    signatures = [
        f for f in snapshot["findings"] if f["rule"] == "diagnostics.signature_recurrence/1"
    ]
    assert len(signatures) == 3
    assert all(f["statistics"]["distinct_reported_incidents"] == 80 for f in signatures)
    tools = ReadOnlyTools(snapshot)
    start = time.perf_counter()
    result = tools.call("diagnostics.search", {"event_type": "diagnostic.crash", "limit": 5})
    timings["filtered_query_seconds"] = time.perf_counter() - start
    assert result["data"]["matched"] == 240 and len(result["data"]["events"]) == 5
    # Six thousand earlier process rows are not allowed to hide later crashes.
    assert result["data"]["events"][0]["process"] == "com.example.searchd"
    start = time.perf_counter()
    diagnostic_queries = {}
    for field, value, expected in (
        ("nonfatal", True, 24),
        ("action_taken", "none", 20),
        ("reason", "vm-pageshortage", 3),
    ):
        answer = tools.call("diagnostics.search", {"where": {field: value}, "limit": 5})
        assert answer["data"]["matched"] == expected
        assert all(e[field] == value for e in answer["data"]["events"])
        diagnostic_queries[field] = answer
    timings["three_exact_queries_seconds"] = time.perf_counter() - start
    (base / "contrary-and-memory-queries.json").write_bytes(canonical(diagnostic_queries))
    before = (store.path(cid) / "state.json").read_bytes()
    start = time.perf_counter()
    report = investigate(
        store,
        cid,
        "Which observations support recurring service failures, and what contradicts treating every report as fatal?",
        {**DEFAULT_CONFIG, "max_total_tokens": 200000},
        all_events=True,
        diagnostic_details=True,
    )
    timings["mock_investigation_seconds"] = time.perf_counter() - start
    assert (store.path(cid) / "state.json").read_bytes() == before and source.read_bytes() == raw
    inventory = store.collection_inventory(cid)
    for name, value in (
        ("inventory.json", inventory),
        ("diagnostics.json", snapshot),
        ("mock-investigation.json", report),
    ):
        (base / name).write_bytes(canonical(value))
    (base / "diagnostics.md").write_text(narrative(snapshot))
    summary = {
        "synthetic": True,
        "case_id": cid,
        "archive_sha256": digest(raw),
        "archive_bytes": len(raw),
        "import": imported,
        "events": len(snapshot["events"]),
        "snapshot_bytes": len(canonical(snapshot)),
        "signature_groups": len(signatures),
        "incidents_per_signature": [
            f["statistics"]["distinct_reported_incidents"] for f in signatures
        ],
        "timings": timings,
        "parent_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "mock_status": report["status"],
        "mock_requests": report["requests"],
        "reserved_token_units": report["reserved_token_estimate"],
        "originals_and_state_unchanged": True,
        "actual_model_quality": "NOT_TESTED",
        "genuine_export_qualification": "OPEN",
        "runtime_sha256": {
            p.name: digest(p.read_bytes()) for p in sorted((ROOT / "src/scryveil").glob("*.py"))
        },
    }
    (base / "measurement.json").write_bytes(canonical(summary))
    assert report["status"] == "completed", report["status"]
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        print(json.dumps(run(args.output)))
    else:
        with tempfile.TemporaryDirectory(prefix="scryveil-collection-demo-") as temp:
            print(json.dumps(run(Path(temp))))
