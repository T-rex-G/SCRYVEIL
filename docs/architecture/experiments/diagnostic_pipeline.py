"""Synthetic IPS preservation, read-only snapshot and mock-loop capacity probe."""

import json
import resource
import sys
import tempfile
import time
from pathlib import Path

from scryveil.investigation import investigate
from scryveil.investigation_tools import snapshot_case
from scryveil.parse import canonical, digest
from scryveil.providers import DEFAULT_CONFIG
from scryveil.store import CaseStore

start, cpu = time.perf_counter(), time.process_time()
capacity = len(sys.argv) > 1 and sys.argv[1] == "capacity"
fixture = Path(__file__).resolve().parents[3] / "fixtures/synthetic/diagnostic-0.ips"
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    store = CaseStore(root / "cases")
    cid = store.create("synthetic-diagnostic-budget", "self")["case_id"]
    for i in range(4 if capacity else 32):
        if capacity:
            head = {"bug_type": "298", "scryveil_fixture": True}
            body = {"incident": f"fictional-{i}", "date": f"2026-01-0{i+1} 12:00:00 +0000", "memoryStatus": {"pageSize": 4096}, "processes": [{"name": f"com.example.process{j}", "pid": j, "rpages": j + 1, **({"reason": "highwater"} if j == 0 else {})} for j in range(5000)]}
        else:
            raw_head, raw_body = fixture.read_bytes().split(b"\n", 1)
            head, body = json.loads(raw_head), json.loads(raw_body)
            head["incident_id"] = body["incident"] = f"fictional-{i}"
            body["captureTime"] = f"2026-01-01 12:{i:02d}:00.125 +0100"
        source = root / f"synthetic-{i}.ips"
        source.write_bytes(canonical(head) + canonical(body))
        store.import_file(cid, source, True, "ips")
    imported = time.perf_counter()
    before = digest((store.path(cid) / "state.json").read_bytes())
    snap = snapshot_case(store, cid)
    coverage = snap["coverage"]
    del snap
    config = {**DEFAULT_CONFIG, "max_total_tokens": 200000}
    report = investigate(store, cid, "Which diagnostic observations recur, and what evidence is missing?", config)
    status, requests = report["status"], report["requests"]
    encoded = canonical(report)
    expected, report_bytes = digest(encoded), len(encoded)
    del report, encoded
    repeat = digest(canonical(investigate(store, cid, "Which diagnostic observations recur, and what evidence is missing?", config)))
    if repeat != expected or before != digest((store.path(cid) / "state.json").read_bytes()):
        raise RuntimeError("report or source state changed")
    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    print(json.dumps({"records": coverage["total_events"], "selected_events": coverage["selected_events"], "omitted_events": coverage["omitted_events"], "status": status, "requests": requests, "seconds": time.perf_counter()-start, "cpu_seconds": time.process_time()-cpu, "worker_cpu_seconds": children.ru_utime+children.ru_stime, "import_seconds": imported-start, "peak_rss_kib": own.ru_maxrss, "max_child_peak_rss_kib": children.ru_maxrss, "report_bytes": report_bytes, "identical_repeated_export": True, "source_state_unchanged": True}))
