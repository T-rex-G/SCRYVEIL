"""Bounded 20,000-record synthetic APR import and sequential review exports."""

import json
import platform
import resource
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scryveil.parse import canonical, digest
from scryveil.privacy import build_privacy_report
from scryveil.store import CaseStore

start = time.perf_counter()
cpu_start = time.process_time()
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    store = CaseStore(root / "cases")
    cid = store.create("synthetic-privacy-budget", "self")["case_id"]
    for part in range(4):
        records = []
        base = datetime(2026, 1, 1, tzinfo=UTC)
        for i in range(5000):
            stamp = (base + timedelta(seconds=i)).isoformat()
            if i % 5 == 4:
                rec = dict(type="networkActivity", bundleID=f"com.example.app{part}", domain="example.invalid", hits=i + 1, firstTimeStamp=base.isoformat(), timeStamp=stamp, initiatedType="AppInitiated", domainType=2)
            else:
                rec = dict(type="access", accessor=dict(identifier=f"com.example.app{part}", identifierType="bundleID"), category="microphone", identifier=f"synthetic-{i // 5}-{i % 5 // 2}", kind="intervalBegin" if i % 5 % 2 == 0 else "intervalEnd", timeStamp=stamp)
            records.append(rec)
        source = root / f"synthetic-{part}.ndjson"
        source.write_bytes(b"".join(canonical(r) for r in records))
        store.import_file(cid, source, True)
    del records
    imported = time.perf_counter()
    report = build_privacy_report(store, cid)
    encoded = canonical(report)
    expected = digest(encoded)
    report_bytes, summary = len(encoded), report["summary"]
    del report, encoded
    first_exported = time.perf_counter()
    if digest(canonical(build_privacy_report(store, cid))) != expected:
        raise RuntimeError("report changed")
    print(json.dumps(dict(records=20000, summary=summary, cpu_seconds=time.process_time() - cpu_start, seconds=time.perf_counter() - start, import_seconds=imported - start, first_export_seconds=first_exported - imported, peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, report_bytes=report_bytes, identical_repeated_export=True, python=platform.python_version(), host=platform.platform())))
