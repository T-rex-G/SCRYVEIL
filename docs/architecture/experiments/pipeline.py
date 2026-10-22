"""Measure complete synthetic case pipeline, including checked repeated export."""
import json
import resource
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scryveil.parse import canonical, digest
from scryveil.report import build_report
from scryveil.store import CaseStore

start = time.perf_counter()
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    store = CaseStore(root / 'cases')
    cid = store.create('synthetic-budget', 'self')['case_id']
    for part in range(4):
        path = root / f'synthetic-{part}.ndjson'
        path.write_bytes(b''.join(canonical(dict(schema='scryveil.events/1', synthetic=True,
            event_type='network.observation', app=f'com.example.app{part}', domain='example.invalid',
            timestamp=(datetime(2026,1,1,tzinfo=UTC)+timedelta(seconds=i*60)).isoformat())) for i in range(5000)))
        store.import_file(cid,path,True)
    store.run(cid)
    report = build_report(store,cid)
    encoded = canonical(report)
    expected_digest = digest(encoded)
    report_bytes = len(encoded)
    records = len(report['timeline'])
    findings = len(report['analysis']['findings'])
    del report, encoded  # Sequential exports, not two complete reports retained by a caller.
    assert expected_digest == digest(canonical(build_report(store,cid)))
    print(json.dumps({'records':records, 'findings':findings,
        'seconds':time.perf_counter()-start, 'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'report_bytes':report_bytes,'identical_repeated_export':True}))
