"""Execute cccacdd's reader, then verify its synthetic IPS cases with current code.

Requires the checkpoint Git object. No existing case or checkout is modified.
Includes a body-version-2 report that the old reader marked unqualified.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "cccacdd5d795570cea365cfcebe4e2a0ed4ce122"
CODE = """
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scryveil.store import CaseStore
from scryveil.parse import canonical,digest
from scryveil.report import build_report
from scryveil.investigation_tools import snapshot_case
root,fixtures=Path(sys.argv[2]),Path(sys.argv[3])
store=CaseStore(root/'cases')
names=['diagnostic-0.ips','diagnostic-1.ips','diagnostic-2.ips',
       'diagnostic-jetsam.ips','diagnostic-v2-crash.ips']
if sys.argv[4]=='old':
    for group in [[n] for n in names]+[names]:
        cid=store.create('synthetic','self')['case_id']
        for name in group:
            store.import_file(cid,fixtures/name,True,'ips')
        store.run(cid)
        (root/(cid+'.report')).write_bytes(canonical(build_report(store,cid)))
        (root/(cid+'.snapshot')).write_bytes(canonical(snapshot_case(store,cid,True)))
        (root/(cid+'.sources')).write_text(json.dumps(group))
else:
    for expected in root.glob('*.report'):
        cid=expected.stem
        assert expected.read_bytes()==canonical(build_report(store,cid))
        assert expected.with_suffix('.snapshot').read_bytes()==canonical(snapshot_case(store,cid,True))
        before=store.snapshot(cid)
        for name in json.loads(expected.with_suffix('.sources').read_text()):
            assert store.import_file(cid,fixtures/name,True,'ips')['status']=='duplicate'
        after=store.snapshot(cid)
        assert before['events']==after['events'] and before['artifacts']==after['artifacts']
        for a in after['artifacts']:
            assert digest((root/'cases'/cid/'originals'/a['sha256']).read_bytes())==a['sha256']
"""

with tempfile.TemporaryDirectory(prefix="scryveil-checkpoint-contract-") as tmp:
    root = Path(tmp)
    old = root / "baseline"
    paths = (
        subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", BASELINE, "src/scryveil"], cwd=ROOT
        )
        .decode()
        .splitlines()
    )
    assert paths, "baseline Git object unavailable"
    for path in paths:
        dest = old / Path(path).relative_to("src")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(subprocess.check_output(["git", "show", BASELINE + ":" + path], cwd=ROOT))
    for src, mode in [(old, "old"), (ROOT / "src", "new")]:
        subprocess.run(
            [
                sys.executable,
                "-c",
                CODE,
                str(src),
                str(root),
                str(ROOT / "fixtures/synthetic"),
                mode,
            ],
            check=True,
        )
    print(
        json.dumps(
            {
                "baseline": BASELINE,
                "cases": len(list(root.glob("*.report"))),
                "old_analysis_reports_byte_equal": True,
                "old_investigation_snapshots_byte_equal": True,
                "reimports_retain_original_reader_and_events": True,
                "original_hashes_unchanged": True,
            }
        )
    )
