"""Execute historical readers, then verify their synthetic IPS cases with current code.

Requires the checkpoint Git object. No existing case or checkout is modified.
Includes a body-version-2 report that the old reader marked unqualified.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINES = {
    "cccacdd5d795570cea365cfcebe4e2a0ed4ce122": [
        "diagnostic-0.ips",
        "diagnostic-1.ips",
        "diagnostic-2.ips",
        "diagnostic-jetsam.ips",
        "diagnostic-v2-crash.ips",
    ],
    "948ec27395765cdbde9f39fb38d1753ff24e2a8e": [
        "diagnostic-v2-crash.ips",
        "diagnostic-v2-exception.ips",
        "diagnostic-text-resource.ips",
        "diagnostic-text-annotated.ips",
    ],
}
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
names=json.loads(sys.argv[5])
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


def check(baseline, names, tmp):
    root = Path(tmp)
    old = root / "baseline"
    paths = (
        subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", baseline, "src/scryveil"], cwd=ROOT
        )
        .decode()
        .splitlines()
    )
    assert paths, "baseline Git object unavailable"
    for path in paths:
        dest = old / Path(path).relative_to("src")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(subprocess.check_output(["git", "show", baseline + ":" + path], cwd=ROOT))
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
                json.dumps(names),
            ],
            check=True,
        )
    print(
        json.dumps(
            {
                "baseline": baseline,
                "cases": len(list(root.glob("*.report"))),
                "old_analysis_reports_byte_equal": True,
                "old_investigation_snapshots_byte_equal": True,
                "reimports_retain_original_reader_and_events": True,
                "original_hashes_unchanged": True,
            }
        )
    )


for baseline, names in BASELINES.items():
    with tempfile.TemporaryDirectory(prefix="scryveil-checkpoint-contract-") as tmp:
        check(baseline, names, tmp)
