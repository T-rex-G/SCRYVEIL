"""Compare previous-code synthetic cases with current report interpretations.

Requires the baseline Git object locally; does not alter a working branch/case.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
python = sys.executable
with tempfile.TemporaryDirectory(prefix="scryveil-old-contract-") as t:
    root = Path(t)
    old = root / "baseline"
    old.mkdir()
    paths = (
        subprocess.check_output(
            [
                "git",
                "ls-tree",
                "-r",
                "--name-only",
                "edbe9b135c25614161151ff679a02b690640b674",
                "src/scryveil",
            ],
            cwd=repo,
        )
        .decode()
        .splitlines()
    )
    for p in paths:
        dest = old / Path(p).relative_to("src")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(
            subprocess.check_output(
                ["git", "show", "edbe9b135c25614161151ff679a02b690640b674:" + p], cwd=repo
            )
        )
    code = """
import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from scryveil.store import CaseStore
from scryveil.parse import canonical
from scryveil.report import build_report
from scryveil.privacy import build_privacy_report
root,fixtures=Path(sys.argv[2]),Path(sys.argv[3])
store=CaseStore(root/'cases')
if sys.argv[4]=='old':
    for f in sorted(fixtures.glob('*.ndjson')):
        cid=store.create('synthetic','self')['case_id']
        store.import_file(cid,f,True); store.run(cid)
        (root/(cid+'.report')).write_bytes(canonical(build_report(store,cid)))
        (root/(cid+'.privacy')).write_bytes(canonical(build_privacy_report(store,cid)))
else:
    for expected in root.glob('*.report'):
        cid=expected.stem
        assert expected.read_bytes()==canonical(build_report(store,cid))
        assert expected.with_suffix('.privacy').read_bytes()==canonical(build_privacy_report(store,cid))
"""
    for src, mode in [(old, "old"), (repo / "src", "new")]:
        subprocess.run(
            [python, "-c", code, str(src), str(root), str(repo / "fixtures/synthetic"), mode],
            check=True,
            capture_output=True,
        )
    print(
        json.dumps(
            {
                "baseline": "edbe9b135c25614161151ff679a02b690640b674",
                "cases": len(list(root.glob("*.report"))),
                "old_case_reports_byte_equal": True,
                "old_privacy_reports_byte_equal": True,
            }
        )
    )
