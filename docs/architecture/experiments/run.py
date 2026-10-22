"""Run bounded cross-runtime spike. Emits measurements, never an overall language rank."""
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

here = Path(__file__).resolve().parent
result = {'host': {'system': platform.platform(), 'machine': platform.machine(),
                   'cpu_count_visible': os.cpu_count(), 'python': platform.python_version(),
                   'node': subprocess.check_output(['node','--version'],text=True).strip(),
                   'cpu': next((x.strip().split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')), 'unknown'),
                   'rustc':shutil.which('rustc'), 'go':shutil.which('go'), 'swift':shutil.which('swift'), 'tsc':shutil.which('tsc')},
          'method': '5 isolated processes per runtime/size; alternating runtime order; warm file cache; includes runtime startup in wall; self peak RSS on Linux; same input/output SHA required; no sandbox or security parity claim', 'runs': []}
with tempfile.TemporaryDirectory() as temp:
 for count in (100,5000,20000):
  path=Path(temp)/'synthetic.ndjson'
  start=datetime(2026,1,1,tzinfo=UTC)
  path.write_text(''.join(json.dumps({'app':f'com.example.app{i%13}', 'domain':'EXAMPLE.INVALID.', 'timestamp':(start+timedelta(seconds=i)).isoformat()})+'\n' for i in range(count)))
  hashes=set()
  for repeat in range(5):
   for lang in (('python','typescript') if repeat%2==0 else ('typescript','python')):
    cmd=[sys.executable,str(here/'normalize.py')] if lang=='python' else ['node',str(here/'normalize.ts')]
    t=time.perf_counter()
    p=subprocess.run([*cmd,str(path)],capture_output=True,text=True,check=True,timeout=30)
    wall=time.perf_counter()-t
    entry=json.loads(p.stdout)
    hashes.add(entry['output_sha256'])
    result['runs'].append(dict(language=lang,repeat=repeat,wall_seconds=wall,input_bytes=path.stat().st_size,**entry))
  assert len(hashes)==1, 'semantic output mismatch'
result['summary']=[]
for count in (100,5000,20000):
 for lang in ('python','typescript'):
  rows=[r for r in result['runs'] if r['language']==lang and r['records']==count]
  result['summary'].append(dict(language=lang,records=count,median_wall_seconds=statistics.median(r['wall_seconds'] for r in rows), median_work_seconds=statistics.median(r['seconds'] for r in rows),max_peak_rss_kib=max(r['peak_rss_kib'] for r in rows)))
print(json.dumps(result,indent=2))
