"""Synthetic architecture spike, not a production parser."""
import hashlib
import json
import resource
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

start = time.perf_counter()
data = Path(sys.argv[1]).read_bytes()
rows = []
for line in data.splitlines():
    r = json.loads(line)
    rows.append([r['app'], r['domain'].lower().rstrip('.'),
                 datetime.fromisoformat(r['timestamp']).astimezone(UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')])
rows.sort()
output = json.dumps(rows, ensure_ascii=False, separators=(',', ':')).encode()
print(json.dumps({'input_sha256': hashlib.sha256(data).hexdigest(),
                  'output_sha256': hashlib.sha256(output).hexdigest(), 'records': len(rows),
                  'seconds': time.perf_counter()-start,
                  'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
