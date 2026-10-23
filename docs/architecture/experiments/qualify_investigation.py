"""Five sequential fresh-process runs per workload; checkpoint every sample."""

import hashlib
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[3]
folder = Path(__file__).parent
result = {"date": "2026-10-23", "host": platform.platform(), "python": platform.python_version(), "baseline_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(), "source_sha256": {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root / "src/scryveil").glob("*.py"))}, "method": "Five alternating sequential fresh processes per workload; shared runner, warm cache; no parallel benchmark jobs; script wall time starts after imports; process_wall_seconds includes interpreter startup; peak RSS per process, not aggregate concurrent resident memory; no real evidence or models.", "samples": []}
for iteration in range(5):
    for workload, arguments in [("core_20000", ["pipeline.py"]), ("privacy_20000", ["privacy_pipeline.py"]), ("diagnostics_32", ["diagnostic_pipeline.py"]), ("jetsam_20000_snapshot_2000", ["diagnostic_pipeline.py", "capacity"])]:
        measured_start = time.perf_counter()
        child = subprocess.run([sys.executable, str(folder / arguments[0]), *arguments[1:]], capture_output=True, text=True, timeout=120)
        if child.returncode:
            sample = {"error": child.stderr[-4000:], "exit_code": child.returncode}
        else:
            sample = json.loads(child.stdout)
        sample["process_wall_seconds"] = time.perf_counter() - measured_start
        current = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root / "src/scryveil").glob("*.py"))}
        if current != result["source_sha256"]:
            raise RuntimeError("source changed during measurement")
        result["source_hashes_unchanged_during_run"] = True
        result["samples"].append({"iteration": iteration + 1, "workload": workload, **sample})
        output = folder / "investigation-results.json"
        temporary = output.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, indent=2) + "\n")
        temporary.replace(output)
        print(json.dumps(result["samples"][-1]), flush=True)
