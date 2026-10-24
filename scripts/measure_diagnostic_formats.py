"""Measure 30 generated mixed-format reports, including bounded-query failures.

Three fresh sequential processes, no provider or network. Output is JSON only;
redirect it to an explicitly selected measurement file. No throughput extrapolation.
"""

import json
import platform
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from scryveil.investigation import investigate
from scryveil.investigation_tools import ReadOnlyTools, snapshot_case
from scryveil.parse import canonical, digest
from scryveil.providers import DEFAULT_CONFIG
from scryveil.store import CaseStore

ROOT = Path(__file__).resolve().parents[1]
NAMES = ("diagnostic-v2-crash.ips", "diagnostic-v2-exception.ips", "diagnostic-text-resource.ips")


def sample():
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="scryveil-format-measurement-") as tmp:
        base = Path(tmp)
        store = CaseStore(base / "cases")
        cid = store.create("synthetic-format-volume", "self")["case_id"]
        for index in range(30):
            raw = (ROOT / "fixtures/synthetic" / NAMES[index % 3]).read_bytes()
            header = json.loads(raw.split(b"\n", 1)[0])
            assert header["scryveil_fixture"] is True
            raw = raw.replace(header["incident_id"].encode(), f"fictional-volume-{index}".encode())
            source = base / f"generated-{index}.ips"
            source.write_bytes(raw)
            store.import_file(cid, source, True, "ips")
        imported = time.monotonic()
        snapshot = snapshot_case(store, cid)
        tools = ReadOnlyTools(snapshot)
        queries = {}
        for limit in (5, 10, 25):
            reply = tools.call("diagnostics.search", {"limit": limit})
            queries[str(limit)] = {
                "ok": reply["ok"],
                "error": reply.get("error"),
                "serialized_bytes": len(canonical(reply)),
                "returned_events": len(reply.get("evidence_ids", [])),
                "truncated": reply["truncated"],
            }
        config = {**DEFAULT_CONFIG, "max_total_tokens": 200000}
        first = investigate(
            store, cid, "Compare recurrence, contrary evidence and coverage.", config
        )
        second = investigate(
            store, cid, "Compare recurrence, contrary evidence and coverage.", config
        )
        assert canonical(first) == canonical(second)
        assert snapshot_case(store, cid)["source_state_sha256"] == snapshot["source_state_sha256"]
        return {
            "seconds": time.monotonic() - started,
            "import_seconds": imported - started,
            "parent_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "largest_child_peak_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            "records": len(snapshot["events"]),
            "snapshot_bytes": len(canonical(snapshot)),
            "query_limits": queries,
            "mock_status": first["status"],
            "mock_requests": first["requests"],
            "mock_reserved_token_estimate": first["reserved_token_estimate"],
            "max_total_tokens": config["max_total_tokens"],
            "context_policy": first.get("context"),
            "mock_errors": [row["error"] for row in first["trace"] if not row["ok"]],
            "repeated_report_identical": True,
            "originals_and_state_unchanged": True,
        }


if __name__ == "__main__":
    if sys.argv[1:] == ["--sample"]:
        print(json.dumps(sample()))
    else:
        hashes = {
            str(p.relative_to(ROOT)): digest(p.read_bytes())
            for p in sorted((ROOT / "src/scryveil").glob("*.py"))
        }
        samples = []
        for _ in range(3):
            started = time.monotonic()
            measured = json.loads(
                subprocess.check_output([sys.executable, __file__, "--sample"], timeout=60)
            )
            measured["process_wall_seconds"] = time.monotonic() - started
            samples.append(measured)
            assert all(digest((ROOT / p).read_bytes()) == sha for p, sha in hashes.items())
        print(
            json.dumps(
                {
                    "host": platform.platform(),
                    "python": platform.python_version(),
                    "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
                    .decode()
                    .strip(),
                    "runtime_sha256": hashes,
                    "measured_working_tree_modified": bool(
                        subprocess.check_output(
                            [
                                "git",
                                "status",
                                "--porcelain",
                                "--",
                                "src/scryveil",
                                "scripts/measure_diagnostic_formats.py",
                            ],
                            cwd=ROOT,
                        ).strip()
                    ),
                    "measurement_script_sha256": digest(Path(__file__).read_bytes()),
                    "method": "Three sequential fresh processes on shared Linux host; no concurrent local benchmark; process wall includes imports; RSS per process, not aggregate; no real evidence or model.",
                    "samples": samples,
                },
                indent=2,
            )
        )
