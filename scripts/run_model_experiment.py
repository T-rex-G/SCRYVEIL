"""Launch the pinned CPU server inside an already isolated network namespace."""

import hashlib
import json
import os
import resource
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from model_timing import parse_server_line

root = Path(__file__).resolve().parents[1]
runtime = Path(sys.argv[1]).resolve()
# A model run must not silently fall back to the host's network namespace.
interfaces = {name for _, name in socket.if_nameindex()}
assert interfaces == {"lo"}, interfaces
probe = socket.socket()
probe.settimeout(1)
try:
    probe.connect(("192.0.2.1", 443))
except OSError:
    pass
else:
    raise RuntimeError("network isolation failed")
finally:
    probe.close()
os.environ.clear()
os.environ["LANG"] = "C.UTF-8"
started = time.monotonic()
server_metrics = []
log_metadata = {"bytes": 0, "saved_bytes": 0, "lines": 0}
log_hash = hashlib.sha256()
with (runtime / "model-server.log").open("wb") as log:
    child = subprocess.Popen(
        [
            str(runtime / "llama/build/bin/llama-server"),
            "--model",
            str(runtime / "model.gguf"),
            "--alias",
            "qualification-qwen",
            "--host",
            "127.0.0.1",
            "--port",
            "18080",
            "--ctx-size",
            "16384",
            "--parallel",
            "1",
            "--threads",
            "2",
            "--threads-batch",
            "2",
            "--seed",
            "41",
            "--temp",
            "0.7",
            "--top-p",
            "0.8",
            "--top-k",
            "20",
            "--min-p",
            "0",
            "--presence-penalty",
            "1.5",
            "--chat-template-kwargs",
            '{"enable_thinking":false}',
            "--jinja",
            "--n-predict",
            "1024",
            "--no-webui",
            "--no-context-shift",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=dict(os.environ),
    )

    def read_log():
        assert child.stdout is not None
        while line := child.stdout.readline(65537):
            log_metadata["bytes"] += len(line)
            log_metadata["lines"] += 1
            log_hash.update(line)
            saved = line[: max(0, 8 * 1024 * 1024 - log_metadata["saved_bytes"])]
            log.write(saved)
            log_metadata["saved_bytes"] += len(saved)
            if len(line) <= 65536 and len(server_metrics) < 10000:
                record = parse_server_line(
                    line.decode("utf-8", errors="replace"), time.monotonic() - started
                )
                if record is not None:
                    server_metrics.append(record)

    reader = threading.Thread(target=read_log, daemon=True)
    reader.start()
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("model server failed to start")
            try:
                with urllib.request.urlopen("http://127.0.0.1:18080/health", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.2)
        else:
            raise RuntimeError("model server readiness timeout")
        print("SCRYVEIL_NETWORK_BOUNDARY=loopback_only; external_route_unreachable", flush=True)
        subprocess.run(
            [
                sys.executable,
                str(root / "scripts/model_qualification.py"),
                "--scenario",
                "recurrence",
                "--adapter",
                "messages-tools",
            ],
            check=True,
            timeout=800,
        )
    finally:
        shutdown_started = time.monotonic()
        child.terminate()
        killed = False
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            killed = True
            child.kill()
            child.wait()
        reader.join(timeout=5)
        print(
            "SCRYVEIL_SERVER_TIMING="
            + json.dumps(
                {
                    "events": server_metrics,
                    "native_log": {
                        **log_metadata,
                        "sha256": log_hash.hexdigest(),
                        "retained_in_public_record": False,
                    },
                    "reader_finished": not reader.is_alive(),
                    "server_returncode": child.returncode,
                    "shutdown_seconds": time.monotonic() - shutdown_started,
                    "required_kill": killed,
                    "interpretation": "Server task IDs are not yet bound to adapter request IDs. Slot release alone does not identify cancellation cause; compare per-request deadlines and timing.",
                }
            ),
            flush=True,
        )
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        print(
            "SCRYVEIL_MODEL_RESOURCES="
            + json.dumps(
                {
                    "scope": "server and evaluation child processes; excludes build/download",
                    "wall_seconds": time.monotonic() - started,
                    "user_cpu_seconds": usage.ru_utime,
                    "system_cpu_seconds": usage.ru_stime,
                    "largest_child_peak_rss_kib": usage.ru_maxrss,
                    "model_threads": 2,
                    "enable_thinking": False,
                    "temperature": 0.7,
                    "top_p": 0.8,
                    "top_k": 20,
                    "min_p": 0,
                    "presence_penalty": 1.5,
                    "seed": 41,
                    "network": "loopback_only",
                }
            ),
            flush=True,
        )
