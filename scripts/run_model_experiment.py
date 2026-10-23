"""Launch the pinned CPU server inside an already isolated network namespace."""

import json
import os
import resource
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

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
            "0",
            "--n-predict",
            "1024",
            "--no-webui",
            "--no-context-shift",
        ],
        stdout=log,
        stderr=log,
        env=dict(os.environ),
    )
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
            [sys.executable, str(root / "scripts/model_qualification.py")], check=True, timeout=1200
        )
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
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
                    "network": "loopback_only",
                }
            ),
            flush=True,
        )
