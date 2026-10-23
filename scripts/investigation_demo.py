"""Demonstrate the complete diagnostic investigation with fictional evidence."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures/synthetic"
    with tempfile.TemporaryDirectory(prefix="scryveil-investigation-synthetic-") as temp:
        root = Path(temp) / "cases"
        base = [sys.executable, "-m", "scryveil", "--root", str(root)]

        def cli(*args: str) -> bytes:
            return subprocess.run(
                [*base, *args], check=True, capture_output=True, timeout=30
            ).stdout

        cid = json.loads(
            cli("case", "create", "--label", "synthetic-diagnostics", "--consent", "self")
        )["case_id"]
        for name in (
            "diagnostic-0.ips",
            "diagnostic-1.ips",
            "diagnostic-2.ips",
            "diagnostic-jetsam.ips",
        ):
            cli(
                "evidence",
                "import",
                "--case",
                cid,
                "--synthetic",
                "--format",
                "ips",
                str(fixtures / name),
            )
        protected = [root / cid / "state.json", *(root / cid / "originals").iterdir()]
        before = {p: p.read_bytes() for p in protected}
        deterministic = json.loads(cli("diagnostics", "report", "--case", cid))
        args = (
            "--case",
            cid,
            "--question",
            "Why does this fictional search service repeatedly fail?",
        )
        preview = json.loads(cli("investigate", "preview", *args))
        first = cli("investigate", "run", *args)
        report = json.loads(first)
        if report["status"] != "completed" or report["requests"] != 8:
            raise RuntimeError("investigation incomplete")
        measurement = report["result"]["derived_measurements"][0]
        if (
            measurement["distinct_reported_incidents"] != 4
            or len(measurement["contradictory_evidence_ids"]) != 1
        ):
            raise RuntimeError("recurrence or contrary evidence lost")
        if first != cli("investigate", "run", *args) or before != {
            p: p.read_bytes() for p in protected
        }:
            raise RuntimeError("reproducibility or preservation failure")
        if b"com.example.searchd" in first or preview["quantities"]["events"] != 5:
            raise RuntimeError("minimization or disclosure mismatch")
        if deterministic["findings"] != report["deterministic_findings"]:
            raise RuntimeError("AI changed deterministic findings")
        print(
            json.dumps(
                {
                    "synthetic": True,
                    "events": 5,
                    "distinct_incidents": 4,
                    "contrary_evidence": 1,
                    "requests": 8,
                    "status": report["status"],
                    "originals_unchanged": True,
                    "identical_repeated_report": True,
                    "provider": "deterministic mock; no model or network",
                    "real_export_qualification": "OPEN",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
