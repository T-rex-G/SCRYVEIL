"""Run the privacy-review CLI against a fictional APR fixture, fully offline."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures/synthetic/privacy_sessions.ndjson"
    with tempfile.TemporaryDirectory(prefix="scryveil-privacy-synthetic-") as temp:
        base = [sys.executable, "-m", "scryveil", "--root", str(Path(temp) / "cases")]

        def cli(*args: str) -> bytes:
            return subprocess.run(
                [*base, *args], check=True, capture_output=True, timeout=30
            ).stdout

        cid = json.loads(
            cli("case", "create", "--label", "synthetic-privacy", "--consent", "self")
        )["case_id"]
        cli("evidence", "import", "--case", cid, "--synthetic", str(fixture))
        first = cli("privacy", "report", "--case", cid)
        if first != cli("privacy", "report", "--case", cid):
            raise RuntimeError("privacy report not reproducible")
        report = json.loads(first)
        if report["summary"]["interval_status_counts"] != {"complete": 2, "missing_end": 1}:
            raise RuntimeError("unexpected interval results")
        if sorted(r["reported_hits"] for r in report["network_summaries"]) != [25, 40]:
            raise RuntimeError("network summaries were incorrectly aggregated")
        markdown = cli("privacy", "report", "--case", cid, "--format", "markdown")
        if any(
            value in first + markdown
            for value in (b"com.example.", b"privacy.example.invalid", b"fixture-camera")
        ):
            raise RuntimeError("identifier redaction failed")
        private = json.loads(cli("privacy", "report", "--case", cid, "--include-identifiers"))
        if private["apps"][0]["identifier"] != "com.example.privacydemo":
            raise RuntimeError("local private view missing identifier")
        print(
            json.dumps(
                {
                    "synthetic": True,
                    **report["summary"],
                    "identical_repeated_report": True,
                    "raw_identifiers_redacted": True,
                    "device_validation": "NOT TESTED",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
