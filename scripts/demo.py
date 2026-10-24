"""One-command synthetic CLI demo, temporary private cases only."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic"
    with tempfile.TemporaryDirectory(prefix="scryveil-synthetic-") as temp:
        base = [sys.executable, "-m", "scryveil", "--root", str(Path(temp) / "cases")]

        def cli(*args: str) -> dict:
            output = subprocess.run(
                [*base, *args], check=True, capture_output=True, text=True, timeout=30
            )
            return json.loads(output.stdout)

        cli("doctor")
        case_id = cli("case", "create", "--label", "synthetic-demo", "--consent", "self")["case_id"]
        for name in ["periodic.ndjson", "indicators.ndjson", "privacy_report.ndjson"]:
            cli("evidence", "import", "--case", case_id, "--synthetic", str(fixtures / name))
        cli("analyze", "--case", case_id)
        result = cli("report", "export", "--case", case_id, "--format", "json")
        again = cli("report", "export", "--case", case_id, "--format", "json")
        if result != again:
            raise RuntimeError("report not reproducible")
        print(
            json.dumps(
                {
                    "synthetic": True,
                    "events": len(result["timeline"]),
                    "findings": [
                        {"rule": f["rule_id"], "assessment": f["assessment"]}
                        for f in result["analysis"]["findings"]
                    ],
                    "identical_repeated_report": True,
                    "device_validation": "NOT TESTED",
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
