"""Defense-in-depth source/fixture gate; not complete secret or PII detection."""

import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
paths = (
    subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    )
    .decode()
    .split("\0")
)
errors = []
blocked = {".pcap", ".pcapng", ".db", ".sqlite3", ".mobileconfig", ".pem", ".p12", ".pfx", ".age"}
patterns = [
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    rb"gh[pousr]_[A-Za-z0-9]{30,}",
    rb"AKIA[A-Z0-9]{16}",
]
for name in sorted(set(paths) - {""}):
    path = root / name
    if (
        path.is_symlink()
        or any(p in {".cases", "cases", "evidence", "private_data"} for p in Path(name).parts)
        or path.suffix in blocked
        or path.name.startswith(".env")
    ):
        errors.append("forbidden path")
        continue
    raw = path.read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        errors.append("unexpected large tracked file")
    if any(re.search(p, raw) for p in patterns):
        errors.append("possible credential")
fixtures = root / "fixtures/synthetic"
manifest = json.loads((fixtures / "manifest.json").read_text())
actual = {p.name for p in fixtures.iterdir() if p.suffix in {".ndjson", ".ips"}}
if not manifest.get("synthetic") or actual != set(manifest["files"]):
    errors.append("fixture allowlist mismatch")
for path in fixtures.glob("*.ips"):
    head, body = path.read_bytes().split(b"\n", 1)
    meta = json.loads(head)
    if meta.get("scryveil_fixture") is not True:
        errors.append("ips fixture provenance missing")
    if meta.get("bug_type") == "145":
        names = re.findall(r"^Command:[ \t]+([^\r\n]+)$", body.decode(), re.MULTILINE)
    else:
        report = json.loads(body)
        names = (
            [report["procName"]]
            if "procName" in report
            else [p["name"] for p in report.get("processes", [])]
        )
    if not names or any(not n.startswith("com.example.") for n in names):
        errors.append("nonfictional ips process")
for path in fixtures.glob("*.ndjson"):
    for line in path.read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            if path.name != "malformed.ndjson":
                errors.append("unexpected malformed fixture")
            continue
        if "domain" in item and not item["domain"].lower().rstrip(".").endswith(".invalid"):
            errors.append("nonreserved fixture domain")
        app = item.get("app", item.get("bundleID", item.get("accessor", {}).get("identifier")))
        if app and not app.startswith("com.example."):
            errors.append("nonfictional fixture app")
if errors:
    raise SystemExit("hygiene failed: " + ", ".join(sorted(set(errors))))
print(
    f"hygiene passed: {len(set(paths) - {''})} source files, {len(actual)} allowlisted synthetic fixtures"
)
