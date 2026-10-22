# SCRYVEIL
Open-source mobile forensic research and threat investigation platform for spyware detection, behavioral analysis, and AI-assisted digital evidence examination.

## Current state

The description above is the project ambition. This release is a **working offline research CLI**, not a live iPhone scanner, full forensic suite or AI assistant. No hardware has been validated. It cannot certify a device spyware-free.

The [stack-neutral ADR-001](docs/architecture/ADR-001-runtime-and-language-selection.md) compares Python, Rust, Go, Swift, TypeScript and minimal hybrids. It selects Python for the bounded Phase 1 based on workload/safety/integration trade-offs, documents actual measurements, and defines explicit revisit gates. It does not prescribe Python for every future component.

Implemented: consent-scoped local cases; preserved originals and SHA-256; bounded NDJSON import; explicit-offset timestamps and byte/line locators; source warnings and coverage; deterministic periodicity on synthetic timed observations; exact domain IOC matching; competing hypotheses; analyst review; provenance graph; repeatable redacted JSON/Markdown reports that revalidate original bytes and findings.

**Experimental real-format parser:** Apple App Privacy Report `access` and `networkActivity` NDJSON. Only independently generated fixtures were tested. Network `hits`/first/latest timestamps are summaries and never used as packet timing. Unknown format variations remain warnings. No backup/sysdiagnose/archive/PCAP/USB/Android/AI adapter is implemented.

## Install and demo (Linux, Python 3.12+)

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-build-isolation --no-deps -e .
scryveil --help
scryveil doctor
python scripts/demo.py
```

Installation needs packages available locally or network access. The core has **zero runtime dependencies**; analysis/demo/test data need no network, iPhone or API key. For core-only installation, `python -m pip install .` installs the package using the pinned build backend. Download/build a wheel in advance for an offline host, then `python -m pip install --no-index --no-deps PATH_TO_WHEEL`.

One-command `python scripts/demo.py` creates temporary private synthetic cases, imports three fixtures, analyzes and verifies identical repeated JSON export. Expected summary: 9 events; `periodic.metadata: review_needed`; `ioc.domain.exact: indicator_match`; real-device validation `NOT TESTED`. Temporary demo cases are removed on completion.

## Persistent synthetic walkthrough

```sh
umask 077
CASE_ID=$(scryveil case create --label synthetic-demo --consent self | python -c 'import json,sys; print(json.load(sys.stdin)["case_id"])')
scryveil evidence import --case "$CASE_ID" --synthetic fixtures/synthetic/benign_sync.ndjson
scryveil analyze --case "$CASE_ID"
scryveil findings --case "$CASE_ID"
scryveil report export --case "$CASE_ID" --format json > .cases/report.json
scryveil report export --case "$CASE_ID" --format markdown > .cases/report.md
scryveil case list
```

Benign scheduled sync produces an **inconclusive** regularity observation with an explicit benign-context alternative, never a malware label. That context is an unverified declaration. A periodic sample is a lead, not proof; no-data means insufficient evidence. IOC matching is exact normalized-domain equality, not trusted threat-intelligence validation. No feeds are downloaded.

Use `--root /private/cases` **before** the command to choose a store. Existing store directories must be owner-only (0700). Cases are unencrypted; choose an encrypted local volume. Use `--consent authorized` only with explicit authorization. `--synthetic` is required for generated fixtures and must be omitted for actual owner-authorized APR exports. Do not place real exports in the checkout.

`review --case CASE_ID --finding FINDING_ID --decision accepted_benign` appends an analyst decision; it preserves the original finding and detector assessment. `analyze --min-events 5 --min-window 240` exposes sample/window controls; full parameters are recorded. Reports retain timestamps/hashes: redacted is not anonymous.

Stable exit codes: `0` success, `2` invalid input/arguments **or imported record warnings**, `3` case busy/analysis required, `4` local I/O/state/lineage failure. A partial import retains original bytes plus warnings; exit 2 does not mean nothing was imported. Errors omit private paths. Archive/plist input is unsupported and never decompressed.

## Validation

```sh
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src/scryveil
python -m bandit -q -r src
python scripts/hygiene.py
python -m build --no-isolation
```

[Validation results](docs/validation/results.md), [limits](docs/validation/known-limitations.md), [hardware matrix](docs/validation/hardware-matrix.md), [schemas](docs/evidence-schema.md), [threat model](docs/threat-model.md) and [upstream research](docs/research/upstream-assessment.md) distinguish tests from documentation claims. GitHub CI uses read-only permissions, pinned actions, synthetic fixtures and no artifact uploads.

## Next bounded milestone

Validate APR variations against consented, locally held real exports without committing them; add explicitly synthetic regression shapes and stricter persisted-state typed validation. Then design one original sysdiagnose plaintext subartifact parser with independent source provenance. Tool adapters, large-case storage, acquisition and UI each require their own evidence-backed gate. No real evidence belongs in GitHub, issues or model services.
