# SCRYVEIL
Open-source mobile forensic research and threat investigation platform for spyware detection, behavioral analysis, and AI-assisted digital evidence examination.

## Current state

The description above is the project ambition. This release is an **experimental forensic CLI with optional bounded AI investigation**. It is not a live iPhone scanner or complete forensic suite. No hardware or genuine owner export has been qualified. A pinned local model was actually evaluated on generated evidence; investigation quality has not passed. It cannot certify a device spyware-free.

The [stack-neutral ADR-001](docs/architecture/ADR-001-runtime-and-language-selection.md) compares Python, Rust, Go, Swift, TypeScript and minimal hybrids. It selects Python for the bounded Phase 1 based on workload/safety/integration trade-offs, documents actual measurements, and defines explicit revisit gates. It does not prescribe Python for every future component.

Implemented: consent-scoped local cases; preserved originals and SHA-256; bounded NDJSON import; explicit-offset timestamps and byte/line locators; source warnings and coverage; deterministic periodicity on synthetic timed observations; exact domain IOC matching; competing hypotheses; analyst review; provenance graph; repeatable redacted JSON/Markdown reports that revalidate original bytes and findings.

**Experimental real-format parsers:** Apple App Privacy Report `access`/`networkActivity` NDJSON and version-aware IPS subsets for 309/308 JSON body version 2, 145 disk-write text and legacy Jetsam reports. Only original generated fixtures were executed. Network aggregates never become packet timings; unknown format variations remain warnings. No backup/sysdiagnose/archive/PCAP/USB/Android acquisition or ingestion is implemented.

**New investigation slice:** deterministic diagnostic recurrence with contrary evidence; 11 versioned read-only tools; Linux syscall isolation; a mock provider and configurable chat-completions JSON adapter; consent-bound optional remote disclosure; evidence-linked JSON reports. The adapter has synthetic HTTP/TLS tests and a measured local CPU model experiment; transport execution is not a model-quality pass. See the [qualification history](docs/validation/diagnostic-model-milestone.md) and [latest actual-model results](docs/validation/qwen3-recovery-comparison.md). Versioned resource-duration parsing and an offline diagnostic coverage report are documented in the [resource continuation](docs/validation/resource-format-continuation.md); version 73 remains unqualified. Read the [capability assessment](docs/capability-assessment.md), [ADR-002](docs/architecture/ADR-002-read-only-ai-investigation.md) and [operator guide](docs/investigation.md).

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

Installation needs packages available locally or network access. The package has **zero third-party Python runtime dependencies**. Investigation additionally requires Linux and the system `libseccomp.so.2` library; it fails closed without isolation. Deterministic analysis and mock demos need no Internet, iPhone or API key. Tests use synthetic loopback HTTP/TLS peers. For core-only installation, `python -m pip install .` uses the pinned build backend. Download/build a wheel in advance for an offline host, then `python -m pip install --no-index --no-deps PATH_TO_WHEEL`.

One-command `python scripts/demo.py` creates temporary private synthetic cases, imports three fixtures, analyzes and verifies identical repeated JSON export. Expected summary: 9 events; `periodic.metadata: review_needed`; `ioc.domain.exact: indicator_match`; real-device validation `NOT TESTED`. Temporary demo cases are removed on completion.

Run `python scripts/investigation_demo.py` for the complete diagnostic slice: four fictional IPS reports, five events, four distinct incident declarations, one nonfatal contrary record and an eight-step mock investigation. Originals and case state remain unchanged. `diagnostics report` works without AI; `investigate preview` makes disclosure reviewable before a configured remote run. No external request is made by default.

Run `python scripts/diagnostic_formats_demo.py` for the new 309/308/145 triad: three observations, three distinct incident declarations, two contrary records, exact resource-line citations and an eight-step mock report. Genuine exports remain a separate authorization and qualification gate.

## Evidence-linked App Privacy Report review

The original case/analysis report remains available. A separate privacy review reconstructs documented resource-access intervals and displays network attribution from verified original bytes. It is useful without indicator feeds or AI. Real iPhone exports and OS-version compatibility are still unverified.

```sh
python scripts/privacy_demo.py
# After importing an owner-authorized APR into a private local case:
scryveil privacy report --case "$CASE_ID" --format markdown
scryveil privacy report --case "$CASE_ID" --format json
# Explicit local JSON view including app identifiers and domains:
scryveil privacy report --case "$CASE_ID" --include-identifiers
```

The synthetic demo produces two complete intervals, one missing end, and two separate network summaries with reported counts 25 and 40. Repeated reports are identical. Missing/ambiguous boundaries have no invented duration; repeated records retain all source references. Counts are never added across summaries/exports. Default reports omit raw identifiers; the explicit private JSON view includes app/domain identifiers, network context and domain owner. Protect both views as case data.

Read [privacy review semantics](docs/privacy-review.md) and [research basis](docs/research/apr-review-evidence.md). `privacy report` derives its own versioned observations without changing saved cases or requiring `analyze`. Exit 0 means a report was generated; inspect its coverage, issues and interval statuses for uncertainty.

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

Exit codes: `0` success, `2` invalid input/arguments **or imported record warnings**, `3` case busy/analysis required or incomplete investigation, `4` local I/O/state/lineage/isolation failure, `130` cancellation. A partial import retains original bytes plus warnings; exit 2 does not mean nothing was imported. Errors omit private paths. The explicit `collection import` route accepts bounded ZIP collections; unsupported members are preserved without interpretation. Plist/backup/PCAP decoding remains unsupported. See [collection investigation](docs/collections.md).

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

The latest five-run local 20,000-record measurements pass 10 seconds/256 MiB for the measured sequential core and privacy workloads. Earlier failures remain recorded. This is a bounded local qualification, not a general scalability guarantee; see [current measurements](docs/validation/investigation-results.md).

## Next bounded milestone

Qualify IPS/APR semantics on separately authorized local exports, improve the measured failures of actual local model investigation with egress disabled, and obtain independent boundary review. Then expand isolated artifact support and indexed persistence through the [prioritized milestones](docs/capability-assessment.md). Model use, collectors, large-case storage and UI require distinct evidence gates. No private evidence belongs in GitHub, CI or model services without separate explicit authorization.

For an end-to-end fictional collection of 266 members and 6,260 events, see [the collection CLI guide](docs/collections.md). Full-case queries and diagnostic details are explicit options; actual-model reasoning and genuine Apple-export qualification remain open.
