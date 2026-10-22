# SCRYVEIL Phase 1 design

Runtime decision reviewed 2026-10-22 under the owner's stack-neutral v2 correction: see [ADR-001](architecture/ADR-001-runtime-and-language-selection.md). Retain original Python3.12+ for bounded Phase1 after comparison and measurements; no upstream code imports or runtime dependencies. Research informed format contracts, not copied algorithms.

Import → bounded NDJSON validation → private hash-addressed originals → normalized records → deterministic rules → evidence confidence ledger → validated, redacted JSON/Markdown.

- Case-scoped JSON state is small, atomically replaced under an exclusive POSIX advisory lock. Each operation appends a hash-chained audit entry in the same transaction. This avoids SQLite dependencies and simplifies independent inspection. Bounds: 32 artifacts, 20,000 normalized records, 8 MiB per artifact, 64 KiB per line, 5,000 lines per input. A larger store is a future migration, not an unbounded load.
- Original bytes have SHA-256 identities and read-only file mode. Ingestion clocks are recorded independently of source clocks; source collection time is unknown, never inferred from import time. Every event has a byte range and line locator. Re-import is idempotent; repeated records remain visible but equal observation times do not inflate periodicity.
- Reports rehash originals, reparse events, and recompute analysis before export. Findings cite event IDs; graph edges cite the same IDs. Audit data is tamper-evident locally, not externally signed chain-of-custody proof.
- APR network summaries never feed the periodicity rule. This follows the `hits` aggregation in iphone-tracker-check and distinguishes Plaso's recorded-time model from packet time. The original APR parser accepts a documented subset; it is experimental pending legally shareable, versioned real-device validation.
- Periodicity operates only on synthetic timed observation inputs in this release. It demonstrates the original analytical core, not a validated live capture pipeline. IOC equality also accepts APR domains. Both include alternative explanations and coverage limits.
- No shell, plugin loader, archive extraction, network client, model client, HTML renderer or phone adapter in the runtime. Unknown formats fail explicitly. Acquisition tools with destructive or stateful options require a future reviewed allowlist.
- Reporting is an allowlist projection: raw names, identifiers, domains, label, consent text, payloads and reasons are private. Timestamps, hashes, record locators and rule statistics remain sensitive metadata. A redacted report is not anonymous.

Linux is the validated host. POSIX file permissions/locking are required; Windows storage is unsupported. macOS is not tested. Future UI consumes these contracts only after engine validation.

Sources: pinned upstream files and comparisons are in [research/upstream-assessment.md](research/upstream-assessment.md). The bounded import and report invariants are additionally justified by executable adversarial tests.
