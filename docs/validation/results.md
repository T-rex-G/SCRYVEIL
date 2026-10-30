# Verified validation

Later qualification and current limits: [diagnostic/model milestone](diagnostic-model-milestone.md). The counts and no-model statements below describe the earlier checkpoint, not current untested claims.

## Current privacy-review continuation — 2026-10-23

Baseline before this continuation: `ba4414257233e6683dab563afa4682c7cde47956` on `feat/forensic-core-genesis` (PR #1). Linux x86_64, CPython 3.12.14, pinned developer tools from `requirements-dev.lock`. All data used here is independently generated; no phone or private export was accessed.

The final local test run passed **159 tests in 8.72 s** (95 prior tests plus 64 added cases). Ruff lint/format, strict mypy (10 source files), Bandit and repository hygiene passed. Source distribution and wheel built successfully. The wheel was installed without dependencies into a separate virtual environment; `doctor` and both complete CLI demos passed from `/tmp`, outside the checkout. CI now runs these installed-wheel demos too. These checks establish the exercised synthetic behavior and static checks, not real-device conformance or spyware-detection accuracy.

The new privacy review tests cover exact microsecond intervals; partial, reversed and ambiguous boundaries; identifier/resource/broadcaster conflicts; duplicate source retention; independent exports; unknown attribution/tracking/context; default redaction and explicit private JSON; report-source partition and arithmetic; changed originals; no-network CLI behavior; and the versioned JSON Schema. Ten fixed random seeds generate **1,000 independent known-duration sessions** with reordered records, duplicate boundaries and five UTC offsets. All generated durations were recovered exactly. This is an algorithmic oracle, not a statistical estimate of field accuracy.

Additional regressions reject boolean/integer/float substitutions in stored normalized evidence, forged findings before analyst review, boolean thresholds and enormous integer metadata/configuration without a traceback. Optimization regressions retain ASCII control rejection, printable Unicode and independent nested mutable event attributes.

The synthetic core demo still produces 9 events, the periodic review-needed observation and exact-domain indicator match, with identical repeated JSON. The new `scripts/privacy_demo.py` checks the actual CLI: 6 access records yield 2 complete intervals and 1 missing-end interval; 3 network records yield 2 distinct summaries with counts 25 and 40. Both duplicate provenance and redaction are checked, repeated reports are identical, and the explicit local identifier view works. Both demos label device validation **NOT TESTED**.

A compatibility experiment executed the previous baseline's modules in a separate temporary module path, created/analyzed/reviewed a synthetic case, then read it with this implementation. The old canonical analysis report was byte-identical and the saved state unchanged after the new privacy review. This checks the exercised baseline case without a migration; it is not exhaustive historical-case compatibility testing.

**Performance gate OPEN / NOT PASSED:** all samples are in `docs/architecture/experiments/privacy-results.json` and interpreted in ADR-001 section 11. Five privacy runs after bounded representation changes took 9.188–14.202 s, max 116,256 KiB RSS; five alternating core runs took 10.684–34.221 s, max 181,180 KiB. The later privacy capacity smoke took 16.486 s, max 116,344 KiB and produced an identical repeated 16,316,912-byte report. These revisions and the subsequent integer-error guards are distinguished in the measurement file. Memory stayed below the 256 MiB measured budget; the 10-second target is not currently satisfied. Earlier passing timing below is retained as history, not the current status.

Native runtime comparison, real Apple exports, per-OS-version behavior, macOS/Windows packaging and acquisition remain untested. No claim of superiority over Plaso, MVT or commercial tools is supported. Source research and known limitations are in `docs/research/apr-review-evidence.md` and `docs/privacy-review.md`. GitHub Actions must be checked for the published commit separately from these local results.

## Initial core validation — 2026-10-22 (historical)

Repository baseline: T-rex-G/SCRYVEIL main `dfef9764308a79a88f8b103cea27a00563606a89`. Main rechecked unchanged before publication. Branch: feat/forensic-core-genesis. Linux x86_64 / CPython3.12.14. No device or private export used.

| Executed command | Actual result |
|---|---|
| python -m venv .venv; .venv/bin/python -m pip install -e '.[dev]' | Editable package installed; dev pins subsequently upgraded after audit |
| .venv/bin/python -m pytest -q | 73 tests passed (unit/integration/adversarial/schema) |
| .venv/bin/python -m ruff check src tests scripts | Passed |
| .venv/bin/python -m ruff format --check src tests scripts | Passed |
| .venv/bin/python -m mypy src/scryveil | Passed, strict config, 8 source files; Any remains in persistence models |
| .venv/bin/python -m bandit -q -r src | Passed; static heuristic, not full audit |
| .venv/bin/python scripts/hygiene.py | Passed synthetic allowlist and credential/path heuristics; not complete DLP |
| .venv/bin/python scripts/demo.py | 9 synthetic events, periodic review_needed + exact-domain indicator_match; identical repeated JSON report |
| .venv/bin/python -m build --no-isolation | Source distribution and wheel built |
| isolated venv pip install --no-index --no-deps dist/*.whl; scryveil doctor outside checkout | Installed-wheel CLI ran; no third-party runtime package needed |
| python docs/architecture/experiments/run.py | 30 Python/TS spike runs, equal normalized output hashes; all samples recorded |
| .venv/bin/python docs/architecture/experiments/pipeline.py (5 isolated processes) | 20,000 records each, 7.368–8.564s, max181,212KiB, identical sequential export |
| isolated pip-audit 2.9.0 --no-deps --disable-pip -r requirements-dev.lock | Initial three vulnerable dev/build pins corrected; final no known vulnerabilities in queried lock |

Synthetic demo excerpt:

```json
{"synthetic":true,"events":9,"findings":[{"rule":"periodic.metadata","assessment":"review_needed"},{"rule":"ioc.domain.exact","assessment":"indicator_match"}],"identical_repeated_report":true,"device_validation":"NOT TESTED"}
```

Tests cover original preservation, hashes/byte offsets, duplicate source idempotence, equal-time sample inflation, malformed/oversized/nonfinite/duplicate-key/nested JSON, naive/invalid/offset timestamps, ordering warnings, rejected archives/plists/symlinks/FIFOs/traversal, source/event/finding/audit tampering, absent IDs and out-of-interval supports, malicious strings, allowlist redaction, no-network core, benign/noisy/minimal/empty fixtures, APR summary exclusion, bounded IOC joins, explicit analyst review and JSON Schema contracts.

Important failed observations preserved: initial static type/lint issues fixed; initial production retained-two-report RSS exceeded budget; unnecessary copies removed and sequential export retention measured separately. See ADR-001. Initial advisory IDs: PYSEC-2026-1845 (pytest), PYSEC-2026-3447 (setuptools), GHSA-8rrh-rw8j-w5fx (wheel). Pinned fixes:9.0.3/83.0.0/0.46.2. No upstream source/test suite/binary or actual device acquisition executed.

GitHub Actions status is separate from local results; inspect the PR checks for the published commit. No preemptive green CI claim. Runtime comparison for Rust/Go/Swift, macOS, Windows, real APR exports, phone services, vulnerability-detection accuracy and future tool adapters remain NOT TESTED.

## Saved-case hardening continuation (2026-10-22)

95 tests pass (73 existing plus 22 metadata corruption/history regressions). Cases now validate closed metadata field sets and operational history before use: consent, collection mode, strict boolean/integer distinctions, valid UTC metadata dates, runtime values, artifact order, nonempty creation audit, analysis input/config binding, and review decisions tied to audit operations. Corruption tests recompute audit hashes to exercise semantic checks independently of the hash chain. Historical reviews survive later imports and reanalysis; repeated exports remain identical. The run start clock is captured before analysis. Existing 0.1.0 cases remain supported; no migration or runtime dependency was added.

Ruff lint/format, strict mypy, Bandit, repository hygiene, synthetic CLI demo and source/wheel build passed. This continuation does not establish real-version APR conformance, hostile-local-user isolation, authenticated metadata, or a fresh performance benchmark.

## Diagnostic investigation continuation

See [current investigation qualification](investigation-results.md) for the 244-test suite, original-format compatibility comparison, OS/HTTP/TLS adversarial checks, installed-wheel demos, five-run measurements and explicit open gates. Older results in this file remain historical rather than claims of final-head qualification.
