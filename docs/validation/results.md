# Verified local validation — 2026-10-22

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
