# SCRYVEIL engineering handoff

Updated 2026-10-24. Branch: `feat/forensic-core-genesis`; [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. Exact code/head checkpoint at reconciliation: **`948ec27395765cdbde9f39fb38d1753ff24e2a8e`** (tree `5cb7abeb2936af77e29bee76f3e35603d3daa229`). A documentation descendant may publish this record; use `git rev-parse HEAD` for that descendant's identity. Do not merge automatically.

## Preserved implementation and verification

- Bounded offline core; legacy NDJSON/APR; IPS 309/308 JSON v2 partial interpretation; legacy 104/298 readers; type-145 disk-write text summary reader. Original hashes, exact source locations and uncertainty preserved.
- Eleven versioned read-only investigation tools, Linux syscall isolation, provider broker, owner disclosure consent, strict exact-field fact validation and separately labeled model hypotheses. No device acquisition or unrestricted agent tools.
- At the code checkpoint: 273 tests passed locally; Ruff, format, strict mypy (18 modules), Bandit, fixture hygiene, four source/installed-wheel demos, wheel/sdist build and historical compatibility checks passed. [Core CI 40038068522](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40038068522) passed all steps. This is regression evidence, not forensic accuracy certification.
- Historical compatibility: ten NDJSON cases/twenty reports at `edbe9b1`; six diagnostic cases/snapshots/reports at `cccacdd`. See `scripts/check_legacy_compatibility.py` and `scripts/check_checkpoint_compatibility.py`.

## Recovered actual-model results

[Qwen3 reconciliation](../validation/qwen3-reconciliation.md) verifies run `40038068563` directly against retained original actions/reports. One of six runs completed mechanically, but zero accepted facts; the completed run retrieved no events. Injection exposure was absent. Injected query-error recovery failed. Repeated invalid arguments, premature finals and re-planning consumed budgets. Operational CI success must never be called successful model reasoning. The two earlier 1.5B failures are also preserved. No unchanged experiment was repeated.

The 30-report mixed-format mock benchmark previously stopped after six requests at the cumulative token-estimate budget. Original measurement files remain unchanged. This is a concrete context-management defect to address, not a reason to raise limits silently.

## In progress / next action

P0: implement bounded corrective feedback, repeated-error termination, compact model context with complete retained traces, and a meaningful nonempty-case completion floor. Add regressions for the recorded Qwen actions, forbidden operations and 30-report context failure. A new same-model experiment is justified only after these runtime changes are verified.

P0: independently research type-145 Report Version 73 and annotated duration representations. Version 73 is an owner compatibility lead, **not qualified**. Never change re-parsing of existing stored v2 cases silently: if interpretation changes, preserve the old reader and record a new reader version for new imports. Types 202/206/509/120 are unsupported leads, not evidence of compromise.

P1: improve explicit diagnostic coverage, omissions and unsupported-input accounting. Current case bound is 32 artifacts; default investigator snapshot is 2000 earliest events (max 20000). Missing records and unimported/rejected files are not inferable from an accepted case. Sysdiagnose/backups/profiles remain unsupported. Do not expand storage or languages without measurements.

## Reproduction and safety

Use the repository's pinned `.venv` or `pip install -e '.[dev]'`. Run `.venv/bin/python -m pytest -q`, Ruff check/format, mypy, Bandit, `scripts/hygiene.py`, all four demos, both compatibility scripts, `python -m build`, then the four demos in a fresh installed-wheel environment outside the checkout. Linux/libseccomp is required for investigation; unsupported isolation fails closed. `scripts/measure_diagnostic_formats.py` reproduces the generated 30-report workload.

The expensive synthetic-model workflow runs inference only when the selected head commit message contains `[model-qualification]`. Do not add that marker to documentation-only checkpoints. Model pins, sample generation and loopback-only controls are in the workflow and `scripts/run_model_experiment.py`. Retain failed results and review the actual actions, not just workflow status.

Pending separate owner authorization: receiving or processing private diagnostic files; any device connection/acquisition; any remote transmission of private evidence. No private diagnostics have been accessed in this continuation. Continue with public structural research and independently authored fictional fixtures. No API keys or genuine logs belong in Git/CI. ADR-001/002 and AGENTS.md remain applicable; no new framework or language decision is needed.
