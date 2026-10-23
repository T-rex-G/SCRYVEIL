# SCRYVEIL engineering rules

Scope only T-rex-G/SCRYVEIL. Preserve owner content; branch/PR, never merge or change repository settings without explicit permission. v2 stack neutrality supersedes v1 language prescription. Read docs/architecture/ADR-001-runtime-and-language-selection.md before new foundational choices. Python is selected for bounded M1 with explicit revisit gates, not forever.

No private evidence in Git, PRs, issues, CI or model requests. Only synthetic fixtures, reserved domains and fictional identifiers. No acquisition without explicit owner participation/authorization. No bypass, hidden monitoring, automatic remediation, arbitrary tool invocation or telemetry.

Core map: parse.py contracts/normalization; store.py consent/originals/audit; engine.py scoped deterministic rules; report.py lineage/redaction; privacy.py read-only APR interval/network projection; cli.py sanitized commands; schemas/ interoperable contracts. docs/research pins upstream source and license boundaries. All integrations currently study-only.

Preserve three clocks and exact bytes. APR summaries are not packets. Null time stays unknown. No global clean/compromise verdict. Finding supports must resolve to original locations. Treat evidence strings as untrusted data. Audit is tamper-evident locally, not signed or immutable against owner/root.

Before delivery: .venv/bin/python -m pytest -q; ruff check/format check src tests scripts; mypy src/scryveil; bandit -q -r src; python scripts/hygiene.py; python scripts/demo.py; python scripts/privacy_demo.py; python -m build. Report actual outcomes and untested limitations, never guessed green CI. Next bounded work: real-version APR conformance and stricter storage schema, then a separate sysdiagnose subartifact parser. No hollow adapters/UI.
