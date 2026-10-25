# SCRYVEIL engineering handoff

Updated 2026-10-25. Branch `feat/forensic-core-genesis`, [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. Verified collection implementation: `f5676df2528e3b64c42f820dbffeb0a4a9087db6`, tree `a3d8c6577b6eefbca9047e864e288aae570b54d7`. Verified native-provider implementation: `4040436af2a893bc9853bcb384024f018042b76a`, tree `801b7b5452b7091f01f9934a79ffceb45fdc7efe`; its CI 40181063602 passed 356 tests in 16.24s and all required checks. The current compact-context/batch follow-up is identified by its enclosing commit pending qualification. Collection measurements apply to f5676df, not later changed runtime files. Run `git rev-parse HEAD` and reconcile newer changes before continuing. Never merge automatically.

## Working capability

- Bounded ZIP collection import preserves original archive/member hashes, membership paths and byte boundaries, unsupported/malformed inventory, unknown ZIP clock offset and duplicate content identity. No path extraction or recursion. Limits: 1,000 members, 1,024 case artifacts, 20,000 events, 64 MiB ZIP/expanded data, 8 MiB/member, 256 MiB case originals, 64 MiB state.
- Opt-in `--all-events` makes every accepted event available to paged queries or fails above 16 MiB snapshot capacity. Legacy default snapshots remain unchanged. In-memory exact-match indexes; no database migration.
- Opt-in `--diagnostic-details` exposes process/exception/termination/source-symbol/OS fields, excluding executable paths and unrelated identifier fields. Exact access profile is consent-bound. Embedded sensitive strings remain a disclosure concern.
- Independent measurements group declared exception/termination/stack signatures, count condition flags, detect conflicting incident declarations, distinguish reasoned Jetsam entries from mere listings, and measure resource proximity without causality claims. Reference omissions are explicit. CLI produces source-linked JSON/Markdown.
- Preserved offline NDJSON/APR, three source clocks, locators, legacy IPS/versioned resource readers, eleven read-only tools, Linux syscall isolation, claim validation, budgets and remote consent. No new framework, language, runtime dependency, acquisition or unrestricted plugin.
- Instrumented model requests and allowlisted native-server timing. Reconciled the first timed recurrence failure and added a separate native Messages client-tool adapter, same permissions and consent. Native protocol/usage/error tests pass; actual-model comparison is the next gate. Corrected pagination in the published action schema, which had lagged runtime/tool schemas.

## Executed validation

Compact-native follow-up local validation: **360 tests passed in 11.26s**, Ruff/format, strict mypy (22 modules), Bandit, hygiene, historical executable compatibility, all five demos, sdist/wheel and installed-wheel demos. The preceding native checkpoint passed 356 tests locally and in CI. Its initial recurrence request was 2,152 bytes including its plan schema; the previous failed JSON context was 6,331 bytes. Smaller input is not proof of improved reasoning.

Local suite: **341 tests passed**, Ruff/check-format, strict mypy (21 modules), Bandit, hygiene, five demos, sdist/wheel and five installed-wheel demos outside checkout. Historical code creates ten NDJSON cases, six earlier IPS cases and five body-v2/text cases; current reports/snapshots remain byte-identical and reimports preserve interpretations/hashes.

[Checkpoint evidence](../validation/collection-continuation.md): 266 fictional members, 267 artifacts, 6,260 events, three signature groups of 80 incidents, zero full-case omissions. Three fresh processes: import 0.340–0.361s, whole workflow 2.783–2.920s, parent RSS 95,676–96,620 KiB. Eight mock requests complete using 155,992/200,000 conservative units, evidence unchanged. Prior six/seven-request budget failures are recorded. No smaller-default-budget, all-maximum-case, genuine-device or model-reasoning qualification is implied.

Security tests cover unsafe ZIP paths/types, nested/oversized content, false output lengths, CRC/descriptor/header mismatch, overlapping members, capacity rejection before state publication, forged lineage, injected symbols and forbidden calls through the worker. Archive parsing remains in the trusted owner process. IO interruption can leave checked content-addressed orphans; no automatic cleanup. Audit hashes are not independently authenticated custody.

Collection [core CI 40137879807](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40137879807), job 121003172786, passed 341 tests in 11.65s plus all required static/compatibility/demo/build/wheel checks. Native [core CI 40181063602](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40181063602) passed; the newer compact-context/batch follow-up requires its own CI.

## Actual-model gate remains failed

| Run | Source | Observed result |
|---|---|---|
| `40038068563` | `948ec27` | One mechanical completion among six, zero accepted facts; completed case read no events; injection unexposed. |
| `40070459394` | `dd27bf6` | Literal-search misuse; zero events/facts; unexplained empty-case completion subsequently rejected by the runtime. |
| `40090072225` | `4f55541` | Recurrence/injection each queried three events then timed out; zero completions/facts; fabricated tool-result envelopes rejected. |

Original records and earlier 1.5B failures remain in [reconciliation](../validation/qwen3-reconciliation.md) and [comparison](../validation/qwen3-recovery-comparison.md). Attack submission followed by timeout does not prove processing or resilience. Qwen3 4B CPU/non-thinking is unqualified. Native timings were absent; latency cannot be attributed solely to reasoning or host speed. Other models and hosted providers remain untested. Native Messages now passes synthetic HTTP/broker/worker protocol tests; its actual-model quality remains unqualified.

## Next action

1. Publish the compact-native checkpoint, inspect core CI and recover its gated recurrence/collection run. Native run 40181063497 is reconciled: accepted plan after 35.117s, second request timed out at 60.061s, zero queries/facts/completions; forced server shutdown after five seconds. Original records and prompt/generation measurements are retained. The f5676df JSON-action timing run 40137879901 is reconciled: first request timed out at 60.028s; zero replies/events/facts; no numeric server events collected. Original records and resource limits are retained in [native continuation](../validation/native-provider-continuation.md).
2. Native Messages translates only existing session/tool operations, accounts for cached inputs and full request bytes, and preserves complete call/result pairs. It has synthetic HTTP/worker validation, not actual-model qualification. The next comparison uses a smaller native schema view, stable policy prefix, exact same question/weights/budgets and 128-token server batches. Exact prior-plan replay is 7,393 bytes versus 8,813. Full worker validation remains unchanged. The 6,260-event model scenario is gated on a completed recurrence report with facts, coverage and contrary citations; skipped means unmeasured. Reconcile it before any further experiment; do not repeat an unchanged full suite. The target remains useful investigation over the generated collection.
3. Genuine Apple-export qualification remains open. Text version 73 is unqualified; types 202/206/509/120 unsupported. Do not obtain owner records without separate authorization.
4. Full sysdiagnose, TAR, backups/SQLite/plist interpretation, profiles, PCAP, live acquisition and Android remain unsupported. Storage/security migrations require measured justification.

The ten requested upstream projects were inspected selectively at source/license level in scratch. No upstream code/dependency was incorporated; unused comparisons were not added to public documentation. Applied lessons are concrete member provenance, bounded retrieval, diagnostic semantics and symbolication uncertainty. ADR-001/002 remain applicable.

## Reproduction and pending authorizations

Use pinned Python 3.12 dependencies and editable install; execute `AGENTS.md` checks. `python scripts/collection_demo.py --output FRESH_DIRECTORY` leaves a fictional CLI-readable case, original archive, inventory, reports and measurements. [Operator guide](../collections.md). `python scripts/model_qualification.py --mock --scenario recurrence` tests only scripted mechanics.

Actual-model CI requires `[model-qualification]` in the selected head commit message. Documentation checkpoints omit it. Pinned public runtime/weights download before loopback-only network isolation; inherited environment is cleared and only generated inputs are accepted. Slot-release timing does not authenticate request attribution or cancellation cause. No private files/API credentials belong in this harness, Git or CI.

Separate owner authorization remains required for private diagnostics, device connection/acquisition and private external disclosure. None occurred. Continue independently authorized work without accessing owner files or unrelated projects.
