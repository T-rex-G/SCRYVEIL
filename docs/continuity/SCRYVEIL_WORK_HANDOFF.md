# SCRYVEIL engineering handoff

Updated 2026-10-24. Branch `feat/forensic-core-genesis`, [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. This implementation descends from exact prior head `bceef32df32bfaa44cc68fa3dd9a77448bd5ba6c`. Runtime hashes in [collection measurements](../validation/collection-measurements.json) identify the code; a qualification descendant will anchor the published SHA and CI. Run `git rev-parse HEAD` and reconcile newer changes before continuing. Never merge automatically.

## Working capability

- Bounded ZIP collection import preserves original archive/member hashes, membership paths and byte boundaries, unsupported/malformed inventory, unknown ZIP clock offset and duplicate content identity. No path extraction or recursion. Limits: 1,000 members, 1,024 case artifacts, 20,000 events, 64 MiB ZIP/expanded data, 8 MiB/member, 256 MiB case originals, 64 MiB state.
- Opt-in `--all-events` makes every accepted event available to paged queries or fails above 16 MiB snapshot capacity. Legacy default snapshots remain unchanged. In-memory exact-match indexes; no database migration.
- Opt-in `--diagnostic-details` exposes process/exception/termination/source-symbol/OS fields, excluding executable paths and unrelated identifier fields. Exact access profile is consent-bound. Embedded sensitive strings remain a disclosure concern.
- Independent measurements group declared exception/termination/stack signatures, count condition flags, detect conflicting incident declarations, distinguish reasoned Jetsam entries from mere listings, and measure resource proximity without causality claims. Reference omissions are explicit. CLI produces source-linked JSON/Markdown.
- Preserved offline NDJSON/APR, three source clocks, locators, legacy IPS/versioned resource readers, eleven read-only tools, Linux syscall isolation, claim validation, budgets and remote consent. No new framework, language, runtime dependency, acquisition or unrestricted plugin.
- Instrumented model requests and allowlisted native-server timing. Next selected experiment is one generated recurrence scenario to recover missing latency evidence, not a repeated full quality suite.

## Executed validation

Local suite: **341 tests passed**, Ruff/check-format, strict mypy (21 modules), Bandit, hygiene, five demos, sdist/wheel and five installed-wheel demos outside checkout. Historical code creates ten NDJSON cases, six earlier IPS cases and five body-v2/text cases; current reports/snapshots remain byte-identical and reimports preserve interpretations/hashes.

[Checkpoint evidence](../validation/collection-continuation.md): 266 fictional members, 267 artifacts, 6,260 events, three signature groups of 80 incidents, zero full-case omissions. Three fresh processes: import 0.340–0.361s, whole workflow 2.783–2.920s, parent RSS 95,676–96,620 KiB. Eight mock requests complete using 155,992/200,000 conservative units, evidence unchanged. Prior six/seven-request budget failures are recorded. No smaller-default-budget, all-maximum-case, genuine-device or model-reasoning qualification is implied.

Security tests cover unsafe ZIP paths/types, nested/oversized content, false output lengths, CRC/descriptor/header mismatch, overlapping members, capacity rejection before state publication, forged lineage, injected symbols and forbidden calls through the worker. Archive parsing remains in the trusted owner process. IO interruption can leave checked content-addressed orphans; no automatic cleanup. Audit hashes are not independently authenticated custody.

Prior green final-head CI: [40091914243](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40091914243). New code CI/model execution are pending publication; prior CI does not validate this patch.

## Actual-model gate remains failed

| Run | Source | Observed result |
|---|---|---|
| `40038068563` | `948ec27` | One mechanical completion among six, zero accepted facts; completed case read no events; injection unexposed. |
| `40070459394` | `dd27bf6` | Literal-search misuse; zero events/facts; unexplained empty-case completion subsequently rejected by the runtime. |
| `40090072225` | `4f55541` | Recurrence/injection each queried three events then timed out; zero completions/facts; fabricated tool-result envelopes rejected. |

Original records and earlier 1.5B failures remain in [reconciliation](../validation/qwen3-reconciliation.md) and [comparison](../validation/qwen3-recovery-comparison.md). Attack submission followed by timeout does not prove processing or resilience. Qwen3 4B CPU/non-thinking is unqualified. Native timings were absent; latency cannot be attributed solely to reasoning or host speed. Other models, native provider protocols and external providers remain untested.

## Next action

1. Publish this checkpoint, inspect final-head core CI, recover the targeted instrumented model execution and compare request/prompt/generation timing. Do not repeat an unchanged full experiment. Separate workflow success from forensic quality.
2. Use measured failures to select a bounded protocol/context correction. Native tool calling is a candidate, not demonstrated support. Preserve worker permissions and exact claim checks. The target is multi-query reasoning over the generated collection, not an empty final object.
3. Genuine Apple-export qualification remains open. Text version 73 is unqualified; types 202/206/509/120 unsupported. Do not obtain owner records without separate authorization.
4. Full sysdiagnose, TAR, backups/SQLite/plist interpretation, profiles, PCAP, live acquisition and Android remain unsupported. Storage/security migrations require measured justification.

The ten requested upstream projects were inspected selectively at source/license level in scratch. No upstream code/dependency was incorporated; unused comparisons were not added to public documentation. Applied lessons are concrete member provenance, bounded retrieval, diagnostic semantics and symbolication uncertainty. ADR-001/002 remain applicable.

## Reproduction and pending authorizations

Use pinned Python 3.12 dependencies and editable install; execute `AGENTS.md` checks. `python scripts/collection_demo.py --output FRESH_DIRECTORY` leaves a fictional CLI-readable case, original archive, inventory, reports and measurements. [Operator guide](../collections.md). `python scripts/model_qualification.py --mock --scenario recurrence` tests only scripted mechanics.

Actual-model CI requires `[model-qualification]` in the selected head commit message. Documentation checkpoints omit it. Pinned public runtime/weights download before loopback-only network isolation; inherited environment is cleared and only generated inputs are accepted. Slot-release timing does not authenticate request attribution or cancellation cause. No private files/API credentials belong in this harness, Git or CI.

Separate owner authorization remains required for private diagnostics, device connection/acquisition and private external disclosure. None occurred. Continue independently authorized work without accessing owner files or unrelated projects.
