# SCRYVEIL engineering handoff

Updated 2026-10-25. Branch `feat/forensic-core-genesis`, [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. Verified coverage checkpoint `9a57ef56e6a490fc2927c9a8e85e9c7e98c9951e`, tree `2674fe2fa7c779b4f2ec45b8660ee481a1de9f91`; [core CI 40205683698](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40205683698) passed 360 tests in 14.03s and all required checks. The smaller native-request follow-up belongs to this document's enclosing commit; its CI and selected actual-model run must be checked separately. Run `git rev-parse HEAD` and inspect newer changes before continuing. Never merge automatically.

## Working capability

- Bounded ZIP collection import preserves original archive/member hashes, membership paths and byte boundaries, unsupported/malformed inventory, unknown ZIP clock offset and duplicate content identity. No path extraction or recursion. Limits: 1,000 members, 1,024 case artifacts, 20,000 events, 64 MiB ZIP/expanded data, 8 MiB/member, 256 MiB case originals, 64 MiB state. Central entries must follow physical member order.
- Opt-in `--all-events` makes every accepted event available to paged queries or fails above 16 MiB snapshot capacity. Expanded coverage now exposes selected event-type/schema-status counts for query discovery. Legacy default snapshot bytes are unchanged; no database migration.
- Opt-in `--diagnostic-details` exposes process/exception/termination/source-symbol/OS fields, excluding executable paths and unrelated identifier fields. Exact access profile is consent-bound. Embedded sensitive strings remain a disclosure concern.
- Independent deterministic measurements group declared exception/termination/stack signatures, count condition flags, detect conflicting incident declarations, distinguish reasoned Jetsam entries from mere listings, and measure resource proximity without causal claims. Reference omissions are explicit. CLI emits source-linked JSON/Markdown.
- Preserved offline NDJSON/APR, three source clocks, locators, versioned readers, eleven read-only tools, Linux syscall isolation, exact factual validation, budgets and remote consent. No framework, language, runtime dependency, acquisition or unrestricted plugin was added.
- JSON-action and native Messages client-tool adapters are separately implemented. Native policy/history, phase-scoped schemas, complete request budgeting, cached-input accounting and error handling have synthetic protocol/security tests. One actual native plan is demonstrated; no complete actual-model investigation is qualified.

## Validation and recovered defects

Native request-cost follow-up: **361 tests passed in 17.21s**, Ruff/format, strict mypy over 22 modules, Bandit, hygiene, historical executable compatibility, all five demos, sdist/wheel and five installed-wheel demos. Direct installed-CLI commands find 240 crashes, return five queried rows, inventory 266 members and emit three signature groups without changing case state.

A strengthened regression caught an inaccurate earlier fixture precondition: `timestamp` was not the supported Jetsam `date` field, so that test had unknown times. The corrected fixture now asserts the first 2,000 selected records are earlier Jetsam entries and the later crash is found through full-case retrieval. The separate collection demo already used `date`; its prior measurements remain valid. See [collection validation](../validation/collection-continuation.md).

Historical executable checks preserve reports/snapshots byte-for-byte for ten NDJSON cases, six earlier IPS cases and five body-v2/text cases. Reimports preserve reader/event/hash identity. Source and installed-wheel collection demos preserve originals/state; eight mock requests complete. The expanded coverage snapshot is 4,884,256 bytes, reserving 157,097/200,000 units. [Single smoke record](../validation/collection-coverage-smoke.json), not a new performance acceptance series.

Original three-run collection measurements apply specifically to `f5676df2528e3b64c42f820dbffeb0a4a9087db6`: 266 members, 267 artifacts, 6,260 events, three signature groups of 80 declared incidents, zero full-case omissions. Import 0.340–0.361s, complete workflow 2.783–2.920s, parent RSS 95,676–96,620 KiB. Prior mock budget failures remain recorded. These do not qualify maximum-size cases, smaller default budgets, genuine devices or model reasoning.

Security checks cover unsafe ZIP paths/types, nested/oversized content, false output lengths, CRC/descriptor/header mismatch, overlap, capacity rejection before state publication, forged lineage, injected symbols and forbidden calls through native HTTP/broker/worker boundaries. Archive parsing remains in the trusted owner process. IO interruption can leave checked content-addressed orphans; no automatic cleanup. Local audit is not independently authenticated custody.

## Actual-model gate remains unqualified

| Run | Source | Observed result |
|---|---|---|
| `40038068563` | `948ec27` | One mechanical completion among six, zero facts; completed case read no events; injection unexposed. |
| `40070459394` | `dd27bf6` | Literal-search misuse; zero events/facts; unexplained empty-case completion later rejected by runtime. |
| `40090072225` | `4f55541` | Recurrence/injection queried three events then timed out; zero completions/facts; fabricated envelopes rejected. |
| `40137879901` | `f5676df` | JSON-action first request timed out at 60.028s; no reply or numeric server events. |
| `40181063497` | `4040436` | Native plan after 35.117s; second request timed out, zero queries/facts; shutdown required SIGKILL. |
| `40182871736` | `38e7b33` | Weight download timeout before inference; no model-quality measurement. |
| `40204579155` | `39bf69c` | Compact native plan after 31.769s; second request timed out during prompt evaluation, zero queries/facts; large collection skipped. |

[Latest original records, timing and resource evidence](../validation/native-provider-continuation.md). Latest second request: 7,406 bytes, timeout 60.063s; server still evaluating prompt at 57.75s (1,280 newly processed tokens, displayed progress 0.79). Shutdown exited normally in 4.224s; cancellation attribution remains unmeasured. Largest-child RSS 6,600,992 KiB. Prompt-processing cost is demonstrated for this two-thread CPU profile; model reasoning on unavailable evidence is not measured. Workflow success is not a forensic pass. Other models, hosted APIs, hypothesis revision and actual-model injection resilience remain unqualified.

Preparation now verifies size/hash before inference and permits a bounded 1,800s public-weight download. A pinned CI cache stores only those verified public weights, never cases/logs/credentials/binaries. Cache save succeeded; a real restore has not yet been exercised. Inference budgets stayed unchanged. No unchanged full-suite rerun is justified by the present evidence.

## Next highest-priority action

1. Recover the selected native request-cost experiment at this enclosing checkpoint and inspect its CI. Deferring the final schema until two distinct successful queries and shortening repeated descriptions reduces the exact failed request from 7,406 to 5,899 bytes (20.3%), retaining all eleven queries and full worker checks. Compacted views may require re-querying before the final schema reappears. Latency and reasoning improvement are not presumed. The same weights, server, 60s request bound and twelve-request ceiling are retained; the collection still requires recurrence facts, coverage and contrary citations. Do not repeat another unchanged investigation or raise budgets to conceal failures.
2. Genuine Apple-export qualification remains open. Text version 73 is unqualified; types 202/206/509/120 unsupported. Owner records require separate explicit authorization.
3. Full sysdiagnose, TAR, backups/SQLite/plist interpretation, profiles, PCAP, live acquisition and Android remain unsupported. Further storage/security migrations need measured justification.

The ten requested forensic upstream projects were inspected selectively at source/license level. No source/dependency was incorporated; unused comparisons were not added to public documentation. Applied lessons: member provenance, bounded retrieval, source semantics and symbolication uncertainty. ADR-001/002 remain applicable.

## Reproduction and pending authorizations

Install pinned Python 3.12 developer dependencies and the original package; execute `AGENTS.md` checks. `python scripts/collection_demo.py --output FRESH_DIRECTORY` leaves an ordinary CLI-readable fictional case, archive, inventory, reports and measurements. [Operator guide](../collections.md). `python scripts/model_qualification.py --mock --scenario recurrence --scenario collection --require-recurrence` tests scripted mechanics only.

Actual-model CI requires `[model-qualification]` in the selected head commit message. Documentation/coverage checkpoints omit it. Pinned public runtime/weights are prepared before loopback-only network isolation; inherited environment is cleared and only generated inputs are accepted. No private files/API credentials belong in this harness, Git or CI.

Separate owner authorization remains required for private diagnostics, device connection/acquisition and private external disclosure. None occurred. Continue independently authorized work without accessing owner files or unrelated projects.
