# SCRYVEIL engineering handoff

Updated 2026-10-26. Branch `feat/forensic-core-genesis`, [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. Last published verified checkpoint `4780efe3d42f6a7fbaa047996ddf395cedf264b8`, tree `2d777720b5ef60309207a349812dec162d24deaa`; core CI 40323901975 passed 374 tests and all required checks. This enclosing continuation reconciles failed actual-model run 40323112109 and adds an optional compact native tool layout. Obtain its exact SHA with `git rev-parse HEAD`; inspect newer changes before continuing. Never merge automatically.

## Working capability

- Bounded ZIP collection import preserves original archive/member hashes, membership paths and byte boundaries, unsupported/malformed inventory, unknown ZIP clock offset and duplicate content identity. No path extraction or recursion. Limits: 1,000 members, 1,024 case artifacts, 20,000 events, 64 MiB ZIP/expanded data, 8 MiB/member, 256 MiB case originals, 64 MiB state. Central entries must follow physical member order.
- Opt-in `--all-events` makes every accepted event available to paged queries or fails above 16 MiB snapshot capacity. Expanded coverage now exposes selected event-type/schema-status counts for query discovery. Legacy default snapshot bytes are unchanged; no database migration.
- Opt-in `--diagnostic-details` exposes process/exception/termination/source-symbol/OS fields, excluding executable paths and unrelated identifier fields. Exact access profile is consent-bound. Embedded sensitive strings remain a disclosure concern.
- Independent deterministic measurements group declared exception/termination/stack signatures, count condition flags, detect conflicting incident declarations, distinguish reasoned Jetsam entries from mere listings, and measure resource proximity without causal claims. Reference omissions are explicit. CLI emits source-linked JSON/Markdown.
- Preserved offline NDJSON/APR, three source clocks, locators, versioned readers, eleven read-only tools, Linux syscall isolation, exact factual validation, budgets and remote consent. No framework, language, runtime dependency, acquisition or unrestricted plugin was added.
- JSON-action and native Messages client-tool adapters are separately implemented. Native policy/history, phase-scoped schemas, complete request budgeting, cached-input accounting and error handling have synthetic protocol/security tests. Actual native plan/query execution is demonstrated; no complete actual-model investigation is qualified.

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
| `40229335744` | `fecbb7a` | Plan plus four valid queries across three tools; two empty literal searches, then three retrieved events; sixth request timed out during prompt evaluation. Zero accepted facts/final reports; collection skipped. |

[Latest original records, timing and resource evidence](../validation/native-provider-continuation.md). The corrected second request was 5,899 bytes and returned coverage after 59.390s. Four valid queries followed the plan; two used the same ineffective literal phrase before an unfiltered page retrieved all three events, including the nonfatal contrary observation. Findings were never queried and no final hypothesis/fact was proposed. The sixth request was 11,719 bytes and timed out after 60.063s; server prompt progress at 56.65s showed 1,024 newly processed tokens and displayed progress 0.97. This is prompt-cost evidence, not proof of completed reasoning or a controlled speedup. Total/request budgets were not exhausted. Shutdown exited normally in 3.722s; request-cancellation attribution remains unmeasured. Largest-child RSS 6,606,572 KiB. Workflow success is not a forensic pass. Hosted APIs, hypothesis revision and actual-model injection resilience remain unqualified.

Offline replay verified the report digest, 22 runtime file hashes, all five action/result hashes through the isolated worker, all six context hashes/request sizes, three exact source events and recomputed metrics. No inference was repeated. Original case state remained unchanged. The preserved records contain independently generated evidence only.

Preparation verifies size/hash before inference and permits a bounded 1,800s public-weight download. A pinned CI cache stores only those verified public weights, never cases/logs/credentials/binaries. Both cache save and restore were observed; restored weights passed hash verification in run 40229335744. Inference budgets stayed unchanged. No unchanged full-suite rerun is justified by the present evidence.

## Next highest-priority action

1. Recover the enclosing routed-layout model run before further experiments. The latest reconciled four-CPU run 40323112109 failed after a plan, with no queries/facts; compact routing reduces its exact second request from 6,895 to 5,050 bytes. This is the technical justification for a new bounded run, not a quality pass. Preserve all original execution records and assess claims/contradictions manually if any final report is accepted. Do not repeat an unchanged profile or raise budgets to conceal failures.
2. Genuine Apple-export qualification remains open. Text version 73 is unqualified; types 202/206/509/120 unsupported. Owner records require separate explicit authorization.
3. Full sysdiagnose, TAR, backups/SQLite/plist interpretation, profiles, PCAP, live acquisition and Android remain unsupported. Further storage/security migrations need measured justification.

The ten requested forensic upstream projects were inspected selectively at source/license level. No source/dependency was incorporated; unused comparisons were not added to public documentation. Applied lessons: member provenance, bounded retrieval, source semantics and symbolication uncertainty. ADR-001/002 remain applicable.

## Reproduction and pending authorizations

Install pinned Python 3.12 developer dependencies and the original package; execute `AGENTS.md` checks. `python scripts/collection_demo.py --output FRESH_DIRECTORY` leaves an ordinary CLI-readable fictional case, archive, inventory, reports and measurements. [Operator guide](../collections.md). `python scripts/model_qualification.py --mock --scenario recurrence --scenario collection --require-recurrence` tests scripted mechanics only.

Actual-model CI requires `[model-qualification]` in the selected head commit message. Documentation/coverage checkpoints omit it. Pinned public runtime/weights are prepared before loopback-only network isolation; inherited environment is cleared and only generated inputs are accepted. No private files/API credentials belong in this harness, Git or CI.

Separate owner authorization remains required for private diagnostics, device connection/acquisition and private external disclosure. None occurred. Continue independently authorized work without accessing owner files or unrelated projects.

## Exact-filter continuation after 079f8db

This enclosing implementation commit adds bounded `where` diagnostic filters,
smallest-posting-first retrieval and stable pagination to the existing tools,
plus CLI `timeline query --where`. The 6,260-event demo now retrieves 24 explicit
nonfatal, 20 no-action and three memory-shortage observations with source links.
The worker still sees only its authorized snapshot. Unknown/null is not false;
no parser, permission or persisted case format changed. JSON-action query
schemas share definitions to retain the unchanged budgets. Native expanded
schemas cost more; actual-model effectiveness is untested and no run is pending.

Local validation: 371 tests in 12.74s, Ruff/format, mypy, Bandit, hygiene,
historical executable compatibility, all source demos, sdist/wheel and all five installed-wheel demos passed.
Installed CLI queries independently returned the expected 24/20/3 counts and
left case state unchanged.
See the collection validation's single-process smoke, including limits and the
two caught-and-fixed budget regressions. Check this enclosing commit's CI before
continuing. Last reconciled remote head was
`079f8dbd2efaefa8375f5675b8292cd5e79caaee`; obtain the enclosing SHA with
`git rev-parse HEAD`. No private evidence or inference credential was used.
The next priority remains reducing measured native prompt cost without hiding
contrary observations, followed by an actual-model completion gate. GLM/native
protocol differences require tested adapters, not a provider-name alias.

## Native wire/serving follow-up after a8aeafe

Baseline implementation `a8aeafede3ba46f94250a37096fd45861828204f` has green
[core CI 40284145637](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40284145637):
371 tests and all required checks. This enclosing follow-up losslessly shares
identical fields in native event pages. Offline replay exactly reconstructs all
results and cuts the recorded sixth request by 1,470 bytes at current schemas.
Reports, source bytes, worker permissions and exact-fact validation are unchanged.
Local 373 tests pass. See native-provider validation for limits and reproduction.

A selected actual-model follow-up uses up to four affinity-available CPUs in the
same standard runner, records actual availability, and retains all inference
budgets/weights and isolation. Recover this enclosing commit's CI and model run
before continuing; a successful workflow is not a reasoning pass. Both serving
resources and wire presentation change, so do not attribute any outcome to one
change without further controlled evidence. No private records or credentials
were used. Genuine Apple-export qualification remains open.

Native implementation is published as `c0645134523e2be54ee3840e51767d09ec68179d`
(tree `c587adff0f7ac85a67c5d3032eb90ecc206e3c85`). Core CI 40323111774 passed
373 tests in 16.39s and all required checks. Actual-model run 40323112109 is
being recovered separately; do not infer quality from core CI.

A subsequent precision correction scopes signature-recurrence contrary
references to matching declared OS/build/bundle, rather than process name alone.
Unrelated observations remain in the per-name inventory and queries. Local
374-test, static/security, historical compatibility, source-demo and packaging
checks pass. No additional model inference is requested for this correction.

## Optional compact routing checkpoint

The latest four-CPU run 40323112109 at `c0645134523e2be54ee3840e51767d09ec68179d`
returned a plan, then timed out during prompt processing; zero queries/facts/finals.
Original JSON, timing and resource records are preserved with the native validation.
Optional Messages `routed-v1` shares query argument definitions behind a fixed
name enum; worker per-tool authorization, isolation and exact grounding remain
unchanged. Default separate definitions and legacy snapshots are preserved.
Both layouts pass full mocked HTTP/worker investigation and injected-evidence
rejection; this is not actual-model security/quality qualification.

Local full suite passed 378 tests; the 28 focused provider/contract checks also
passed. Static/security checks, historical
compatibility, all five source/installed-wheel demos and build passed. The report
schema omission detected in testing was corrected. No private evidence or external
inference was used. The selected model job uses only generated fixtures and the
existing pinned local model with unchanged budgets. Reconcile its result next.
