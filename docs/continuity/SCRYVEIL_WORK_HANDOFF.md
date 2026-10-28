# SCRYVEIL engineering handoff

Updated 2026-10-28. Branch `feat/forensic-core-genesis`, [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. Verified implementation: `e8f1ebd5ba5c36efa7d0828a11662c8fdea50138`, tree `527e0ca7d808ebef6ac7e1079d627c8ef9b85a20`. [Core CI 40743614263](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40743614263), job `123011451460`, passed **498 tests in 25.11s** and every required static/security, hygiene, historical compatibility, source-demo, packaging and installed-wheel gate. This enclosing documentation checkpoint records the completed access check; use `git rev-parse HEAD` for its SHA. Parent `6058a0d9df07c753e87392c9c4689f7c59039bc7` and its failed hosted attempt were reconciled. No private records/devices or merge.

## Current continuation: distinguish gateway access from model reasoning

The owner authorized using the apmix key for the prepared fictional benchmark. The key was saved as repository Actions secret `SCRYVEIL_PROVIDER_API_KEY`; never request or put it in chat/Git/cases. Run [40580100780](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40580100780), job `122456873922`, verified the exact approved plan, then its **first request returned HTTP 403 after 0.979s**. Zero model actions, queries, facts or final reports. Six subsequent scenarios were correctly skipped. This is an access failure, not evidence of model reasoning failure or success. Original case/state bytes remained unchanged. No usage was returned; zero reported tokens is not verified zero billing.

[Original machine record](../validation/apmix-access-40580100780.json) and [original disclosure](../validation/apmix-disclosure-6058a0d.json) preserve the selected commit, hashes and exact result. Offline verification recomputed the plan/report digests and all 36 historical file hashes. The old transport discarded the error body, so the exact 403 subtype cannot be recovered from this run. Do not assert a missing plan, expired key or bot block as established fact.

Implemented now:

- Native errors retain only a closed set of provider-reported JSON error codes, including unavailable model access, expired credentials and quota conditions. Arbitrary provider messages, identifiers and credential echoes never appear in reports. Unknown/oversized/malformed errors retain the generic HTTP status. No retry or fallback.
- A separate owner-operated catalog check makes exactly one GET to an explicitly reviewed same-origin URL. No case paths, evidence, prompts or inference requests. It reuses the pinned-TLS, isolated broker and outputs only counts and membership of operator-selected model IDs. Catalog membership is not verified access, price, model identity or intelligence.
- Catalog preview/approval binds source, endpoint, auth, candidates and one-request budget before credential access. The `provider-access` workflow marker is separate from inference activation; it never starts an investigation or changes the selected model. The eleven investigator tools remain unchanged.
- Custom URL/auth behavior, native assistant state, source preservation, grounding, report contracts and historical case compatibility remain in place.

Completed live check: [40743613991](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40743613991), job `123011450525`, made the single approved catalog GET and received **zero entries**, no pagination indication, and none of the three explicitly checked MiniMax/free-Claude IDs. [Exact record](../validation/apmix-catalog-40743613991.json). Offline reconciliation verified its digest and all 25 historical bound file hashes. This is consistent with unavailable model access; it does not prove the precise earlier 403 cause, account billing status or universal absence of a free tier. Inference workflow 40743613945 skipped every credential/inference step; no new inference occurred.

Next highest-value action: obtain an explicitly authorized, actually accessible model configuration before another hosted qualification. No unchanged APMIX/Qwen rerun, subscription purchase, unreviewed provider switch or relaxed validation is justified. Preserve the current access blocker and continue independent functionality when no model is available. The original nonfatal/contrary-evidence benchmark remains the first reasoning gate. Private diagnostics/devices and new private disclosure still require separate authorization.

[Catalog plan](../validation/provider-access-plan.json), [operator procedure](../investigation.md), [qualification record](../validation/provider-qualification.md). `provider-disclosure-plan.json` is regenerated for current code but **not activated**; the executed old plan is archived separately. Hosted actual-model completion, semantic hypothesis review and actual-model injection qualification remain open. Private diagnostics/devices remain unauthorized.

Local validation: **498 tests passed in 21.07s**, Ruff/check and format, strict mypy (22 modules), Bandit, all three historical compatibility records, all five source demos, sdist/wheel build and all five installed-wheel demos. A relative `runpy` path defect in catalog-plan generation was caught and fixed; its focused checks and source/wheel offline plan were verified afterward. Repository hygiene also recognizes gateway-key patterns. Core CI independently confirms the implementation as recorded above. No unchanged Qwen rerun is warranted.

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
| `40323112109` | `c064513` | Four CPUs: plan then second-request prompt timeout, zero queries/facts/finals. |
| `40325749077` | `05e2e56` | Routed layout: empty speculative query then three events retrieved; fourth request timed out, zero facts/finals, coverage/findings unread. |

[Latest original records, timing and resource evidence](../validation/native-provider-continuation.md). The corrected second request was 5,899 bytes and returned coverage after 59.390s. Four valid queries followed the plan; two used the same ineffective literal phrase before an unfiltered page retrieved all three events, including the nonfatal contrary observation. Findings were never queried and no final hypothesis/fact was proposed. The sixth request was 11,719 bytes and timed out after 60.063s; server prompt progress at 56.65s showed 1,024 newly processed tokens and displayed progress 0.97. This is prompt-cost evidence, not proof of completed reasoning or a controlled speedup. Total/request budgets were not exhausted. Shutdown exited normally in 3.722s; request-cancellation attribution remains unmeasured. Largest-child RSS 6,606,572 KiB. Workflow success is not a forensic pass. Hosted APIs, hypothesis revision and actual-model injection resilience remain unqualified.

Offline replay verified the report digest, 22 runtime file hashes, all five action/result hashes through the isolated worker, all six context hashes/request sizes, three exact source events and recomputed metrics. No inference was repeated. Original case state remained unchanged. The preserved records contain independently generated evidence only.

Preparation verifies size/hash before inference and permits a bounded 1,800s public-weight download. A pinned CI cache stores only those verified public weights, never cases/logs/credentials/binaries. Both cache save and restore were observed; restored weights passed hash verification in run 40229335744. Inference budgets stayed unchanged. No unchanged full-suite rerun is justified by the present evidence.

## Next highest-priority action

1. Superseded by the current provider-qualification action above. The routed actual-model run 40325749077 is fully recovered. It made an empty speculative search, recovered to an unfiltered query and read three events, then timed out on request four (8,422 bytes). Coverage and findings were never inspected; zero facts/finals. Profile the exact request/serving bottleneck before further full investigations. Do not repeat an unchanged profile, raise budgets, or treat valid tool calls as successful reasoning. A complete actual-model investigation, hypothesis revision and actual-model injection qualification remain open.
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

## Interval correlation and reconciled routing result

Resource correlation now uses the parsed start/end interval, not only its start.
Sorted endpoint counts avoid materializing all crash/resource pairs. Reversed
intervals are excluded; missing ends remain point observations, never inferred
from duration or tracking time. All source bytes/locators and legacy snapshots
remain unchanged. The 6,260-event fictional demo measures 220 neighbor pairs
(previously 200 from starts alone), including 40 inside reported intervals.
These are supplied-record pairs, not unique incidents or proof of simultaneous
writes/causation. No new parser format is claimed.

Local 380 tests, static/security checks, historical compatibility, five source
demos, build and five installed-wheel demos pass. The single-process collection
smoke records 0.392s import, 0.651s verified snapshot, 101,960 KiB parent RSS,
eight mock requests and unchanged originals/state. Exact boundary/source-locator
and independent brute-force interval comparisons pass. Core CI 40387249887 verifies the published implementation.

Run 40325749077 at 05e2e56 is preserved with original result/timing/resources.
Offline verification checked the report digest, 22 historical source hashes,
three isolated-worker actions/results, four contexts/request sizes and recomputed
metrics. No model inference was repeated during reconciliation. No private
records, devices or external model credentials were accessed.
