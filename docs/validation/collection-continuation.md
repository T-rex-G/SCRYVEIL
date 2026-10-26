# Collection investigation checkpoint

Generated evidence only. No owner diagnostic, device connection, external inference request, additional runtime dependency or upstream implementation was used. This checkpoint is a functional collection improvement, not completion of the actual-model or genuine-export gates.

## Executed workflow

`python scripts/collection_demo.py --output FRESH_DIRECTORY` generates 266 ZIP members: 240 crash reports, 20 text resource reports, three Jetsam reports containing 6,000 process entries, two unsupported members and one malformed diagnostic. It preserves 267 distinct artifacts including the archive, 6,260 normalized events, all memberships and original hashes. The three recurring signature groups each contain 80 declared incidents. There are 24 nonfatal flags, 20 resource reports declaring no action and three explicitly reasoned Jetsam entries. These are independently authored expected observations; they do not establish real-device accuracy.

The earlier process entries do not hide later crashes: a full-case filtered query finds all 240. Unsupported and malformed sources remain inventoried. All eight mock requests complete, accepted facts retain original locators, and originals/state remain unchanged. The mock's first diagnostic page contains earlier Jetsam records; its completion is workflow mechanics, not a demonstration of root-cause reasoning.

[Measurements](collection-measurements.json) record three sequential fresh processes, source hashes and commands: import 0.340–0.361s, verified snapshot 0.613–0.648s, indexed filtered query 0.644–0.754ms, mock investigation 1.254–1.321s, complete process 2.783–2.920s, parent peak RSS 95,676–96,620 KiB. Shared-host interference is uncontrolled. Snapshot size is 4,884,049 bytes. These measurements qualify this workload, not every 20,000-event case or general scalability.

The [fictional deterministic report](collection-example.md) contains source-linked measurements, contrary observations and outstanding questions. Reproduce the complete source inventory/JSON with the demo; large generated case stores and ZIP files are not committed.

## Corrected failures and checks

Initial large-collection mock runs exhausted the selected 200,000-unit budget: at six requests with 40 references per finding, and at seven after reducing references to eight but retaining 25 default event rows. Explicit reference omission counts plus five-row full-case defaults now complete eight requests at 155,992 conservative reserved units. No evidence is silently removed from full-case query scope. The smaller default budget remains unqualified for this collection.

Local verification: 341 tests; Ruff/check-format; strict mypy over 21 runtime modules; Bandit; hygiene with 18 allowlisted fictional fixtures; all five demos; sdist/wheel and five demos from a fresh installed wheel outside the checkout. Historical executable compatibility checks cover ten NDJSON cases, six earlier IPS cases and five body-v2/text cases, preserving reports/snapshots byte-for-byte and reader/event/hash identity on reimport.

New adversarial checks cover traversal, ambiguous paths, special files, nested archives, expansion limits, CRC/header/descriptor inconsistency, overlapping members, forged decompressed lengths, capacity rejection before publication, manifest tampering, malicious diagnostic symbols, forbidden calls and fabricated paths. ZIP parsing remains bounded in the trusted owner process, not a separate audited sandbox. Existing worker/broker seccomp and eleven-tool boundaries remain intact.

## Remaining qualification

- Actual-model success remains absent at this checkpoint. New request timing records include errors and cancellation; allowlisted native-server measurements retain timing/task/slot data, not arbitrary log text. `server_cancellation_confirmed: false` means unmeasured, not a demonstrated cancellation failure. Slot release alone does not identify cancellation cause.
- The selected next experiment runs only the existing generated recurrence scenario to recover missing latency evidence. Same pinned weights/runtime and original budgets; this is not another unchanged six-scenario quality rerun. Tool schemas have gained optional pagination, so comparisons are not a strict single-variable experiment. A green workflow is not a quality pass.
- Apple-export qualification remains open; text version 73 is unqualified. No new genuine-format qualification is inferred from collection size or public field documentation.
- Only bounded stored/deflate ZIP collections are supported. Complete sysdiagnose, TAR, backups, plist/SQLite interpretation, PCAP, live acquisition, Android, independent custody authentication and cross-platform investigation isolation remain open.
- Current persistence is bounded JSON with in-memory query indexes. Full-case selection fails above the snapshot budget; it does not silently truncate. There is no persistent database index or unbounded collection claim.

Operator commands and precise limits: [collections](../collections.md). Latest commit/CI and next action: [handoff](../continuity/SCRYVEIL_WORK_HANDOFF.md).

## Coverage retrieval follow-up

The opt-in expanded snapshot now reports selected event-type and diagnostic schema-status counts, so the investigator can discover valid category filters before browsing thousands of records. Legacy default snapshot bytes remain unchanged. Missing qualification metadata from earlier readers is labeled `legacy_status_not_recorded`, never qualified by inference.

The strengthened ordering test exposed an incorrect fixture precondition: it had used `timestamp` instead of the supported Jetsam `date`, producing unknown times. It now uses `date` and explicitly asserts that the legacy capped view contains 2,000 earlier Jetsam entries and omits the later crash, while full-case retrieval finds it. The independently generated collection demo already used `date`; its prior measurements stand. This corrects test evidence rather than broadening parser claims.

Local follow-up: 360 tests in 11.55s, all static/hygiene checks, historical executable compatibility, five demos, package builds and five installed-wheel demos passed. A direct installed-CLI walkthrough retrieved a five-row page from 240 matching crashes, inventoried 266 members, produced all three signature groups in Markdown and preserved case state. [One smoke measurement](collection-coverage-smoke.json) records the new 4,884,256-byte snapshot and eight mock requests at 157,097/200,000 reserved units. It ran alongside a build and is not a new performance acceptance series. Actual-model results remain separately failed in [native continuation](native-provider-continuation.md).

## Indexed diagnostic retrieval follow-up (2026-10-26)

The exact-filter increment retrieves 24 explicit nonfatal declarations, 20
no-action resource observations and three source-declared memory-shortage
reasons from the 6,260-event fictional collection. Each bounded result preserves
full event/source references; `collection_demo.py` now saves those queries as
`contrary-and-memory-queries.json`. These are source observations, not causal or
malware conclusions. Typed index keys distinguish booleans from strings, and
null/absent values are never treated as false. Candidate intersections begin
with the smallest posting list and restore snapshot order before pagination;
a regression forbids scanning unmatched records on an indexed query.

[Single-process smoke](indexed-retrieval-smoke.json): the three exact queries
completed in 1.254ms combined; parent peak RSS 102,524 KiB. Index construction is
outside that query measurement. This is not a maximum-capacity or comparative
speedup qualification. Mock investigation completed eight requests using
151,769/200,000 reservation units; original bytes/state remained unchanged.

Initial schema duplication caused two existing mock-budget regressions. Shared
JSON-action query definitions reduce the current schema view from 4,617 to
2,474 bytes, restoring both tests without changing budgets. Executable schemas
remain fully expanded; a regression checks reference resolution and rejected
inputs. Native Messages schemas remain expanded and are larger with the added
filters; this change does not resolve its measured inference bottleneck. No
actual-model experiment was repeated. Old case/report/snapshot compatibility,
371 tests, static/security checks, five source demos and packaging checks pass.
No new parser qualification, provider qualification or third-party dependency
is implied.

### Contrary-evidence identity correction

Signature recurrence groups already required matching declared process,
OS/build and bundle, but their contrary-reference lookup previously used only
process name. A nonfatal observation from a different build/bundle could therefore
appear to contradict a specific signature group. The lookup now applies the
same OS/build/bundle identity scope. Other observations remain available in the
per-name condition inventory and full-case queries. A regression changes each
identity field independently and verifies that relevant contrary evidence is
retained while unrelated groups are excluded. Equal declarations still do not
authenticate device identity; missing values remain unknown. This corrects
correlation precision without changing parser outputs or report field contracts.
