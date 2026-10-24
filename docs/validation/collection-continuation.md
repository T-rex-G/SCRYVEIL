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
