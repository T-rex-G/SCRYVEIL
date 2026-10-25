# Capability assessment and next evidence gates

Updated 2026-10-24, continuing PR #1 through `cccacdd` and the [diagnostic/model milestone](validation/diagnostic-model-milestone.md). The existing 159-test core, APR privacy review, ADR-001 and pinned upstream research were inspected before extending them. The new slice uses an explicit IPS import route and separate investigation reports. Existing NDJSON parsing, stored analysis and report formats are retained. No existing functional component was replaced for style.

This platform remains substantially narrower than established forensic suites. No device was connected or private record examined. Pinned public model weights were downloaded before isolation; generated cases were evaluated with external routing disabled. No external inference provider was used. Green tests below demonstrate specified mechanical behavior on generated data; they do not establish real-world spyware accuracy.

## Qualification categories

1. **Implemented and independently validated:** no SCRYVEIL real-device forensic conclusion currently meets this category. Apple documentation is independent semantic evidence, not independent execution of our parser. There is no external audit or ground-truth field study. Direct byte comparisons, kernel syscall-denial checks and loopback protocol tests verify engineering invariants locally, with their own stated scope.
2. **Implemented, synthetic validation only:** persisted consent-scoped cases, original hashing/reparse checks, explicit source clocks/locators, deterministic synthetic periodicity and exact-domain IOC rules, analyst decisions, provenance graph, reproducible reports; IPS normalization/recurrence; bounded read-only investigation; mock provider, configured HTTP adapter and disclosure policy.
3. **Partial:** APR documented access/network subset; IPS crash/resource/Jetsam subset; identifier minimization; cross-artifact event queries; whole-state JSON persistence; local audit chain; local/remote model integration. Missing versions, clock calibration, authenticated device identity, indexed storage and measured model-quality failures constrain each.
4. **Unsupported:** live acquisition; encrypted or unencrypted backup ingestion; SQLite/plist artifact ingestion; sysdiagnose archive extraction; PCAP/PCAPNG ingestion; configuration-profile inventory; Android; STIX and authenticated IOC feeds; calibrated malware detection; generic plugin loading; desktop installers.
5. **Proposed, unproven:** safe archive/member workers, signed acquisition manifests, indexed evidence store, authenticated source/device identities, scoped third-party acquisition adapters, richer evidence graph, native performance alternatives and MCP exposure. Documentation is not delivered capability.

## What the new slice actually establishes

| Area | Working behavior | Qualification gap |
|---|---|---|
| Diagnostics | Explicit two-object IPS JSON envelope; process/exception/termination fields; bounded faulting frames; resource/nonfatal flags; Jetsam victim reason and pages × page size; byte region + JSON pointer | Original generated fixtures only; 309/308 JSON body v2 and 145 text v29/55/60 have structurally recognized partial profiles; v73 remains unqualified; legacy 104/309 and 298 behavior remains compatible, not all `.ips` |
| Deterministic usefulness | Distinct reported incident IDs for a declared process, contrary nonfatal/simulated/action-none evidence, alternatives and coverage | Same process name does not prove same device/version; no crash-root-cause or spyware classifier |
| Cross-artifact queries | Time/type/process/app/domain filters, pagination, coverage, finding support and contradictions; opt-in full-case snapshot | No clock correction or inferred process↔app↔packet join; legacy capped snapshot discloses omissions; full-case mode fails above its byte bound |
| Autonomous workflow | Plan → model-selected bounded queries → comparison → exact-field facts and trusted measurements → unresolved hypotheses/report | Mock is scripted; actual small-model failures measured; see preserved runs. Mock success does not establish useful model reasoning |
| Privacy/security | No default egress; one-case snapshot; OS-denied file/network/process capabilities; explicit remote disclosure binding; private config | Parent/host trusted; local model server can forward unless independently offline; semantic prompt injection remains possible within allowed data |
| Persistence/integrity | Original bytes and event interpretation reverified before/after; unchanged source state; separate stdout report | Unsigned local audit, cooperative locks, no complete transaction recovery, no adversarial same-UID isolation |
| Performance/packaging | Five fresh runs per bounded workload; wheel and installed CLI checks; no third-party Python runtime packages | Shared-runner variance and earlier failures; Linux-only AI isolation; system libseccomp; no desktop signing or large-case claim |

The original 30-report probe exhausted the mock context budget after six requests. The bounded-context correction at `dd27bf6` completes eight steps under the same budget in three fresh-process samples (0.398–0.414 seconds). Historical failures remain retained. This is a scripted capacity regression, not an AI-scale or reasoning qualification. [Qwen3 reconciliation](validation/qwen3-reconciliation.md) verifies one empty mechanical completion and zero accepted facts at `948ec27`; the changed-runtime comparison is separately recorded.

[Resource-format continuation](validation/resource-format-continuation.md) adds a separate reader for observed sampling-duration annotations, preserves old v2 cases, and leaves v73 explicitly unqualified. The owner-facing diagnostic coverage report exposes omissions, partial/unqualified interpretation, source warnings and unknown unimported/rejected files. Types 202/206/509/120, sysdiagnose and backups remain unsupported.

## Collection continuation at the next review checkpoint

The eight owner observations were checked against `bceef32`: all held, with the qualification that snapshot omissions were already disclosed and generic configurable HTTP transport already existed. The following changes address selected product limitations, not all qualification gaps:

| Observation | Current change / remaining limit |
|---|---|
| Basic detectors | Opt-in full-case signature recurrence, condition/incident contradictions, explicit Jetsam reasons and bounded temporal resource neighbors; no root-cause or malware classifier |
| Hidden diagnostic detail | Explicit diagnostic-detail permission scope; process names/symbols/exception/OS fields available without executable paths or unrelated identifiers |
| No qualified AI investigation | Still open; synthetic mock capacity is separate from actual-model quality |
| One compatible JSON adapter | Separate JSON-action and native Messages client-tool protocols now implemented; synthetic conformance and one actual native plan, no completed actual-model investigation or universal vendor interoperability claim |
| 32 artifacts / earliest 2000 | Batched ZIP import, 1024-artifact bounded case, explicit complete-case query snapshot and paging; legacy default remains compatible; no persistent indexed database |
| Partial Apple formats | Existing reader interpretations preserved; v73 still unqualified; new collection support does not qualify input semantics |
| No archive pipeline | Bounded ZIP preservation/inventory/import implemented; unsupported members retained. TAR, complete sysdiagnose, backup, PCAP and live acquisition remain open |
| Unauthenticated custody | Unchanged: local byte hashes/reparse/audit, no authenticated acquisition or hostile-owner protection |

[Operational guide and bounds](collections.md). Initial large mock runs exhausted the unchanged 200000-unit budget with 40 references per finding and then with 25 event rows; smaller disclosed finding-reference lists and five-row full-case query defaults resolve this mechanical workload. All source events remain available for paged queries. Do not infer real-model quality from it.

## Comparison with inspected references

The [original source review](research/upstream-assessment.md), [access matrix](research/source-access-matrix.md), [license matrix](research/license-matrix.md) and ADR-001 retain exact full SHAs, paths and untested claims. These are pinned historical observations, not assertions about every current head. No competing test suite or hardware path was executed. No upstream code or fixture was copied.

| Reference / reviewed revision | Relevant strength and boundary | SCRYVEIL consequence |
|---|---|---|
| MVT `f4bfc39` | Broader backup/filesystem artifacts and IOC workflow; MVT License 1.1 includes consent terms. Shutdown source associates records with shutdown timestamps and checks path/process indicators | Our exact-domain-only IOC support is much narrower; keep source and indicator provenance separate. Never infer cleanliness from no match |
| iLEAPP `7ec17ed` | Broad extracted/backup artifacts; inspected shutdown EOF tests and PrivacyAccounting SEGB parser; MIT plus bundled dependency terms | Adopt the practice of testing missing boundaries and version semantics, not its runtime wholesale |
| SAF `545c900` | Sysdiagnose parser ecosystem and JSONL events; EUPL-1.2 plus extensive notices. Selected shutdown parser can omit unfinished groups | Add per-member coverage/errors when archives eventually enter scope; an exit code is not proof of completeness |
| PyMobileDevice3 `aa20272` | Real service/tunnel/pcapd APIs and process metadata; broad mutation surface; GPL-3.0-or-later | Future owner-authorized collector must isolate exact methods and document pairing/service side effects; no library access for AI |
| libimobiledevice `fa0f791` | Native service access, backups/crash retrieval; component-specific LGPL/GPL terms | Re-read crash tool: delete-after-copy default unless keep; crashreportmover also changes device state. Do not advertise generic acquisition as read-only |
| iShutdown `6e1312c` | Focused shutdown delay/path heuristics; MIT | Useful complementary lead; no calibrated probability and no assumed individual process event time |
| Triangle Check `ea9e5a8` | Campaign-specific backup markers and temporal co-occurrence; MIT with packaging notices | Campaign-specific detection does not generalize; preserve expected signals, negatives and timing uncertainty |
| iphone-tracker-check `8c34c6b` | APR/network analysis prototype; MIT original code with GPL PMD3 dependency | Do not turn aggregate hits into packet timestamps, close missing intervals using unrelated events or treat Apple-range suppression as proof of safety |
| Plaso `3733f4d` | Broad event normalization and inspected APR parser/test semantics; Apache-2.0 | Independent source interpretation helps specify original fixtures; no imported dependency or real-export qualification follows |
| go-ios / idevice | Actual Go/Rust Apple service implementations inspected in ADR-001, with capture normalization and version/feature trade-offs | Native acquisition remains a serious alternative, not an assumed performance win; no demonstrated reason to rewrite this slice |

Additional research for the AI boundary: Apple crash/Jetsam documentation; 0xche's assessment; Linux seccomp documentation; Ollama HTTP compatibility; pinned llama.cpp server README/license; pinned libseccomp license. See [research notes](research/diagnostic-ai-evidence.md).

## Prioritized milestones with falsifiable acceptance

| Priority | Gap and engineering milestone | Required evidence before upgrading the claim |
|---|---|---|
| P0 | Qualify IPS/APR semantics on consented local exports | Owner-approved samples stay outside Git/model prompts; independent expected timestamps/identities and original hashes; record OS/report version, missing fields and discrepancies; publish only fictional regressions |
| P0 | Resolve actual local model qualification failures | Pinned 1.5B and 4B profiles have no qualified evidence-grounded final result. Compact-native run 40204579155 returned a plan, then timed out while still evaluating the second prompt; zero evidence queries/facts. The collection was skipped. Demonstrate a serving-throughput or request-cost improvement before another investigation; preserve fixed questions, grounding, limits and isolated local weights. No cloud test inferred from protocol compatibility |
| P0 | Independent isolation/privacy review | Reproduce forbidden syscall, cross-case, disclosure-change and TLS tests; review parent/broker trust boundary; no prompt-only security claim |
| P1 | Persistence and performance | Profile named reference hardware; compare indexed/streamed storage and a bounded native hot-path prototype only where measured; preserve exact report semantics and rollback. Current local five-run pass does not erase earlier failures |
| P1 | Sysdiagnose member support | Start with a known plaintext member format; preserve parent archive and member hashes/locations. Before extraction: reject absolute/traversal/link/device entries; bound total expanded bytes, ratio, members, nesting and time in isolated worker; never use member names as output paths. ZIP member preservation now implemented; isolated archive worker/TAR/sysdiagnose member interpretation remain open |
| P1 | Backup SQLite/plist and profiles | Authorized acquisition method, encryption/password handling outside prompts, consistent SQLite/WAL snapshots, safe identifier/path handling and independent artifact fixtures; no mutation/remediation |
| P1 | Network captures and richer intelligence | Packet timestamps and link-layer provenance; process association only when supplied by that capture source. Versioned STIX/indicator provenance, expiry/reliability and known-ground-truth false positives/negatives; no automatic IOC download |
| P2 | Evidence graph and Android | Clock uncertainty, duplicate source lineage, competing explanations, scoped collection permissions and versioned Android artifact contracts. Nearby timestamps alone must not create causal edges |

The sequence prioritizes independently qualified inputs and secure model usefulness before additional collectors or UI. The immediate vertical slice is implemented; these milestones identify the remaining work rather than treating architecture diagrams as completion.


Native-provider follow-up (2026-10-25): `messages-tools` supplies a second wire protocol with synthetic HTTP/broker/worker conformance, phase-scoped native client calls, full request budgeting and cached-token accounting. Native plans were executed, but no complete actual-model investigation or hosted API was qualified. Expanded coverage now lists selected event-type/schema-status counts to support retrieval. See [retained execution evidence and next gate](validation/native-provider-continuation.md).
