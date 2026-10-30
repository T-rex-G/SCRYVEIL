# APR review: evidence, boundaries and implementation decisions

Reviewed 2026-10-22. This is a source-grounded extension of the original offline core, not a new acquisition or threat-detection claim.

## Primary evidence inspected

| Source | Inspection | Consequence |
|---|---|---|
| [Apple: Inspecting app activity data](https://developer.apple.com/documentation/network/inspecting-app-activity-data?changes=_6_5) | Full article: access dictionaries, interval identifiers and boundaries; network field definitions and attribution | Pair matching begin/end identifiers. Preserve app identity, resource, time offset and screen broadcaster consistency. Network contacts retain their own count and first/latest time. |
| [Apple: About App Privacy Report](https://support.apple.com/en-us/102188), published 2025-12-19 | Enablement, retention, clearing and private-browser exclusions | A missing record cannot establish absence of activity. Report limitations remain visible even for syntactically complete intervals. |
| [Plaso parser](https://github.com/log2timeline/plaso/blob/3733f4d78f9c0c951a56bc8a5749fd0809c31aca/plaso/parsers/jsonl_plugins/ios_app_privacy.py) and [test](https://github.com/log2timeline/plaso/blob/3733f4d78f9c0c951a56bc8a5749fd0809c31aca/tests/parsers/jsonl_plugins/ios_app_privacy.py) | Pinned source and assertions read. Accessor/resource/identifier and recorded-time extraction; two record types. The reviewed plugin does not reconstruct access durations. | Independent field-shape cross-check, not an executed differential benchmark or evidence that SCRYVEIL exceeds Plaso's overall capability. Test-data export was not imported or redistributed. |
| [Kaspersky original shutdown research](https://securelist.com/shutdown-log-lightweight-ios-malware-detection-method/111734/) and [parser](https://github.com/KasperskyLab/iShutdown/blob/6e1312ce58b99f46bd7a155d234c61e2205409c6/iShutdown_parse.py) | Research and pinned parser source reviewed as a candidate next artifact family | Related shutdown heuristics depend on reboot/record availability and need independent corroboration. No new shutdown detector or perfect spyware-detection claim follows. |

Documentation describes a format, not coverage of every OS release. Apple-produced exports were **not tested**. A JSON-only documentation link returned an unsupported Markdown content type; the indexed official article provided the field descriptions. An initial guessed Plaso path returned 404; the pinned Git tree supplied the actual paths above.

## Original design decisions

1. Add a separate derived contract, `scryveil.privacy-review/1`, without changing persisted events, case schema, existing analysis results or parser interpretation. Read verified original bytes while holding the case lock; recheck the hash on the exact bytes read for this interpretation. This works on existing 0.1.0 cases with no migration.
2. Pair only within one original artifact. No device identity or independent coverage proof exists to justify combining windows across files. Same-ID conflicting apps/resources/broadcasters, multiple distinct boundaries, unknown kinds/identities or reversed source time produce explicit unresolved statuses and no duration.
3. Collapse exact duplicate record bytes (ignoring CR/LF terminators) only for interpretation. Preserve every original source reference and duplicate count. Semantically similar records with differing raw metadata remain distinct and can make a pair ambiguous; this intentionally favors uncertainty.
4. Calculate complete intervals with integer microseconds. Precision reflects source formatting, not a claim about clock accuracy. Do not add durations across overlapping intervals or exports. Missing boundaries have no invented duration.
5. Keep network counts per source summary. Do not sum overlapping exports, manufacture packets, infer foreground/background execution from source attribution, infer exfiltration from access/network co-occurrence, or interpret a source tracking flag as malware.
6. Default exports replace apps/domains with report-local references assigned in source order. Identifiers can be shown explicitly in local JSON. Neither view is anonymous; metadata and relationships remain sensitive. Reports never fetch domains or open evidence-supplied links.
7. Existing lineage comparison now distinguishes booleans, integers and floats. Analyst decisions require independently recomputed findings before being appended. These are integrity corrections, not externally authenticated chain of custody.

## Licensing and dependency decision

All new implementation, fixtures and tests are original and covered by SCRYVEIL's MIT license. No upstream code, data fixture, binary or runtime dependency was adopted. Plaso's Apache-2.0 source and iShutdown's previously recorded MIT notices remain study-only. There is no claim of legal clearance for future distribution of upstream integrations.

## Unresolved questions

Real export/version conformance, malformed real-world patterns, truncation rates, clock discontinuities and false-positive rates on owner-verified activity remain unmeasured. Synthetic duration recovery tests measure algorithmic correctness against a generated oracle; they do not estimate spyware sensitivity or specificity. A shutdown subartifact parser is still a later milestone. No additional language is justified by this text/JSON workload; production performance is measured separately.
