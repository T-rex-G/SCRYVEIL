# Collection investigation

The CLI can import a bounded ZIP collection, preserve unsupported members, and investigate recurring service reports across the complete accepted case. This is an offline capability with optional AI. It is not complete sysdiagnose or backup support, and genuine Apple-export qualification remains open.

## Try the fictional investigation

After installing SCRYVEIL, run from a checkout:

```sh
python scripts/collection_demo.py --output /tmp/scryveil-example
CID=$(cat /tmp/scryveil-example/case-id.txt)
scryveil --root /tmp/scryveil-example/cases diagnostics report --case "$CID" --all-events --diagnostic-details --format markdown
scryveil --root /tmp/scryveil-example/cases timeline query --case "$CID" --event-type diagnostic.crash --limit 5 --diagnostic-details
scryveil --root /tmp/scryveil-example/cases collection inventory --case "$CID"
```

The generated collection contains 240 JSON crash reports, 20 text disk-write reports, three Jetsam reports with 6,000 process entries, two unsupported members and one malformed diagnostic. Expected observations: 6,260 events; three declared exception/stack signature groups with 80 incident IDs each; 24 nonfatal flags; 20 resource reports declaring no action; three explicit Jetsam reason entries. Mere listing in Jetsam is not counted as termination. The early memory records precede all crashes, exercising retrieval beyond the old chronological cap.

The output directory also contains original ZIP, inventory, full diagnostic JSON, readable Markdown, and a mock investigation. The mock is scripted; it does not qualify a model's reasoning. Its explicit 200,000-unit budget is preserved in `mock-provider.json`; the smaller default is not claimed qualified for this workload.

For an owner-authorized collection:

```sh
scryveil --root PRIVATE_CASE_ROOT case create --label investigation --consent authorized
scryveil --root PRIVATE_CASE_ROOT collection import --case CASE_ID supplied.zip
scryveil --root PRIVATE_CASE_ROOT diagnostics report --case CASE_ID --all-events --format markdown
```

Use `--synthetic` only for generated data. A case authorization does not authorize device acquisition or external disclosure. This development session did not receive or process owner diagnostics.

## Preservation and bounds

ZIP stored/deflate members are decoded to bounded bytes, never extracted to their declared paths. The original archive and distinct member content are saved under SHA-256 identities with read-only file modes. Inventory records each central-directory index, original member path, local-header/compressed-data offsets, sizes, method, member hash and untrusted local ZIP time. Identical content at different paths keeps every membership but does not duplicate events. ZIP time is never used as event time.

Traversal, absolute/backslash/ambiguous names, links/special files, encryption, unsupported compression, ZIP64/split/self-extracting layouts, recognized nested archives, CRC/header/size inconsistencies and overlapping members are rejected. Both declared and actual decompression lengths are checked. Limits: 64 MiB archive and expanded content, 8 MiB per member, 1,000 entries, ratio 200, 30-second checked processing deadline; 1,024 artifacts/20,000 events/256 MiB stored originals/64 MiB state per case. An archive occupies an artifact slot. Rejection precedes publishing case metadata. IO interruption can leave content-addressed orphan originals, checked on a subsequent import; automatic cleanup is not implemented.

Unsupported/malformed regular members remain preserved and inventoried. Interpretation status distinguishes parsed subsets, partial results, unqualified versions, no parsed events, unsupported and malformed input. None means independently qualified. No recursion, executable plugin, acquisition library or additional runtime dependency is introduced. Parsing/decompression still runs in the trusted owner process; bounds are not a separately audited archive sandbox. The existing investigator and provider syscall boundaries are unchanged. Local hashes/audit chains are not independently authenticated custody.

The supported ZIP layout requires central-directory entries in physical member order. An otherwise valid archive with reordered entries is rejected by this strict subset; it is not thereby classified as malicious.

## Queries, privacy and conclusions

`--all-events` supplies the whole bounded case to the isolated read-only worker, or fails on the 16 MiB snapshot limit. It does not put the whole case into model context. Exact-match indexes and paged tools select results, defaulting to five event rows in this mode. `timeline query` also uses full-case scope. Legacy snapshot defaults/reader outputs remain unchanged. `evidence.list` and `findings.inspect` accept optional `cursor`/`limit`; when `truncated` is true, advance the cursor by the returned count.

Full-case diagnostics enable a separate measurement profile: exact declared exception/termination fields and first five source symbol slots; report condition flags; conflicting incident declarations; Jetsam reasons/footprints; same-declared-process/OS/build resource observations within five minutes. Combined text OS/build fields are split only by a bounded trailing-parenthesis grammar. Missing symbols remain unknown; numeric image offsets are not treated as stable cross-report identities. No symbolication, executable identity authentication or causal verdict is performed. Counts use all selected observations; each finding includes at most eight supporting and eight contrary references with explicit omitted counts. Full events remain queryable.

The expanded coverage view lists selected event-type counts as valid query filter values, plus diagnostic schema-status counts. `legacy_status_not_recorded` means the earlier reader did not store that qualification field. These counts describe selected observations, not unimported sources or a qualified device history.

`--diagnostic-details` separately authorizes process names, exception/termination details, source symbols and OS/build fields. It excludes executable paths, bundle/domain identifiers and unrelated source text; `--include-identifiers` remains the broader existing option. Evidence strings can still contain sensitive data or malicious instructions. The exact snapshot and access profile change the remote-consent digest. Configuration alone never transmits evidence. A loopback model is not independently private unless its own egress is controlled.

Source semantics: Apple's [crash JSON field reference](https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report) and [Jetsam interpretation](https://developer.apple.com/documentation/xcode/identifying-high-memory-use-with-jetsam-event-reports). These document field meanings, not execution qualification of this implementation. No upstream implementation or genuine diagnostic fixture was incorporated.

### Exact diagnostic queries

Use `timeline query --case CASE_ID --where '{"nonfatal":true}' --limit 5`
to retrieve explicit nonfatal observations, or `--where '{"reason":"vm-pageshortage"}'`
for source-declared Jetsam reasons. `--where '{"action_taken":"none"}'` selects
resource reports explicitly recording no action. These queries work without AI.

The same optional `where` object is available to `timeline.query`,
`diagnostics.search` and `network.query`. Its closed fields are `exception_type`,
`termination_namespace`, `action_taken`, `resource_kind`, `reason`, `os_build`,
`nonfatal` and `simulated`. All conditions combine with AND; strings compare
exactly and booleans require JSON `true`/`false`. Missing/null values match neither
boolean. A false nonfatal flag alone is not proof of a fatal termination.

Filters inspect only the authorized snapshot, never hidden originals. For
example OS build requires diagnostic detail authorization; a zero-match result
in a minimized view cannot establish its absence in the source. Original event
IDs, source locators and page ordering are retained. No SQL, regex, arbitrary
field, file path or model-supplied expression is accepted.

Resource neighbors use reported start/end intervals when both are valid, with a
300-second margin; missing ends remain point observations and reversed intervals
are excluded. Reports separate interval-contained pairs from nearby observations.
These counts do not establish continuous activity, a common device or causation.
Original interval fields and their byte locations remain available for review.
