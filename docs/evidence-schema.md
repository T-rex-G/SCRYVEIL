# Versioned evidence contracts

`schemas/case-and-report-v0.1.0.schema.json` is JSON Schema draft2020-12 with local `$defs` for Case, Artifact, Event, Finding, Hypothesis, Relation, Coverage, AuditEvent, RuleRun, Review and redacted Report. Top-level `$ref` is Case; use `#/$defs/Report` for exports. No remote schema fetch needed. Typed Event/Finding dataclasses are constructed by validated parser/rule paths; storage currently uses typed dictionaries with semantic validation, not fully typed persistence models. Schema conformance is independently tested with jsonschema (development-only). Runtime does input field validation and source/semantic export validation without a schema-library dependency.

## Input records

- Synthetic events: `schema=scryveil.events/1`, `synthetic=true`, event_type `network.observation` or `context.approved_sync`, explicit-offset timestamp, app (string or null), domain. Context also has `valid_until` and is an unverified imported declaration, not a signed analyst approval. This interface intentionally does not claim live collection.
- Indicators: `schema=scryveil.indicators/1`, domain, source, license, explicit-offset created/updated dates. Source/license/date are preserved private, and raw artifact hash identifies the set. This is not STIX, signed intelligence or an authenticity check.
- Experimental APR: `type=access` with `timeStamp`, `accessor.identifier`, category, optional kind/identifierType; `type=networkActivity` with domain, optional bundleID/hits/timeStamp/firstTimeStamp. Summary timestamps are first/latest reported contact, never a synthesized series. Missing timestamp remains null. Unsupported record types yield per-line warning codes; no inferred session end.

The default route accepts NDJSON, not JSON arrays, plist, archive or SQLite, classifying content rather than suffix. The separate explicit `--format ips` route dispatches the JSON-envelope IPS subset to JSON or bounded type-145 disk-write text interpretation. Integers used as counts are bounded; duplicate JSON keys, NaN/Infinity tokens, overlong records and invalid date offsets fail visibly. Unknown extra source fields remain in preserved raw bytes but are not propagated to report attributes.

## Identity, clocks and canonicalization

Artifact ID: `artifact-` + SHA256(exact input bytes). NDJSON Event ID: `evt-` + SHA256(UTF8(artifact ID + ':' + physical line number)). IPS uses artifact ID + ':ips:' + normalized row ordinal; the exact body region starts on line 2, with `attributes.json_pointer` selecting a process row. Each event stores byte offset/length, physical line, parser/version, exact original timestamp, source offset, source precision and normalized UTC microseconds. Original repeated lines have distinct IDs; equal timestamps do not increase distinct sample count. Same artifact imported again does not duplicate events; conflicting synthetic/import provenance is rejected.

Source-observed time differs from `Artifact.collection_time` (null: unknown) and `Artifact.imported_at`. Event ingestion time is obtained through its artifact reference, not fabricated as observation time. Formatting precision is not clock accuracy. Source skew is unknown; backward source ordering is a visible warning, not proof of clock compromise. `-00:00` unknown offsets and naive timestamps are rejected.

Canonical format v0.1.0: CPython JSON, sorted keys, ASCII escapes, comma/colon separators, finite numbers only and trailing LF. Original source hashes are independent of serializer choice. Report digest is SHA256(canonical report excluding report_sha256). No RFC8785/cross-runtime canonical-number equivalence is claimed; a replacement runtime must match the golden serializer or introduce a versioned migration. Statistics have explicit rounding where needed; no calibrated infection probabilities.

## Validation and unknowns

Import validates record types, bounded fields, dates and domains. Export rehashes originals, reparses events, compares stored normalized content, recomputes rules/config, checks every support/contradiction/graph ID and confirms supporting event time is within finding interval. Metadata with no event time (e.g. indicators) is explicitly atemporal. Coverage intervals are extrema of available records, not continuous capture windows.

Assessments: observed/review-needed semantics are scope-specific; implemented findings use review_needed, indicator_match or inconclusive. Rule outcomes may use not_observed_in_scope or insufficient_evidence. No `device_clean`. Severity remains informational/unknown, separate from evidentiary assessment. Reviews append decisions without deleting evidence. Fine-grained entity resolver and multi-source causal/temporal joins are deferred; graph currently links artifacts, events and findings only.

Repeated report export from unchanged case/config is byte-identical. Separate independently created cases differ in UUID, clocks, audit and runtime metadata; semantic comparisons must explicitly project those fields out. A new import/review changes case history and therefore the report.

## Derived privacy review v1

`schemas/privacy-review-v1.schema.json` is a separate standalone JSON Schema for `scryveil.privacy-review/1`. It does not replace or mutate case/report 0.1.0. It defines redacted and explicit private views, source locators, artifact hashes, coverage, access intervals, network summaries and issue codes. `analyzer_version=1.0.0` versions this interpretation, not the product release. Reports bind to the case audit head and hash their complete canonical content before adding `report_sha256`.

Source records are re-read from verified originals to recover fields the initial normalized parser intentionally left in raw storage. Every selected APR record occurs exactly once in interval or network-summary support lists; duplicates remain supported source records. Complete interval endpoints must match their referenced timestamps and integer microsecond duration. Entity references group declared identifiers within the report, not independently verified devices or app installations. Raw interval identifiers and broadcaster strings remain private in the originals even in the identifier-enabled view. See privacy-review.md for status semantics.

## Diagnostic and investigation contracts

IPS parser `apple_ips_json_v1` / version `1.0.0` adds diagnostic.crash, diagnostic.resource and diagnostic.jetsam events to the existing 0.1.0 case schema. Legacy NDJSON case/report exports remain unchanged; older binaries are not promised to read these new event types. Reimport with a conflicting parser selection is rejected. Real-export conformance remains open.

New imports may use `apple_ips_diagnostic_v2` / `2.0.0`: 309/308 body v2 and 145 disk-write text Report Version 29. It adds diagnostic.exception and optional format/schema/partial-status, raw exception and aggregate resource fields. Stored v1 cases are reverified by their recorded reader, including formerly unqualified body-v2 cases. Reimport remains idempotent with its original interpretation; it still appends the normal reimport audit record. The generated version-104 compatibility fixture is not an assertion about modern Apple JSON body versioning.

Selected `field_locations` map normalized fields to original body JSON pointers, metadata-line pointers or exact text line byte spans. Grounded facts use these when present, otherwise the event's original body locator. They are produced by the trusted parser and checked by source reparse, not accepted from a model. Raw displayed resource quantities use decimal strings plus explicit units; unknown/invalid values remain null with warnings. Text event time is the report interval start, with a separate end time and source-offset/precision fields. No individual write events or exact bytes are synthesized from rounded accounting.

The investigator uses separately versioned tool inputs/results, agent actions, provider configuration, extension declarations and report schemas under `schemas/`. The worker validates closed schemas, case scope, budgets and exact claim references in executable code. JSON Schema is not permission enforcement. `evidence.read_excerpt` returns only a normalized projection, never arbitrary original bytes. See [operator guide](investigation.md) and [ADR-002](architecture/ADR-002-read-only-ai-investigation.md).
