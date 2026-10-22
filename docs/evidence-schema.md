# Versioned evidence contracts

`schemas/case-and-report-v0.1.0.schema.json` is JSON Schema draft2020-12 with local `$defs` for Case, Artifact, Event, Finding, Hypothesis, Relation, Coverage, AuditEvent, RuleRun, Review and redacted Report. Top-level `$ref` is Case; use `#/$defs/Report` for exports. No remote schema fetch needed. Typed Event/Finding dataclasses are constructed by validated parser/rule paths; storage currently uses typed dictionaries with semantic validation, not fully typed persistence models. Schema conformance is independently tested with jsonschema (development-only). Runtime does input field validation and source/semantic export validation without a schema-library dependency.

## Input records

- Synthetic events: `schema=scryveil.events/1`, `synthetic=true`, event_type `network.observation` or `context.approved_sync`, explicit-offset timestamp, app (string or null), domain. Context also has `valid_until` and is an unverified imported declaration, not a signed analyst approval. This interface intentionally does not claim live collection.
- Indicators: `schema=scryveil.indicators/1`, domain, source, license, explicit-offset created/updated dates. Source/license/date are preserved private, and raw artifact hash identifies the set. This is not STIX, signed intelligence or an authenticity check.
- Experimental APR: `type=access` with `timeStamp`, `accessor.identifier`, category, optional kind/identifierType; `type=networkActivity` with domain, optional bundleID/hits/timeStamp/firstTimeStamp. Summary timestamps are first/latest reported contact, never a synthesized series. Missing timestamp remains null. Unsupported record types yield per-line warning codes; no inferred session end.

Only NDJSON, not JSON arrays, plist, archive or SQLite. The parser sniffs content, not suffix. Integers used as counts are bounded; duplicate JSON keys, NaN/Infinity tokens, overlong records and invalid date offsets fail visibly. Unknown extra source fields remain in preserved raw bytes but are not propagated to report attributes.

## Identity, clocks and canonicalization

Artifact ID: `artifact-` + SHA256(exact input bytes). Event ID: `evt-` + SHA256(UTF8(artifact ID + ':' + physical line number)). Each event stores byte offset/length, physical line, parser/version, exact original timestamp, source offset, source precision and normalized UTC microseconds. Original repeated lines have distinct IDs; equal timestamps do not increase distinct sample count. Same artifact imported again does not duplicate events; conflicting synthetic/import provenance is rejected.

Source-observed time differs from `Artifact.collection_time` (null: unknown) and `Artifact.imported_at`. Event ingestion time is obtained through its artifact reference, not fabricated as observation time. Formatting precision is not clock accuracy. Source skew is unknown; backward source ordering is a visible warning, not proof of clock compromise. `-00:00` unknown offsets and naive timestamps are rejected.

Canonical format v0.1.0: CPython JSON, sorted keys, ASCII escapes, comma/colon separators, finite numbers only and trailing LF. Original source hashes are independent of serializer choice. Report digest is SHA256(canonical report excluding report_sha256). No RFC8785/cross-runtime canonical-number equivalence is claimed; a replacement runtime must match the golden serializer or introduce a versioned migration. Statistics have explicit rounding where needed; no calibrated infection probabilities.

## Validation and unknowns

Import validates record types, bounded fields, dates and domains. Export rehashes originals, reparses events, compares stored normalized content, recomputes rules/config, checks every support/contradiction/graph ID and confirms supporting event time is within finding interval. Metadata with no event time (e.g. indicators) is explicitly atemporal. Coverage intervals are extrema of available records, not continuous capture windows.

Assessments: observed/review-needed semantics are scope-specific; implemented findings use review_needed, indicator_match or inconclusive. Rule outcomes may use not_observed_in_scope or insufficient_evidence. No `device_clean`. Severity remains informational/unknown, separate from evidentiary assessment. Reviews append decisions without deleting evidence. Fine-grained entity resolver and multi-source causal/temporal joins are deferred; graph currently links artifacts, events and findings only.

Repeated report export from unchanged case/config is byte-identical. Separate independently created cases differ in UUID, clocks, audit and runtime metadata; semantic comparisons must explicitly project those fields out. A new import/review changes case history and therefore the report.
