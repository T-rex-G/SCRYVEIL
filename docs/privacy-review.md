# Local App Privacy Report review

Use an existing consent-scoped case containing imported APR NDJSON:

```sh
umask 077
scryveil --root /private/cases privacy report --case CASE_ID --format json
scryveil --root /private/cases privacy report --case CASE_ID --format markdown
scryveil --root /private/cases privacy report --case CASE_ID --include-identifiers
```

Replace the example root and CASE_ID with your local values. Run `python scripts/privacy_demo.py` for a complete synthetic demonstration needing no phone. Only generated fixtures belong in the repository; keep real exports and generated private reports on an owner-controlled host.

## What the review answers

- Which declared app identifiers have recorded accesses to each supported resource?
- Which access boundaries form one unambiguous interval, and which are incomplete or conflicting?
- Which normalized domains appear in network summaries, with what reported counts, first/latest time and source attribution?
- Which exact preserved records support each observation, and which records could not be interpreted?

The access resources are camera, contacts, location, media library, microphone, photos and screen recording. Unknown resources remain `unknown` with an issue. Recorded accesses do not prove that content was saved, transmitted or obtained without permission.

## Interval decisions

| Status | Interpretation | Duration |
|---|---|---|
| complete | One distinct supported begin and end, matching declared identity/resource/broadcaster, ordered source times | Exact integer microseconds between recorded boundaries |
| missing_begin | End boundary present, beginning absent in this artifact | Unknown |
| missing_end | Begin boundary present, ending absent in this artifact | Unknown |
| ambiguous | Multiple distinct boundaries or conflicting declared identities/resources/broadcasters | Unknown |
| unresolved_identity_or_kind | Missing interval/app identity, unsupported boundary/resource or unusable broadcaster | Unknown |
| invalid_time_order | Unique end precedes unique begin on the normalized source clock | Unknown |

Pairing uses a shared interval identifier within a single original artifact. File order is not chronology; timestamps carry their explicit UTC offsets. Source clock error and discontinuities are unknown. Exact duplicate bytes, excluding line endings, retain separate evidence references but count once when deciding whether a boundary is unique. A repeated identifier with multiple distinct begin/end records is ambiguous even if one possible pairing looks plausible.

## Network decisions

`reported_hits` remains the count in its source record. Separate rows can overlap in time, context or collection window, so the review does not add them. Empty/unknown counts and dates remain null. `AppInitiated` and `NonAppInitiated` are source attribution labels; they do not distinguish background execution, prove user intent or establish malicious activity. `flagged_by_source` and `not_flagged_by_source` describe the source's tracking classification; neither is a device safety assessment. Unknown values produce issue codes. No DNS, URL, threat-feed or model call occurs.

## Provenance and privacy

The report records artifact SHA-256, byte/line locators, source time/offset/precision, synthetic provenance, all supporting event IDs, case audit tip, analyzer version and a digest over canonical JSON without its digest field. Metadata export does not authenticate the source against an attacker able to rewrite the entire case. Every report revalidates stored sources. The original state and normal analysis reports are unchanged.

Default JSON and Markdown use report-local app/domain references. They are neither stable global identifiers nor evidence that different exports concern the same device. `--include-identifiers` makes app/domain identifiers, network context and domain owner visible in **JSON only**, using escaped JSON strings. Review this output locally. Raw interval identifiers, broadcaster strings and arbitrary extra fields remain only in originals. Timings, hashes and relationships remain sensitive even with default redaction.

A successful command means report generation succeeded. Incomplete intervals, source parse failures and unsupported fields remain in statuses, `coverage`, artifact warnings and `issues`. An empty report is absence of usable supplied APR records, never a clean-device result.

## Qualification status

Documented shapes and independently generated regression data have been tested. No physical device, Apple-produced export or per-iOS-version compatibility has been verified. Before relying on a real export, compare its recorded boundaries with owner-verified activity locally, record device/OS/export provenance privately, and examine all parse warnings. Never submit that export to public CI, an issue or a model for qualification.
