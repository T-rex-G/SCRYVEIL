# Resource-format and incomplete-evidence continuation

Research and generated regression validation, 2026-10-24. This does **not** qualify the owner's private exports. No private diagnostic was received or processed. Types 309/308 body v2, type 298 and the earlier text subset remain available; types 202/206/509/120 remain explicitly unsupported.

## Independent structural evidence

- A [public author-posted type-145 report at commit `9f295469c47aa3d6e1fb8a421647e9e506544192`](https://github.com/rickmark/mojo_thor/blob/9f295469c47aa3d6e1fb8a421647e9e506544192/BackupAgent2.diskwrites_resource-2025-04-06-235507.ips) declares text Report Version 55. Its sampling-duration field has a decimal seconds value followed by an annotation describing how far the event begins before the samples.
- A [Brave developer issue, #48689](https://github.com/brave/brave-browser/issues/48689), posted 2025-08-25, last updated 2025-08-26 when inspected, supplies a Report Version 60 disk-write report. Its sampling annotation includes both the start gap and an event-end gap after sampling. This is first-hand bug-report material, not an authenticated acquisition.
- Both distinguish header milliseconds, body duration, sampled duration, writes duration and displayed resource quantities. These are not interchangeable clocks or individual write records. No upstream parser code or posted identifiers were copied. The new fixture uses independently chosen fictional names, times, amounts and gaps.
- Targeted public research did not establish Report Version 73's complete structure or semantics. The owner's format description remains a compatibility lead. The new fictional v73 fixture exercises shared field handling and **expects `unqualified_version`**, not a passing genuine-format gate.

## Implementation and preserved interpretation

New imports of disk-write text use reader `apple_ips_resource_text_v1`, version `1.0.0`. Versions 29/55/60 have a structurally recognized partial subset; all still lack authenticated genuine-export execution qualification. Other numeric versions, including 73, retain shared known fields with an explicit qualification warning. Stacks, per-process powerstats, sample loss and broader resource events are not interpreted.

The reader handles plain decimal seconds and the two observed sampling-annotation forms. It preserves the complete duration text, the displayed numeric precision, separate start/end gaps, and header `duration_ms` when it is a nonnegative bounded integer representation. Invalid suffixes, negative/exponential durations, unknown time forms and inconsistent metadata stay unknown with warnings. It does not infer an absolute sampling interval, replace body time with header metadata, convert rounded MB to exact bytes, or infer termination/compromise from `Action taken`.

Normalized annotation fields cite the exact original sampling line, including CRLF byte counts. Header milliseconds cite line 1 and `/duration_ms`. The source SHA-256 and original byte stream remain independently verifiable. Known values in an unqualified schema are still explicitly partial observations, not global format certification.

Existing `apple_ips_diagnostic_v2` text cases continue to use the historical parser, including its earlier inability to interpret annotated durations. Verification and reimport never upgrade stored evidence silently. `scripts/check_checkpoint_compatibility.py` now executes both historical checkpoints: six cases from `cccacdd` and five from `948ec27`, including a generated annotated v73 case. Old analysis reports and investigation snapshots remain byte-identical; reimports retain original readers, events, warnings and hashes. Future reinterpretation should be an explicit derived analysis, not a mutation of recorded lineage.

## Coverage that states what was examined

`scryveil --root PRIVATE_CASE_ROOT diagnostics coverage --case CASE_ID [--max-events 2000]` produces `scryveil.diagnostic-coverage/1` offline. It binds to the verified source/snapshot digests and distinguishes selected/omitted events, imported artifacts without selected events, diagnostic categories not observed in the selection, profile/schema/partial-interpretation counts, unknown source times and artifact-linked warnings. Legacy readers lacking profile metadata report `not_reported_by_reader` rather than implied qualification.

Unimported/rejected files are explicitly unknown; warning counts are not fabricated rejected-record counts. A category absent from the selected snapshot is not declared absent from the device. Source clocks, shared device identity, missing historical records and post-snapshot changes remain uncertain. No absence-of-IOC safety verdict is produced.

This is an owner-facing deterministic report. The eleven existing AI tools and default snapshot/coverage contracts are unchanged. Enriching the model's coverage view is a separate future adapter-contract qualification. No archive extraction, acquisition, new language or storage migration was introduced. The 32-artifact case bound and 2000-event default snapshot remain documented limits; the context fix does not remove either bound.

Reproduce with the resource/coverage tests, historical compatibility script and the standard regression/static/build/installed-wheel gates. The public fixture's v73 label does not authorize access to an owner's v73 report. Genuine-export conformance and additional format families remain open pending separate authorized qualification.

## Measured validation

Full local regression suite: 309 passed in 8.57s, followed by 23 resource tests including a new malicious-duration/real-isolated-worker denial test. Ruff/format, strict mypy over 19 modules, Bandit, synthetic hygiene, all historical compatibility checks, all four demos and a fresh installed wheel passed. The fourth demo now includes a separate fictional v73 case, checks exact sampling-line provenance and requires unqualified status.

[Three fresh-process measurements](resource-recovery-measurements.json) of 30 generated reports complete eight mock steps with repeated identical reports and unchanged source state: 0.425–0.523 seconds process wall, 16896 KiB parent RSS, 76571-byte snapshot, 185203 of the unchanged 200000 conservative token units. This is close to the chosen budget and does not qualify larger collections, actual-model reasoning, or the smaller default token budget. Runtime hashes identify the measured working tree; its source commit field is the parent checkpoint when the dirty flag is true. Earlier failed/successful measurements remain retained.

Published implementation checkpoint: `cd7a55e530ef8922a41e5b95a18c48cd2ddbd0de`. [Core CI 40090406608](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40090406608), job `120861735392`, passed **310 tests in 12.91s**, all static/security/hygiene checks, all three historical compatibility baselines, four demos and installed-wheel packaging. Model inference was intentionally skipped at this parser checkpoint; it is not an actual-model qualification result.
