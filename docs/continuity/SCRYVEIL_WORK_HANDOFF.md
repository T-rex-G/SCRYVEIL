# SCRYVEIL engineering handoff

Updated 2026-10-24. Branch: `feat/forensic-core-genesis`; [PR #1](https://github.com/T-rex-G/SCRYVEIL/pull/1), open and unmerged. **Verified implementation: `cd7a55e530ef8922a41e5b95a18c48cd2ddbd0de`**, tree `c04644b3af937200309fed8a0ef7c2e50f43d4e0`. This record is published in a documentation descendant; `git rev-parse HEAD` identifies that descendant. Reconcile newer commits/working-tree edits before continuing. Original owner checkpoint: `948ec27395765cdbde9f39fb38d1753ff24e2a8e`. Never merge automatically.

## Completed and verified

- Preserved offline NDJSON/APR, original byte hashes, source clocks/locations, legacy IPS/JSON-v2 interpretation, deterministic findings and existing case/report contracts.
- Added bounded corrective feedback, explicit literal-filter guidance, compact deterministic model context, and termination after three identical or five consecutive rejected actions. No automatic repair or execution of invalid model requests.
- Nonempty investigations must actually retrieve an event, provide an exact grounded fact and inspect available deterministic findings. Empty cases must state an unanswered question. Finding IDs alone do not authorize claims about unread event fields. These are completion floors, not semantic quality scores.
- Preserved all eleven read-only tools, Linux syscall isolation, provider broker, single-case scope, budgets and remote disclosure consent. Untrusted strings remain data. No new framework, implementation language, acquisition or unrestricted tool was added.
- Added `apple_ips_resource_text_v1` for observed sampling-duration annotations, separate header milliseconds and exact text/JSON locations. Stored v2 text cases retain their original reader, warnings and interpretation. Text versions 29/55/60 have a structurally recognized partial subset; **73 remains unqualified**. Types 202/206/509/120 remain unsupported.
- Added offline owner command `diagnostics coverage`: snapshot omissions, unobserved diagnostic categories, profile/schema/partial counts, unknown source times, artifact-linked warnings and explicitly unknown unimported/rejected-file counts. Default AI coverage/tool contracts remain unchanged.

## Validation evidence

[Core CI 40090406608](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40090406608), job `120861735392`, passed **310 tests in 12.91s**, Ruff/format, strict mypy over 19 runtime modules, Bandit, synthetic-only hygiene, all four demos, sdist/wheel and installed-wheel checks. Local full suite passed 309 tests, followed by all 23 resource tests including one added isolated-worker attack test; final CI includes all 310. Model inference at this parser checkpoint was deliberately skipped, not qualified by a green skipped job.

Compatibility scripts execute historical code: ten NDJSON cases/twenty reports at `edbe9b1`, six diagnostic cases at `cccacdd`, and five v2/annotated-text cases at `948ec27`. Existing analysis reports and investigator snapshots remain byte-identical; reimports preserve reader/events/warnings/hashes. Independent generated fixtures only; 18 allowlisted fixtures, no owner exports.

[Thirty-report measurements](../validation/resource-recovery-measurements.json): three fresh processes, eight mock steps, repeated identical reports and unchanged originals/state; 0.425–0.523s process wall, 16896 KiB parent RSS, 76571-byte snapshot, **185203/200000 conservative token units**. This repairs the earlier six-step budget failure but does not qualify the smaller default budget or larger cases. Runtime hashes match the published implementation; the dirty-tree flag identifies measurements made before commit. Earlier five-run deterministic/20,000-record evidence is retained, not relabeled as a current full-volume qualification.

## Actual-model evidence: quality gate remains failed

| Execution | Source | Reconciled result |
|---|---|---|
| `40038068563` | `948ec27` | One mechanical completion among six scenarios; no accepted facts. Completed case retrieved no events. Injection unexposed; fault recovery failed. |
| `40070459394` | `dd27bf6` | Valid actions but literal-search misuse; zero events/facts; empty case completed with no explanation. Nonempty empty-final loops correctly rejected. |
| `40090072225` | `4f55541` | Recurrence/injection each queried three events, then timed out. Zero completed investigations or accepted facts. Fault response fabricated six event entries in rejected envelopes; empty-case actions remained malformed. |

The two earlier 1.5B failures are also retained. See [reconciliation](../validation/qwen3-reconciliation.md) and [changed-runtime comparison](../validation/qwen3-recovery-comparison.md) for original JSON, actions, contexts, resources and interpretation. No unchanged experiment was repeated: each comparison followed a documented runtime correction. The second comparison deliberately predates the new resource reader to keep forensic inputs unchanged.

In the latest run, attack text was submitted to the adapter, but the response timed out; model processing/reaction and resilience are unmeasured. Zero final-field-fact attempts does not mean zero hallucinations: fabricated tool-result envelopes were manually identified. No deterministic finding review, contradiction evaluation or hypothesis revision was completed. All generated originals/state remained unchanged and no forbidden tool was accepted.

Qwen3 4B CPU/non-thinking is not a qualified investigator. The same first-request context succeeded previously but timed out in the last run; latency cause is not isolated. Native per-request timing/queue/cancellation records were not retained. Do not claim the failure is solely model intelligence or solely host performance. Other models, external providers and actual-model handling of the new annotation reader remain untested. Scripted mock success is not model reasoning.

## Highest-priority unfinished work

1. Instrument per-request/server timing and cancellation using only generated evidence, then select a justified model/resource profile and a controlled comparison. Preserve the questions, ground truth, permission boundary, exact claims and consent. Do not repeat the unchanged full experiment or simply raise limits to conceal failures.
2. Genuine Apple-export/version qualification remains open. Version 73 is a compatibility lead, not verified schema support. Do not access any owner files without separate explicit approval. Preserve old reader identities for future interpretation changes.
3. Expand incomplete-evidence handling toward indexed retrieval/secure sysdiagnose members only after the P0 gates have defensible evidence. Case limit remains 32 artifacts/20000 events; default snapshot selects the earliest 2000 (max 20000). Unimported/rejected files and missing device history remain unknown. Backups, archives, profiles, PCAP, Android and live acquisition remain unsupported.

No implementation is left unpublished at the code checkpoint. Remaining work is qualification/instrumentation, not an unrecorded patch. Detailed parser research and limits: [resource continuation](../validation/resource-format-continuation.md). ADR-001/002 remain applicable; no language/framework migration is justified by these results.

## Reproduction and pending authorizations

Use pinned Python 3.12 developer dependencies (`requirements-dev.lock`, then editable install). Run `python -m pytest -q`, Ruff check/format, mypy, Bandit, `scripts/hygiene.py`, all four demos, both compatibility scripts, build, and demos from a fresh installed wheel outside the checkout. Linux/libseccomp is required; unsupported isolation fails closed. `scripts/measure_diagnostic_formats.py` reproduces the 30-report workload. `scripts/model_qualification.py --mock` validates only scripted mechanics.

The expensive model workflow requires the literal `[model-qualification]` marker in the selected head commit message. Documentation checkpoints must omit it. Pins, generation and loopback-only controls are recorded in the workflow and `scripts/run_model_experiment.py`. No private files or API credentials may enter that harness, Git or CI.

Pending separate owner authorization: receiving/processing private diagnostics; device connection or acquisition; transmitting private evidence externally. None occurred in this continuation. A reference to files in prior conversation/storage is not authorization. Continue independently authorized work using public structural research and fictional fixtures. No private evidence is required for the next timing/instrumentation task.
