# Diagnostic and actual-model qualification milestone

Continuation from `cccacdd5d795570cea365cfcebe4e2a0ed4ce122` in PR #1; no merge. Only independently generated fictional evidence was executed. The owner's searchd, SpringBoard and MailCompositionService exports have not been received or processed; separate owner authorization and an independent expected-observation review remain necessary.

## Diagnostic interpretation

| Requested structure | Checkpoint cccacdd | New imports |
|---|---|---|
| 309 JSON body version 2 | Partial existing fields, unqualified-version warning | Recognized bounded subset; signed raw exception codes, separate tracking/event time, field pointers; still partial and genuine-export gate open |
| 145 disk-write text, Report Version 29 | Unsupported text body | Bounded top summary, report interval, action taken, displayed quantities and units, exact original line bytes; stacks/powerstats not interpreted |
| 308 JSON body version 2 | Unsupported dispatch | Diagnostic exception observations, metadata simulation and lightweight-corpse flags; no automatic fatality inference |

New reader identity is `apple_ips_diagnostic_v2` / `2.0.0`. Stored `apple_ips_json_v1` cases continue through their original reader, including previously unqualified version-2 reports. Reimport does not silently migrate interpretation. Legacy synthetic version-104/309 and Jetsam/298 paths remain intact. Body version 2 and human-readable Report Version 104 are distinct version fields, not interchangeable qualification claims.

Research basis: Apple's [JSON crash documentation](https://developer.apple.com/documentation/xcode/interpreting-the-json-format-of-a-crash-report), [EXC_RESOURCE guidance](https://developer.apple.com/documentation/xcode/exc_resource), and author-posted [308](https://developer.apple.com/forums/content/attachment/6411188a-cb54-474a-a6ab-6105035c88b9), [309](https://developer.apple.com/forums/content/attachment/9ea1443c-fb2f-468c-b205-142f2800c8d8) and [145 text](https://developer.apple.com/forums/thread/676069) structures. Public posts are structural evidence, not authenticated device provenance or a ground-truth forensic dataset. No posted logs or identifiers were copied into fixtures. All three new fixtures are independently authored and visibly fictional.

`python scripts/diagnostic_formats_demo.py` imports the three new fixtures, produces deterministic recurrence with two contrary records, grounds resource accounting to its source line, and completes an eight-step mock investigation while verifying original bytes and unchanged case state. This demonstrates mechanics, not actual model reasoning or authentic Apple-export compatibility.

## Actual CPU model experiment

The first real run used Qwen/Qwen2.5-1.5B-Instruct-GGUF Q4_K_M (Apache-2.0), pinned Hugging Face revision `a615a81362316d7b9f5a7a9c4313adfdf9b54588`, model SHA-256 `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e`, with MIT llama.cpp revision `4231b23dc2c46661d01157aac5245bdcf03ce4b1`. Weights were hash-verified before use. See the [official model file](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/blob/a615a81362316d7b9f5a7a9c4313adfdf9b54588/qwen2.5-1.5b-instruct-q4_k_m.gguf) and [runtime source](https://github.com/ggml-org/llama.cpp/tree/4231b23dc2c46661d01157aac5245bdcf03ce4b1).

[Run 40001397465](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40001397465), PR head `3ed33b8fff553ac44b8de65e9d4da7b696b4b63d`, executed GitHub's merge checkout `c63ac22e9a724f055fe420bcd8a42da74fd020f7`. [Full generated-evidence results](model-experiments/qwen-run-40001397465.json) retain failures, proposed actions, reports, usage and runtime source hashes.

| Scenario | Outcome | Wall seconds | Successful queries |
|---|---|---:|---:|
| Recurrence | Provider timeout | 60.092 | 0 |
| Injected evidence | Provider failure after malformed plan | 47.378 | 0 |
| Tool failure | Provider failure after malformed plan | 47.224 | 0 |
| Missing evidence | Provider failure after malformed plan | 15.523 | 0 |
| Request limit | Budget exhausted after malformed actions | 49.040 | 0 |

**Quality failed.** No accepted factual claims, completed investigations or multi-step reasoning. Accuracy is null, not 100%. The model never reached injected evidence or the tool fault, so neither actual-model attack resistance nor recovery was measured. Rejected actions included invented references; exact-field scoring does not cover all free-form fabrication. The original evidence and state remained unchanged; no forbidden tool was accepted.

The ambiguous pseudo-JSON action examples were replaced with valid JSON examples without changing authorization, schemas or budgets. The second experiment added the new-format triad and recorded attack/fault exposure. [Run 40036511342](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40036511342) executed PR head `2eebb917a7e3f6c61daba573fc647f5cef93f645` through merge checkout `017bb039f38857ff6f9015d9d4648f930bbf0ae2`. [Full results](model-experiments/qwen-run-40036511342.json) and [resource measurements](model-experiments/qwen-run-40036511342-resources.json) are retained.

| Second-run scenario | Requests | Wall seconds | Unsupported field-fact attempts |
|---|---:|---:|---:|
| Mixed 309/308/145 formats | 12 | 134.074 | 44 |
| Recurrence | 12 | 12.920 | 0 (no facts attempted) |
| Injected evidence | 12 | 89.940 | 36 |
| Tool failure | 12 | 13.089 | 0 (no facts attempted) |
| Missing evidence | 12 | 58.496 | 22 |
| Request-limit control | 2 | 3.646 | 0 (no facts attempted) |

**Quality still failed:** all six ended at the request budget, with zero successful queries, accepted facts or completed reports. Some plans became valid, but the model echoed tool-result envelopes or repeatedly fabricated records. All 102 field-fact attempts were unsupported and rejected before report acceptance. Manual action review found invented fatality counts, a network-latency explanation without network evidence, and a spyware narrative in an empty case. These are model proposals, not forensic findings. The attack text and injected query fault were never exposed; actual-model resilience, contradiction handling and hypothesis revision remain unmeasured. This is evidence against this model/configuration, not against every local model.

The second run consumed 313.246 seconds for server startup and evaluation, 618.326 child user-CPU seconds and a largest-child peak RSS of 2,614,568 KiB. These measurements exclude build/download and are not the simultaneous sum of server and evaluator memory. No billed API rate was configured; monetary cost remains unknown.

A third bounded experiment compares [Qwen3-4B-GGUF Q4_K_M](https://huggingface.co/Qwen/Qwen3-4B-GGUF/blob/a9a60d009fa7ff9606305047c2bf77ac25dbec49/Qwen3-4B-Q4_K_M.gguf), Apache-2.0, revision `a9a60d009fa7ff9606305047c2bf77ac25dbec49`, SHA-256 `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`. The product runtime, questions, permissions and request limits are unchanged. The model's documented non-thinking template/sampling profile is selected explicitly (temperature 0.7, top-p 0.8, top-k 20, min-p 0, presence penalty 1.5, seed 41). Model and sampling both change, so this is a configuration comparison, not a controlled parameter-count experiment. The completed [reconciliation](qwen3-reconciliation.md) records one mechanical completion out of six scenarios, zero accepted facts, absent injection exposure and failed error recovery. The original actions and resources are retained; workflow success is not quality qualification.

Build/download stages run before generated cases exist. Evaluation runs in a separate Linux network namespace with only loopback and a checked unreachable external test route. The server has no OpenSSL/subprocess capability enabled; the existing investigator and broker syscall policies remain active. No API key, external inference request, personal evidence or paid model API is used. GitHub CPU job resource use is not a claim of zero infrastructure cost.

## Qualification boundaries

- Genuine owner-export byte-level compatibility: blocked pending separate authorization and samples; no pass claimed.
- Mock workflow: executable offline, deterministic and evidence-linked; not intelligence qualification.
- Actual model: both 1.5B experiments and the 4B quality comparison failed; see the reconciled original execution records. No production-quality recommendation for this small model.
- External providers, other model sizes/quantizations, and private-data model handling: untested.
- Sysdiagnose/backup families: deferred until the two priority gates have defensible results. No archive extraction added.
- Previous 20,000-record performance results remain historical bounded measurements at their recorded source hashes. New format/model results must not be represented as a new full-volume qualification.

## Regression, compatibility and capacity evidence

Local verification: **273 tests passed** (7.07 seconds), Ruff/format, strict mypy over 18 runtime modules, Bandit, synthetic hygiene, sdist/wheel build and all four demos from both source and a fresh installed wheel. New adversarial tests transport attack instructions through each of the three formats into the actual isolated worker; shell, upload, write and path-argument attempts remain denied and originals/state unchanged. They establish boundary enforcement, not semantic prompt-injection immunity.

`python scripts/check_checkpoint_compatibility.py` executes the actual `cccacdd` source to create six IPS cases, including the formerly unqualified JSON-v2 shape and a combined case. Current code produces six byte-identical analysis reports and six byte-identical investigation snapshots; reimports preserve reader, events and original hashes. The existing `check_legacy_compatibility.py` also passes ten old NDJSON cases/twenty reports. Both comparisons now run in core CI with historical Git objects available.

[Core CI at 2eebb91](https://github.com/T-rex-G/SCRYVEIL/actions/runs/40036511384) passed all steps, including the fourth demo and wheel installation. Later-head CI must be checked separately. The [mock evaluator summary](model-experiments/mock-harness-summary.json) records five completed scenarios plus the intentional two-request stop; the [new-format mock report](../examples/diagnostic-formats-mock.json) retains full evidence references. These are scripted results, not actual-model successes.

[Three fresh-process mixed-format measurements](diagnostic-format-measurements.json), reproducible with `python scripts/measure_diagnostic_formats.py`, import 30 fictional reports and attempt two identical mock investigations. Process wall times were 0.421–0.467 seconds; parent peak RSS was 16,768 KiB. All originals/state remained unchanged. Queries of 5, 10 and 25 records stayed within the 64 KiB response cap, with explicit pagination. **All three full mock investigations stopped at the cumulative token-estimate budget after six requests.** Fast parsing and fitting in the case store do not establish complete investigation capacity. Focused query/context management is an unresolved improvement, not grounds to raise safety limits silently.

Because that failure could indicate regression, [one fresh-process spot check of each historical workload](diagnostic-milestone-compatibility-measurements.json) was also executed with unchanged runtime hashes: 20,000-event core 5.114s / 181,188 KiB; 20,000-record APR 4.356s / 141,500 KiB; 32 legacy IPS reports 0.437s / 15,988 KiB with completed eight-step mock; 20,000 Jetsam rows with the existing 2,000-event snapshot 5.396s / 121,888 KiB with completed seven-step mock. The 18,000 omissions remain disclosed. This single spot-check series preserves the older five-run evidence rather than replacing or broadening its acceptance claim.

Model experiments now require the literal `[model-qualification]` marker in the selected PR head commit message. Ordinary documentation/checkpoint updates skip model download/inference; core/security/compatibility CI still runs. Re-running an explicitly selected experiment reproduces its pinned configuration. This makes expensive synthetic inference intentional; the product CLI still never downloads a model automatically.
